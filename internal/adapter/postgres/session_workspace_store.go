package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/meshtransit/meshtransit/internal/audit"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
	"github.com/meshtransit/meshtransit/internal/workspace/selection"
)

const listSessionWorkspacesSQL = `SELECT mesh_ops.list_session_workspaces_v1(` + sessionArguments + `)::TEXT`

const switchSessionWorkspaceSQL = `SELECT session_version, workspace_public_id::TEXT, replayed
FROM mesh_ops.switch_account_session_workspace_v1(` + sessionArguments + `,$10::UUID,$11::UUID)`

const appendSessionWorkspaceSwitchEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
 $1::BIGINT,$2::UUID,$3::UUID,$4::BIGINT,$5::BYTEA,$6::BYTEA,
 'account_session',$7::UUID,$8::BIGINT,NULL::BIGINT,$9::UUID,'account_session.workspace_switched','identity.session',
 $10::UUID,NULL::BYTEA,$11::BYTEA,$12::JSONB,'identity.account_session.workspace_switched',$12::JSONB)`

// SessionWorkspaceStore lists and switches the Workspace bound to an Account Session.
type SessionWorkspaceStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

// NewSessionWorkspaceStore uses the runtime pool.
func NewSessionWorkspaceStore(pool *Pool, options AccountSessionOptions) (*SessionWorkspaceStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, selection.ErrInvalid
	}
	return &SessionWorkspaceStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

func (store *SessionWorkspaceStore) begin(ctx context.Context) (accountSessionTransaction, error) {
	if ctx == nil || store == nil || store.database == nil {
		return nil, selection.ErrInvalid
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return nil, selection.ErrUnavailable
	}
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return nil, errors.Join(selection.ErrUnavailable, err, rollbackAccountSessionTransaction(tx))
	}
	return tx, nil
}

// sessionWorkspaceError maps the schema 103 error classes; anything else is uncertain.
func sessionWorkspaceError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return selection.ErrForbidden
	}
	var databaseError *pgconn.PgError
	if errors.As(err, &databaseError) {
		switch databaseError.Code {
		case "42501":
			return selection.ErrForbidden
		case "22023":
			return selection.ErrInvalid
		case "P0002":
			return selection.ErrNotAvailable
		case "40001":
			return selection.ErrSessionChanged
		}
	}
	return errors.Join(selection.ErrUnavailable, err)
}

type sessionWorkspaceRecord struct {
	WorkspaceID string `json:"workspace_id"`
	DisplayName string `json:"display_name"`
	DisplayCode string `json:"display_code"`
	Owner       bool   `json:"owner"`
	Current     bool   `json:"current"`
}

// List reads the bounded set of Workspaces the Session may switch to.
func (store *SessionWorkspaceStore) List(ctx context.Context, session accountsession.Session) (_ []selection.Candidate, resultErr error) {
	if !session.IsValid() {
		return nil, selection.ErrInvalid
	}
	tx, err := store.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx)) }()
	var encoded *string
	if err := tx.QueryRow(ctx, listSessionWorkspacesSQL, sessionQueryArguments(session)...).Scan(&encoded); err != nil {
		return nil, sessionWorkspaceError(err)
	}
	if encoded == nil {
		return nil, selection.ErrForbidden
	}
	var records []sessionWorkspaceRecord
	if err := json.Unmarshal([]byte(*encoded), &records); err != nil || len(records) > selection.MaxCandidates {
		return nil, selection.ErrInvalid
	}
	candidates := make([]selection.Candidate, 0, len(records))
	for _, record := range records {
		workspaceID, idErr := workspace.ParseID(record.WorkspaceID)
		code, codeErr := identity.ParseDisplayCode(record.DisplayCode)
		if errors.Join(idErr, codeErr) != nil {
			return nil, selection.ErrInvalid
		}
		candidates = append(candidates, selection.Candidate{WorkspaceID: workspaceID, DisplayName: record.DisplayName,
			DisplayCode: code, Owner: record.Owner, Current: record.Current})
	}
	return candidates, nil
}

// Switch rebinds the Session and appends one audit/outbox record on the
// Deployment stream. A replay appends nothing.
func (store *SessionWorkspaceStore) Switch(ctx context.Context, command selection.SwitchCommand) (_ selection.SwitchResult, resultErr error) {
	if !command.IsValid() {
		return selection.SwitchResult{}, selection.ErrInvalid
	}
	var ids [3]publicid.ID
	for index := range ids {
		id, err := publicid.New()
		if err != nil {
			return selection.SwitchResult{}, selection.ErrUnavailable
		}
		ids[index] = id
	}
	change, event, outbox := ids[0], ids[1], ids[2]
	tx, err := store.begin(ctx)
	if err != nil {
		return selection.SwitchResult{}, err
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx))
		}
	}()
	args := append(sessionQueryArguments(command.Session), command.WorkspaceID.String(), change.String())
	var version int64
	var workspaceText string
	var replayed bool
	if err := tx.QueryRow(ctx, switchSessionWorkspaceSQL, args...).Scan(&version, &workspaceText, &replayed); err != nil {
		return selection.SwitchResult{}, sessionWorkspaceError(err)
	}
	if workspaceText != command.WorkspaceID.String() || version <= 0 {
		return selection.SwitchResult{}, selection.ErrInvalid
	}
	if !replayed {
		if err := appendSessionWorkspaceSwitchEvidence(ctx, tx, command, version, change, event, outbox); err != nil {
			return selection.SwitchResult{}, errors.Join(selection.ErrUnavailable, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		committed = true
		return selection.SwitchResult{}, errors.Join(selection.ErrUnavailable, err)
	}
	committed = true
	return selection.SwitchResult{WorkspaceID: command.WorkspaceID, SessionVersion: version, Replayed: replayed}, nil
}

func appendSessionWorkspaceSwitchEvidence(ctx context.Context, tx accountSessionTransaction,
	command selection.SwitchCommand, version int64, change, event, outbox publicid.ID) error {
	var streamID, sequence int64
	var previous []byte
	if err := tx.QueryRow(ctx, lockAccountSessionLogoutAuditStreamSQL,
		command.Session.DeploymentID().String()).Scan(&streamID, &sequence, &previous); err != nil {
		return err
	}
	if streamID <= 0 || sequence <= 0 || len(previous) != sha256.Size {
		return selection.ErrInvalid
	}
	previousWorkspace := ""
	if login, ok := command.Session.LoginWorkspaceID(); ok {
		previousWorkspace = login.String()
	}
	payload, err := json.Marshal(struct {
		SessionID         string `json:"session_public_id"`
		PrincipalID       string `json:"principal_public_id"`
		PreviousWorkspace string `json:"previous_workspace_id,omitempty"`
		WorkspaceID       string `json:"workspace_id"`
		SessionVersion    int64  `json:"session_version"`
	}{command.Session.ID().String(), command.Session.PrincipalID().String(), previousWorkspace,
		command.WorkspaceID.String(), version})
	if err != nil {
		return err
	}
	after := sha256.Sum256(payload)
	var previousHash [32]byte
	copy(previousHash[:], previous)
	actor := publicid.ID(command.Session.PrincipalID())
	sessionID := publicid.ID(command.Session.ID())
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: previousHash, EventID: event, ChangeID: change,
		AggregateKind: "account_session", AggregateID: sessionID, AggregateVersion: version,
		ActorPrincipalID: actor, Action: "account_session.workspace_switched", Permission: "identity.session",
		CorrelationID: command.CorrelationID, AfterSemanticHash: after, AuditPayloadHash: after,
		OutboxEventClass: "identity.account_session.workspace_switched", OutboxPayloadHash: after,
	})
	if err != nil {
		return err
	}
	var appended int64
	return tx.QueryRow(ctx, appendSessionWorkspaceSwitchEvidenceSQL, streamID, event.String(), outbox.String(), sequence,
		previousHash[:], eventHash[:], sessionID.String(), version, actor.String(), command.CorrelationID.String(),
		after[:], payload).Scan(&appended)
}
