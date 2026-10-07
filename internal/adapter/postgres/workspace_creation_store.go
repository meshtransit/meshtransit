package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/meshtransit/meshtransit/internal/audit"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace/creation"
)

const createWorkspaceSQL = `SELECT workspace_public_id::TEXT, workspace_display_code, workspace_version,
 workspace_created_at, replayed
FROM mesh_ops.create_workspace_v1(` + sessionArguments + `,
 $10::UUID,$11::TEXT,$12::UUID,$13::UUID,$14::UUID,$15::UUID,$16::UUID,$17::CIDR,$18::UUID)`

const appendWorkspaceCreationEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
 $1::BIGINT,$2::UUID,$3::UUID,$4::BIGINT,$5::BYTEA,$6::BYTEA,
 'workspace',$7::UUID,1,NULL::BIGINT,$8::UUID,'workspace.created','workspace.create',
 $9::UUID,NULL::BYTEA,$10::BYTEA,$11::JSONB,'workspace.created',$11::JSONB)`

// WorkspaceCreationStore commits Account-initiated Workspace creation.
type WorkspaceCreationStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

// NewWorkspaceCreationStore uses the runtime pool.
func NewWorkspaceCreationStore(pool *Pool, options AccountSessionOptions) (*WorkspaceCreationStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, creation.ErrInvalid
	}
	return &WorkspaceCreationStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

func workspaceCreationError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "42501":
			return creation.ErrForbidden
		case "MTE01":
			return creation.ErrEntitlementMissing
		case "MTE02":
			return creation.ErrEntitlementExpired
		case "MTL01":
			return creation.ErrDeploymentLimit
		case "MTL02":
			return creation.ErrAccountLimit
		case "23505":
			return creation.ErrConflict
		case "22023":
			return creation.ErrInvalid
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return creation.ErrForbidden
	}
	return errors.Join(creation.ErrUnavailable, err)
}

// Create runs create_workspace_v1 and appends one audit/outbox record for a
// new Workspace. A replay appends nothing.
func (store *WorkspaceCreationStore) Create(ctx context.Context, command creation.Command) (_ creation.Result, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !command.IsValid() {
		return creation.Result{}, creation.ErrInvalid
	}
	var ids [8]publicid.ID
	for index := range ids {
		id, err := publicid.New()
		if err != nil {
			return creation.Result{}, creation.ErrUnavailable
		}
		ids[index] = id
	}
	change, event, outbox := ids[0], ids[1], ids[2]
	prefix, err := randomWorkspaceULA()
	if err != nil {
		return creation.Result{}, creation.ErrUnavailable
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return creation.Result{}, creation.ErrUnavailable
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx))
		}
	}()
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return creation.Result{}, errors.Join(creation.ErrUnavailable, err)
	}
	args := append(sessionQueryArguments(command.Session), command.WorkspaceID.String(), command.DisplayName,
		ids[3].String(), ids[4].String(), ids[5].String(), ids[6].String(), ids[7].String(), prefix.String(),
		change.String())
	var workspaceID, displayCode string
	var version int64
	var createdAt time.Time
	var replayed bool
	if err := tx.QueryRow(ctx, createWorkspaceSQL, args...).Scan(&workspaceID, &displayCode, &version, &createdAt,
		&replayed); err != nil {
		return creation.Result{}, workspaceCreationError(err)
	}
	code, err := identity.ParseDisplayCode(displayCode)
	if err != nil || workspaceID != command.WorkspaceID.String() || version <= 0 {
		return creation.Result{}, creation.ErrInvalid
	}
	if !replayed {
		if err := appendWorkspaceCreationEvidence(ctx, tx, command, change, event, outbox, code); err != nil {
			return creation.Result{}, errors.Join(creation.ErrUnavailable, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		committed = true
		return creation.Result{}, errors.Join(creation.ErrUnavailable, err)
	}
	committed = true
	return creation.Result{WorkspaceID: command.WorkspaceID, DisplayName: command.DisplayName, DisplayCode: code,
		Version: version, CreatedAt: createdAt.UTC(), Replayed: replayed}, nil
}

// lockWorkspaceStreamHeadSQL locks the Workspace's own audit stream, where
// evidence about the Workspace itself (creation, name, roles) is chained.
const lockWorkspaceStreamHeadSQL = `SELECT stream_internal_id,next_sequence,latest_event_hash
FROM mesh_audit.lock_workspace_stream_head($1::UUID,$2::UUID)`

func appendWorkspaceCreationEvidence(ctx context.Context, tx accountSessionTransaction, command creation.Command,
	change, event, outbox publicid.ID, code identity.DisplayCode) error {
	var streamID, sequence int64
	var previous []byte
	if err := tx.QueryRow(ctx, lockWorkspaceStreamHeadSQL, command.Session.DeploymentID().String(), command.WorkspaceID.String()).Scan(&streamID, &sequence, &previous); err != nil {
		return err
	}
	if streamID <= 0 || sequence <= 0 || len(previous) != sha256.Size {
		return creation.ErrInvalid
	}
	payload, err := json.Marshal(struct {
		WorkspaceID string `json:"workspace_id"`
		DisplayCode string `json:"display_code"`
		SessionID   string `json:"session_id"`
	}{command.WorkspaceID.String(), code.String(), command.Session.ID().String()})
	if err != nil {
		return err
	}
	after := sha256.Sum256(payload)
	var previousHash [32]byte
	copy(previousHash[:], previous)
	actor := publicid.ID(command.Session.PrincipalID())
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: previousHash, EventID: event, ChangeID: change,
		AggregateKind: "workspace", AggregateID: publicid.ID(command.WorkspaceID), AggregateVersion: 1,
		ActorPrincipalID: actor, Action: "workspace.created", Permission: "workspace.create",
		CorrelationID: command.CorrelationID, AfterSemanticHash: after, AuditPayloadHash: after,
		OutboxEventClass: "workspace.created", OutboxPayloadHash: after,
	})
	if err != nil {
		return err
	}
	var appended int64
	return tx.QueryRow(ctx, appendWorkspaceCreationEvidenceSQL, streamID, event.String(), outbox.String(), sequence,
		previousHash[:], eventHash[:], command.WorkspaceID.String(), actor.String(),
		command.CorrelationID.String(), after[:], payload).Scan(&appended)
}
