package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/meshtransit/meshtransit/core/internal/domain/audit"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace/settings"
)

// WorkspaceRenameStore owns an explicit write transaction port, separate from Session reads.
type WorkspaceRenameStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

// NewWorkspaceRenameStore validates a runtime pool and bounded database waits.
func NewWorkspaceRenameStore(pool *Pool, options AccountSessionOptions) (*WorkspaceRenameStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil || !validAccountSessionOptions(options) {
		return nil, settings.ErrInvalid
	}
	return &WorkspaceRenameStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

const renameOwnedWorkspaceSQL = `SELECT renamed_workspace_public_id::TEXT,previous_display_name,
 renamed_display_name,renamed_display_code,renamed_version,
 workspace_owner_authority_generation,membership_authority_generation
FROM mesh_ops.rename_owned_workspace_v1(
 $1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,$7::BIGINT,$8::BIGINT,$9::BIGINT,
 $10::UUID,$11::BIGINT,$12::TEXT,$13::UUID)`

const appendWorkspaceRenameEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
 $1::BIGINT,$2::UUID,$3::UUID,$4::BIGINT,$5::BYTEA,$6::BYTEA,
 'workspace',$7::UUID,$8::BIGINT,NULL::BIGINT,$9::UUID,'workspace.renamed','workspace.update',
 $10::UUID,$11::BYTEA,$12::BYTEA,$13::JSONB,'workspace.renamed',$14::JSONB)`

// Rename rechecks the current owner, Session and membership before a short
// audited transaction. An uncertain commit returns no success and is not retried.
func (store *WorkspaceRenameStore) Rename(ctx context.Context, command settings.Command) (_ settings.Result, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) || !command.IsValid() {
		return settings.Result{}, settings.ErrInvalid
	}
	changeID, err := publicid.New()
	if err != nil {
		return settings.Result{}, settings.ErrUnavailable
	}
	eventID, err := publicid.New()
	if err != nil {
		return settings.Result{}, settings.ErrUnavailable
	}
	outboxID, err := publicid.New()
	if err != nil {
		return settings.Result{}, settings.ErrUnavailable
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return settings.Result{}, settings.ErrUnavailable
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx))
		}
	}()
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL, postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return settings.Result{}, errors.Join(settings.ErrUnavailable, err)
	}
	session := command.Session
	var returnedID, previousName, displayName, displayCode string
	var version, ownerGeneration, membershipGeneration int64
	err = tx.QueryRow(ctx, renameOwnedWorkspaceSQL, session.ID().String(), session.DeploymentID().String(),
		session.PrincipalID().String(), session.IdentitySubjectID().String(), session.Version(), session.PrincipalAuthorityGeneration(),
		session.AccountSessionGeneration(), session.ProviderGeneration(), session.DeploymentRecoveryEpoch(),
		command.WorkspaceID.String(), command.ExpectedVersion, command.DisplayName, changeID.String()).Scan(
		&returnedID, &previousName, &displayName, &displayCode, &version, &ownerGeneration, &membershipGeneration)
	if errors.Is(err, pgx.ErrNoRows) {
		return settings.Result{}, settings.ErrForbidden
	}
	if err != nil {
		var databaseError *pgconn.PgError
		if errors.As(err, &databaseError) && (databaseError.Code == "40001" || databaseError.Code == "23505") {
			return settings.Result{}, settings.ErrConflict
		}
		return settings.Result{}, errors.Join(settings.ErrUnavailable, err)
	}
	result := settings.Result{WorkspaceID: command.WorkspaceID, DisplayName: displayName, DisplayCode: identity.DisplayCode(displayCode), Version: version}
	if returnedID != command.WorkspaceID.String() || !result.IsValid() || previousName == "" || len(previousName) > 128 || !utf8.ValidString(previousName) ||
		result.Version != command.ExpectedVersion+1 || result.DisplayName != command.DisplayName || ownerGeneration <= 0 || membershipGeneration <= 0 {
		return settings.Result{}, settings.ErrInvalid
	}
	if err := appendWorkspaceRenameEvidence(ctx, tx, command, result, previousName, ownerGeneration, membershipGeneration, changeID, eventID, outboxID); err != nil {
		return settings.Result{}, errors.Join(settings.ErrUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return settings.Result{}, errors.Join(settings.ErrUnavailable, err)
	}
	closed = true
	return result, nil
}

func appendWorkspaceRenameEvidence(ctx context.Context, tx accountSessionTransaction, command settings.Command,
	result settings.Result, previousName string, ownerGeneration, membershipGeneration int64, changeID, eventID, outboxID publicid.ID) error {
	var streamID, sequence int64
	var previous []byte
	if err := tx.QueryRow(ctx, lockWorkspaceStreamHeadSQL, command.Session.DeploymentID().String(), command.WorkspaceID.String()).Scan(&streamID, &sequence, &previous); err != nil {
		return err
	}
	if streamID <= 0 || sequence <= 0 || len(previous) != sha256.Size {
		return settings.ErrInvalid
	}
	semantic := func(name string, version int64) ([32]byte, error) {
		encoded, err := json.Marshal(struct {
			ID      string `json:"workspace_id"`
			Name    string `json:"display_name"`
			Code    string `json:"display_code"`
			Version int64  `json:"version"`
		}{
			command.WorkspaceID.String(), name, result.DisplayCode.String(), version,
		})
		return sha256.Sum256(encoded), err
	}
	before, err := semantic(previousName, command.ExpectedVersion)
	if err != nil {
		return err
	}
	after, err := semantic(result.DisplayName, result.Version)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(struct {
		WorkspaceID          string `json:"workspace_id"`
		SessionID            string `json:"session_id"`
		OwnerGeneration      int64  `json:"workspace_owner_authority_generation"`
		MembershipGeneration int64  `json:"workspace_membership_authority_generation"`
	}{command.WorkspaceID.String(), command.Session.ID().String(), ownerGeneration, membershipGeneration})
	if err != nil {
		return err
	}
	outbox, err := json.Marshal(struct {
		WorkspaceID string `json:"workspace_id"`
		Version     int64  `json:"version"`
	}{command.WorkspaceID.String(), result.Version})
	if err != nil {
		return err
	}
	var previousHash [32]byte
	copy(previousHash[:], previous)
	workspaceID, err := publicid.Parse(command.WorkspaceID.String())
	if err != nil {
		return err
	}
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: previousHash, EventID: eventID, ChangeID: changeID, AggregateKind: "workspace", AggregateID: workspaceID,
		AggregateVersion: result.Version, ActorPrincipalID: publicid.ID(command.Session.PrincipalID()), Action: "workspace.renamed",
		Permission: "workspace.update", CorrelationID: command.CorrelationID, BeforeSemanticHash: before, AfterSemanticHash: after,
		AuditPayloadHash: sha256.Sum256(payload), OutboxEventClass: "workspace.renamed", OutboxPayloadHash: sha256.Sum256(outbox),
	})
	if err != nil {
		return err
	}
	var appended int64
	if err := tx.QueryRow(ctx, appendWorkspaceRenameEvidenceSQL, streamID, eventID.String(), outboxID.String(), sequence,
		previousHash[:], eventHash[:], command.WorkspaceID.String(), result.Version, command.Session.PrincipalID().String(),
		command.CorrelationID.String(), before[:], after[:], payload, outbox).Scan(&appended); err != nil {
		return err
	}
	if appended != sequence {
		return settings.ErrInvalid
	}
	return nil
}

var _ settings.Store = (*WorkspaceRenameStore)(nil)
