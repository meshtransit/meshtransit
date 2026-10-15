package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/publicid"
)

const logoutAllAccountSessionsSQL = `SELECT account_public_id::TEXT, account_version, session_generation,
 sessions_ended, ended_at
FROM mesh_ops.logout_all_account_sessions_v1(` + sessionArguments + `,$10::UUID)`

const lockAccountEvidenceStreamSQL = `SELECT stream_internal_id, next_sequence, latest_event_hash
FROM mesh_audit.lock_deployment_stream_head($1::UUID)`

const appendAccountEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
 $1::BIGINT,$2::UUID,$3::UUID,$4::BIGINT,$5::BYTEA,$6::BYTEA,
 'account',$7::UUID,$8::BIGINT,NULL::BIGINT,$9::UUID,$10::TEXT,$11::TEXT,
 $12::UUID,NULL::BYTEA,$13::BYTEA,$14::JSONB,$15::TEXT,$14::JSONB)`

// ErrAccountSessionRevocation reports malformed sign-out results or evidence.
var ErrAccountSessionRevocation = errors.New("postgres account session revocation is invalid")

// AccountSessionRevocationStore ends every Console session of the Account
// behind one active session, through the runtime pool.
type AccountSessionRevocationStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

// NewAccountSessionRevocationStore uses the runtime pool.
func NewAccountSessionRevocationStore(pool *Pool, options AccountSessionOptions) (
	*AccountSessionRevocationStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, ErrAccountSessionRevocation
	}
	return &AccountSessionRevocationStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

// RevokeAll advances the Account's session generation, ends every active
// session including the caller's, and records one event on the Deployment
// stream. It returns how many sessions ended. A session that is no longer
// active is accountsession.ErrUnauthenticated.
func (store *AccountSessionRevocationStore) RevokeAll(ctx context.Context, session accountsession.Session,
	correlationID publicid.ID) (_ int, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionOptions(store.options) ||
		!session.IsValid() || !correlationID.IsValid() {
		return 0, ErrAccountSessionRevocation
	}
	ids, err := newAccountEvidenceIDs()
	if err != nil {
		return 0, errors.Join(accountsession.ErrLogoutUnavailable, err)
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return 0, errors.Join(accountsession.ErrLogoutUnavailable, err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx))
		}
	}()
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return 0, errors.Join(accountsession.ErrLogoutUnavailable, err)
	}
	var result accountRecoveryResult
	var accountID string
	if err := tx.QueryRow(ctx, logoutAllAccountSessionsSQL,
		append(sessionQueryArguments(session), ids.change.String())...).Scan(
		&accountID, &result.version, &result.generation, &result.sessionsEnded, &result.changedAt); err != nil {
		var pgError *pgconn.PgError
		if errors.As(err, &pgError) && pgError.Code == "42501" || errors.Is(err, pgx.ErrNoRows) {
			return 0, accountsession.ErrUnauthenticated
		}
		return 0, errors.Join(accountsession.ErrLogoutUnavailable, err)
	}
	if result.account, err = publicid.Parse(accountID); err != nil || !result.valid() {
		return 0, ErrAccountSessionRevocation
	}
	actor := publicid.ID(session.PrincipalID())
	if err := appendAccountEvidence(ctx, tx.QueryRow, accountEvidence{
		deploymentID: session.DeploymentID().String(), ids: ids, result: result, actor: &actor,
		action: "account.sessions_revoked", permission: "identity.logout", correlationID: correlationID,
		outboxClass: "identity.account.sessions_revoked",
		payload: map[string]any{
			"account_public_id": result.account.String(), "principal_public_id": actor.String(),
			"session_public_id": session.ID().String(), "session_generation": result.generation,
			"sessions_ended": result.sessionsEnded, "end_reason": "logout_all",
			"ended_at": result.changedAt.UTC().Format(time.RFC3339Nano),
		},
	}); err != nil {
		return 0, errors.Join(accountsession.ErrLogoutUnavailable, err)
	}
	if err := tx.Commit(ctx); err != nil {
		committed = true
		return 0, errors.Join(accountsession.ErrLogoutUnavailable, err)
	}
	committed = true
	return result.sessionsEnded, nil
}

type accountEvidenceIDs struct{ change, event, outbox publicid.ID }

func newAccountEvidenceIDs() (accountEvidenceIDs, error) {
	var ids [3]publicid.ID
	for index := range ids {
		id, err := publicid.New()
		if err != nil {
			return accountEvidenceIDs{}, err
		}
		ids[index] = id
	}
	return accountEvidenceIDs{change: ids[0], event: ids[1], outbox: ids[2]}, nil
}

// accountRecoveryResult is the Account after one session or recovery change.
type accountRecoveryResult struct {
	account             publicid.ID
	version, generation int64
	recoveryState       string
	sessionsEnded       int
	changedAt           time.Time
}

func (result accountRecoveryResult) valid() bool {
	return result.account.IsValid() && result.version > 1 && result.generation > 0 &&
		result.sessionsEnded >= 0 && !result.changedAt.IsZero()
}

type accountEvidence struct {
	deploymentID       string
	ids                accountEvidenceIDs
	result             accountRecoveryResult
	actor              *publicid.ID
	action, permission string
	correlationID      publicid.ID
	outboxClass        string
	payload            map[string]any
}

// appendAccountEvidence chains one audit/outbox record about the Account on
// the Deployment stream.
func appendAccountEvidence[R interface{ Scan(...any) error }](ctx context.Context,
	queryRow func(context.Context, string, ...any) R, evidence accountEvidence) error {
	payload, err := json.Marshal(evidence.payload)
	if err != nil {
		return err
	}
	var streamID, sequence int64
	var previous []byte
	if err := queryRow(ctx, lockAccountEvidenceStreamSQL, evidence.deploymentID).Scan(
		&streamID, &sequence, &previous); err != nil {
		return err
	}
	if streamID <= 0 || sequence <= 0 || len(previous) != sha256.Size {
		return ErrAccountSessionRevocation
	}
	var previousHash [sha256.Size]byte
	copy(previousHash[:], previous)
	after := sha256.Sum256(payload)
	var actor publicid.ID
	var actorArgument any
	if evidence.actor != nil {
		actor, actorArgument = *evidence.actor, evidence.actor.String()
	}
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: previousHash, EventID: evidence.ids.event, ChangeID: evidence.ids.change,
		AggregateKind: "account", AggregateID: evidence.result.account, AggregateVersion: evidence.result.version,
		ActorPrincipalID: actor, Action: evidence.action, Permission: evidence.permission,
		CorrelationID: evidence.correlationID, AfterSemanticHash: after, AuditPayloadHash: after,
		OutboxEventClass: evidence.outboxClass, OutboxPayloadHash: after,
	})
	if err != nil {
		return err
	}
	var appended int64
	if err := queryRow(ctx, appendAccountEvidenceSQL, streamID, evidence.ids.event.String(),
		evidence.ids.outbox.String(), sequence, previousHash[:], eventHash[:], evidence.result.account.String(),
		evidence.result.version, actorArgument, evidence.action, evidence.permission,
		evidence.correlationID.String(), after[:], payload, evidence.outboxClass).Scan(&appended); err != nil {
		return err
	}
	if appended != sequence {
		return ErrAccountSessionRevocation
	}
	return nil
}
