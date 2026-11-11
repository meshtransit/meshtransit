package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"meshtransit.net/core/internal/domain/identity/oidcauth"
	"meshtransit.net/core/internal/domain/publicid"
)

// recordAccountEmailSQL is schema 288's writer, bound to the exact consuming
// sign-in (S4c §3.1).
const recordAccountEmailSQL = `SELECT changed, principal_public_id::TEXT, account_email_public_id::TEXT,
 account_email_version, verified_at
FROM mesh_ops.record_account_verified_email_v1(
 $1::UUID,$2::UUID,$3::UUID,$4::BIGINT,$5::BIGINT,$6::UUID,$7::BIGINT,$8::BYTEA,$9::TIMESTAMPTZ,
 $10::TEXT,$11::TEXT,$12::BYTEA,$13::TEXT,$14::BYTEA,$15::TEXT,$16::UUID,$17::UUID)`

// ErrAccountEmailStore reports a store that cannot be built.
var ErrAccountEmailStore = errors.New("postgres account email store is invalid")

// AccountEmailStore records an Account's verified email through the runtime
// pool, with evidence on the Deployment stream that never carries the email
// or a hash of it.
type AccountEmailStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
}

var _ oidcauth.AccountEmailStore = (*AccountEmailStore)(nil)

// NewAccountEmailStore uses the runtime pool.
func NewAccountEmailStore(pool *Pool, options AccountSessionOptions) (*AccountEmailStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) {
		return nil, ErrAccountEmailStore
	}
	return &AccountEmailStore{database: pool.workspaceRenameDatabase, options: options}, nil
}

type accountEmailRow struct {
	changed            bool
	principal, row     string
	version            int64
	verifiedAt         time.Time
	principalID, rowID publicid.ID
}

// RecordEmail writes the email when it differs from the stored one. The
// email never appears in an error.
func (store *AccountEmailStore) RecordEmail(ctx context.Context, email oidcauth.AccountEmail) (
	_ oidcauth.AccountEmailResult, resultErr error,
) {
	if ctx == nil || store == nil || store.database == nil || !email.Lookup.IsValid() {
		return 0, oidcauth.ErrAccountEmailUnavailable
	}
	if !oidcauth.ValidDisplayEmail(email.Email) {
		return 0, oidcauth.ErrAccountEmailUnavailable
	}
	rowID, err := publicid.New()
	if err != nil {
		return 0, oidcauth.ErrAccountEmailUnavailable
	}
	ids, err := newAccountEvidenceIDs()
	if err != nil {
		return 0, oidcauth.ErrAccountEmailUnavailable
	}
	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return 0, oidcauth.ErrAccountEmailUnavailable
	}
	committed := false
	defer func() {
		if !committed && rollbackAccountSessionTransaction(tx) != nil {
			resultErr = oidcauth.ErrAccountEmailUnavailable
		}
	}()
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return 0, oidcauth.ErrAccountEmailUnavailable
	}
	row, found, err := store.record(ctx, tx, email, rowID, ids.change)
	if err != nil {
		return 0, err
	}
	if !found {
		return oidcauth.AccountEmailNoAccount, nil
	}
	if !row.changed {
		return oidcauth.AccountEmailUnchanged, nil
	}
	snapshot := email.Lookup.Snapshot()
	actor := row.principalID
	if err := appendAccountEvidence(ctx, tx.QueryRow, accountEvidence{
		aggregateKind: "account_email", deploymentID: snapshot.Route().DeploymentID().String(), ids: ids,
		result: accountRecoveryResult{account: row.rowID, version: row.version}, actor: &actor,
		action: "account.email_verified", permission: "identity.login", correlationID: ids.change,
		outboxClass: "identity.account.email_verified",
		payload: map[string]any{
			"account_email_public_id": row.rowID.String(), "principal_public_id": actor.String(),
			"email_version": row.version, "auth_transaction_id": snapshot.TransactionID().String(),
			"verified_at": row.verifiedAt.UTC().Format(time.RFC3339Nano),
		},
	}); err != nil {
		return 0, oidcauth.ErrAccountEmailUnavailable
	}
	if err := tx.Commit(ctx); err != nil {
		committed = true
		return 0, oidcauth.ErrAccountEmailUnavailable
	}
	committed = true
	return oidcauth.AccountEmailRecorded, nil
}

func (store *AccountEmailStore) record(ctx context.Context, tx accountSessionTransaction,
	email oidcauth.AccountEmail, rowID, changeID publicid.ID,
) (accountEmailRow, bool, error) {
	snapshot := email.Lookup.Snapshot()
	route, claimed, digests := snapshot.Route(), email.Lookup.Claimed(), email.Lookup.Digests()
	active := digests[0].Bytes()
	var previousID *string
	var previousBytes []byte
	if len(digests) == 2 {
		id := digests[1].KeyID().String()
		previousID = &id
		previous := digests[1].Bytes()
		previousBytes = previous[:]
	}
	hash := snapshot.SemanticHash()
	var row accountEmailRow
	err := tx.QueryRow(ctx, recordAccountEmailSQL, route.DeploymentID().String(), route.ProviderID().String(),
		route.ClientID().String(), route.ProviderGeneration(), route.RecoveryEpoch(),
		snapshot.TransactionID().String(), claimed.Version(), hash[:], claimed.ConsumedAt(),
		digests[0].Algorithm(), digests[0].KeyID().String(), active[:], previousID, previousBytes,
		email.Email, rowID.String(), changeID.String()).Scan(
		&row.changed, &row.principal, &row.row, &row.version, &row.verifiedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return accountEmailRow{}, false, nil
	}
	if err != nil {
		// A mismatched sign-in (42501) and a database failure alike skip the
		// email; neither error carries it.
		return accountEmailRow{}, false, oidcauth.ErrAccountEmailUnavailable
	}
	principal, principalErr := publicid.Parse(row.principal)
	stored, rowErr := publicid.Parse(row.row)
	if principalErr != nil || rowErr != nil || row.version <= 0 || row.verifiedAt.IsZero() {
		return accountEmailRow{}, false, oidcauth.ErrAccountEmailUnavailable
	}
	row.principalID, row.rowID = principal, stored
	return row, true, nil
}
