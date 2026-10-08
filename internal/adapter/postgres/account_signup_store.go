package postgres

import (
	"context"
	"crypto/sha256"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const signUpAccountSQL = `SELECT mesh_ops.sign_up_account_v1(
 $1::UUID,$2::UUID,$3::UUID,$4::BIGINT,$5::BIGINT,$6::UUID,$7::BIGINT,$8::BYTEA,$9::TIMESTAMPTZ,
 $10::TEXT,$11::TEXT,$12::BYTEA,$13::TEXT,$14::BYTEA,$15::TEXT,
 $16::UUID,$17::UUID,$18::UUID,$19::UUID,$20::UUID,$21::UUID,$22::CIDR,
 $23::BYTEA,$24::INTEGER,$25::INTEGER,$26::UUID)::TEXT`

// SignupLimits bound self sign-up: per source network each day and per
// deployment each hour. The entitlement's Workspace limit applies as well.
type SignupLimits struct {
	SourcePerDay      int
	DeploymentPerHour int
}

// IsValid reports limits inside the ranges the database accepts.
func (limits SignupLimits) IsValid() bool {
	return limits.SourcePerDay >= 1 && limits.SourcePerDay <= 1000 &&
		limits.DeploymentPerHour >= 1 && limits.DeploymentPerHour <= 100000
}

// AccountSignupStore gives a first sign-in its own Account and default
// Workspace through the runtime pool, with evidence on the new Workspace's
// stream whose actor is the new principal.
type AccountSignupStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
	limits   SignupLimits
}

var _ oidcauth.AccountSignupStore = (*AccountSignupStore)(nil)

// NewAccountSignupStore uses the runtime pool.
func NewAccountSignupStore(pool *Pool, options AccountSessionOptions, limits SignupLimits) (
	*AccountSignupStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.workspaceRenameDatabase == nil ||
		!validAccountSessionOptions(options) || !limits.IsValid() {
		return nil, oidcauth.ErrSignupUnavailable
	}
	return &AccountSignupStore{database: pool.workspaceRenameDatabase, options: options, limits: limits}, nil
}

func accountSignupError(err error) error {
	var pgError *pgconn.PgError
	if errors.As(err, &pgError) {
		switch pgError.Code {
		case "MTS01", "MTS02", "MTS03", "42501", "22023", "23505":
			return oidcauth.ErrSignupRejected
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return oidcauth.ErrSignupRejected
	}
	return errors.Join(oidcauth.ErrSignupUnavailable, err)
}

type accountSignupRecord struct {
	Created     *bool  `json:"created"`
	PrincipalID string `json:"principal_id"`
	AccountID   string `json:"account_id"`
	WorkspaceID string `json:"workspace_id"`
}

// SignUp creates the Account and Workspace when the identity has none and
// commits nothing when it has one.
func (store *AccountSignupStore) SignUp(ctx context.Context, signup oidcauth.AccountSignup) (resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !signup.Lookup.IsValid() || !signup.Source.IsValid() ||
		signup.DisplayName == "" {
		return oidcauth.ErrSignupRejected
	}
	var ids [8]publicid.ID
	for index := range ids {
		id, err := publicid.New()
		if err != nil {
			return oidcauth.ErrSignupUnavailable
		}
		ids[index] = id
	}
	workspaceID, changeID := ids[0], ids[7]
	prefix, err := randomWorkspaceULA()
	if err != nil {
		return oidcauth.ErrSignupUnavailable
	}
	snapshot := signup.Lookup.Snapshot()
	route, claimed, digests := snapshot.Route(), signup.Lookup.Claimed(), signup.Lookup.Digests()
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
	source := signup.Source.Digest()

	tx, err := store.database.Begin(ctx)
	if err != nil || tx == nil {
		return errors.Join(oidcauth.ErrSignupUnavailable, err)
	}
	committed := false
	defer func() {
		if !committed {
			resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(tx))
		}
	}()
	if err := tx.Exec(ctx, configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout), postgresTimeout(store.options.IdleTimeout)); err != nil {
		return errors.Join(oidcauth.ErrSignupUnavailable, err)
	}
	var encoded string
	if err := tx.QueryRow(ctx, signUpAccountSQL, route.DeploymentID().String(), route.ProviderID().String(),
		route.ClientID().String(), route.ProviderGeneration(), route.RecoveryEpoch(),
		snapshot.TransactionID().String(), claimed.Version(), hash[:], claimed.ConsumedAt(),
		digests[0].Algorithm(), digests[0].KeyID().String(), active[:], previousID, previousBytes,
		signup.DisplayName, workspaceID.String(), ids[1].String(), ids[2].String(), ids[3].String(),
		ids[4].String(), ids[5].String(), prefix.String(), source[:], store.limits.SourcePerDay,
		store.limits.DeploymentPerHour, changeID.String()).Scan(&encoded); err != nil {
		return accountSignupError(err)
	}
	var record accountSignupRecord
	if err := decodeIdentityCatalogJSON([]byte(encoded), &record); err != nil || record.Created == nil {
		return oidcauth.ErrSignupUnavailable
	}
	if !*record.Created {
		return nil // A known identity: nothing to commit.
	}
	principal, principalErr := publicid.Parse(record.PrincipalID)
	account, accountErr := publicid.Parse(record.AccountID)
	created, workspaceErr := workspace.ParseID(record.WorkspaceID)
	if principalErr != nil || accountErr != nil || workspaceErr != nil || created != workspace.ID(workspaceID) {
		return oidcauth.ErrSignupUnavailable
	}
	after := sha256.Sum256([]byte("signed_up\x00" + principal.String() + "\x00" + workspaceID.String()))
	event := catalogEvent{
		correlationID: changeID, changeID: changeID, aggregateKind: "workspace", aggregateID: workspaceID,
		version: 1, action: "account.signed_up", permission: "workspace.create", after: after,
		actor: principal, deployment: route.DeploymentID().String(),
		payload: struct {
			WorkspaceID  string `json:"workspace_id"`
			PrincipalID  string `json:"principal_id"`
			AccountID    string `json:"account_id"`
			IPv6Overlay  string `json:"ipv6_overlay"`
			Transaction  string `json:"auth_transaction_id"`
			Provisioning string `json:"provisioning"`
		}{workspaceID.String(), principal.String(), account.String(), prefix.String(),
			snapshot.TransactionID().String(), "self_signup"},
		outboxClass: "account.signed_up",
		outbox: struct {
			WorkspaceID string `json:"workspace_id"`
			PrincipalID string `json:"principal_id"`
		}{workspaceID.String(), principal.String()},
	}
	if err := appendWorkspaceCatalogEvent(ctx, tx, created, event); err != nil {
		return errors.Join(oidcauth.ErrSignupUnavailable, err)
	}
	committed = true
	if err := tx.Commit(ctx); err != nil {
		return errors.Join(oidcauth.ErrSignupUnavailable, err)
	}
	return nil
}
