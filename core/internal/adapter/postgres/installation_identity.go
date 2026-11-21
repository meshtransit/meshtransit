package postgres

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"
)

// ReadInstallationIDs returns the Deployment IDs the Core database holds
// (deployments not deleted), read as the migrator, the database's owner; none
// before the first migration. The Kubernetes bootstrap compares them with the
// configured ID before it records one for the pods.
func ReadInstallationIDs(ctx context.Context, options ServerBootstrapOptions) ([]string, error) {
	if err := options.validate(); err != nil {
		return nil, err
	}
	index := slices.IndexFunc(options.Logins, func(login ServerBootstrapLogin) bool { return login.Name == options.Migrator })
	caPEM, err := options.CAFile.Read()
	if err != nil {
		return nil, errors.Join(ErrMigrationOpen, err)
	}
	migrator, err := options.connect(ctx, options.CoreDatabase, options.Migrator, options.Logins[index].Password, caPEM)
	if err != nil {
		return nil, fmt.Errorf("connect as %s: %w", options.Migrator, err)
	}
	defer func() { _ = migrator.Close(context.WithoutCancel(ctx)) }()
	var present bool
	if err := migrator.QueryRow(ctx, `SELECT pg_catalog.to_regclass('mesh.deployment') IS NOT NULL`).Scan(&present); err != nil {
		return nil, fmt.Errorf("read the deployment table: %w", err)
	}
	if !present {
		return []string{}, nil
	}
	var total, alive int
	if err := migrator.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE deleted_at IS NULL)
FROM mesh.deployment`).Scan(&total, &alive); err != nil {
		return nil, fmt.Errorf("read deployments: %w", err)
	}
	// Only deleted deployments: the deployment bootstrap would skip (it
	// counts every row) while new IDs were recorded; refuse instead.
	if total > 0 && alive == 0 {
		return nil, fmt.Errorf("%w: the database holds only deleted deployments", ErrLoginIdentityConflict)
	}
	rows, err := migrator.Query(ctx, `SELECT installation_public_id::text FROM mesh.deployment
WHERE deleted_at IS NULL ORDER BY id LIMIT 16`)
	if err != nil {
		return nil, fmt.Errorf("read deployments: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("read deployments: %w", err)
	}
	return ids, nil
}

// ErrLoginIdentityConflict reports a Core database whose login provider
// does not match the install's names: none or several providers for the
// issuer and OIDC client ID while a deployment exists (the public names
// are fixed once installed).
var ErrLoginIdentityConflict = errors.New("postgres: the login provider for this issuer and client is missing or ambiguous")

// LoginIdentityRecord is the login route's identity the database holds.
type LoginIdentityRecord struct {
	ProviderID, ClientID              string
	ProviderGeneration, RecoveryEpoch int64
}

// LoginIdentityQuery names the login route to find: the installation's
// Deployment ID, the issuer and the OIDC client ID.
type LoginIdentityQuery struct {
	DeploymentID, Issuer, OIDCClientID string
}

// ReadLoginIdentity reads, as the migrator, the provider and client of the
// installation's deployment for the issuer and the OIDC client ID, with the
// provider's current generation and the deployment's recovery epoch, in one
// read-only transaction. It reports false before the first deployment. A
// suspended provider or client is still found: an upgrade must not be
// blocked by it (it fails closed at sign-in).
func ReadLoginIdentity(ctx context.Context, options ServerBootstrapOptions, query LoginIdentityQuery,
) (LoginIdentityRecord, bool, error) {
	if err := options.validate(); err != nil {
		return LoginIdentityRecord{}, false, err
	}
	issuer, oidcClientID := query.Issuer, query.OIDCClientID
	if issuer == "" || oidcClientID == "" || len(issuer) > 2048 || len(oidcClientID) > 256 ||
		query.DeploymentID == "" {
		return LoginIdentityRecord{}, false, ErrInvalidServerBootstrap
	}
	index := slices.IndexFunc(options.Logins, func(login ServerBootstrapLogin) bool { return login.Name == options.Migrator })
	caPEM, err := options.CAFile.Read()
	if err != nil {
		return LoginIdentityRecord{}, false, errors.Join(ErrMigrationOpen, err)
	}
	migrator, err := options.connect(ctx, options.CoreDatabase, options.Migrator, options.Logins[index].Password, caPEM)
	if err != nil {
		return LoginIdentityRecord{}, false, fmt.Errorf("connect as %s: %w", options.Migrator, err)
	}
	defer func() { _ = migrator.Close(context.WithoutCancel(ctx)) }()
	transaction, err := migrator.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return LoginIdentityRecord{}, false, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = transaction.Rollback(context.WithoutCancel(ctx)) }()
	var deployments int
	if err := transaction.QueryRow(ctx, `SELECT CASE WHEN pg_catalog.to_regclass('mesh.deployment') IS NULL THEN 0
    ELSE (SELECT count(*) FROM mesh.deployment WHERE deleted_at IS NULL) END`).Scan(&deployments); err != nil {
		return LoginIdentityRecord{}, false, fmt.Errorf("read deployments: %w", err)
	}
	if deployments == 0 {
		return LoginIdentityRecord{}, false, nil
	}
	rows, err := transaction.Query(ctx, `SELECT p.public_id::text, c.public_id::text, p.current_generation, d.recovery_epoch
FROM mesh.deployment d
JOIN mesh.identity_provider p ON p.deployment_id = d.id
JOIN mesh.identity_provider_client c ON c.deployment_id = d.id AND c.identity_provider_id = p.id
WHERE d.deleted_at IS NULL AND d.installation_public_id = $3::UUID AND p.issuer = $1 AND c.client_id = $2
  AND p.state <> 'deleted' AND c.state <> 'deleted'
LIMIT 2`, issuer, oidcClientID, query.DeploymentID)
	if err != nil {
		return LoginIdentityRecord{}, false, fmt.Errorf("read the login provider: %w", err)
	}
	records, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (LoginIdentityRecord, error) {
		var record LoginIdentityRecord
		return record, row.Scan(&record.ProviderID, &record.ClientID, &record.ProviderGeneration, &record.RecoveryEpoch)
	})
	if err != nil {
		return LoginIdentityRecord{}, false, fmt.Errorf("read the login provider: %w", err)
	}
	if len(records) != 1 || deployments != 1 {
		return LoginIdentityRecord{}, false, fmt.Errorf("%w: %d providers, %d deployments", ErrLoginIdentityConflict,
			len(records), deployments)
	}
	return records[0], true, nil
}
