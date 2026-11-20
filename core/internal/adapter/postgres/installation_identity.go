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
