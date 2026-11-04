package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// DeploymentInstalled reports whether the database already holds a
// Deployment: one bounded read, in a read-only transaction, with the
// migration identity. A self-hosted server bootstraps only while it holds
// none; after that the Console owns accounts and Workspaces, whatever state
// the Deployment is in.
func DeploymentInstalled(ctx context.Context, options MigrationOptions) (installed bool, resultErr error) {
	if ctx == nil {
		return false, ErrInvalidMigrationOptions
	}
	password, err := options.PasswordFile.Read()
	if err != nil {
		return false, errors.Join(ErrBootstrapUnavailable, err)
	}
	caPEM, err := options.CAFile.Read()
	if err != nil {
		return false, errors.Join(ErrBootstrapUnavailable, err)
	}
	connectionConfig, err := buildMigrationConnectionConfig(options, password, caPEM)
	if err != nil {
		return false, err
	}
	connectionConfig.RuntimeParams["application_name"] = "meshcore-setup"
	connection, err := pgx.ConnectConfig(ctx, connectionConfig)
	if err != nil {
		return false, errors.Join(ErrBootstrapUnavailable, err)
	}
	defer func() {
		closeContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), options.ConnectTimeout)
		defer cancel()
		resultErr = errors.Join(resultErr, connection.Close(closeContext))
	}()
	err = pgx.BeginTxFunc(ctx, connection, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM mesh.deployment)`).Scan(&installed)
	})
	if err != nil {
		return false, errors.Join(ErrBootstrapUnavailable, err)
	}
	return installed, nil
}
