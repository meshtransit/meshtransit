package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/migrations"
)

// OpenMigrationRunner opens one direct, authenticated TLS connection. It does
// not apply migrations until Up is explicitly called.
func OpenMigrationRunner(ctx context.Context, options MigrationOptions) (*MigrationRunner, error) {
	if ctx == nil {
		return nil, ErrInvalidMigrationOptions
	}
	password, err := options.PasswordFile.Read()
	if err != nil {
		return nil, errors.Join(ErrMigrationOpen, err)
	}
	caPEM, err := options.CAFile.Read()
	if err != nil {
		return nil, errors.Join(ErrMigrationOpen, err)
	}
	connectionConfig, err := buildMigrationConnectionConfig(options, password, caPEM)
	if err != nil {
		return nil, errors.Join(ErrMigrationOpen, err)
	}
	connection, err := pgx.ConnectConfig(ctx, connectionConfig)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMigrationOpen, err)
	}
	runner, err := newMigrationRunner(
		&pgxMigrationConnection{connection: connection},
		options,
		migrations.Catalog(),
	)
	if err != nil {
		closeContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), options.ConnectTimeout)
		defer cancel()
		return nil, errors.Join(err, connection.Close(closeContext))
	}
	return runner, nil
}

type pgxMigrationConnection struct {
	connection *pgx.Conn
}

func (connection *pgxMigrationConnection) Begin(
	ctx context.Context,
	readOnly bool,
) (migrationTransaction, error) {
	accessMode := pgx.ReadWrite
	if readOnly {
		accessMode = pgx.ReadOnly
	}
	transaction, err := connection.connection.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.ReadCommitted,
		AccessMode: accessMode,
	})
	if err != nil {
		return nil, err
	}
	return pgxMigrationTransaction{transaction: transaction}, nil
}

func (connection *pgxMigrationConnection) Close(ctx context.Context) error {
	return connection.connection.Close(ctx)
}

type pgxMigrationTransaction struct {
	transaction pgx.Tx
}

func (transaction pgxMigrationTransaction) Exec(
	ctx context.Context,
	query string,
	arguments ...any,
) error {
	_, err := transaction.transaction.Exec(ctx, query, arguments...)
	return err
}

func (transaction pgxMigrationTransaction) QueryRow(
	ctx context.Context,
	query string,
	arguments ...any,
) migrationRow {
	return transaction.transaction.QueryRow(ctx, query, arguments...)
}

func (transaction pgxMigrationTransaction) Query(
	ctx context.Context,
	query string,
	arguments ...any,
) (migrationRows, error) {
	return transaction.transaction.Query(ctx, query, arguments...)
}

func (transaction pgxMigrationTransaction) Commit(ctx context.Context) error {
	return transaction.transaction.Commit(ctx)
}

func (transaction pgxMigrationTransaction) Rollback(ctx context.Context) error {
	return transaction.transaction.Rollback(ctx)
}
