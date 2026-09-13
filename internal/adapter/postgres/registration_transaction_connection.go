package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type registrationTransactionDatabase interface {
	Begin(context.Context) (registrationDatabaseTransaction, error)
}

type registrationDatabaseTransaction interface {
	Exec(context.Context, string, ...any) (registrationCommandResult, error)
	Query(context.Context, string, ...any) (registrationRows, error)
	QueryRow(context.Context, string, ...any) registrationRow
	Commit(context.Context) error
	Rollback(context.Context) error
}

type registrationCommandResult interface {
	RowsAffected() int64
}

type registrationRow interface {
	Scan(...any) error
}

type registrationRows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close()
}

type pgxRegistrationTransactionDatabase struct {
	pool *pgxpool.Pool
}

func (database pgxRegistrationTransactionDatabase) Begin(
	ctx context.Context,
) (registrationDatabaseTransaction, error) {
	transaction, err := database.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.ReadCommitted,
		AccessMode: pgx.ReadWrite,
	})
	if err != nil {
		return nil, err
	}
	return pgxRegistrationDatabaseTransaction{transaction: transaction}, nil
}

type pgxRegistrationDatabaseTransaction struct {
	transaction pgx.Tx
}

func (transaction pgxRegistrationDatabaseTransaction) Exec(
	ctx context.Context,
	query string,
	arguments ...any,
) (registrationCommandResult, error) {
	return transaction.transaction.Exec(ctx, query, arguments...)
}

func (transaction pgxRegistrationDatabaseTransaction) Query(
	ctx context.Context,
	query string,
	arguments ...any,
) (registrationRows, error) {
	return transaction.transaction.Query(ctx, query, arguments...)
}

func (transaction pgxRegistrationDatabaseTransaction) QueryRow(
	ctx context.Context,
	query string,
	arguments ...any,
) registrationRow {
	return transaction.transaction.QueryRow(ctx, query, arguments...)
}

func (transaction pgxRegistrationDatabaseTransaction) Commit(ctx context.Context) error {
	return transaction.transaction.Commit(ctx)
}

func (transaction pgxRegistrationDatabaseTransaction) Rollback(ctx context.Context) error {
	return transaction.transaction.Rollback(ctx)
}
