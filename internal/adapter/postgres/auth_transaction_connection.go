package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type authTransactionDatabase interface {
	Begin(context.Context, bool) (authTransactionDatabaseTransaction, error)
}

type authTransactionDatabaseTransaction interface {
	Exec(context.Context, string, ...any) error
	QueryRow(context.Context, string, ...any) authTransactionRow
	Commit(context.Context) error
	Rollback(context.Context) error
}

type authTransactionRow interface {
	Scan(...any) error
}

type pgxAuthTransactionDatabase struct {
	pool *pgxpool.Pool
}

func (database pgxAuthTransactionDatabase) Begin(
	ctx context.Context,
	readOnly bool,
) (authTransactionDatabaseTransaction, error) {
	accessMode := pgx.ReadWrite
	if readOnly {
		accessMode = pgx.ReadOnly
	}
	transaction, err := database.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.ReadCommitted,
		AccessMode: accessMode,
	})
	if err != nil {
		return nil, err
	}
	return pgxAuthTransactionDatabaseTransaction{transaction: transaction}, nil
}

type pgxAuthTransactionDatabaseTransaction struct {
	transaction pgx.Tx
}

func (transaction pgxAuthTransactionDatabaseTransaction) Exec(
	ctx context.Context,
	query string,
	arguments ...any,
) error {
	_, err := transaction.transaction.Exec(ctx, query, arguments...)
	return err
}

func (transaction pgxAuthTransactionDatabaseTransaction) QueryRow(
	ctx context.Context,
	query string,
	arguments ...any,
) authTransactionRow {
	return transaction.transaction.QueryRow(ctx, query, arguments...)
}

func (transaction pgxAuthTransactionDatabaseTransaction) Commit(ctx context.Context) error {
	return transaction.transaction.Commit(ctx)
}

func (transaction pgxAuthTransactionDatabaseTransaction) Rollback(ctx context.Context) error {
	return transaction.transaction.Rollback(ctx)
}
