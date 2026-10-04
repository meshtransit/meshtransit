package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type accountSessionDatabase interface {
	Begin(context.Context) (accountSessionTransaction, error)
}

type activityAccountSessionDatabase interface {
	accountSessionDatabase
	BeginActivity(context.Context) (accountSessionTransaction, error)
}

type accountSessionTransaction interface {
	Exec(context.Context, string, ...any) error
	QueryRow(context.Context, string, ...any) accountSessionRow
	Commit(context.Context) error
	Rollback(context.Context) error
}

type accountSessionRow interface {
	Scan(...any) error
}

type pgxAccountSessionDatabase struct{ pool *pgxpool.Pool }

func (database pgxAccountSessionDatabase) Begin(
	ctx context.Context,
) (accountSessionTransaction, error) {
	transaction, err := database.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.ReadCommitted,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return nil, err
	}
	return pgxAccountSessionTransaction{transaction: transaction}, nil
}

func (database pgxAccountSessionDatabase) BeginActivity(
	ctx context.Context,
) (accountSessionTransaction, error) {
	transaction, err := database.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.ReadCommitted,
		AccessMode: pgx.ReadWrite,
	})
	if err != nil {
		return nil, err
	}
	return pgxAccountSessionTransaction{transaction: transaction}, nil
}

type pgxAccountSessionTransaction struct{ transaction pgx.Tx }

func (transaction pgxAccountSessionTransaction) Exec(
	ctx context.Context,
	query string,
	arguments ...any,
) error {
	_, err := transaction.transaction.Exec(ctx, query, arguments...)
	return err
}

func (transaction pgxAccountSessionTransaction) QueryRow(
	ctx context.Context,
	query string,
	arguments ...any,
) accountSessionRow {
	return transaction.transaction.QueryRow(ctx, query, arguments...)
}

func (transaction pgxAccountSessionTransaction) Commit(ctx context.Context) error {
	return transaction.transaction.Commit(ctx)
}

func (transaction pgxAccountSessionTransaction) Rollback(ctx context.Context) error {
	return transaction.transaction.Rollback(ctx)
}
