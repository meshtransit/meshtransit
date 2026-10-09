package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type accountSessionLogoutDatabase interface {
	Begin(context.Context) (accountSessionLogoutTransaction, error)
}

type accountSessionLogoutTransaction interface {
	Exec(context.Context, string, ...any) error
	QueryRow(context.Context, string, ...any) accountSessionLogoutRow
	Commit(context.Context) error
	Rollback(context.Context) error
}

type accountSessionLogoutRow interface {
	Scan(...any) error
}

type pgxAccountSessionLogoutDatabase struct{ pool *pgxpool.Pool }

func (database pgxAccountSessionLogoutDatabase) Begin(
	ctx context.Context,
) (accountSessionLogoutTransaction, error) {
	transaction, err := database.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.ReadCommitted,
		AccessMode: pgx.ReadWrite,
	})
	if err != nil {
		return nil, err
	}
	return pgxAccountSessionLogoutTransaction{transaction: transaction}, nil
}

type pgxAccountSessionLogoutTransaction struct{ transaction pgx.Tx }

func (transaction pgxAccountSessionLogoutTransaction) Exec(
	ctx context.Context,
	query string,
	arguments ...any,
) error {
	_, err := transaction.transaction.Exec(ctx, query, arguments...)
	return err
}

func (transaction pgxAccountSessionLogoutTransaction) QueryRow(
	ctx context.Context,
	query string,
	arguments ...any,
) accountSessionLogoutRow {
	return transaction.transaction.QueryRow(ctx, query, arguments...)
}

func (transaction pgxAccountSessionLogoutTransaction) Commit(ctx context.Context) error {
	return transaction.transaction.Commit(ctx)
}

func (transaction pgxAccountSessionLogoutTransaction) Rollback(ctx context.Context) error {
	return transaction.transaction.Rollback(ctx)
}
