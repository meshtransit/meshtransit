package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type resourceAuthorityDatabase interface {
	Begin(context.Context, bool) (resourceAuthorityDatabaseTransaction, error)
}

type resourceAuthorityDatabaseTransaction interface {
	Exec(context.Context, string, ...any) error
	QueryRow(context.Context, string, ...any) resourceAuthorityRow
	Commit(context.Context) error
	Rollback(context.Context) error
}

type resourceAuthorityRow interface{ Scan(...any) error }

type pgxResourceAuthorityDatabase struct{ pool *pgxpool.Pool }

func (database pgxResourceAuthorityDatabase) Begin(
	ctx context.Context,
	readOnly bool,
) (resourceAuthorityDatabaseTransaction, error) {
	accessMode := pgx.ReadWrite
	if readOnly {
		accessMode = pgx.ReadOnly
	}
	transaction, err := database.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.ReadCommitted, AccessMode: accessMode,
	})
	if err != nil {
		return nil, err
	}
	return pgxResourceAuthorityTransaction{transaction: transaction}, nil
}

type pgxResourceAuthorityTransaction struct{ transaction pgx.Tx }

func (transaction pgxResourceAuthorityTransaction) Exec(
	ctx context.Context,
	query string,
	arguments ...any,
) error {
	_, err := transaction.transaction.Exec(ctx, query, arguments...)
	return err
}

func (transaction pgxResourceAuthorityTransaction) QueryRow(
	ctx context.Context,
	query string,
	arguments ...any,
) resourceAuthorityRow {
	return transaction.transaction.QueryRow(ctx, query, arguments...)
}

func (transaction pgxResourceAuthorityTransaction) Commit(ctx context.Context) error {
	return transaction.transaction.Commit(ctx)
}

func (transaction pgxResourceAuthorityTransaction) Rollback(ctx context.Context) error {
	return transaction.transaction.Rollback(ctx)
}
