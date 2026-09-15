package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type policyPublicationDatabase interface {
	Begin(context.Context, bool) (policyPublicationDatabaseTransaction, error)
}

type policyPublicationDatabaseTransaction interface {
	Exec(context.Context, string, ...any) error
	QueryRow(context.Context, string, ...any) policyPublicationRow
	Commit(context.Context) error
	Rollback(context.Context) error
}

type policyPublicationRow interface {
	Scan(...any) error
}

type pgxPolicyPublicationDatabase struct {
	pool *pgxpool.Pool
}

func (database pgxPolicyPublicationDatabase) Begin(
	ctx context.Context,
	readOnly bool,
) (policyPublicationDatabaseTransaction, error) {
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
	return pgxPolicyPublicationTransaction{transaction: transaction}, nil
}

type pgxPolicyPublicationTransaction struct {
	transaction pgx.Tx
}

func (transaction pgxPolicyPublicationTransaction) Exec(
	ctx context.Context,
	query string,
	arguments ...any,
) error {
	_, err := transaction.transaction.Exec(ctx, query, arguments...)
	return err
}

func (transaction pgxPolicyPublicationTransaction) QueryRow(
	ctx context.Context,
	query string,
	arguments ...any,
) policyPublicationRow {
	return transaction.transaction.QueryRow(ctx, query, arguments...)
}

func (transaction pgxPolicyPublicationTransaction) Commit(ctx context.Context) error {
	return transaction.transaction.Commit(ctx)
}

func (transaction pgxPolicyPublicationTransaction) Rollback(ctx context.Context) error {
	return transaction.transaction.Rollback(ctx)
}
