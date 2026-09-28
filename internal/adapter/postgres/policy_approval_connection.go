package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type policyApprovalDatabase interface {
	Begin(context.Context, bool) (policyApprovalDatabaseTransaction, error)
}

type policyApprovalDatabaseTransaction interface {
	Exec(context.Context, string, ...any) error
	QueryRow(context.Context, string, ...any) policyApprovalRow
	Commit(context.Context) error
	Rollback(context.Context) error
}

type policyApprovalRow interface{ Scan(...any) error }

type pgxPolicyApprovalDatabase struct{ pool *pgxpool.Pool }

func (database pgxPolicyApprovalDatabase) Begin(
	ctx context.Context,
	readOnly bool,
) (policyApprovalDatabaseTransaction, error) {
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
	return pgxPolicyApprovalTransaction{transaction: transaction}, nil
}

type pgxPolicyApprovalTransaction struct{ transaction pgx.Tx }

func (transaction pgxPolicyApprovalTransaction) Exec(
	ctx context.Context,
	query string,
	arguments ...any,
) error {
	_, err := transaction.transaction.Exec(ctx, query, arguments...)
	return err
}

func (transaction pgxPolicyApprovalTransaction) QueryRow(
	ctx context.Context,
	query string,
	arguments ...any,
) policyApprovalRow {
	return transaction.transaction.QueryRow(ctx, query, arguments...)
}

func (transaction pgxPolicyApprovalTransaction) Commit(ctx context.Context) error {
	return transaction.transaction.Commit(ctx)
}

func (transaction pgxPolicyApprovalTransaction) Rollback(ctx context.Context) error {
	return transaction.transaction.Rollback(ctx)
}
