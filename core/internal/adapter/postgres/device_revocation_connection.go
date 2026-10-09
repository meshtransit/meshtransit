package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type deviceRevocationDatabase interface {
	Begin(context.Context, bool) (deviceRevocationDatabaseTransaction, error)
}

type deviceRevocationDatabaseTransaction interface {
	Exec(context.Context, string, ...any) error
	QueryRow(context.Context, string, ...any) deviceRevocationRow
	Commit(context.Context) error
	Rollback(context.Context) error
}

type deviceRevocationRow interface {
	Scan(...any) error
}

type pgxDeviceRevocationDatabase struct {
	pool *pgxpool.Pool
}

func (database pgxDeviceRevocationDatabase) Begin(
	ctx context.Context,
	readOnly bool,
) (deviceRevocationDatabaseTransaction, error) {
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
	return pgxDeviceRevocationTransaction{transaction: transaction}, nil
}

type pgxDeviceRevocationTransaction struct {
	transaction pgx.Tx
}

func (transaction pgxDeviceRevocationTransaction) Exec(
	ctx context.Context,
	query string,
	arguments ...any,
) error {
	_, err := transaction.transaction.Exec(ctx, query, arguments...)
	return err
}

func (transaction pgxDeviceRevocationTransaction) QueryRow(
	ctx context.Context,
	query string,
	arguments ...any,
) deviceRevocationRow {
	return transaction.transaction.QueryRow(ctx, query, arguments...)
}

func (transaction pgxDeviceRevocationTransaction) Commit(ctx context.Context) error {
	return transaction.transaction.Commit(ctx)
}

func (transaction pgxDeviceRevocationTransaction) Rollback(ctx context.Context) error {
	return transaction.transaction.Rollback(ctx)
}
