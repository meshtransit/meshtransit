package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type outboxDatabase interface {
	Query(context.Context, string, ...any) (outboxRows, error)
	QueryRow(context.Context, string, ...any) outboxRow
	Exec(context.Context, string, ...any) (outboxCommandResult, error)
	Begin(context.Context, bool) (outboxTransaction, error)
}

type outboxCommandResult interface {
	RowsAffected() int64
}

type outboxTransaction interface {
	Exec(context.Context, string, ...any) error
	QueryRow(context.Context, string, ...any) outboxRow
	Commit(context.Context) error
	Rollback(context.Context) error
}

type outboxRow interface {
	Scan(...any) error
}

type outboxRows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close()
}

type pgxOutboxDatabase struct {
	pool *pgxpool.Pool
}

func (database pgxOutboxDatabase) Query(
	ctx context.Context,
	query string,
	arguments ...any,
) (outboxRows, error) {
	return database.pool.Query(ctx, query, arguments...)
}

func (database pgxOutboxDatabase) Exec(
	ctx context.Context,
	query string,
	arguments ...any,
) (outboxCommandResult, error) {
	return database.pool.Exec(ctx, query, arguments...)
}

func (database pgxOutboxDatabase) QueryRow(
	ctx context.Context,
	query string,
	arguments ...any,
) outboxRow {
	return database.pool.QueryRow(ctx, query, arguments...)
}

func (database pgxOutboxDatabase) Begin(
	ctx context.Context,
	readOnly bool,
) (outboxTransaction, error) {
	options := pgx.TxOptions{}
	if readOnly {
		options.AccessMode = pgx.ReadOnly
	}
	transaction, err := database.pool.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return pgxOutboxTransaction{transaction: transaction}, nil
}

type pgxOutboxTransaction struct {
	transaction pgx.Tx
}

func (transaction pgxOutboxTransaction) Exec(
	ctx context.Context,
	query string,
	arguments ...any,
) error {
	_, err := transaction.transaction.Exec(ctx, query, arguments...)
	return err
}

func (transaction pgxOutboxTransaction) QueryRow(
	ctx context.Context,
	query string,
	arguments ...any,
) outboxRow {
	return transaction.transaction.QueryRow(ctx, query, arguments...)
}

func (transaction pgxOutboxTransaction) Commit(ctx context.Context) error {
	return transaction.transaction.Commit(ctx)
}

func (transaction pgxOutboxTransaction) Rollback(ctx context.Context) error {
	return transaction.transaction.Rollback(ctx)
}
