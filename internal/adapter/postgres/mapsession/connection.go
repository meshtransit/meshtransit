// Package mapsession reads authoritative map-session snapshots from PostgreSQL.
package mapsession

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type database interface {
	Begin(context.Context) (databaseTransaction, error)
}

type databaseTransaction interface {
	Exec(context.Context, string, ...any) error
	Query(context.Context, string, ...any) (databaseRows, error)
	QueryRow(context.Context, string, ...any) databaseRow
	Commit(context.Context) error
	Rollback(context.Context) error
}

type databaseRows interface {
	Next() bool
	Scan(...any) error
	Err() error
	Close()
}

type databaseRow interface {
	Scan(...any) error
}

type pgxDatabase struct {
	pool *pgxpool.Pool
}

func newPGXDatabase(pool *pgxpool.Pool) database {
	if pool == nil {
		return nil
	}
	return pgxDatabase{pool: pool}
}

func (database pgxDatabase) Begin(ctx context.Context) (databaseTransaction, error) {
	transaction, err := database.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return nil, err
	}
	return pgxDatabaseTransaction{transaction: transaction}, nil
}

type pgxDatabaseTransaction struct {
	transaction pgx.Tx
}

func (transaction pgxDatabaseTransaction) Exec(
	ctx context.Context,
	query string,
	arguments ...any,
) error {
	_, err := transaction.transaction.Exec(ctx, query, arguments...)
	return err
}

func (transaction pgxDatabaseTransaction) QueryRow(
	ctx context.Context,
	query string,
	arguments ...any,
) databaseRow {
	return transaction.transaction.QueryRow(ctx, query, arguments...)
}

func (transaction pgxDatabaseTransaction) Query(
	ctx context.Context,
	query string,
	arguments ...any,
) (databaseRows, error) {
	return transaction.transaction.Query(ctx, query, arguments...)
}

func (transaction pgxDatabaseTransaction) Commit(ctx context.Context) error {
	return transaction.transaction.Commit(ctx)
}

func (transaction pgxDatabaseTransaction) Rollback(ctx context.Context) error {
	return transaction.transaction.Rollback(ctx)
}
