package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type registrationReplayDatabase interface {
	Begin(context.Context, bool) (registrationReplayTransaction, error)
}

type registrationReplayTransaction interface {
	Exec(context.Context, string, ...any) error
	QueryRow(context.Context, string, ...any) registrationReplayRow
	Commit(context.Context) error
	Rollback(context.Context) error
}

type registrationReplayRow interface {
	Scan(...any) error
}

type pgxRegistrationReplayDatabase struct {
	pool *pgxpool.Pool
}

func (database pgxRegistrationReplayDatabase) Begin(
	ctx context.Context,
	readOnly bool,
) (registrationReplayTransaction, error) {
	options := pgx.TxOptions{}
	if readOnly {
		options.AccessMode = pgx.ReadOnly
	}
	transaction, err := database.pool.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return pgxRegistrationReplayTransaction{transaction: transaction}, nil
}

type pgxRegistrationReplayTransaction struct {
	transaction pgx.Tx
}

func (transaction pgxRegistrationReplayTransaction) Exec(
	ctx context.Context,
	query string,
	arguments ...any,
) error {
	_, err := transaction.transaction.Exec(ctx, query, arguments...)
	return err
}

func (transaction pgxRegistrationReplayTransaction) QueryRow(
	ctx context.Context,
	query string,
	arguments ...any,
) registrationReplayRow {
	return transaction.transaction.QueryRow(ctx, query, arguments...)
}

func (transaction pgxRegistrationReplayTransaction) Commit(ctx context.Context) error {
	return transaction.transaction.Commit(ctx)
}

func (transaction pgxRegistrationReplayTransaction) Rollback(ctx context.Context) error {
	return transaction.transaction.Rollback(ctx)
}
