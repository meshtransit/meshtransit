package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type browserIntentDatabase interface {
	Begin(context.Context) (accountSessionTransaction, error)
}

type pgxBrowserIntentDatabase struct{ pool *pgxpool.Pool }

func (database pgxBrowserIntentDatabase) Begin(ctx context.Context) (accountSessionTransaction, error) {
	transaction, err := database.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite,
	})
	if err != nil {
		return nil, err
	}
	return pgxAccountSessionTransaction{transaction: transaction}, nil
}
