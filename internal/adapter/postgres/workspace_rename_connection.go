package postgres

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type pgxWorkspaceRenameDatabase struct{ pool *pgxpool.Pool }

func (database pgxWorkspaceRenameDatabase) Begin(ctx context.Context) (accountSessionTransaction, error) {
	tx, err := database.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted, AccessMode: pgx.ReadWrite})
	if err != nil {
		return nil, err
	}
	return pgxAccountSessionTransaction{transaction: tx}, nil
}
