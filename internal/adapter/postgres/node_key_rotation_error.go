package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/meshtransit/meshtransit/internal/node/keyrotation"
)

func classifyNodeKeyRotationDatabaseError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return errors.Join(ctx.Err(), err)
	}
	postgresError, ok := errors.AsType[*pgconn.PgError](err)
	if !ok {
		return err
	}
	switch postgresError.Code {
	case "23505", "23514":
		return errors.Join(keyrotation.ErrConflict, err)
	case "40001", "40P01", "55P03":
		return errors.Join(keyrotation.ErrRetryableTransaction, err)
	default:
		return err
	}
}

func classifyNodeKeyRotationCommitError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := errors.AsType[*pgconn.PgError](err); ok || errors.Is(err, pgx.ErrTxCommitRollback) {
		return classifyNodeKeyRotationDatabaseError(ctx, err)
	}
	if ctx != nil && ctx.Err() != nil {
		return errors.Join(keyrotation.ErrCommitOutcomeUnknown, ctx.Err(), err)
	}
	return errors.Join(keyrotation.ErrCommitOutcomeUnknown, err)
}
