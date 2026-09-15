package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/meshtransit/meshtransit/internal/node/revocation"
)

func classifyDeviceRevocationDatabaseError(ctx context.Context, err error) error {
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
	case "MT002":
		return errors.Join(revocation.ErrNotFound, err)
	case "23505":
		return errors.Join(revocation.ErrIntentConflict, err)
	case "40001", "40P01", "55P03":
		return errors.Join(revocation.ErrRetryableTransaction, err)
	default:
		return err
	}
}

func classifyDeviceRevocationCommitError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := errors.AsType[*pgconn.PgError](err); ok || errors.Is(err, pgx.ErrTxCommitRollback) {
		return classifyDeviceRevocationDatabaseError(ctx, err)
	}
	if ctx != nil && ctx.Err() != nil {
		return errors.Join(revocation.ErrCommitOutcomeUnknown, ctx.Err(), err)
	}
	return errors.Join(revocation.ErrCommitOutcomeUnknown, err)
}
