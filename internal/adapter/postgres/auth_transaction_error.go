package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func classifyAuthTransactionDatabaseError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	postgresError, ok := errors.AsType[*pgconn.PgError](err)
	if ok {
		// Constraint DETAIL can include a state/nonce digest or ciphertext. Keep
		// SQLSTATE classification without propagating secret-derived row values.
		err = &pgconn.PgError{Code: postgresError.Code, Message: "OIDC database operation rejected"}
	}
	if ctx != nil && ctx.Err() != nil {
		return errors.Join(ctx.Err(), err)
	}
	if !ok {
		return err
	}
	switch postgresError.Code {
	case "23503":
		return errors.Join(ErrAuthTransactionRouteUnavailable, err)
	case "23505", "23P01":
		return errors.Join(ErrAuthTransactionConflict, err)
	case "23514":
		return errors.Join(ErrAuthTransactionEvidence, err)
	case "40001", "40P01", "55P03":
		return errors.Join(ErrAuthTransactionRetryable, err)
	default:
		return err
	}
}

func classifyAuthTransactionCommitError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := errors.AsType[*pgconn.PgError](err); ok || errors.Is(err, pgx.ErrTxCommitRollback) {
		return classifyAuthTransactionDatabaseError(ctx, err)
	}
	if ctx != nil && ctx.Err() != nil {
		return errors.Join(ErrAuthTransactionCommitOutcomeUnknown, ctx.Err(), err)
	}
	return errors.Join(ErrAuthTransactionCommitOutcomeUnknown, err)
}
