package registrationintake

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	appintake "github.com/meshtransit/meshtransit/core/internal/domain/enrollment/registration/intake"
)

func classifyDatabaseError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return errors.Join(ctx.Err(), err)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return appintake.ErrCredentialRejected
	}
	postgresError, ok := errors.AsType[*pgconn.PgError](err)
	if !ok {
		return err
	}
	switch postgresError.Code {
	case "23503":
		return appintake.ErrCredentialRejected
	case "40001", "40P01", "55P03":
		return errors.Join(appintake.ErrRetryableTransaction, err)
	case "23505":
		if retryableConstraint(postgresError.ConstraintName) {
			return errors.Join(appintake.ErrRetryableTransaction, err)
		}
	}
	return err
}

func classifyCommitError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := errors.AsType[*pgconn.PgError](err); ok || errors.Is(err, pgx.ErrTxCommitRollback) {
		return classifyDatabaseError(ctx, err)
	}
	if ctx != nil && ctx.Err() != nil {
		return errors.Join(appintake.ErrCommitOutcomeUnknown, ctx.Err(), err)
	}
	return errors.Join(appintake.ErrCommitOutcomeUnknown, err)
}

func retryableConstraint(name string) bool {
	switch name {
	case "pending_registration_public_id_key", "pending_registration_machine_active_uidx":
		return true
	default:
		return false
	}
}
