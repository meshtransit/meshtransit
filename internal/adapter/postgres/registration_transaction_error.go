package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/meshtransit/meshtransit/internal/enrollment/registration"
)

func classifyRegistrationDatabaseError(ctx context.Context, err error) error {
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
	case "40001", "40P01", "55P03":
		return errors.Join(registration.ErrRetryableTransaction, err)
	case "23505":
		if retryableRegistrationConstraint(postgresError.ConstraintName) {
			return errors.Join(registration.ErrRetryableTransaction, err)
		}
	}
	return err
}

func classifyRegistrationCommitError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := errors.AsType[*pgconn.PgError](err); ok || errors.Is(err, pgx.ErrTxCommitRollback) {
		return classifyRegistrationDatabaseError(ctx, err)
	}
	if ctx != nil && ctx.Err() != nil {
		return errors.Join(registration.ErrCommitOutcomeUnknown, ctx.Err(), err)
	}
	return errors.Join(registration.ErrCommitOutcomeUnknown, err)
}

func retryableRegistrationConstraint(name string) bool {
	switch name {
	case "device_network_hostname_active_uidx",
		"node_address_lease_address_live_uidx",
		"node_address_lease_device_primary_uidx":
		return true
	default:
		return false
	}
}
