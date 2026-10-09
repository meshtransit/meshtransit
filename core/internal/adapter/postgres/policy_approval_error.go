package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	approval "meshtransit.net/core/internal/domain/policy/approval"
)

func classifyPolicyApprovalDatabaseError(ctx context.Context, err error) error {
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
	case "MT001":
		return errors.Join(approval.ErrImpactChanged, err)
	case "MT002":
		return errors.Join(approval.ErrRequestVersionConflict, err)
	case "MT003":
		return errors.Join(approval.ErrRequestStateConflict, err)
	case "MT006":
		return errors.Join(approval.ErrImpactChanged, err)
	case "MT008":
		return errors.Join(approval.ErrRequestExpired, err)
	case "MT009":
		return errors.Join(approval.ErrCandidateChanged, err)
	case "MT010":
		return errors.Join(approval.ErrIndependentApproverRequired, err)
	case "42501":
		return errors.Join(approval.ErrForbidden, err)
	case "23505", "40001", "40P01", "55P03":
		return errors.Join(approval.ErrRetryableTransaction, err)
	default:
		return err
	}
}

func classifyPolicyApprovalCommitError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := errors.AsType[*pgconn.PgError](err); ok || errors.Is(err, pgx.ErrTxCommitRollback) {
		return classifyPolicyApprovalDatabaseError(ctx, err)
	}
	if ctx != nil && ctx.Err() != nil {
		return errors.Join(approval.ErrCommitOutcomeUnknown, ctx.Err(), err)
	}
	return errors.Join(approval.ErrCommitOutcomeUnknown, err)
}
