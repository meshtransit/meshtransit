package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	publication "meshtransit.net/core/internal/domain/policy/publication"
)

func classifyPolicyPublicationDatabaseError(ctx context.Context, err error) error {
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
		return errors.Join(publication.ErrConflict, err)
	case "MTD06":
		return errors.Join(publication.ErrEdgeBudget, err)
	case "MT003", "MT006", "MT008", "MT009", "MT011", "42501":
		return errors.Join(publication.ErrApprovalUnavailable, err)
	case "40001", "40P01", "55P03":
		return errors.Join(publication.ErrRetryableTransaction, err)
	default:
		return err
	}
}

func classifyPolicyPublicationCommitError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := errors.AsType[*pgconn.PgError](err); ok || errors.Is(err, pgx.ErrTxCommitRollback) {
		return classifyPolicyPublicationDatabaseError(ctx, err)
	}
	if ctx != nil && ctx.Err() != nil {
		return errors.Join(publication.ErrCommitOutcomeUnknown, ctx.Err(), err)
	}
	return errors.Join(publication.ErrCommitOutcomeUnknown, err)
}
