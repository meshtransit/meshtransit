package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	authority "github.com/meshtransit/meshtransit/internal/resource/authority"
)

func classifyResourceAuthorityDatabaseError(ctx context.Context, err error) error {
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
	case "MT001", "23505":
		return errors.Join(authority.ErrConflict, err)
	case "MT002":
		return errors.Join(
			authority.ErrLifecycleVersionConflict, authority.ErrRebindVersionConflict,
			authority.ErrGroupReplaceVersionConflict, err,
		)
	case "MT003":
		return errors.Join(authority.ErrInvalidLifecycleTransition, err)
	case "MT004":
		return errors.Join(
			authority.ErrRebindStateConflict, authority.ErrGroupReplaceStateConflict, err,
		)
	case "MT005":
		return errors.Join(authority.ErrRebindTargetConflict, err)
	case "MT006":
		return errors.Join(authority.ErrGroupReplaceMemberConflict, err)
	case "MT404":
		return errors.Join(
			authority.ErrLifecycleNotFound, authority.ErrRebindNotFound,
			authority.ErrGroupReplaceNotFound, err,
		)
	case "42501":
		return errors.Join(authority.ErrForbidden, err)
	case "40001", "40P01", "55P03":
		return errors.Join(authority.ErrRetryableTransaction, err)
	default:
		return err
	}
}

func classifyResourceAuthorityCommitError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if _, ok := errors.AsType[*pgconn.PgError](err); ok || errors.Is(err, pgx.ErrTxCommitRollback) {
		return classifyResourceAuthorityDatabaseError(ctx, err)
	}
	if ctx != nil && ctx.Err() != nil {
		return errors.Join(authority.ErrCommitOutcomeUnknown, ctx.Err(), err)
	}
	return errors.Join(authority.ErrCommitOutcomeUnknown, err)
}
