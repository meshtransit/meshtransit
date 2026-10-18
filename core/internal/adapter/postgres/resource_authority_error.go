package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	authority "meshtransit.net/core/internal/domain/resource/authority"
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
	case "23505":
		switch postgresError.ConstraintName {
		case "resource_network_name_current_uidx":
			return errors.Join(authority.ErrNameTaken, err)
		case "resource_device_target_active_device_uidx":
			return errors.Join(authority.ErrDeviceResourceExists, err)
		case "resource_group_network_name_current_uidx":
			return errors.Join(authority.ErrGroupNameTaken, err)
		}
		return errors.Join(authority.ErrConflict, err)
	case "MT001":
		return errors.Join(authority.ErrConflict, err)
	case "MT002":
		return errors.Join(
			authority.ErrLifecycleVersionConflict, authority.ErrRebindVersionConflict,
			authority.ErrGroupReplaceVersionConflict,
			authority.ErrAuthorityChangeVersionConflict,
			authority.ErrAuthorityChangeRequestVersionConflict, err,
		)
	case "MT003":
		return errors.Join(authority.ErrInvalidLifecycleTransition, err)
	case "MT004":
		return errors.Join(
			authority.ErrRebindStateConflict, authority.ErrGroupReplaceStateConflict,
			authority.ErrAuthorityChangeStateConflict,
			authority.ErrAuthorityChangeRequestStateConflict, err,
		)
	case "MT005":
		return errors.Join(
			authority.ErrRebindTargetConflict, authority.ErrAuthorityChangeTargetConflict, err,
		)
	case "MT006":
		return errors.Join(
			authority.ErrGroupReplaceMemberConflict,
			authority.ErrAuthorityChangeImpactChanged, err,
		)
	case "MT007":
		return errors.Join(authority.ErrAuthorityChangeStepUpRequired, err)
	case "MT008":
		return errors.Join(authority.ErrAuthorityChangeRequestExpired, err)
	case "MT404":
		return errors.Join(
			authority.ErrLifecycleNotFound, authority.ErrRebindNotFound,
			authority.ErrGroupReplaceNotFound, authority.ErrAuthorityChangeNotFound, err,
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
