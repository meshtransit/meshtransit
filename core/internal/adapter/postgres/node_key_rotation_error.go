package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"meshtransit.net/core/internal/domain/node/keyrotation"
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
	// consume_kubernetes_gateway_rotation_token_v1: the session is no longer
	// the Device's.
	case "P0002":
		return errors.Join(keyrotation.ErrNotFound, err)
	// Schema 232: a gateway's pod token was used for this key, checked
	// against a trust that changed, absent at its new epoch, or expired.
	case "MTK17", "MTK18", "MTK19", "MTK20":
		return errors.Join(keyrotation.ErrGatewayTokenRefused, err)
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
