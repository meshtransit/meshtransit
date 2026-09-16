package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

var errAuthExpiryOperation = errors.New("postgres browser expiry operation failed")

// Worker errors carry fixed classes only, including non-PostgreSQL transport
// errors; neither metrics nor the later poller may log private dependency text.
func classifyAuthExpiryError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	result := errAuthExpiryOperation
	if _, ok := errors.AsType[*pgconn.PgError](err); ok {
		result = errors.Join(result, classifyAuthTransactionDatabaseError(ctx, err))
	}
	for _, class := range []error{
		oidcauth.ErrCommitOutcomeUnknown, ErrAuthTransactionEvidence, ErrAuthTransactionState,
		ErrRollbackAuthTransaction, context.Canceled, context.DeadlineExceeded,
	} {
		if errors.Is(err, class) {
			result = errors.Join(result, class)
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		result = errors.Join(result, ErrAuthTransactionEvidence)
	}
	if ctx != nil {
		result = errors.Join(result, ctx.Err())
	}
	return result
}
