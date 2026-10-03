package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

// ErrAuthCreationClock classifies failed reads of the authoritative creation time.
var ErrAuthCreationClock = errors.New("read postgres auth creation time")

var _ oidcauth.CreationClock = (*AuthTransactionStore)(nil)

// CreationTime completes one bounded read-only unit before releasing the DB time.
// The Start service seals this time into the pending hash before any creation.
// Sampling never grants authority or extends a subsequently checked deadline.
func (store *AuthTransactionStore) CreationTime(ctx context.Context) (at time.Time, resultErr error) {
	startedAt := time.Now()
	defer func() {
		if resultErr != nil {
			at = time.Time{}
		}
		store.observe(postgresOperationAuthCreationClock, startedAt, resultErr)
	}()
	if ctx == nil || store == nil || store.database == nil || !validAuthTransactionOptions(store.options) {
		return time.Time{}, ErrInvalidAuthTransactionStore
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return time.Time{}, errors.Join(ErrAuthCreationClock, err)
	}
	transaction, beginErr := store.database.Begin(ctx, true)
	closed := false
	if transaction != nil {
		defer func() {
			if closed {
				return
			}
			cleanup, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), authTransactionSetupRollbackWindow)
			defer cleanupCancel()
			err := transaction.Rollback(cleanup)
			if errors.Is(err, pgx.ErrTxClosed) {
				err = nil
			}
			if err = errors.Join(err, cleanup.Err()); err != nil {
				resultErr = errors.Join(resultErr, ErrAuthCreationClock, classifyAuthTransactionDatabaseError(cleanup, err))
			}
		}()
	}
	if beginErr != nil {
		return time.Time{}, errors.Join(ErrAuthCreationClock, classifyAuthTransactionDatabaseError(ctx, beginErr))
	}
	if transaction == nil {
		return time.Time{}, errors.Join(ErrAuthCreationClock, ErrAuthTransactionEvidence)
	}
	if err := store.configure(ctx, transaction); err != nil {
		return time.Time{}, errors.Join(ErrAuthCreationClock, err)
	}
	if err := transaction.QueryRow(ctx, authClaimClockSQL).Scan(&at); err != nil {
		return time.Time{}, errors.Join(ErrAuthCreationClock, classifyAuthTransactionDatabaseError(ctx, err))
	}
	if at.IsZero() {
		return time.Time{}, errors.Join(ErrAuthCreationClock, ErrAuthTransactionEvidence)
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, errors.Join(ErrAuthCreationClock, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return time.Time{}, errors.Join(ErrAuthCreationClock, classifyAuthTransactionDatabaseError(ctx, err))
	}
	closed = true
	if err := ctx.Err(); err != nil {
		return time.Time{}, errors.Join(ErrAuthCreationClock, err)
	}
	return at.UTC(), nil
}
