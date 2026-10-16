package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/network"
)

type registrationTransactionState uint8

const (
	registrationTransactionOpen registrationTransactionState = iota
	registrationTransactionResolved
	registrationTransactionApplied
	registrationTransactionClosed
)

type registrationTransaction struct {
	mu sync.Mutex

	decisionAt          time.Time
	database            registrationDatabaseTransaction
	scope               network.Scope
	workspaceInternalID int64
	networkInternalID   int64
	candidateLimit      int
	metrics             *postgresPoolMetrics
	state               registrationTransactionState
	locked              registrationLockedState
}

// DecisionTime is this transaction's time on the database clock.
func (transaction *registrationTransaction) DecisionTime() time.Time { return transaction.decisionAt }

var _ registration.Transaction = (*registrationTransaction)(nil)

func (transaction *registrationTransaction) Commit(ctx context.Context) (resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationRegistrationCommit, startedAt, resultErr)
	}()

	if ctx == nil || transaction == nil {
		return ErrRegistrationTransactionState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != registrationTransactionApplied {
		return ErrRegistrationTransactionState
	}

	transaction.state = registrationTransactionClosed
	if err := transaction.database.Commit(ctx); err != nil {
		return errors.Join(
			ErrCommitRegistrationTransaction,
			classifyRegistrationCommitError(ctx, err),
		)
	}
	return nil
}

func (transaction *registrationTransaction) Rollback(ctx context.Context) (resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationRegistrationRollback, startedAt, resultErr)
	}()

	if ctx == nil || transaction == nil {
		return ErrRegistrationTransactionState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil {
		return ErrRegistrationTransactionState
	}
	if transaction.state == registrationTransactionClosed {
		return nil
	}

	transaction.state = registrationTransactionClosed
	if err := transaction.database.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return errors.Join(
			ErrRollbackRegistrationTransaction,
			fmt.Errorf("roll back database transaction: %w", err),
		)
	}
	return nil
}

func (transaction *registrationTransaction) observe(
	operation postgresOperation,
	startedAt time.Time,
	err error,
) {
	if transaction == nil {
		return
	}
	transaction.metrics.observeOperation(operation, time.Since(startedAt), err)
}
