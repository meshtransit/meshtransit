package registrationintake

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/deployment"
	appintake "meshtransit.net/core/internal/domain/enrollment/registration/intake"
	"meshtransit.net/core/internal/domain/network"
)

type transactionState uint8

const (
	transactionOpen transactionState = iota
	transactionResolved
	transactionApplied
	transactionClosed
)

type transaction struct {
	mu sync.Mutex

	database            databaseTransaction
	lookup              appintake.Lookup
	deploymentID        deployment.ID
	scope               network.Scope
	recoveryEpoch       int64
	workspaceInternalID int64
	networkInternalID   int64
	observer            Observer
	state               transactionState
	locked              lockedState
}

var _ appintake.Transaction = (*transaction)(nil)

func (transaction *transaction) Commit(ctx context.Context) (resultErr error) {
	startedAt := time.Now()
	defer func() {
		if transaction != nil {
			observe(transaction.observer, OperationCommit, startedAt, resultErr)
		}
	}()
	if ctx == nil || transaction == nil {
		return ErrTransactionState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != transactionApplied {
		return ErrTransactionState
	}
	transaction.state = transactionClosed
	if err := transaction.database.Commit(ctx); err != nil {
		return errors.Join(ErrCommitTransaction, classifyCommitError(ctx, err))
	}
	return nil
}

func (transaction *transaction) Rollback(ctx context.Context) (resultErr error) {
	startedAt := time.Now()
	defer func() {
		if transaction != nil {
			observe(transaction.observer, OperationRollback, startedAt, resultErr)
		}
	}()
	if ctx == nil || transaction == nil {
		return ErrTransactionState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil {
		return ErrTransactionState
	}
	if transaction.state == transactionClosed {
		return nil
	}
	transaction.state = transactionClosed
	if err := transaction.database.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return errors.Join(
			ErrRollbackTransaction,
			fmt.Errorf("roll back database transaction: %w", err),
		)
	}
	return nil
}

type lockedState struct {
	resolution             appintake.Resolution
	credentialInternalID   int64
	profileInternalID      int64
	issuerPublicID         string
	currentNetworkRevision int64
	audit                  auditHead
}

type auditHead struct {
	streamInternalID int64
	nextSequence     int64
	previousHash     [32]byte
}
