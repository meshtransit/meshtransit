package keyrotation

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const maximumAttempts = 5

var (
	// ErrInvalidService reports missing dependencies or unsafe retry settings.
	ErrInvalidService = errors.New("node key rotation: invalid service")
	// ErrRotationFailed classifies an operation that did not converge.
	ErrRotationFailed = errors.New("node key rotation: operation failed")
	// ErrRetryableTransaction marks a whole transaction that may be replayed.
	ErrRetryableTransaction = errors.New("node key rotation: retryable transaction")
	// ErrCommitOutcomeUnknown requires replay of the same old/new transition.
	ErrCommitOutcomeUnknown = errors.New("node key rotation: commit outcome unknown")
	// ErrRetryExhausted reports exhaustion of the bounded retry budget.
	ErrRetryExhausted = errors.New("node key rotation: retry budget exhausted")
	// ErrRollbackFailed reports failure to close an unsuccessful transaction.
	ErrRollbackFailed = errors.New("node key rotation: rollback failed")
)

// Options bounds whole-transaction retry and cleanup behavior.
type Options struct {
	MaxAttempts     int
	RollbackTimeout time.Duration
}

// Service owns authenticated Node-key rotation transaction boundaries.
type Service struct {
	options      Options
	transactions Transactions
	mutationIDs  MutationIDGenerator
	clock        Clock
	retry        RetryWaiter
}

// NewService validates and constructs a Node-key rotation service.
func NewService(options Options, dependencies Dependencies) (*Service, error) {
	if dependencies.Transactions == nil || dependencies.MutationIDs == nil ||
		dependencies.Clock == nil || dependencies.Retry == nil ||
		options.MaxAttempts <= 0 || options.MaxAttempts > maximumAttempts ||
		options.RollbackTimeout <= 0 || options.RollbackTimeout > 5*time.Second {
		return nil, ErrInvalidService
	}
	return &Service{
		options:      options,
		transactions: dependencies.Transactions,
		mutationIDs:  dependencies.MutationIDs,
		clock:        dependencies.Clock,
		retry:        dependencies.Retry,
	}, nil
}

// Rotate advances exactly one key/session/revision generation or returns its replay.
func (service *Service) Rotate(ctx context.Context, command Command) (Result, error) {
	if ctx == nil || service == nil || service.transactions == nil ||
		service.mutationIDs == nil || service.clock == nil || service.retry == nil ||
		!command.IsValid() {
		return Result{}, ErrInvalidCommand
	}
	if err := ctx.Err(); err != nil {
		return Result{}, errors.Join(ErrRotationFailed, err)
	}
	occurredAt := service.clock.Now().UTC()
	if occurredAt.IsZero() {
		return Result{}, ErrInvalidService
	}
	mutationIDs, err := service.mutationIDs.NewMutationIDs()
	if err != nil || !mutationIDs.IsValid() {
		return Result{}, errors.Join(ErrRotationFailed, errInvalidMutationIDs, err)
	}

	var lastErr error
	for attempt := 1; attempt <= service.options.MaxAttempts; attempt++ {
		result, attemptErr := service.attempt(ctx, command, mutationIDs, occurredAt)
		if attemptErr == nil {
			return result, nil
		}
		lastErr = attemptErr
		if !errors.Is(attemptErr, ErrRetryableTransaction) &&
			!errors.Is(attemptErr, ErrCommitOutcomeUnknown) {
			return Result{}, errors.Join(ErrRotationFailed, attemptErr)
		}
		if attempt == service.options.MaxAttempts {
			return Result{}, errors.Join(ErrRotationFailed, ErrRetryExhausted, lastErr)
		}
		if err := service.retry.Wait(ctx, attempt); err != nil {
			return Result{}, errors.Join(ErrRotationFailed, lastErr, err)
		}
	}
	return Result{}, errors.Join(ErrRotationFailed, ErrRetryExhausted, lastErr)
}

func (service *Service) attempt(
	ctx context.Context,
	command Command,
	mutationIDs MutationIDs,
	occurredAt time.Time,
) (result Result, resultErr error) {
	transaction, err := service.transactions.Begin(ctx, command)
	if err != nil || transaction == nil {
		if err == nil {
			err = ErrInvalidService
		}
		return Result{}, fmt.Errorf("begin Node-key rotation transaction: %w", err)
	}
	finished := false
	defer func() {
		if finished {
			return
		}
		rollbackCtx, cancel := context.WithTimeout(
			context.WithoutCancel(ctx),
			service.options.RollbackTimeout,
		)
		defer cancel()
		if err := transaction.Rollback(rollbackCtx); err != nil {
			unknownCommit := errors.Is(resultErr, ErrCommitOutcomeUnknown)
			result = Result{}
			resultErr = errors.Join(ErrRollbackFailed, err)
			if unknownCommit {
				resultErr = errors.Join(resultErr, ErrCommitOutcomeUnknown)
			}
		}
	}()

	resolution, err := transaction.Resolve(ctx, command)
	if err != nil {
		return Result{}, fmt.Errorf("resolve Node-key rotation under lock: %w", err)
	}
	if completed, ok := resolution.CompletedResult(); ok {
		if !resultMatchesCommand(completed, command) {
			return Result{}, ErrInvalidResolution
		}
		return completed, nil
	}
	if !resolution.isOpenValid() || resolution.MachineKey() != command.MachineKey() ||
		resolution.CurrentNodeKey() != command.OldNodeKey() {
		return Result{}, ErrConflict
	}
	change, err := NewChange(command, resolution, mutationIDs, occurredAt)
	if err != nil {
		return Result{}, err
	}
	result, err = transaction.Apply(ctx, change)
	if err != nil {
		return Result{}, fmt.Errorf("apply Node-key rotation: %w", err)
	}
	if !resultMatchesChange(result, change) {
		return Result{}, ErrInvalidResult
	}
	if err := transaction.Commit(ctx); err != nil {
		return Result{}, fmt.Errorf("commit Node-key rotation: %w", err)
	}
	finished = true
	return result, nil
}

func resultMatchesCommand(result Result, command Command) bool {
	return result.IsValid() && result.OperationID() == command.OperationID()
}

func resultMatchesChange(result Result, change Change) bool {
	resolution := change.Resolution()
	return resultMatchesCommand(result, change.Command()) &&
		result.Scope() == resolution.Scope() && result.NodeID() == resolution.NodeID() &&
		result.Hostname() == resolution.Hostname() &&
		result.DeviceVersion() == resolution.DeviceVersion()+1 &&
		result.NodeKeyEpoch() == resolution.NodeKeyEpoch()+1 &&
		result.SessionGeneration() == resolution.SessionGeneration()+1 &&
		result.NetworkRevision() == resolution.NetworkRevision()+1 &&
		result.InventoryRevision() == resolution.InventoryRevision()+1
}
