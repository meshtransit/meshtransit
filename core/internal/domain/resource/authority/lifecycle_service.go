package authority

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// LifecycleService owns transaction and retry boundaries for state transitions.
type LifecycleService struct {
	options      Options
	transactions LifecycleTransactions
	committed    CommittedLifecycleResultResolver
	mutationIDs  LifecycleMutationIDGenerator
	retry        RetryWaiter
}

// NewLifecycleService validates and constructs the lifecycle application service.
func NewLifecycleService(
	options Options,
	dependencies LifecycleDependencies,
) (*LifecycleService, error) {
	if dependencies.Transactions == nil || dependencies.CommittedResults == nil ||
		dependencies.MutationIDs == nil || dependencies.Retry == nil ||
		options.MaxAttempts <= 0 || options.MaxAttempts > maximumAttempts ||
		options.RollbackTimeout <= 0 || options.RollbackTimeout > 5*time.Second ||
		options.IdempotencyWindow < minimumIdempotencyWindow ||
		options.IdempotencyWindow > maximumIdempotencyWindow {
		return nil, ErrInvalidService
	}
	return &LifecycleService{
		options: options, transactions: dependencies.Transactions,
		committed: dependencies.CommittedResults, mutationIDs: dependencies.MutationIDs,
		retry: dependencies.Retry,
	}, nil
}

// Transition commits one Resource or Resource Group lifecycle transition.
func (service *LifecycleService) Transition(
	ctx context.Context,
	command LifecycleCommand,
) (LifecycleResult, error) {
	if ctx == nil || service == nil || service.transactions == nil || service.committed == nil ||
		service.mutationIDs == nil || service.retry == nil ||
		!command.IsValid() {
		return LifecycleResult{}, ErrInvalidLifecycleCommand
	}
	if err := ctx.Err(); err != nil {
		return LifecycleResult{}, errors.Join(ErrMutationFailed, err)
	}
	mutationIDs, err := service.mutationIDs.NewLifecycleMutationIDs(command)
	if err != nil || !mutationIDs.IsValid() {
		return LifecycleResult{}, errors.Join(ErrMutationFailed, ErrInvalidLifecycleMutationIDs, err)
	}
	var lastErr error
	for attempt := 1; attempt <= service.options.MaxAttempts; attempt++ {
		result, attemptErr := service.lifecycleAttempt(ctx, command, mutationIDs)
		if attemptErr == nil {
			return result, nil
		}
		lastErr = attemptErr
		if errors.Is(attemptErr, ErrCommitOutcomeUnknown) {
			resolved, found, resolveErr := service.committed.ResolveCommittedLifecycle(
				ctx, command, mutationIDs,
			)
			if resolveErr == nil && found {
				if !lifecycleResultMatches(resolved, command) {
					return LifecycleResult{}, errors.Join(ErrMutationFailed, ErrInvalidLifecycleResult)
				}
				return resolved, nil
			}
			lastErr = errors.Join(lastErr, resolveErr)
		}
		if !errors.Is(attemptErr, ErrRetryableTransaction) &&
			!errors.Is(attemptErr, ErrCommitOutcomeUnknown) {
			return LifecycleResult{}, errors.Join(ErrMutationFailed, attemptErr)
		}
		if attempt == service.options.MaxAttempts {
			return LifecycleResult{}, errors.Join(ErrMutationFailed, ErrRetryExhausted, lastErr)
		}
		if err := service.retry.Wait(ctx, attempt); err != nil {
			return LifecycleResult{}, errors.Join(ErrMutationFailed, lastErr, err)
		}
	}
	return LifecycleResult{}, errors.Join(ErrMutationFailed, ErrRetryExhausted, lastErr)
}

func (service *LifecycleService) lifecycleAttempt(
	ctx context.Context,
	command LifecycleCommand,
	mutationIDs LifecycleMutationIDs,
) (result LifecycleResult, resultErr error) {
	transaction, err := service.transactions.BeginLifecycle(ctx, command.Scope())
	if err != nil || transaction == nil {
		if err == nil {
			err = ErrInvalidService
		}
		return LifecycleResult{}, fmt.Errorf("begin Resource lifecycle transaction: %w", err)
	}
	finished := false
	defer func() {
		if finished {
			return
		}
		rollbackCtx, cancel := context.WithTimeout(
			context.WithoutCancel(ctx), service.options.RollbackTimeout,
		)
		defer cancel()
		if err := transaction.Rollback(rollbackCtx); err != nil {
			unknownCommit := errors.Is(resultErr, ErrCommitOutcomeUnknown)
			result = LifecycleResult{}
			resultErr = errors.Join(ErrRollbackFailed, err)
			if unknownCommit {
				resultErr = errors.Join(resultErr, ErrCommitOutcomeUnknown)
			}
		}
	}()
	// Every time of this attempt is the database clock's.
	now := transaction.DecisionTime()
	expiresAt := now.Add(service.options.IdempotencyWindow)
	if now.IsZero() || !expiresAt.After(now) {
		return LifecycleResult{}, ErrInvalidService
	}
	resolution, err := transaction.Resolve(ctx, command, mutationIDs, now, expiresAt)
	if err != nil {
		return LifecycleResult{}, fmt.Errorf("resolve Resource lifecycle under lock: %w", err)
	}
	if !resolution.IsValid() || resolution.Scope() != command.Scope() {
		return LifecycleResult{}, ErrInvalidLifecycleResolution
	}
	if resolution.IsCompleted() {
		replayed := resolution.CompletedResult()
		if !lifecycleResultMatches(replayed, command) {
			return LifecycleResult{}, ErrInvalidLifecycleResult
		}
		rollbackCtx, cancel := context.WithTimeout(
			context.WithoutCancel(ctx), service.options.RollbackTimeout,
		)
		defer cancel()
		if err := transaction.Rollback(rollbackCtx); err != nil {
			return LifecycleResult{}, errors.Join(ErrRollbackFailed, err)
		}
		finished = true
		return replayed, nil
	}
	change, err := NewLifecycleChange(command, resolution, mutationIDs, now, expiresAt)
	if err != nil {
		return LifecycleResult{}, err
	}
	result, err = transaction.Apply(ctx, change)
	if err != nil {
		return LifecycleResult{}, fmt.Errorf("apply Resource lifecycle: %w", err)
	}
	if !lifecycleResultMatches(result, command) ||
		result.NetworkRevision() != resolution.NetworkRevision()+1 {
		return LifecycleResult{}, ErrInvalidLifecycleResult
	}
	expectedSubsystemRevision := resolution.InventoryRevision() + 1
	if command.Operation().IsGroup() {
		expectedSubsystemRevision = resolution.GroupRevision() + 1
	}
	if result.SubsystemRevision() != expectedSubsystemRevision {
		return LifecycleResult{}, ErrInvalidLifecycleResult
	}
	if err := transaction.Commit(ctx); err != nil {
		return LifecycleResult{}, fmt.Errorf("commit Resource lifecycle: %w", err)
	}
	finished = true
	return result, nil
}

func lifecycleResultMatches(result LifecycleResult, command LifecycleCommand) bool {
	if !result.IsValid() || result.Operation() != command.Operation() ||
		result.Scope() != command.Scope() || result.State() != command.Operation().TargetState() ||
		result.Version() != command.ExpectedVersion()+1 {
		return false
	}
	if command.Operation().IsGroup() {
		return result.GroupID() == command.GroupID() && !result.ResourceID().IsValid()
	}
	return result.ResourceID() == command.ResourceID() && !result.GroupID().IsValid()
}
