package revocation

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	maximumAttempts       = 5
	minimumIdempotencyTTL = time.Minute
	maximumIdempotencyTTL = 24 * time.Hour
)

var (
	// ErrInvalidService reports missing dependencies or unsafe retry settings.
	ErrInvalidService = errors.New("device revocation: invalid service")
	// ErrRevocationFailed classifies a revocation that did not commit.
	ErrRevocationFailed = errors.New("device revocation: operation failed")
	// ErrRetryableTransaction marks a complete transaction that may be replayed.
	ErrRetryableTransaction = errors.New("device revocation: retryable transaction")
	// ErrCommitOutcomeUnknown requires durable idempotency lookup before retry.
	ErrCommitOutcomeUnknown = errors.New("device revocation: commit outcome unknown")
	// ErrRetryExhausted reports exhaustion of the bounded transaction budget.
	ErrRetryExhausted = errors.New("device revocation: retry budget exhausted")
	// ErrRollbackFailed reports failure to close an unsuccessful transaction.
	ErrRollbackFailed = errors.New("device revocation: rollback failed")
)

// Options bounds whole-transaction retries, cleanup, and replay retention.
type Options struct {
	MaxAttempts     int
	RollbackTimeout time.Duration
	IdempotencyTTL  time.Duration
}

// Service owns Device revocation transaction and replay boundaries.
// It starts no goroutines and retains no request-specific mutable state.
type Service struct {
	options      Options
	transactions Transactions
	committed    CommittedResultResolver
	mutationIDs  MutationIDGenerator
	retry        RetryWaiter
}

// NewService validates and constructs a Device revocation service.
func NewService(options Options, dependencies Dependencies) (*Service, error) {
	if dependencies.Transactions == nil || dependencies.CommittedResults == nil ||
		dependencies.MutationIDs == nil || dependencies.Retry == nil ||
		options.MaxAttempts <= 0 || options.MaxAttempts > maximumAttempts ||
		options.RollbackTimeout <= 0 || options.RollbackTimeout > 5*time.Second ||
		options.IdempotencyTTL < minimumIdempotencyTTL ||
		options.IdempotencyTTL > maximumIdempotencyTTL {
		return nil, ErrInvalidService
	}
	return &Service{
		options:      options,
		transactions: dependencies.Transactions,
		committed:    dependencies.CommittedResults,
		mutationIDs:  dependencies.MutationIDs,
		retry:        dependencies.Retry,
	}, nil
}

// Revoke terminally revokes one Device and its current machine/Node key epochs.
// Every retry reuses the same IDs; each attempt decides on its own
// transaction's database time.
func (service *Service) Revoke(ctx context.Context, command Command) (Result, error) {
	if ctx == nil || service == nil || service.transactions == nil || service.committed == nil ||
		service.mutationIDs == nil || service.retry == nil ||
		!command.IsValid() {
		return Result{}, ErrInvalidCommand
	}
	if err := ctx.Err(); err != nil {
		return Result{}, errors.Join(ErrRevocationFailed, err)
	}
	mutationIDs, err := service.mutationIDs.NewMutationIDs()
	if err != nil || !mutationIDs.IsValid() {
		return Result{}, errors.Join(ErrRevocationFailed, ErrInvalidMutationIDs, err)
	}

	var lastErr error
	for ordinal := 1; ordinal <= service.options.MaxAttempts; ordinal++ {
		result, attemptErr := service.attempt(ctx, command, mutationIDs)
		if attemptErr == nil {
			return result, nil
		}
		lastErr = attemptErr
		if errors.Is(attemptErr, ErrCommitOutcomeUnknown) {
			resolved, found, resolveErr := service.committed.ResolveCommitted(ctx, command, mutationIDs)
			if resolveErr == nil && found {
				if !resultMatchesCommand(resolved, command) {
					return Result{}, errors.Join(ErrRevocationFailed, ErrInvalidResult)
				}
				return resolved, nil
			}
			lastErr = errors.Join(lastErr, resolveErr)
		}
		if !errors.Is(attemptErr, ErrRetryableTransaction) &&
			!errors.Is(attemptErr, ErrCommitOutcomeUnknown) {
			return Result{}, errors.Join(ErrRevocationFailed, attemptErr)
		}
		if ordinal == service.options.MaxAttempts {
			return Result{}, errors.Join(ErrRevocationFailed, ErrRetryExhausted, lastErr)
		}
		if err := service.retry.Wait(ctx, ordinal); err != nil {
			return Result{}, errors.Join(ErrRevocationFailed, lastErr, err)
		}
	}
	return Result{}, errors.Join(ErrRevocationFailed, ErrRetryExhausted, lastErr)
}

func (service *Service) attempt(
	ctx context.Context,
	command Command,
	mutationIDs MutationIDs,
) (result Result, resultErr error) {
	transaction, err := service.transactions.Begin(ctx, command.Scope())
	if err != nil || transaction == nil {
		if err == nil {
			err = ErrInvalidService
		}
		return Result{}, fmt.Errorf("begin device revocation transaction: %w", err)
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
			resultErr = errors.Join(
				ErrRollbackFailed,
				fmt.Errorf("rollback device revocation transaction: %w", err),
			)
			if unknownCommit {
				resultErr = errors.Join(resultErr, ErrCommitOutcomeUnknown)
			}
		}
	}()

	// The session check, the decision time and the replay window are the
	// database clock's.
	now := transaction.DecisionTime()
	if now.IsZero() {
		return Result{}, ErrInvalidService
	}
	if !command.AccountSession().IsActiveAt(now) {
		return Result{}, ErrForbidden
	}
	attempt, err := NewAttempt(mutationIDs, now, now.Add(service.options.IdempotencyTTL))
	if err != nil {
		return Result{}, err
	}
	resolution, err := transaction.Resolve(ctx, command, attempt)
	if err != nil {
		return Result{}, fmt.Errorf("resolve device revocation under lock: %w", err)
	}
	if err := validateResolution(command, resolution, attempt); err != nil {
		return Result{}, err
	}
	if completed, ok := resolution.CompletedResult(); ok {
		return completed, nil
	}
	change, err := NewChange(command, resolution, attempt)
	if err != nil {
		return Result{}, err
	}
	result, err = transaction.Apply(ctx, change)
	if err != nil {
		return Result{}, fmt.Errorf("apply device revocation: %w", err)
	}
	if !resultMatchesChange(result, change) {
		return Result{}, ErrInvalidResult
	}
	if err := transaction.Commit(ctx); err != nil {
		return Result{}, fmt.Errorf("commit device revocation transaction: %w", err)
	}
	finished = true
	return result, nil
}

func validateResolution(command Command, resolution Resolution, attempt Attempt) error {
	if !resolution.IsValid() || !attempt.IsValid() {
		return ErrInvalidResolution
	}
	requestHash, err := command.RequestHash()
	if err != nil {
		return ErrInvalidCommand
	}
	if resolution.RequestHash() != requestHash {
		return ErrIntentConflict
	}
	if completed, ok := resolution.CompletedResult(); ok {
		if !resultMatchesCommand(completed, command) {
			return ErrInvalidResult
		}
		return nil
	}
	if resolution.Scope() != command.Scope() || resolution.NodeID() != command.NodeID() {
		return ErrInvalidResolution
	}
	if resolution.DeviceVersion() != command.ExpectedVersion() {
		return ErrConflict
	}
	if resolution.DeviceState() == DeviceStateRevoked {
		return ErrAlreadyRevoked
	}
	if resolution.DeviceState() != DeviceStateActive ||
		resolution.MachineKeyState() != KeyStateActive ||
		resolution.NodeKeyState() != KeyStateActive ||
		attempt.OccurredAt().Before(resolution.MachineKeyValidFrom()) ||
		attempt.OccurredAt().Before(resolution.NodeKeyValidFrom()) {
		return ErrInvalidTransition
	}
	return nil
}

func resultMatchesCommand(result Result, command Command) bool {
	return result.IsValid() && result.Scope() == command.Scope() &&
		result.NodeID() == command.NodeID() &&
		result.DeviceVersion() == command.ExpectedVersion()+1
}

func resultMatchesChange(result Result, change Change) bool {
	resolution := change.Resolution()
	return resultMatchesCommand(result, change.Command()) &&
		result.IdempotencyRecordID() == resolution.IdempotencyRecordID() &&
		result.SessionGeneration() == resolution.SessionGeneration()+1 &&
		result.NetworkRevision() == resolution.NetworkRevision()+1 &&
		result.InventoryRevision() == resolution.InventoryRevision()+1
}
