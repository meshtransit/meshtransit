package authority

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"
)

const (
	maximumAttempts          = 5
	maximumRetryDelay        = time.Minute
	minimumIdempotencyWindow = time.Minute
	maximumIdempotencyWindow = 24 * time.Hour
)

var (
	// ErrInvalidService reports missing dependencies or unsafe retry settings.
	ErrInvalidService = errors.New("resource authority: invalid service")
	// ErrMutationFailed classifies a mutation that did not commit.
	ErrMutationFailed = errors.New("resource authority: operation failed")
	// ErrRetryableTransaction marks a complete transaction attempt that may replay.
	ErrRetryableTransaction = errors.New("resource authority: retryable transaction")
	// ErrCommitOutcomeUnknown requires resolution by stable aggregate identity.
	ErrCommitOutcomeUnknown = errors.New("resource authority: commit outcome unknown")
	// ErrRetryExhausted reports a consumed bounded retry budget.
	ErrRetryExhausted = errors.New("resource authority: retry budget exhausted")
	// ErrRollbackFailed reports that a failed transaction did not close cleanly.
	ErrRollbackFailed = errors.New("resource authority: rollback failed")
	// ErrInvalidBackoff reports unsafe delay bounds or attempt ordinals.
	ErrInvalidBackoff = errors.New("resource authority: invalid retry backoff")
)

// Options bounds whole-transaction retry and cleanup behavior.
type Options struct {
	MaxAttempts       int
	RollbackTimeout   time.Duration
	IdempotencyWindow time.Duration
}

// Service owns the Resource authority transaction boundary and retry protocol.
type Service struct {
	options      Options
	transactions Transactions
	committed    CommittedResultResolver
	mutationIDs  MutationIDGenerator
	retry        RetryWaiter
}

// NewService validates and constructs the application service.
func NewService(options Options, dependencies Dependencies) (*Service, error) {
	if dependencies.Transactions == nil || dependencies.CommittedResults == nil ||
		dependencies.MutationIDs == nil || dependencies.Retry == nil ||
		options.MaxAttempts <= 0 || options.MaxAttempts > maximumAttempts ||
		options.RollbackTimeout <= 0 || options.RollbackTimeout > 5*time.Second ||
		options.IdempotencyWindow < minimumIdempotencyWindow ||
		options.IdempotencyWindow > maximumIdempotencyWindow {
		return nil, ErrInvalidService
	}
	return &Service{
		options: options, transactions: dependencies.Transactions,
		committed: dependencies.CommittedResults, mutationIDs: dependencies.MutationIDs,
		retry: dependencies.Retry,
	}, nil
}

// Create commits one Resource or Resource Group with atomic evidence.
func (service *Service) Create(ctx context.Context, command Command) (Result, error) {
	if ctx == nil || service == nil || service.transactions == nil || service.committed == nil ||
		service.mutationIDs == nil || service.retry == nil ||
		!command.IsValid() {
		return Result{}, ErrInvalidCommand
	}
	if err := ctx.Err(); err != nil {
		return Result{}, errors.Join(ErrMutationFailed, err)
	}
	mutationIDs, err := service.mutationIDs.NewMutationIDs(command)
	if err != nil || !mutationIDs.IsValidFor(command) {
		return Result{}, errors.Join(ErrMutationFailed, ErrInvalidMutationIDs, err)
	}
	var lastErr error
	for attempt := 1; attempt <= service.options.MaxAttempts; attempt++ {
		result, attemptErr := service.attempt(ctx, command, mutationIDs)
		if attemptErr == nil {
			return result, nil
		}
		lastErr = attemptErr
		if errors.Is(attemptErr, ErrCommitOutcomeUnknown) {
			resolved, found, resolveErr := service.committed.ResolveCommitted(ctx, command, mutationIDs)
			if resolveErr == nil && found {
				if !resultMatches(resolved, command, mutationIDs) {
					return Result{}, errors.Join(ErrMutationFailed, ErrInvalidResult)
				}
				return resolved, nil
			}
			lastErr = errors.Join(lastErr, resolveErr)
		}
		if !errors.Is(attemptErr, ErrRetryableTransaction) &&
			!errors.Is(attemptErr, ErrCommitOutcomeUnknown) {
			return Result{}, errors.Join(ErrMutationFailed, attemptErr)
		}
		if attempt == service.options.MaxAttempts {
			return Result{}, errors.Join(ErrMutationFailed, ErrRetryExhausted, lastErr)
		}
		if err := service.retry.Wait(ctx, attempt); err != nil {
			return Result{}, errors.Join(ErrMutationFailed, lastErr, err)
		}
	}
	return Result{}, errors.Join(ErrMutationFailed, ErrRetryExhausted, lastErr)
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
		return Result{}, fmt.Errorf("begin resource authority transaction: %w", err)
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
			result = Result{}
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
		return Result{}, ErrInvalidService
	}
	resolution, err := transaction.Resolve(ctx, command, mutationIDs, now, expiresAt)
	if err != nil {
		return Result{}, fmt.Errorf("resolve resource authority under lock: %w", err)
	}
	if err := validateResolution(command, resolution); err != nil {
		return Result{}, err
	}
	if resolution.IsCompleted() {
		replayed := resolution.CompletedResult()
		if !resultMatchesCommand(replayed, command) {
			return Result{}, ErrInvalidResult
		}
		rollbackCtx, cancel := context.WithTimeout(
			context.WithoutCancel(ctx), service.options.RollbackTimeout,
		)
		defer cancel()
		if err := transaction.Rollback(rollbackCtx); err != nil {
			return Result{}, errors.Join(ErrRollbackFailed, err)
		}
		finished = true
		return replayed, nil
	}
	change, err := NewChange(command, resolution, mutationIDs, now, expiresAt)
	if err != nil {
		return Result{}, err
	}
	result, err = transaction.Apply(ctx, change)
	if err != nil {
		return Result{}, fmt.Errorf("apply resource authority: %w", err)
	}
	if !resultMatchesChange(result, change) {
		return Result{}, ErrInvalidResult
	}
	if err := transaction.Commit(ctx); err != nil {
		return Result{}, fmt.Errorf("commit resource authority: %w", err)
	}
	finished = true
	return result, nil
}

func validateResolution(command Command, resolution Resolution) error {
	if !resolution.IsValid() || resolution.Scope() != command.Scope() {
		return ErrInvalidResolution
	}
	if resolution.IsCompleted() {
		return nil
	}
	current := resolution.InventoryRevision()
	if command.Operation() == OperationCreateGroup {
		current = resolution.GroupRevision()
	}
	if current != command.ExpectedSubsystemRevision() {
		return ErrConflict
	}
	return nil
}

func resultMatches(result Result, command Command, ids MutationIDs) bool {
	if !resultMatchesCommand(result, command) {
		return false
	}
	if command.Operation() == OperationCreateDevice {
		return result.ResourceID() == ids.ResourceID()
	}
	return result.GroupID() == ids.GroupID()
}

func resultMatchesCommand(result Result, command Command) bool {
	return result.IsValid() && result.Operation() == command.Operation() &&
		result.Scope() == command.Scope() && result.SemanticHash() == command.SemanticHash()
}

func resultMatchesChange(result Result, change Change) bool {
	return resultMatches(result, change.Command(), change.MutationIDs()) &&
		result.NetworkRevision() == change.Resolution().NetworkRevision()+1 &&
		result.SubsystemRevision() == change.Command().ExpectedSubsystemRevision()+1
}

// ExponentialBackoff provides capped exponential delay with 50-100% jitter.
type ExponentialBackoff struct {
	initial time.Duration
	maximum time.Duration
	entropy io.Reader
}

// NewExponentialBackoff validates retry bounds and uses operating-system entropy.
func NewExponentialBackoff(initial, maximum time.Duration) (*ExponentialBackoff, error) {
	return newExponentialBackoff(initial, maximum, rand.Reader)
}

func newExponentialBackoff(
	initial, maximum time.Duration,
	entropy io.Reader,
) (*ExponentialBackoff, error) {
	if initial <= 0 || maximum < initial || maximum > maximumRetryDelay || entropy == nil {
		return nil, ErrInvalidBackoff
	}
	return &ExponentialBackoff{initial: initial, maximum: maximum, entropy: entropy}, nil
}

// Wait blocks the caller until jittered delay or cancellation.
func (backoff *ExponentialBackoff) Wait(ctx context.Context, attempt int) error {
	if ctx == nil || backoff == nil || backoff.entropy == nil || attempt <= 0 {
		return ErrInvalidBackoff
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	delay := backoff.initial
	for step := 1; step < attempt && delay < backoff.maximum; step++ {
		if delay > backoff.maximum/2 {
			delay = backoff.maximum
			break
		}
		delay *= 2
	}
	if delay > backoff.maximum {
		delay = backoff.maximum
	}
	half := delay / 2
	offset, err := rand.Int(backoff.entropy, big.NewInt(int64(delay-half)+1))
	if err != nil {
		return fmt.Errorf("read resource authority retry jitter: %w", err)
	}
	timer := time.NewTimer(half + time.Duration(offset.Int64()))
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
