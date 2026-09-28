package publication

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const maximumPublicationAttempts = 5

var (
	// ErrInvalidService reports missing dependencies or unsafe retry settings.
	ErrInvalidService = errors.New("policy publication: invalid service")
	// ErrPublicationFailed classifies a publication that did not commit.
	ErrPublicationFailed = errors.New("policy publication: operation failed")
	// ErrRetryableTransaction marks a complete transaction attempt that may be replayed.
	ErrRetryableTransaction = errors.New("policy publication: retryable transaction")
	// ErrCommitOutcomeUnknown marks a commit that must be resolved by release identity.
	ErrCommitOutcomeUnknown = errors.New("policy publication: commit outcome unknown")
	// ErrRetryExhausted reports that the bounded transaction retry budget was consumed.
	ErrRetryExhausted = errors.New("policy publication: retry budget exhausted")
	// ErrRollbackFailed reports that a failed transaction could not be closed cleanly.
	ErrRollbackFailed = errors.New("policy publication: rollback failed")
)

// Options bounds whole-transaction retry and rollback cleanup behavior.
type Options struct {
	MaxAttempts     int
	RollbackTimeout time.Duration
}

// Service owns the Policy Release transaction boundary and retry protocol.
// It starts no goroutines and retains no request-specific state.
type Service struct {
	options      Options
	transactions Transactions
	committed    CommittedResultResolver
	mutationIDs  MutationIDGenerator
	clock        Clock
	retry        RetryWaiter
}

// NewService validates and constructs a policy publication application service.
func NewService(options Options, dependencies Dependencies) (*Service, error) {
	if dependencies.Transactions == nil || dependencies.CommittedResults == nil ||
		dependencies.MutationIDs == nil || dependencies.Clock == nil || dependencies.Retry == nil ||
		options.MaxAttempts <= 0 || options.MaxAttempts > maximumPublicationAttempts ||
		options.RollbackTimeout <= 0 || options.RollbackTimeout > 5*time.Second {
		return nil, ErrInvalidService
	}
	return &Service{
		options:      options,
		transactions: dependencies.Transactions,
		committed:    dependencies.CommittedResults,
		mutationIDs:  dependencies.MutationIDs,
		clock:        dependencies.Clock,
		retry:        dependencies.Retry,
	}, nil
}

// Publish activates one precompiled candidate with CAS and atomic evidence.
// Every retry reuses the same decision time and durable public identities.
func (service *Service) Publish(ctx context.Context, command Command) (Result, error) {
	if ctx == nil || service == nil || service.transactions == nil || service.committed == nil ||
		service.mutationIDs == nil || service.clock == nil || service.retry == nil ||
		!command.IsValid() {
		return Result{}, ErrInvalidCommand
	}
	if err := ctx.Err(); err != nil {
		return Result{}, errors.Join(ErrPublicationFailed, err)
	}
	now := service.clock.Now().UTC()
	if now.IsZero() {
		return Result{}, ErrInvalidService
	}
	ruleCount := len(command.Candidate().Snapshot().Rules())
	mutationIDs, err := service.mutationIDs.NewMutationIDs(ruleCount)
	if err != nil || !mutationIDs.IsValid() || len(mutationIDs.ProjectionIDs()) != ruleCount {
		return Result{}, errors.Join(ErrPublicationFailed, ErrInvalidMutationIDs, err)
	}

	var lastErr error
	for attempt := 1; attempt <= service.options.MaxAttempts; attempt++ {
		result, attemptErr := service.attempt(ctx, command, mutationIDs, now)
		if attemptErr == nil {
			return result, nil
		}
		lastErr = attemptErr
		if errors.Is(attemptErr, ErrCommitOutcomeUnknown) {
			resolved, found, resolveErr := service.committed.ResolveCommitted(
				ctx,
				command,
				mutationIDs.ReleaseID(),
			)
			if resolveErr == nil && found {
				if !resultMatchesCommand(resolved, command, mutationIDs.ReleaseID()) {
					return Result{}, errors.Join(ErrPublicationFailed, ErrInvalidResult)
				}
				return resolved, nil
			}
			lastErr = errors.Join(lastErr, resolveErr)
		}
		if !errors.Is(attemptErr, ErrRetryableTransaction) &&
			!errors.Is(attemptErr, ErrCommitOutcomeUnknown) {
			return Result{}, errors.Join(ErrPublicationFailed, attemptErr)
		}
		if attempt == service.options.MaxAttempts {
			return Result{}, errors.Join(ErrPublicationFailed, ErrRetryExhausted, lastErr)
		}
		if err := service.retry.Wait(ctx, attempt); err != nil {
			return Result{}, errors.Join(ErrPublicationFailed, lastErr, err)
		}
	}
	return Result{}, errors.Join(ErrPublicationFailed, ErrRetryExhausted, lastErr)
}

func (service *Service) attempt(
	ctx context.Context,
	command Command,
	mutationIDs MutationIDs,
	now time.Time,
) (result Result, resultErr error) {
	transaction, err := service.transactions.Begin(ctx, command.Candidate().Snapshot().Scope())
	if err != nil || transaction == nil {
		if err == nil {
			err = ErrInvalidService
		}
		return Result{}, fmt.Errorf("begin policy publication transaction: %w", err)
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
				fmt.Errorf("rollback policy publication transaction: %w", err),
			)
			if unknownCommit {
				resultErr = errors.Join(resultErr, ErrCommitOutcomeUnknown)
			}
		}
	}()

	resolution, err := transaction.Resolve(ctx, command, now)
	if err != nil {
		return Result{}, fmt.Errorf("resolve policy publication under lock: %w", err)
	}
	if err := validateResolution(command, resolution, now); err != nil {
		return Result{}, err
	}
	change, err := NewChange(ChangeParams{
		Command:     command,
		Resolution:  resolution,
		MutationIDs: mutationIDs,
		OccurredAt:  now,
	})
	if err != nil {
		return Result{}, err
	}
	result, err = transaction.Apply(ctx, change)
	if err != nil {
		return Result{}, fmt.Errorf("apply policy publication: %w", err)
	}
	if !resultMatchesChange(result, change) {
		return Result{}, ErrInvalidResult
	}
	if err := transaction.Commit(ctx); err != nil {
		return Result{}, fmt.Errorf("commit policy publication transaction: %w", err)
	}
	finished = true
	return result, nil
}

func validateResolution(command Command, resolution Resolution, evaluatedAt time.Time) error {
	if !resolution.IsValid() || resolution.Scope() != command.Candidate().Snapshot().Scope() {
		return ErrInvalidResolution
	}
	if resolution.PolicyRevision() != command.BasePolicyRevision() {
		return ErrConflict
	}
	if !approvalGateMatchesCommand(command, resolution, evaluatedAt) {
		return ErrApprovalUnavailable
	}
	return nil
}

func resultMatchesCommand(result Result, command Command, releaseID ReleaseID) bool {
	return result.IsValid() && result.ReleaseID() == releaseID &&
		result.Scope() == command.Candidate().Snapshot().Scope() &&
		result.PolicyRevision() == command.Candidate().Snapshot().Revision() &&
		result.SemanticHash() == command.Candidate().SemanticHash()
}

func resultMatchesChange(result Result, change Change) bool {
	return resultMatchesCommand(result, change.Command(), change.MutationIDs().ReleaseID()) &&
		result.NetworkRevision() == change.Resolution().NetworkRevision()+1
}
