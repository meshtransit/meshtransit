package authority

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"
)

// GroupReplaceService owns impact preview and definition-replacement retry boundaries.
type GroupReplaceService struct {
	options      Options
	impacts      GroupReplaceImpactReader
	transactions GroupReplaceTransactions
	committed    CommittedGroupReplaceResultResolver
	mutationIDs  GroupReplaceMutationIDGenerator
	retry        RetryWaiter
}

// NewGroupReplaceService validates and constructs the definition-replacement service.
func NewGroupReplaceService(
	options Options,
	dependencies GroupReplaceDependencies,
) (*GroupReplaceService, error) {
	if dependencies.Impacts == nil || dependencies.Transactions == nil ||
		dependencies.CommittedResults == nil || dependencies.MutationIDs == nil ||
		dependencies.Retry == nil ||
		options.MaxAttempts <= 0 || options.MaxAttempts > maximumAttempts ||
		options.RollbackTimeout <= 0 || options.RollbackTimeout > 5*time.Second ||
		options.IdempotencyWindow < minimumIdempotencyWindow ||
		options.IdempotencyWindow > maximumIdempotencyWindow {
		return nil, ErrInvalidService
	}
	return &GroupReplaceService{
		options: options, impacts: dependencies.Impacts, transactions: dependencies.Transactions,
		committed: dependencies.CommittedResults, mutationIDs: dependencies.MutationIDs,
		retry: dependencies.Retry,
	}, nil
}

// Preview returns freshly authorized deterministic definition impact.
func (service *GroupReplaceService) Preview(
	ctx context.Context,
	preview GroupReplacePreview,
) (GroupReplaceImpact, error) {
	if ctx == nil || service == nil || service.impacts == nil ||
		!preview.IsValid() {
		return GroupReplaceImpact{}, ErrInvalidGroupReplacePreview
	}
	if err := ctx.Err(); err != nil {
		return GroupReplaceImpact{}, errors.Join(ErrMutationFailed, err)
	}
	impact, err := service.impacts.PreviewGroupReplace(ctx, preview)
	if err != nil {
		return GroupReplaceImpact{}, err
	}
	if !groupReplaceImpactMatchesPreview(impact, preview) {
		return GroupReplaceImpact{}, ErrInvalidGroupReplaceImpact
	}
	return impact, nil
}

// Replace atomically appends and activates one immutable Resource Group definition.
func (service *GroupReplaceService) Replace(
	ctx context.Context,
	command GroupReplaceCommand,
) (GroupReplaceResult, error) {
	if ctx == nil || service == nil || service.transactions == nil || service.committed == nil ||
		service.mutationIDs == nil || service.retry == nil ||
		!command.IsValid() {
		return GroupReplaceResult{}, ErrInvalidGroupReplaceCommand
	}
	if err := ctx.Err(); err != nil {
		return GroupReplaceResult{}, errors.Join(ErrMutationFailed, err)
	}
	mutationIDs, err := service.mutationIDs.NewGroupReplaceMutationIDs(command)
	if err != nil || !mutationIDs.IsValidFor(command) {
		return GroupReplaceResult{}, errors.Join(
			ErrMutationFailed, ErrInvalidGroupReplaceMutationIDs, err,
		)
	}
	var lastErr error
	for attempt := 1; attempt <= service.options.MaxAttempts; attempt++ {
		result, attemptErr := service.attemptReplace(ctx, command, mutationIDs)
		if attemptErr == nil {
			return result, nil
		}
		lastErr = attemptErr
		if errors.Is(attemptErr, ErrCommitOutcomeUnknown) {
			resolved, found, resolveErr := service.committed.ResolveCommittedGroupReplace(
				ctx, command, mutationIDs,
			)
			if resolveErr == nil && found {
				if !groupReplaceResultMatches(resolved, command) {
					return GroupReplaceResult{}, errors.Join(
						ErrMutationFailed, ErrInvalidGroupReplaceResult,
					)
				}
				return resolved, nil
			}
			lastErr = errors.Join(lastErr, resolveErr)
		}
		if !errors.Is(attemptErr, ErrRetryableTransaction) &&
			!errors.Is(attemptErr, ErrCommitOutcomeUnknown) {
			return GroupReplaceResult{}, errors.Join(ErrMutationFailed, attemptErr)
		}
		if attempt == service.options.MaxAttempts {
			return GroupReplaceResult{}, errors.Join(ErrMutationFailed, ErrRetryExhausted, lastErr)
		}
		if err := service.retry.Wait(ctx, attempt); err != nil {
			return GroupReplaceResult{}, errors.Join(ErrMutationFailed, lastErr, err)
		}
	}
	return GroupReplaceResult{}, errors.Join(ErrMutationFailed, ErrRetryExhausted, lastErr)
}

func (service *GroupReplaceService) attemptReplace(
	ctx context.Context,
	command GroupReplaceCommand,
	mutationIDs GroupReplaceMutationIDs,
) (result GroupReplaceResult, resultErr error) {
	transaction, err := service.transactions.BeginGroupReplace(ctx, command.Scope())
	if err != nil || transaction == nil {
		if err == nil {
			err = ErrInvalidService
		}
		return GroupReplaceResult{}, fmt.Errorf("begin Resource Group replacement transaction: %w", err)
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
			result = GroupReplaceResult{}
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
		return GroupReplaceResult{}, ErrInvalidService
	}
	resolution, err := transaction.Resolve(ctx, command, mutationIDs, now, expiresAt)
	if err != nil {
		return GroupReplaceResult{}, fmt.Errorf("resolve Resource Group replacement under lock: %w", err)
	}
	if !resolution.IsValid() || resolution.Scope() != command.Scope() {
		return GroupReplaceResult{}, ErrInvalidGroupReplaceResolution
	}
	if resolution.IsCompleted() {
		replayed := resolution.CompletedResult()
		if !groupReplaceResultMatches(replayed, command) {
			return GroupReplaceResult{}, ErrInvalidGroupReplaceResult
		}
		rollbackCtx, cancel := context.WithTimeout(
			context.WithoutCancel(ctx), service.options.RollbackTimeout,
		)
		defer cancel()
		if err := transaction.Rollback(rollbackCtx); err != nil {
			return GroupReplaceResult{}, errors.Join(ErrRollbackFailed, err)
		}
		finished = true
		return replayed, nil
	}
	if resolution.Impact().Hash() != command.ImpactHash() {
		return GroupReplaceResult{}, ErrGroupReplaceImpactChanged
	}
	change, err := NewGroupReplaceChange(command, resolution, mutationIDs, now, expiresAt)
	if err != nil {
		return GroupReplaceResult{}, err
	}
	result, err = transaction.Apply(ctx, change)
	if err != nil {
		return GroupReplaceResult{}, fmt.Errorf("apply Resource Group replacement: %w", err)
	}
	proposed := resolution.Impact().ProposedRevision()
	if !groupReplaceResultMatches(result, command) ||
		result.DefinitionVersion() != proposed.DefinitionVersion() ||
		result.SemanticHash() != proposed.SemanticHash() ||
		result.NetworkRevision() != resolution.NetworkRevision()+1 ||
		result.GroupRevision() != resolution.GroupRevision()+1 {
		return GroupReplaceResult{}, ErrInvalidGroupReplaceResult
	}
	if err := transaction.Commit(ctx); err != nil {
		return GroupReplaceResult{}, fmt.Errorf("commit Resource Group replacement: %w", err)
	}
	finished = true
	return result, nil
}

func groupReplaceImpactMatchesPreview(
	impact GroupReplaceImpact,
	preview GroupReplacePreview,
) bool {
	return impact.IsValid() && impact.GroupID() == preview.GroupID() &&
		impact.ExpectedVersion() == preview.ExpectedVersion() &&
		impact.ProposedRevision().Scope() == preview.Scope() &&
		slices.Equal(impact.ProposedRevision().Members(), preview.Members())
}

func groupReplaceResultMatches(
	result GroupReplaceResult,
	command GroupReplaceCommand,
) bool {
	return result.IsValid() && result.GroupID() == command.GroupID() &&
		result.Scope() == command.Scope() && result.Version() == command.ExpectedVersion()+1 &&
		result.ImpactHash() == command.ImpactHash()
}
