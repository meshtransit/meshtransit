package authority

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// RebindService owns impact preview plus target-replacement retry boundaries.
type RebindService struct {
	options      Options
	impacts      RebindImpactReader
	transactions RebindTransactions
	committed    CommittedRebindResultResolver
	mutationIDs  RebindMutationIDGenerator
	clock        Clock
	retry        RetryWaiter
}

// NewRebindService validates and constructs the target-rebinding service.
func NewRebindService(options Options, dependencies RebindDependencies) (*RebindService, error) {
	if dependencies.Impacts == nil || dependencies.Transactions == nil ||
		dependencies.CommittedResults == nil || dependencies.MutationIDs == nil ||
		dependencies.Clock == nil || dependencies.Retry == nil ||
		options.MaxAttempts <= 0 || options.MaxAttempts > maximumAttempts ||
		options.RollbackTimeout <= 0 || options.RollbackTimeout > 5*time.Second ||
		options.IdempotencyWindow < minimumIdempotencyWindow ||
		options.IdempotencyWindow > maximumIdempotencyWindow {
		return nil, ErrInvalidService
	}
	return &RebindService{
		options: options, impacts: dependencies.Impacts, transactions: dependencies.Transactions,
		committed: dependencies.CommittedResults, mutationIDs: dependencies.MutationIDs,
		clock: dependencies.Clock, retry: dependencies.Retry,
	}, nil
}

// Preview returns freshly authorized deterministic impact evidence.
func (service *RebindService) Preview(
	ctx context.Context,
	preview RebindPreview,
) (RebindImpact, error) {
	if ctx == nil || service == nil || service.impacts == nil || service.clock == nil ||
		!preview.IsValid() {
		return RebindImpact{}, ErrInvalidRebindPreview
	}
	if err := ctx.Err(); err != nil {
		return RebindImpact{}, errors.Join(ErrMutationFailed, err)
	}
	now := service.clock.Now().UTC()
	if now.IsZero() {
		return RebindImpact{}, ErrInvalidService
	}
	impact, err := service.impacts.PreviewRebind(ctx, preview, now)
	if err != nil {
		return RebindImpact{}, err
	}
	if !impact.IsValid() || impact.ResourceID() != preview.ResourceID() ||
		impact.ExpectedVersion() != preview.ExpectedVersion() ||
		impact.ProposedRevision().Scope() != preview.Scope() ||
		impact.ProposedRevision().DeviceID() != preview.DeviceID() {
		return RebindImpact{}, ErrInvalidRebindImpact
	}
	return impact, nil
}

// Rebind atomically replaces one Device target after exact impact acknowledgement.
func (service *RebindService) Rebind(
	ctx context.Context,
	command RebindCommand,
) (RebindResult, error) {
	if ctx == nil || service == nil || service.transactions == nil || service.committed == nil ||
		service.mutationIDs == nil || service.clock == nil || service.retry == nil ||
		!command.IsValid() {
		return RebindResult{}, ErrInvalidRebindCommand
	}
	if err := ctx.Err(); err != nil {
		return RebindResult{}, errors.Join(ErrMutationFailed, err)
	}
	now := service.clock.Now().UTC()
	if now.IsZero() {
		return RebindResult{}, ErrInvalidService
	}
	expiresAt := now.Add(service.options.IdempotencyWindow)
	if !expiresAt.After(now) {
		return RebindResult{}, ErrInvalidService
	}
	mutationIDs, err := service.mutationIDs.NewRebindMutationIDs(command)
	if err != nil || !mutationIDs.IsValid() {
		return RebindResult{}, errors.Join(ErrMutationFailed, ErrInvalidRebindMutationIDs, err)
	}
	var lastErr error
	for attempt := 1; attempt <= service.options.MaxAttempts; attempt++ {
		result, attemptErr := service.attemptRebind(ctx, command, mutationIDs, now, expiresAt)
		if attemptErr == nil {
			return result, nil
		}
		lastErr = attemptErr
		if errors.Is(attemptErr, ErrCommitOutcomeUnknown) {
			resolved, found, resolveErr := service.committed.ResolveCommittedRebind(
				ctx, command, mutationIDs,
			)
			if resolveErr == nil && found {
				if !rebindResultMatches(resolved, command) {
					return RebindResult{}, errors.Join(ErrMutationFailed, ErrInvalidRebindResult)
				}
				return resolved, nil
			}
			lastErr = errors.Join(lastErr, resolveErr)
		}
		if !errors.Is(attemptErr, ErrRetryableTransaction) &&
			!errors.Is(attemptErr, ErrCommitOutcomeUnknown) {
			return RebindResult{}, errors.Join(ErrMutationFailed, attemptErr)
		}
		if attempt == service.options.MaxAttempts {
			return RebindResult{}, errors.Join(ErrMutationFailed, ErrRetryExhausted, lastErr)
		}
		if err := service.retry.Wait(ctx, attempt); err != nil {
			return RebindResult{}, errors.Join(ErrMutationFailed, lastErr, err)
		}
	}
	return RebindResult{}, errors.Join(ErrMutationFailed, ErrRetryExhausted, lastErr)
}

func (service *RebindService) attemptRebind(
	ctx context.Context,
	command RebindCommand,
	mutationIDs RebindMutationIDs,
	now, expiresAt time.Time,
) (result RebindResult, resultErr error) {
	transaction, err := service.transactions.BeginRebind(ctx, command.Scope())
	if err != nil || transaction == nil {
		if err == nil {
			err = ErrInvalidService
		}
		return RebindResult{}, fmt.Errorf("begin Resource rebind transaction: %w", err)
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
			result = RebindResult{}
			resultErr = errors.Join(ErrRollbackFailed, err)
			if unknownCommit {
				resultErr = errors.Join(resultErr, ErrCommitOutcomeUnknown)
			}
		}
	}()
	resolution, err := transaction.Resolve(ctx, command, mutationIDs, now, expiresAt)
	if err != nil {
		return RebindResult{}, fmt.Errorf("resolve Resource rebind under lock: %w", err)
	}
	if !resolution.IsValid() || resolution.Scope() != command.Scope() {
		return RebindResult{}, ErrInvalidRebindResolution
	}
	if resolution.IsCompleted() {
		replayed := resolution.CompletedResult()
		if !rebindResultMatches(replayed, command) {
			return RebindResult{}, ErrInvalidRebindResult
		}
		rollbackCtx, cancel := context.WithTimeout(
			context.WithoutCancel(ctx), service.options.RollbackTimeout,
		)
		defer cancel()
		if err := transaction.Rollback(rollbackCtx); err != nil {
			return RebindResult{}, errors.Join(ErrRollbackFailed, err)
		}
		finished = true
		return replayed, nil
	}
	if resolution.Impact().Hash() != command.ImpactHash() {
		return RebindResult{}, ErrRebindImpactChanged
	}
	change, err := NewRebindChange(command, resolution, mutationIDs, now, expiresAt)
	if err != nil {
		return RebindResult{}, err
	}
	result, err = transaction.Apply(ctx, change)
	if err != nil {
		return RebindResult{}, fmt.Errorf("apply Resource rebind: %w", err)
	}
	if !rebindResultMatches(result, command) ||
		result.TargetGeneration() != resolution.Impact().ProposedRevision().TargetGeneration() ||
		result.SemanticHash() != resolution.Impact().ProposedRevision().SemanticHash() ||
		result.NetworkRevision() != resolution.NetworkRevision()+1 ||
		result.InventoryRevision() != resolution.InventoryRevision()+1 {
		return RebindResult{}, ErrInvalidRebindResult
	}
	if err := transaction.Commit(ctx); err != nil {
		return RebindResult{}, fmt.Errorf("commit Resource rebind: %w", err)
	}
	finished = true
	return result, nil
}

func rebindResultMatches(result RebindResult, command RebindCommand) bool {
	return result.IsValid() && result.ResourceID() == command.ResourceID() &&
		result.Scope() == command.Scope() && result.DeviceID() == command.DeviceID() &&
		result.Version() == command.ExpectedVersion()+1 && result.ImpactHash() == command.ImpactHash()
}
