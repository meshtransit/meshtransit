package authority

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ChangeService owns protected proposal and confirmation boundaries.
type ChangeService struct {
	options                  Options
	impacts                  ChangeImpactReader
	requestTransactions      ChangeRequestTransactions
	committedRequests        CommittedAuthorityChangeRequestResolver
	confirmationTransactions ChangeConfirmationTransactions
	committedConfirmations   CommittedAuthorityChangeConfirmationResolver
	mutationIDs              ChangeMutationIDGenerator
	clock                    Clock
	retry                    RetryWaiter
}

// NewAuthorityChangeService validates and constructs the protected workflow.
func NewAuthorityChangeService(
	options Options,
	dependencies ChangeDependencies,
) (*ChangeService, error) {
	if dependencies.Impacts == nil || dependencies.RequestTransactions == nil ||
		dependencies.CommittedRequests == nil ||
		dependencies.ConfirmationTransactions == nil ||
		dependencies.CommittedConfirmations == nil || dependencies.MutationIDs == nil ||
		dependencies.Clock == nil || dependencies.Retry == nil ||
		options.MaxAttempts <= 0 || options.MaxAttempts > maximumAttempts ||
		options.RollbackTimeout <= 0 || options.RollbackTimeout > 5*time.Second ||
		options.IdempotencyWindow <= AuthorityChangeRequestLifetime ||
		options.IdempotencyWindow > maximumIdempotencyWindow {
		return nil, ErrInvalidService
	}
	return &ChangeService{
		options: options, impacts: dependencies.Impacts,
		requestTransactions:      dependencies.RequestTransactions,
		committedRequests:        dependencies.CommittedRequests,
		confirmationTransactions: dependencies.ConfirmationTransactions,
		committedConfirmations:   dependencies.CommittedConfirmations,
		mutationIDs:              dependencies.MutationIDs, clock: dependencies.Clock,
		retry: dependencies.Retry,
	}, nil
}

// Preview returns freshly authorized deterministic protected-change impact.
func (service *ChangeService) Preview(
	ctx context.Context,
	preview ChangePreview,
) (ChangeImpact, error) {
	if ctx == nil || service == nil || service.impacts == nil || service.clock == nil ||
		!preview.IsValid() {
		return ChangeImpact{}, ErrInvalidAuthorityChangePreview
	}
	if err := ctx.Err(); err != nil {
		return ChangeImpact{}, errors.Join(ErrMutationFailed, err)
	}
	now := service.clock.Now().UTC()
	if now.IsZero() {
		return ChangeImpact{}, ErrInvalidService
	}
	impact, err := service.impacts.PreviewAuthorityChange(ctx, preview, now)
	if err != nil {
		return ChangeImpact{}, err
	}
	if !authorityChangeImpactMatchesPreview(impact, preview) {
		return ChangeImpact{}, ErrInvalidAuthorityChangeImpact
	}
	return impact, nil
}

// Request persists one step-up-bound proposal awaiting its target Principal.
func (service *ChangeService) Request(
	ctx context.Context,
	command ChangeRequestCommand,
) (ChangeRequestResult, error) {
	if ctx == nil || service == nil || service.requestTransactions == nil ||
		service.committedRequests == nil || service.mutationIDs == nil ||
		service.clock == nil || service.retry == nil || !command.IsValid() {
		return ChangeRequestResult{}, ErrInvalidAuthorityChangeRequestCommand
	}
	if err := ctx.Err(); err != nil {
		return ChangeRequestResult{}, errors.Join(ErrMutationFailed, err)
	}
	now := service.clock.Now().UTC()
	if now.IsZero() {
		return ChangeRequestResult{}, ErrInvalidService
	}
	requestExpiresAt := now.Add(AuthorityChangeRequestLifetime)
	idempotencyExpiresAt := now.Add(service.options.IdempotencyWindow)
	if !idempotencyExpiresAt.After(requestExpiresAt) {
		return ChangeRequestResult{}, ErrInvalidService
	}
	mutationIDs, err := service.mutationIDs.NewAuthorityChangeRequestMutationIDs(command)
	if err != nil || !mutationIDs.IsValid() {
		return ChangeRequestResult{}, errors.Join(
			ErrMutationFailed, ErrInvalidAuthorityChangeRequestMutationIDs, err,
		)
	}
	var lastErr error
	for attempt := 1; attempt <= service.options.MaxAttempts; attempt++ {
		result, attemptErr := service.attemptRequest(
			ctx, command, mutationIDs, now, requestExpiresAt, idempotencyExpiresAt,
		)
		if attemptErr == nil {
			return result, nil
		}
		lastErr = attemptErr
		if errors.Is(attemptErr, ErrCommitOutcomeUnknown) {
			resolved, found, resolveErr := service.committedRequests.ResolveCommittedAuthorityChangeRequest(
				ctx, command, mutationIDs,
			)
			if resolveErr == nil && found {
				if !authorityChangeRequestResultMatches(resolved, command) ||
					resolved.RequestID() != mutationIDs.RequestID() {
					return ChangeRequestResult{}, errors.Join(
						ErrMutationFailed, ErrInvalidAuthorityChangeRequestResult,
					)
				}
				return resolved, nil
			}
			lastErr = errors.Join(lastErr, resolveErr)
		}
		if !errors.Is(attemptErr, ErrRetryableTransaction) &&
			!errors.Is(attemptErr, ErrCommitOutcomeUnknown) {
			return ChangeRequestResult{}, errors.Join(ErrMutationFailed, attemptErr)
		}
		if attempt == service.options.MaxAttempts {
			return ChangeRequestResult{}, errors.Join(
				ErrMutationFailed, ErrRetryExhausted, lastErr,
			)
		}
		if err := service.retry.Wait(ctx, attempt); err != nil {
			return ChangeRequestResult{}, errors.Join(ErrMutationFailed, lastErr, err)
		}
	}
	return ChangeRequestResult{}, errors.Join(ErrMutationFailed, ErrRetryExhausted, lastErr)
}

func (service *ChangeService) attemptRequest(
	ctx context.Context,
	command ChangeRequestCommand,
	mutationIDs ChangeRequestMutationIDs,
	now, requestExpiresAt, idempotencyExpiresAt time.Time,
) (result ChangeRequestResult, resultErr error) {
	transaction, err := service.requestTransactions.BeginAuthorityChangeRequest(ctx, command.Scope())
	if err != nil || transaction == nil {
		if err == nil {
			err = ErrInvalidService
		}
		return ChangeRequestResult{}, fmt.Errorf("begin authority-change request transaction: %w", err)
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
			result = ChangeRequestResult{}
			resultErr = errors.Join(ErrRollbackFailed, err)
			if unknownCommit {
				resultErr = errors.Join(resultErr, ErrCommitOutcomeUnknown)
			}
		}
	}()
	resolution, err := transaction.Resolve(
		ctx, command, mutationIDs, now, idempotencyExpiresAt,
	)
	if err != nil {
		return ChangeRequestResult{}, fmt.Errorf("resolve authority-change request under lock: %w", err)
	}
	if !resolution.IsValid() || resolution.Scope() != command.Scope() {
		return ChangeRequestResult{}, ErrInvalidAuthorityChangeRequestResolution
	}
	if resolution.IsCompleted() {
		replayed := resolution.CompletedResult()
		if !authorityChangeRequestResultMatches(replayed, command) {
			return ChangeRequestResult{}, ErrInvalidAuthorityChangeRequestResult
		}
		rollbackCtx, cancel := context.WithTimeout(
			context.WithoutCancel(ctx), service.options.RollbackTimeout,
		)
		defer cancel()
		if err := transaction.Rollback(rollbackCtx); err != nil {
			return ChangeRequestResult{}, errors.Join(ErrRollbackFailed, err)
		}
		finished = true
		return replayed, nil
	}
	if resolution.Impact().Hash() != command.ImpactHash() {
		return ChangeRequestResult{}, ErrAuthorityChangeImpactChanged
	}
	change, err := NewAuthorityChangeRequestChange(
		command, resolution, mutationIDs, now, requestExpiresAt, idempotencyExpiresAt,
	)
	if err != nil {
		return ChangeRequestResult{}, err
	}
	result, err = transaction.Apply(ctx, change)
	if err != nil {
		return ChangeRequestResult{}, fmt.Errorf("apply authority-change request: %w", err)
	}
	if !authorityChangeRequestResultMatches(result, command) ||
		result.RequestID() != mutationIDs.RequestID() ||
		result.NetworkRevision() != resolution.NetworkRevision()+1 ||
		result.SubsystemRevision() != resolution.SubsystemRevision()+1 ||
		!result.ExpiresAt().Equal(requestExpiresAt) {
		return ChangeRequestResult{}, ErrInvalidAuthorityChangeRequestResult
	}
	if err := transaction.Commit(ctx); err != nil {
		return ChangeRequestResult{}, fmt.Errorf("commit authority-change request: %w", err)
	}
	finished = true
	return result, nil
}

// Confirm consumes a distinct step-up session and atomically applies the request.
func (service *ChangeService) Confirm(
	ctx context.Context,
	command ChangeConfirmationCommand,
) (ChangeConfirmationResult, error) {
	if ctx == nil || service == nil || service.confirmationTransactions == nil ||
		service.committedConfirmations == nil || service.mutationIDs == nil ||
		service.clock == nil || service.retry == nil || !command.IsValid() {
		return ChangeConfirmationResult{}, ErrInvalidAuthorityChangeConfirmationCommand
	}
	if err := ctx.Err(); err != nil {
		return ChangeConfirmationResult{}, errors.Join(ErrMutationFailed, err)
	}
	now := service.clock.Now().UTC()
	if now.IsZero() {
		return ChangeConfirmationResult{}, ErrInvalidService
	}
	expiresAt := now.Add(service.options.IdempotencyWindow)
	if !expiresAt.After(now) {
		return ChangeConfirmationResult{}, ErrInvalidService
	}
	mutationIDs, err := service.mutationIDs.NewAuthorityChangeConfirmationMutationIDs(command)
	if err != nil || !mutationIDs.IsValid() {
		return ChangeConfirmationResult{}, errors.Join(
			ErrMutationFailed, ErrInvalidAuthorityChangeConfirmationMutationIDs, err,
		)
	}
	var lastErr error
	for attempt := 1; attempt <= service.options.MaxAttempts; attempt++ {
		result, attemptErr := service.attemptConfirmation(
			ctx, command, mutationIDs, now, expiresAt,
		)
		if attemptErr == nil {
			return result, nil
		}
		lastErr = attemptErr
		if errors.Is(attemptErr, ErrCommitOutcomeUnknown) {
			resolved, found, resolveErr := service.committedConfirmations.ResolveCommittedAuthorityChangeConfirmation(
				ctx, command, mutationIDs,
			)
			if resolveErr == nil && found {
				if !authorityChangeConfirmationResultMatches(resolved, command) {
					return ChangeConfirmationResult{}, errors.Join(
						ErrMutationFailed, ErrInvalidAuthorityChangeConfirmationResult,
					)
				}
				return resolved, nil
			}
			lastErr = errors.Join(lastErr, resolveErr)
		}
		if !errors.Is(attemptErr, ErrRetryableTransaction) &&
			!errors.Is(attemptErr, ErrCommitOutcomeUnknown) {
			return ChangeConfirmationResult{}, errors.Join(ErrMutationFailed, attemptErr)
		}
		if attempt == service.options.MaxAttempts {
			return ChangeConfirmationResult{}, errors.Join(
				ErrMutationFailed, ErrRetryExhausted, lastErr,
			)
		}
		if err := service.retry.Wait(ctx, attempt); err != nil {
			return ChangeConfirmationResult{}, errors.Join(ErrMutationFailed, lastErr, err)
		}
	}
	return ChangeConfirmationResult{}, errors.Join(
		ErrMutationFailed, ErrRetryExhausted, lastErr,
	)
}

func (service *ChangeService) attemptConfirmation(
	ctx context.Context,
	command ChangeConfirmationCommand,
	mutationIDs ChangeConfirmationMutationIDs,
	now, expiresAt time.Time,
) (result ChangeConfirmationResult, resultErr error) {
	transaction, err := service.confirmationTransactions.BeginAuthorityChangeConfirmation(
		ctx, command.Scope(),
	)
	if err != nil || transaction == nil {
		if err == nil {
			err = ErrInvalidService
		}
		return ChangeConfirmationResult{}, fmt.Errorf(
			"begin authority-change confirmation transaction: %w", err,
		)
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
			result = ChangeConfirmationResult{}
			resultErr = errors.Join(ErrRollbackFailed, err)
			if unknownCommit {
				resultErr = errors.Join(resultErr, ErrCommitOutcomeUnknown)
			}
		}
	}()
	resolution, err := transaction.Resolve(ctx, command, mutationIDs, now, expiresAt)
	if err != nil {
		return ChangeConfirmationResult{}, fmt.Errorf(
			"resolve authority-change confirmation under lock: %w", err,
		)
	}
	if !resolution.IsValid() || resolution.Scope() != command.Scope() {
		return ChangeConfirmationResult{}, ErrInvalidAuthorityChangeConfirmationResolution
	}
	if resolution.IsCompleted() {
		replayed := resolution.CompletedResult()
		if !authorityChangeConfirmationResultMatches(replayed, command) {
			return ChangeConfirmationResult{}, ErrInvalidAuthorityChangeConfirmationResult
		}
		rollbackCtx, cancel := context.WithTimeout(
			context.WithoutCancel(ctx), service.options.RollbackTimeout,
		)
		defer cancel()
		if err := transaction.Rollback(rollbackCtx); err != nil {
			return ChangeConfirmationResult{}, errors.Join(ErrRollbackFailed, err)
		}
		finished = true
		return replayed, nil
	}
	if resolution.Impact().Hash() != command.ImpactHash() {
		return ChangeConfirmationResult{}, ErrAuthorityChangeImpactChanged
	}
	change, err := NewAuthorityChangeConfirmationChange(
		command, resolution, mutationIDs, now, expiresAt,
	)
	if err != nil {
		return ChangeConfirmationResult{}, err
	}
	result, err = transaction.Apply(ctx, change)
	if err != nil {
		return ChangeConfirmationResult{}, fmt.Errorf(
			"apply authority-change confirmation: %w", err,
		)
	}
	impact := resolution.Impact()
	if !authorityChangeConfirmationResultMatches(result, command) ||
		result.SubjectVersion() != impact.Preview().ExpectedVersion()+1 ||
		result.RequestVersion() != resolution.RequestVersion()+1 ||
		result.NetworkRevision() != resolution.NetworkRevision()+1 ||
		result.SubsystemRevision() != resolution.SubsystemRevision()+1 ||
		result.OwnerPrincipalID() != impact.ProposedOwnerPrincipalID() ||
		result.CustodianPrincipalID() != impact.ProposedCustodianPrincipalID() ||
		result.SemanticHash() != impact.ProposedSemanticHash() {
		return ChangeConfirmationResult{}, ErrInvalidAuthorityChangeConfirmationResult
	}
	if err := transaction.Commit(ctx); err != nil {
		return ChangeConfirmationResult{}, fmt.Errorf(
			"commit authority-change confirmation: %w", err,
		)
	}
	finished = true
	return result, nil
}

func authorityChangeImpactMatchesPreview(
	impact ChangeImpact,
	preview ChangePreview,
) bool {
	actual := impact.Preview()
	return impact.IsValid() && actual.Scope() == preview.Scope() &&
		actual.SubjectKind() == preview.SubjectKind() &&
		actual.SubjectPublicID() == preview.SubjectPublicID() &&
		actual.ExpectedVersion() == preview.ExpectedVersion() &&
		actual.Action() == preview.Action() &&
		actual.TargetPrincipalID() == preview.TargetPrincipalID() &&
		actual.AccountSession().ID() == preview.AccountSession().ID() &&
		actual.AccountSession().PrincipalID() == preview.AccountSession().PrincipalID()
}

func authorityChangeRequestResultMatches(
	result ChangeRequestResult,
	command ChangeRequestCommand,
) bool {
	return result.IsValid() &&
		authorityChangePreviewSemanticsEqual(result.Preview(), command.Preview()) &&
		result.ImpactHash() == command.ImpactHash()
}

func authorityChangeConfirmationResultMatches(
	result ChangeConfirmationResult,
	command ChangeConfirmationCommand,
) bool {
	return result.IsValid() && result.RequestID() == command.RequestID() &&
		result.Scope() == command.Scope() && result.SubjectKind() == command.SubjectKind() &&
		result.SubjectPublicID() == command.SubjectPublicID() &&
		result.RequestVersion() == command.ExpectedRequestVersion()+1 &&
		result.ImpactHash() == command.ImpactHash()
}

func authorityChangePreviewSemanticsEqual(
	left, right ChangePreview,
) bool {
	return left.IsValid() && right.IsValid() && left.Scope() == right.Scope() &&
		left.SubjectKind() == right.SubjectKind() &&
		left.SubjectPublicID() == right.SubjectPublicID() &&
		left.ExpectedVersion() == right.ExpectedVersion() && left.Action() == right.Action() &&
		left.TargetPrincipalID() == right.TargetPrincipalID() &&
		left.AccountSession().ID() == right.AccountSession().ID() &&
		left.AccountSession().PrincipalID() == right.AccountSession().PrincipalID()
}
