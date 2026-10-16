package approval

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	maximumAttempts          = 5
	maximumIdempotencyWindow = 24 * time.Hour
)

var (
	// ErrInvalidService reports missing dependencies or unsafe retry settings.
	ErrInvalidService = errors.New("policy approval: invalid service")
	// ErrOperationFailed classifies a proposal or approval that did not commit.
	ErrOperationFailed = errors.New("policy approval: operation failed")
	// ErrRetryableTransaction marks one complete transaction attempt for replay.
	ErrRetryableTransaction = errors.New("policy approval: retryable transaction")
	// ErrCommitOutcomeUnknown marks a commit requiring immutable-ID resolution.
	ErrCommitOutcomeUnknown = errors.New("policy approval: commit outcome unknown")
	// ErrRetryExhausted reports consumption of the bounded transaction budget.
	ErrRetryExhausted = errors.New("policy approval: retry budget exhausted")
	// ErrRollbackFailed reports a failed transaction that did not close cleanly.
	ErrRollbackFailed = errors.New("policy approval: rollback failed")
)

// Options bounds whole-transaction retry, cleanup, and replay retention.
type Options struct {
	MaxAttempts       int
	RollbackTimeout   time.Duration
	IdempotencyWindow time.Duration
}

// Service owns proposal and independent-human decision transaction boundaries.
// It starts no goroutines and retains no request-specific state.
type Service struct {
	options              Options
	simulator            Simulator
	requestTransactions  RequestTransactions
	committedRequests    CommittedRequestResolver
	approvalTransactions Transactions
	committedApprovals   CommittedApprovalResolver
	mutationIDs          MutationIDGenerator
	retry                RetryWaiter
}

// NewService validates and constructs a policy approval application service.
func NewService(options Options, dependencies Dependencies) (*Service, error) {
	if dependencies.Simulator == nil || dependencies.RequestTransactions == nil ||
		dependencies.CommittedRequests == nil || dependencies.ApprovalTransactions == nil ||
		dependencies.CommittedApprovals == nil || dependencies.MutationIDs == nil ||
		dependencies.Retry == nil ||
		options.MaxAttempts <= 0 || options.MaxAttempts > maximumAttempts ||
		options.RollbackTimeout <= 0 || options.RollbackTimeout > 5*time.Second ||
		options.IdempotencyWindow <= RequestLifetime ||
		options.IdempotencyWindow > maximumIdempotencyWindow {
		return nil, ErrInvalidService
	}
	return &Service{
		options: options, simulator: dependencies.Simulator,
		requestTransactions:  dependencies.RequestTransactions,
		committedRequests:    dependencies.CommittedRequests,
		approvalTransactions: dependencies.ApprovalTransactions,
		committedApprovals:   dependencies.CommittedApprovals,
		mutationIDs:          dependencies.MutationIDs,
		retry:                dependencies.Retry,
	}, nil
}

// Request freshly simulates a draft and persists an exact pending proposal.
func (service *Service) Request(
	ctx context.Context,
	intent RequestIntent,
) (RequestResult, error) {
	if ctx == nil || service == nil || service.simulator == nil ||
		service.requestTransactions == nil || service.committedRequests == nil ||
		service.mutationIDs == nil || service.retry == nil ||
		!intent.IsValid() {
		return RequestResult{}, ErrInvalidRequestIntent
	}
	if err := ctx.Err(); err != nil {
		return RequestResult{}, errors.Join(ErrOperationFailed, err)
	}
	simulated, err := service.simulator.Simulate(
		ctx,
		intent.AccountSession(),
		intent.CompilationRequest(),
	)
	if err != nil {
		return RequestResult{}, err
	}
	compilationRequest := intent.CompilationRequest()
	if !simulated.IsValid() || simulated.Baseline().Scope() != compilationRequest.Scope() ||
		simulated.ProposedCandidate().Snapshot().Revision() != compilationRequest.Revision() {
		return RequestResult{}, ErrInvalidBinding
	}
	if simulated.ProposedCandidate().SemanticHash() != intent.CandidateSemanticHash() {
		return RequestResult{}, ErrCandidateChanged
	}
	if simulated.ImpactHash() != intent.ImpactHash() {
		return RequestResult{}, ErrImpactChanged
	}
	binding, err := NewBindingFromSimulation(simulated)
	if err != nil {
		return RequestResult{}, err
	}
	command, err := NewRequestCommand(
		binding,
		intent.AccountSession(),
		intent.AuditReason(),
		intent.IdempotencyEvidence(),
	)
	if err != nil {
		return RequestResult{}, err
	}
	mutationIDs, err := service.mutationIDs.NewApprovalRequestMutationIDs(command)
	if err != nil || !mutationIDs.IsValid() {
		return RequestResult{}, errors.Join(
			ErrOperationFailed,
			ErrInvalidRequestMutationIDs,
			err,
		)
	}
	return service.requestWithRetry(ctx, command, mutationIDs)
}

func (service *Service) requestWithRetry(
	ctx context.Context,
	command RequestCommand,
	mutationIDs RequestMutationIDs,
) (RequestResult, error) {
	var lastErr error
	for attempt := 1; attempt <= service.options.MaxAttempts; attempt++ {
		result, attemptErr := service.attemptRequest(ctx, command, mutationIDs)
		if attemptErr == nil {
			return result, nil
		}
		lastErr = attemptErr
		if errors.Is(attemptErr, ErrCommitOutcomeUnknown) {
			resolved, found, resolveErr := service.committedRequests.ResolveCommittedApprovalRequest(
				ctx,
				command,
				mutationIDs,
			)
			if resolveErr == nil && found {
				if !requestResultMatchesCommand(resolved, command) ||
					resolved.RequestID() != mutationIDs.RequestID() {
					return RequestResult{}, errors.Join(
						ErrOperationFailed,
						ErrInvalidRequestResult,
					)
				}
				return resolved, nil
			}
			lastErr = errors.Join(lastErr, resolveErr)
		}
		if !errors.Is(attemptErr, ErrRetryableTransaction) &&
			!errors.Is(attemptErr, ErrCommitOutcomeUnknown) {
			return RequestResult{}, errors.Join(ErrOperationFailed, attemptErr)
		}
		if attempt == service.options.MaxAttempts {
			return RequestResult{}, errors.Join(ErrOperationFailed, ErrRetryExhausted, lastErr)
		}
		if err := service.retry.Wait(ctx, attempt); err != nil {
			return RequestResult{}, errors.Join(ErrOperationFailed, lastErr, err)
		}
	}
	return RequestResult{}, errors.Join(ErrOperationFailed, ErrRetryExhausted, lastErr)
}

func (service *Service) attemptRequest(
	ctx context.Context,
	command RequestCommand,
	mutationIDs RequestMutationIDs,
) (result RequestResult, resultErr error) {
	transaction, err := service.requestTransactions.BeginApprovalRequest(ctx, command.Scope())
	if err != nil || transaction == nil {
		if err == nil {
			err = ErrInvalidService
		}
		return RequestResult{}, fmt.Errorf("begin policy approval request transaction: %w", err)
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
			result = RequestResult{}
			resultErr = errors.Join(ErrRollbackFailed, err)
			if unknownCommit {
				resultErr = errors.Join(resultErr, ErrCommitOutcomeUnknown)
			}
		}
	}()

	// One database-clock instant for the session check, the idempotency
	// lease, the approval lifetime and the committed evidence comparison.
	// PostgreSQL retains microseconds; truncation never extends a deadline.
	now := transaction.DecisionTime().Truncate(time.Microsecond)
	if now.IsZero() {
		return RequestResult{}, ErrInvalidService
	}
	if !command.AccountSession().IsActiveAt(now) {
		return RequestResult{}, ErrForbidden
	}
	requestExpiresAt := now.Add(RequestLifetime)
	idempotencyExpiresAt := now.Add(service.options.IdempotencyWindow)
	resolution, err := transaction.Resolve(
		ctx,
		command,
		mutationIDs,
		now,
		idempotencyExpiresAt,
	)
	if err != nil {
		return RequestResult{}, fmt.Errorf("resolve policy approval request under lock: %w", err)
	}
	if !resolution.IsValid() || resolution.Scope() != command.Scope() {
		return RequestResult{}, ErrInvalidRequestResolution
	}
	expectedHash, err := command.RequestHash()
	if err != nil || resolution.RequestHash() != expectedHash ||
		resolution.IdempotencyRecordID() != mutationIDs.IdempotencyRecordID() {
		return RequestResult{}, ErrInvalidRequestResolution
	}
	if resolution.IsCompleted() {
		replayed := resolution.CompletedResult()
		if !requestResultMatchesCommand(replayed, command) ||
			replayed.RequestID() != mutationIDs.RequestID() {
			return RequestResult{}, ErrInvalidRequestResult
		}
		if err := rollbackCompletedRequest(
			ctx,
			transaction,
			service.options.RollbackTimeout,
		); err != nil {
			return RequestResult{}, err
		}
		finished = true
		return replayed, nil
	}
	if !resolution.BaselineVector().Equal(command.Binding().BaselineVector()) {
		return RequestResult{}, ErrImpactChanged
	}
	change, err := NewRequestChange(RequestChangeParams{
		Command: command, Resolution: resolution, MutationIDs: mutationIDs,
		OccurredAt: now, RequestExpiresAt: requestExpiresAt,
		IdempotencyExpiresAt: idempotencyExpiresAt,
	})
	if err != nil {
		return RequestResult{}, err
	}
	result, err = transaction.Apply(ctx, change)
	if err != nil {
		return RequestResult{}, fmt.Errorf("apply policy approval request: %w", err)
	}
	if !requestResultMatchesCommand(result, command) ||
		result.RequestID() != mutationIDs.RequestID() ||
		!result.CreatedAt().Equal(now) || !result.ExpiresAt().Equal(requestExpiresAt) {
		return RequestResult{}, ErrInvalidRequestResult
	}
	if err := transaction.Commit(ctx); err != nil {
		return RequestResult{}, fmt.Errorf("commit policy approval request: %w", err)
	}
	finished = true
	return result, nil
}

// Approve persists one distinct authorized human decision over unchanged evidence.
func (service *Service) Approve(
	ctx context.Context,
	command Command,
) (Result, error) {
	if ctx == nil || service == nil || service.approvalTransactions == nil ||
		service.committedApprovals == nil || service.mutationIDs == nil ||
		service.retry == nil || !command.IsValid() {
		return Result{}, ErrInvalidApprovalCommand
	}
	if err := ctx.Err(); err != nil {
		return Result{}, errors.Join(ErrOperationFailed, err)
	}
	mutationIDs, err := service.mutationIDs.NewPolicyApprovalMutationIDs(command)
	if err != nil || !mutationIDs.IsValid() {
		return Result{}, errors.Join(
			ErrOperationFailed,
			ErrInvalidApprovalMutationIDs,
			err,
		)
	}
	return service.approveWithRetry(ctx, command, mutationIDs)
}

func (service *Service) approveWithRetry(
	ctx context.Context,
	command Command,
	mutationIDs MutationIDs,
) (Result, error) {
	var lastErr error
	for attempt := 1; attempt <= service.options.MaxAttempts; attempt++ {
		result, attemptErr := service.attemptApproval(ctx, command, mutationIDs)
		if attemptErr == nil {
			return result, nil
		}
		lastErr = attemptErr
		if errors.Is(attemptErr, ErrCommitOutcomeUnknown) {
			resolved, found, resolveErr := service.committedApprovals.ResolveCommittedPolicyApproval(
				ctx,
				command,
				mutationIDs,
			)
			if resolveErr == nil && found {
				if !approvalResultMatchesCommand(resolved, command) ||
					resolved.EvidenceID() != mutationIDs.EvidenceID() {
					return Result{}, errors.Join(
						ErrOperationFailed,
						ErrInvalidApprovalResult,
					)
				}
				return resolved, nil
			}
			lastErr = errors.Join(lastErr, resolveErr)
		}
		if !errors.Is(attemptErr, ErrRetryableTransaction) &&
			!errors.Is(attemptErr, ErrCommitOutcomeUnknown) {
			return Result{}, errors.Join(ErrOperationFailed, attemptErr)
		}
		if attempt == service.options.MaxAttempts {
			return Result{}, errors.Join(ErrOperationFailed, ErrRetryExhausted, lastErr)
		}
		if err := service.retry.Wait(ctx, attempt); err != nil {
			return Result{}, errors.Join(ErrOperationFailed, lastErr, err)
		}
	}
	return Result{}, errors.Join(ErrOperationFailed, ErrRetryExhausted, lastErr)
}

func (service *Service) attemptApproval(
	ctx context.Context,
	command Command,
	mutationIDs MutationIDs,
) (result Result, resultErr error) {
	transaction, err := service.approvalTransactions.BeginPolicyApproval(ctx, command.Scope())
	if err != nil || transaction == nil {
		if err == nil {
			err = ErrInvalidService
		}
		return Result{}, fmt.Errorf("begin policy approval transaction: %w", err)
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

	// One database-clock instant for the session check, the idempotency
	// lease, the request deadline and the evidence.
	now := transaction.DecisionTime().Truncate(time.Microsecond)
	if now.IsZero() {
		return Result{}, ErrInvalidService
	}
	if !command.AccountSession().IsActiveAt(now) {
		return Result{}, ErrForbidden
	}
	idempotencyExpiresAt := now.Add(service.options.IdempotencyWindow)
	resolution, err := transaction.Resolve(
		ctx,
		command,
		mutationIDs,
		now,
		idempotencyExpiresAt,
	)
	if err != nil {
		return Result{}, fmt.Errorf("resolve policy approval under lock: %w", err)
	}
	if !resolution.IsValid() || resolution.Scope() != command.Scope() ||
		resolution.RequestID() != command.RequestID() {
		return Result{}, ErrInvalidApprovalResolution
	}
	expectedHash, err := command.DecisionHash()
	if err != nil || resolution.DecisionHash() != expectedHash ||
		resolution.IdempotencyRecordID() != mutationIDs.IdempotencyRecordID() {
		return Result{}, ErrInvalidApprovalResolution
	}
	if resolution.IsCompleted() {
		replayed := resolution.CompletedResult()
		if !approvalResultMatchesCommand(replayed, command) ||
			replayed.EvidenceID() != mutationIDs.EvidenceID() {
			return Result{}, ErrInvalidApprovalResult
		}
		if err := rollbackCompletedApproval(
			ctx,
			transaction,
			service.options.RollbackTimeout,
		); err != nil {
			return Result{}, err
		}
		finished = true
		return replayed, nil
	}
	if resolution.RequestVersion() != command.ExpectedRequestVersion() {
		return Result{}, ErrRequestVersionConflict
	}
	if !now.Before(resolution.RequestExpiresAt()) {
		return Result{}, ErrRequestExpired
	}
	if resolution.Binding().CandidateSemanticHash() != command.CandidateSemanticHash() {
		return Result{}, ErrCandidateChanged
	}
	if resolution.Binding().ImpactHash() != command.ImpactHash() {
		return Result{}, ErrImpactChanged
	}
	if resolution.ProposerPrincipalID() == command.AccountSession().PrincipalID() ||
		resolution.ProposerSessionID() == command.AccountSession().ID() {
		return Result{}, ErrIndependentApproverRequired
	}
	change, err := NewChange(ChangeParams{
		Command: command, Resolution: resolution, MutationIDs: mutationIDs,
		OccurredAt: now, IdempotencyExpiresAt: idempotencyExpiresAt,
	})
	if err != nil {
		return Result{}, err
	}
	result, err = transaction.Apply(ctx, change)
	if err != nil {
		return Result{}, fmt.Errorf("apply policy approval: %w", err)
	}
	if !approvalResultMatchesCommand(result, command) ||
		result.EvidenceID() != mutationIDs.EvidenceID() ||
		!result.Binding().Equal(resolution.Binding()) ||
		result.ProposerPrincipalID() != resolution.ProposerPrincipalID() ||
		result.ProposerSessionID() != resolution.ProposerSessionID() ||
		!result.ApprovedAt().Equal(now) ||
		!result.ExpiresAt().Equal(resolution.RequestExpiresAt()) {
		return Result{}, ErrInvalidApprovalResult
	}
	if err := transaction.Commit(ctx); err != nil {
		return Result{}, fmt.Errorf("commit policy approval: %w", err)
	}
	finished = true
	return result, nil
}

func rollbackCompletedRequest(
	ctx context.Context,
	transaction RequestTransaction,
	timeout time.Duration,
) error {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	if err := transaction.Rollback(rollbackCtx); err != nil {
		return errors.Join(ErrRollbackFailed, err)
	}
	return nil
}

func rollbackCompletedApproval(
	ctx context.Context,
	transaction Transaction,
	timeout time.Duration,
) error {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	if err := transaction.Rollback(rollbackCtx); err != nil {
		return errors.Join(ErrRollbackFailed, err)
	}
	return nil
}

func requestResultMatchesCommand(result RequestResult, command RequestCommand) bool {
	return result.IsValid() && result.Binding().Equal(command.Binding()) &&
		result.ProposerPrincipalID() == command.AccountSession().PrincipalID() &&
		result.ProposerSessionID() == command.AccountSession().ID()
}

func approvalResultMatchesCommand(result Result, command Command) bool {
	return result.IsValid() && result.Scope() == command.Scope() &&
		result.RequestID() == command.RequestID() &&
		result.RequestVersion() == command.ExpectedRequestVersion()+1 &&
		result.Binding().CandidateSemanticHash() == command.CandidateSemanticHash() &&
		result.Binding().ImpactHash() == command.ImpactHash() &&
		result.ApproverPrincipalID() == command.AccountSession().PrincipalID() &&
		result.ApproverSessionID() == command.AccountSession().ID()
}
