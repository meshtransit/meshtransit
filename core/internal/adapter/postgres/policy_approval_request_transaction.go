package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/authorization"
	approval "github.com/meshtransit/meshtransit/core/internal/domain/policy/approval"
)

const policyApprovalRequestResultKind = "policy_approval_request"

type policyApprovalRequestTransaction struct {
	core       policyApprovalTransactionCore
	resolution approval.RequestResolution
}

var _ approval.RequestTransaction = (*policyApprovalRequestTransaction)(nil)

func (transaction *policyApprovalRequestTransaction) Resolve(
	ctx context.Context,
	command approval.RequestCommand,
	mutationIDs approval.RequestMutationIDs,
	evaluatedAt time.Time,
	idempotencyExpiresAt time.Time,
) (_ approval.RequestResolution, resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationPolicyApprovalRequestResolve, startedAt, resultErr)
	}()
	if ctx == nil || transaction == nil || !command.IsValid() || !mutationIDs.IsValid() ||
		evaluatedAt.IsZero() || !idempotencyExpiresAt.After(evaluatedAt) {
		return approval.RequestResolution{}, ErrPolicyApprovalState
	}
	transaction.core.mu.Lock()
	defer transaction.core.mu.Unlock()
	if err := transaction.core.validateOpen(command.Scope()); err != nil {
		return approval.RequestResolution{}, err
	}
	authorizationEvidence, err := transaction.core.resolveAuthorization(
		ctx,
		command.AccountSession(),
		string(authorization.PermissionPolicyValidate),
		evaluatedAt,
	)
	if err != nil {
		return approval.RequestResolution{}, errors.Join(ErrResolvePolicyApproval, err)
	}
	baseline, err := transaction.core.lockRevision(ctx)
	if err != nil {
		return approval.RequestResolution{}, errors.Join(ErrResolvePolicyApproval, err)
	}
	requestHash, err := command.RequestHash()
	if err != nil {
		return approval.RequestResolution{}, errors.Join(ErrResolvePolicyApproval, err)
	}
	hashValue := requestHash.Bytes()
	proof := command.IdempotencyEvidence()
	keyDigest := proof.Digest()
	claim, err := transaction.core.claimIdempotency(
		ctx,
		mutationIDs.IdempotencyRecordID(),
		command.AccountSession().PrincipalID().String(),
		policyApprovalRequestOperation,
		proof.DigestKeyID(),
		keyDigest,
		hashValue,
		evaluatedAt,
		idempotencyExpiresAt,
	)
	if err != nil {
		return approval.RequestResolution{}, errors.Join(ErrResolvePolicyApproval, err)
	}
	recordID, err := claim.parsedRecordID()
	if err != nil {
		return approval.RequestResolution{}, errors.Join(ErrResolvePolicyApproval, err)
	}
	if resultIDValue, completed := claim.isCompleted(policyApprovalRequestResultKind); completed {
		resultID, parseErr := approval.ParseRequestID(resultIDValue)
		if parseErr != nil {
			return approval.RequestResolution{}, errors.Join(
				ErrResolvePolicyApproval, ErrPolicyApprovalEvidence, parseErr,
			)
		}
		record, loadErr := scanPolicyApprovalRequest(transaction.core.database.QueryRow(
			ctx, loadPolicyApprovalRequestSQL, resultID.String(),
		))
		if loadErr != nil {
			return approval.RequestResolution{}, errors.Join(
				ErrResolvePolicyApproval,
				classifyPolicyApprovalDatabaseError(ctx, loadErr),
			)
		}
		result, resultErr := record.result(command.Scope(), resultID)
		if resultErr != nil {
			return approval.RequestResolution{}, errors.Join(ErrResolvePolicyApproval, resultErr)
		}
		if !claim.matchesCompletedResult(
			result.RequestVersion(),
			result.Binding().BaselineVector().NetworkRevision(),
		) {
			return approval.RequestResolution{}, errors.Join(
				ErrResolvePolicyApproval,
				ErrPolicyApprovalEvidence,
			)
		}
		resolution, resolutionErr := approval.NewCompletedRequestResolution(
			result, recordID, requestHash,
		)
		if resolutionErr != nil {
			return approval.RequestResolution{}, errors.Join(ErrResolvePolicyApproval, resolutionErr)
		}
		transaction.resolution = resolution
		transaction.core.state = policyApprovalTransactionResolved
		return resolution, nil
	}
	if claim.state != "pending" {
		return approval.RequestResolution{}, errors.Join(
			ErrResolvePolicyApproval, ErrPolicyApprovalEvidence,
		)
	}
	if err := transaction.core.lockAuditHead(ctx); err != nil {
		return approval.RequestResolution{}, errors.Join(ErrResolvePolicyApproval, err)
	}
	resolution, err := approval.NewRequestResolution(
		command.Scope(), baseline, recordID, requestHash,
	)
	if err != nil {
		return approval.RequestResolution{}, errors.Join(ErrResolvePolicyApproval, err)
	}
	transaction.core.authorization = authorizationEvidence
	transaction.resolution = resolution
	transaction.core.state = policyApprovalTransactionResolved
	return resolution, nil
}

func (transaction *policyApprovalRequestTransaction) Apply(
	ctx context.Context,
	change approval.RequestChange,
) (_ approval.RequestResult, resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationPolicyApprovalRequestApply, startedAt, resultErr)
	}()
	if ctx == nil || transaction == nil || !change.IsValid() {
		return approval.RequestResult{}, ErrPolicyApprovalState
	}
	transaction.core.mu.Lock()
	defer transaction.core.mu.Unlock()
	if transaction.core.database == nil ||
		transaction.core.state != policyApprovalTransactionResolved ||
		change.Resolution() != transaction.resolution ||
		change.Command().Scope() != transaction.core.scope ||
		transaction.resolution.IsCompleted() {
		return approval.RequestResult{}, ErrPolicyApprovalState
	}
	result, err := transaction.applyLocked(ctx, change)
	if err != nil {
		return approval.RequestResult{}, errors.Join(
			ErrApplyPolicyApproval,
			classifyPolicyApprovalDatabaseError(ctx, err),
		)
	}
	transaction.core.state = policyApprovalTransactionApplied
	return result, nil
}

func (transaction *policyApprovalRequestTransaction) applyLocked(
	ctx context.Context,
	change approval.RequestChange,
) (approval.RequestResult, error) {
	command := change.Command()
	binding := command.Binding()
	baseline := binding.BaselineVector()
	proposed := binding.ProposedVector()
	mutationIDs := change.MutationIDs()
	if err := transaction.core.database.Exec(
		ctx, setPolicyApprovalChangeSQL, mutationIDs.ChangeID().String(),
	); err != nil {
		return approval.RequestResult{}, fmt.Errorf("set Policy approval change context: %w", err)
	}
	candidateHash := binding.CandidateSemanticHash().Bytes()
	impactHash := binding.ImpactHash().Bytes()
	requestHash, err := command.RequestHash()
	if err != nil {
		return approval.RequestResult{}, err
	}
	requestHashValue := requestHash.Bytes()
	session := command.AccountSession()
	var requestVersion int64
	if err := transaction.core.database.QueryRow(
		ctx,
		createPolicyApprovalRequestSQL,
		mutationIDs.RequestID().String(),
		mutationIDs.ChangeID().String(),
		session.ID().String(),
		session.DeploymentID().String(),
		session.PrincipalID().String(),
		session.Version(),
		session.PrincipalAuthorityGeneration(),
		session.AccountSessionGeneration(),
		session.ProviderGeneration(),
		session.DeploymentRecoveryEpoch(),
		baseline.NetworkRevision(), baseline.InventoryRevision(),
		baseline.GroupRevision(), baseline.PolicyRevision(),
		baseline.DNSRevision(), baseline.RouteRevision(),
		baseline.SharingRevision(), baseline.IsolationGeneration(),
		proposed.NetworkRevision(), proposed.InventoryRevision(),
		proposed.GroupRevision(), proposed.PolicyRevision(),
		proposed.DNSRevision(), proposed.RouteRevision(),
		proposed.SharingRevision(), proposed.IsolationGeneration(),
		candidateHash[:], binding.CompilerFormatVersion(), impactHash[:],
		requestHashValue[:], command.AuditReason().String(),
		change.OccurredAt(), change.RequestExpiresAt(),
	).Scan(&requestVersion); err != nil {
		return approval.RequestResult{}, fmt.Errorf("create Policy approval request: %w", err)
	}
	result, err := approval.NewRequestResult(approval.RequestResultParams{
		RequestID: mutationIDs.RequestID(), Binding: binding,
		ProposerPrincipalID: session.PrincipalID(), ProposerSessionID: session.ID(),
		RequestVersion: requestVersion, CreatedAt: change.OccurredAt(),
		ExpiresAt: change.RequestExpiresAt(),
	})
	if err != nil {
		return approval.RequestResult{}, err
	}
	if err := transaction.appendRequestEvidence(ctx, change, result); err != nil {
		return approval.RequestResult{}, err
	}
	proof := command.IdempotencyEvidence()
	keyDigest := proof.Digest()
	if err := transaction.core.completeIdempotency(
		ctx,
		mutationIDs.IdempotencyRecordID(),
		session.PrincipalID().String(),
		policyApprovalRequestOperation,
		proof.DigestKeyID(),
		keyDigest,
		requestHashValue,
		policyApprovalRequestResultKind,
		mutationIDs.RequestID().String(),
		result.RequestVersion(),
		baseline.NetworkRevision(),
		mutationIDs.OutboxEventID(),
		change.OccurredAt(),
	); err != nil {
		return approval.RequestResult{}, fmt.Errorf("complete Policy approval request replay: %w", err)
	}
	return result, nil
}

func (transaction *policyApprovalRequestTransaction) Commit(ctx context.Context) error {
	return transaction.core.commit(ctx, postgresOperationPolicyApprovalRequestCommit)
}

func (transaction *policyApprovalRequestTransaction) Rollback(ctx context.Context) error {
	return transaction.core.rollback(ctx, postgresOperationPolicyApprovalRequestRollback)
}

func (transaction *policyApprovalRequestTransaction) observe(
	operation postgresOperation,
	startedAt time.Time,
	err error,
) {
	if transaction != nil {
		transaction.core.metrics.observeOperation(operation, time.Since(startedAt), err)
	}
}
