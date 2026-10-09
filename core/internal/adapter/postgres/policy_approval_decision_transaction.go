package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/core/internal/domain/authorization"
	approval "github.com/meshtransit/meshtransit/core/internal/domain/policy/approval"
)

const policyApprovalDecisionResultKind = "policy_approval_evidence"

type policyApprovalDecisionTransaction struct {
	core       policyApprovalTransactionCore
	resolution approval.Resolution
}

var _ approval.Transaction = (*policyApprovalDecisionTransaction)(nil)

func (transaction *policyApprovalDecisionTransaction) Resolve(
	ctx context.Context,
	command approval.Command,
	mutationIDs approval.MutationIDs,
	evaluatedAt time.Time,
	idempotencyExpiresAt time.Time,
) (_ approval.Resolution, resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationPolicyApprovalDecisionResolve, startedAt, resultErr)
	}()
	if ctx == nil || transaction == nil || !command.IsValid() || !mutationIDs.IsValid() ||
		evaluatedAt.IsZero() || !idempotencyExpiresAt.After(evaluatedAt) {
		return approval.Resolution{}, ErrPolicyApprovalState
	}
	transaction.core.mu.Lock()
	defer transaction.core.mu.Unlock()
	if err := transaction.core.validateOpen(command.Scope()); err != nil {
		return approval.Resolution{}, err
	}
	authorizationEvidence, err := transaction.core.resolveAuthorization(
		ctx,
		command.AccountSession(),
		string(authorization.PermissionPolicyApprove),
		evaluatedAt,
	)
	if err != nil {
		return approval.Resolution{}, errors.Join(ErrResolvePolicyApproval, err)
	}
	decisionHash, err := command.DecisionHash()
	if err != nil {
		return approval.Resolution{}, errors.Join(ErrResolvePolicyApproval, err)
	}
	hashValue := decisionHash.Bytes()
	proof := command.IdempotencyEvidence()
	keyDigest := proof.Digest()
	claim, err := transaction.core.claimIdempotency(
		ctx,
		mutationIDs.IdempotencyRecordID(),
		command.AccountSession().PrincipalID().String(),
		policyApprovalDecisionOperation,
		proof.DigestKeyID(),
		keyDigest,
		hashValue,
		evaluatedAt,
		idempotencyExpiresAt,
	)
	if err != nil {
		return approval.Resolution{}, errors.Join(ErrResolvePolicyApproval, err)
	}
	recordID, err := claim.parsedRecordID()
	if err != nil {
		return approval.Resolution{}, errors.Join(ErrResolvePolicyApproval, err)
	}
	if resultIDValue, completed := claim.isCompleted(policyApprovalDecisionResultKind); completed {
		evidenceID, parseErr := approval.ParseEvidenceID(resultIDValue)
		if parseErr != nil {
			return approval.Resolution{}, errors.Join(
				ErrResolvePolicyApproval, ErrPolicyApprovalEvidence, parseErr,
			)
		}
		record, loadErr := scanPolicyApprovalEvidence(transaction.core.database.QueryRow(
			ctx, loadPolicyApprovalEvidenceSQL, evidenceID.String(),
		))
		if loadErr != nil {
			return approval.Resolution{}, errors.Join(
				ErrResolvePolicyApproval,
				classifyPolicyApprovalDatabaseError(ctx, loadErr),
			)
		}
		result, resultErr := record.result(command.Scope(), evidenceID)
		if resultErr != nil {
			return approval.Resolution{}, errors.Join(ErrResolvePolicyApproval, resultErr)
		}
		if !claim.matchesCompletedResult(
			result.EvidenceVersion(),
			result.Binding().BaselineVector().NetworkRevision(),
		) {
			return approval.Resolution{}, errors.Join(
				ErrResolvePolicyApproval,
				ErrPolicyApprovalEvidence,
			)
		}
		resolution, resolutionErr := approval.NewCompletedResolution(
			result, recordID, decisionHash,
		)
		if resolutionErr != nil {
			return approval.Resolution{}, errors.Join(ErrResolvePolicyApproval, resolutionErr)
		}
		transaction.resolution = resolution
		transaction.core.state = policyApprovalTransactionResolved
		return resolution, nil
	}
	if claim.state != "pending" {
		return approval.Resolution{}, errors.Join(
			ErrResolvePolicyApproval, ErrPolicyApprovalEvidence,
		)
	}
	record, err := scanLockedPolicyApprovalRequest(transaction.core.database.QueryRow(
		ctx, lockPolicyApprovalRequestSQL, command.RequestID().String(),
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return approval.Resolution{}, errors.Join(ErrResolvePolicyApproval, approval.ErrForbidden)
	}
	if err != nil {
		return approval.Resolution{}, errors.Join(
			ErrResolvePolicyApproval,
			classifyPolicyApprovalDatabaseError(ctx, err),
		)
	}
	if record.state != approval.StatePending.String() {
		return approval.Resolution{}, errors.Join(
			ErrResolvePolicyApproval, approval.ErrRequestStateConflict,
		)
	}
	if err := transaction.core.lockAuditHead(ctx); err != nil {
		return approval.Resolution{}, errors.Join(ErrResolvePolicyApproval, err)
	}
	resolution, err := record.resolution(
		command.Scope(), command.RequestID(), recordID, decisionHash,
	)
	if err != nil {
		return approval.Resolution{}, errors.Join(ErrResolvePolicyApproval, err)
	}
	transaction.core.authorization = authorizationEvidence
	transaction.resolution = resolution
	transaction.core.state = policyApprovalTransactionResolved
	return resolution, nil
}

func (transaction *policyApprovalDecisionTransaction) Apply(
	ctx context.Context,
	change approval.Change,
) (_ approval.Result, resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationPolicyApprovalDecisionApply, startedAt, resultErr)
	}()
	if ctx == nil || transaction == nil || !change.IsValid() {
		return approval.Result{}, ErrPolicyApprovalState
	}
	transaction.core.mu.Lock()
	defer transaction.core.mu.Unlock()
	if transaction.core.database == nil ||
		transaction.core.state != policyApprovalTransactionResolved ||
		change.Resolution() != transaction.resolution ||
		change.Command().Scope() != transaction.core.scope ||
		transaction.resolution.IsCompleted() {
		return approval.Result{}, ErrPolicyApprovalState
	}
	result, err := transaction.applyLocked(ctx, change)
	if err != nil {
		return approval.Result{}, errors.Join(
			ErrApplyPolicyApproval,
			classifyPolicyApprovalDatabaseError(ctx, err),
		)
	}
	transaction.core.state = policyApprovalTransactionApplied
	return result, nil
}

func (transaction *policyApprovalDecisionTransaction) applyLocked(
	ctx context.Context,
	change approval.Change,
) (approval.Result, error) {
	command := change.Command()
	resolution := change.Resolution()
	mutationIDs := change.MutationIDs()
	if err := transaction.core.database.Exec(
		ctx, setPolicyApprovalChangeSQL, mutationIDs.ChangeID().String(),
	); err != nil {
		return approval.Result{}, fmt.Errorf("set Policy approval change context: %w", err)
	}
	candidateHash := command.CandidateSemanticHash().Bytes()
	impactHash := command.ImpactHash().Bytes()
	decisionHash, err := command.DecisionHash()
	if err != nil {
		return approval.Result{}, err
	}
	decisionHashValue := decisionHash.Bytes()
	session := command.AccountSession()
	var requestVersion, evidenceVersion int64
	if err := transaction.core.database.QueryRow(
		ctx,
		approvePolicyApprovalRequestSQL,
		mutationIDs.EvidenceID().String(),
		mutationIDs.ChangeID().String(),
		command.RequestID().String(),
		command.ExpectedRequestVersion(),
		candidateHash[:],
		impactHash[:],
		session.ID().String(),
		session.DeploymentID().String(),
		session.PrincipalID().String(),
		session.Version(),
		session.PrincipalAuthorityGeneration(),
		session.AccountSessionGeneration(),
		session.ProviderGeneration(),
		session.DeploymentRecoveryEpoch(),
		decisionHashValue[:],
		command.AuditReason().String(),
		change.OccurredAt(),
	).Scan(&requestVersion, &evidenceVersion); err != nil {
		return approval.Result{}, fmt.Errorf("approve Policy approval request: %w", err)
	}
	result, err := approval.NewResult(approval.ResultParams{
		EvidenceID: mutationIDs.EvidenceID(), RequestID: command.RequestID(),
		Binding:             resolution.Binding(),
		ProposerPrincipalID: resolution.ProposerPrincipalID(),
		ProposerSessionID:   resolution.ProposerSessionID(),
		ApproverPrincipalID: session.PrincipalID(), ApproverSessionID: session.ID(),
		RequestVersion: requestVersion, EvidenceVersion: evidenceVersion,
		ApprovedAt: change.OccurredAt(), ExpiresAt: resolution.RequestExpiresAt(),
	})
	if err != nil {
		return approval.Result{}, err
	}
	if err := transaction.appendDecisionEvidence(ctx, change, result); err != nil {
		return approval.Result{}, err
	}
	proof := command.IdempotencyEvidence()
	keyDigest := proof.Digest()
	baseline := resolution.Binding().BaselineVector()
	if err := transaction.core.completeIdempotency(
		ctx,
		mutationIDs.IdempotencyRecordID(),
		session.PrincipalID().String(),
		policyApprovalDecisionOperation,
		proof.DigestKeyID(),
		keyDigest,
		decisionHashValue,
		policyApprovalDecisionResultKind,
		mutationIDs.EvidenceID().String(),
		result.EvidenceVersion(),
		baseline.NetworkRevision(),
		mutationIDs.OutboxEventID(),
		change.OccurredAt(),
	); err != nil {
		return approval.Result{}, fmt.Errorf("complete Policy approval decision replay: %w", err)
	}
	return result, nil
}

func (transaction *policyApprovalDecisionTransaction) Commit(ctx context.Context) error {
	return transaction.core.commit(ctx, postgresOperationPolicyApprovalDecisionCommit)
}

func (transaction *policyApprovalDecisionTransaction) Rollback(ctx context.Context) error {
	return transaction.core.rollback(ctx, postgresOperationPolicyApprovalDecisionRollback)
}

func (transaction *policyApprovalDecisionTransaction) observe(
	operation postgresOperation,
	startedAt time.Time,
	err error,
) {
	if transaction != nil {
		transaction.core.metrics.observeOperation(operation, time.Since(startedAt), err)
	}
}
