package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	authority "meshtransit.net/core/internal/domain/resource/authority"
)

type resourceAuthorityChangeRequestTransaction struct {
	mu sync.Mutex

	decisionAt    time.Time
	database      resourceAuthorityDatabaseTransaction
	scope         network.Scope
	metrics       *postgresPoolMetrics
	state         resourceAuthorityTransactionState
	resolution    authority.ChangeRequestResolution
	audit         resourceAuthorityAuditHead
	authorization resourceAuthorityAuthorizationEvidence
}

// DecisionTime is this transaction's time on the database clock.
func (transaction *resourceAuthorityChangeRequestTransaction) DecisionTime() time.Time {
	return transaction.decisionAt
}

var _ authority.ChangeRequestTransaction = (*resourceAuthorityChangeRequestTransaction)(nil)

func (transaction *resourceAuthorityChangeRequestTransaction) Resolve(
	ctx context.Context,
	command authority.ChangeRequestCommand,
	ids authority.ChangeRequestMutationIDs,
	evaluatedAt, expiresAt time.Time,
) (resolution authority.ChangeRequestResolution, resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationResourceAuthorityResolve, startedAt, resultErr)
	}()
	if ctx == nil || transaction == nil || !command.IsValid() || !ids.IsValid() ||
		evaluatedAt.IsZero() || !expiresAt.After(evaluatedAt) {
		return authority.ChangeRequestResolution{}, ErrResourceAuthorityState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != resourceAuthorityTransactionOpen ||
		command.Scope() != transaction.scope {
		return authority.ChangeRequestResolution{}, ErrResourceAuthorityState
	}
	preview := command.Preview()
	authorizationEvidence, err := authorizeResourceAuthorityChange(
		ctx, transaction.database, transaction.scope, preview.AccountSession(),
		authorityChangePermission(preview.SubjectKind()), evaluatedAt,
	)
	if err != nil {
		return authority.ChangeRequestResolution{}, errors.Join(
			ErrResolveResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	transaction.authorization = authorizationEvidence
	resolution, err = transaction.resolveLocked(ctx, command, ids, evaluatedAt, expiresAt)
	if err != nil {
		return authority.ChangeRequestResolution{}, errors.Join(
			ErrResolveResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	transaction.resolution = resolution
	transaction.state = resourceAuthorityTransactionResolved
	return resolution, nil
}

func (transaction *resourceAuthorityChangeRequestTransaction) resolveLocked(
	ctx context.Context,
	command authority.ChangeRequestCommand,
	ids authority.ChangeRequestMutationIDs,
	evaluatedAt, expiresAt time.Time,
) (authority.ChangeRequestResolution, error) {
	requestHash, err := command.RequestHash()
	if err != nil {
		return authority.ChangeRequestResolution{},
			authority.ErrInvalidAuthorityChangeRequestCommand
	}
	proof := command.IdempotencyEvidence()
	digest := proof.Digest()
	hashBytes := requestHash.Bytes()
	preview := command.Preview()
	record, err := scanResourceAuthorityIdempotencyRecord(
		transaction.database.QueryRow(
			ctx, claimResourceAuthorityIdempotencySQL,
			ids.IdempotencyRecordID().String(), preview.AccountSession().PrincipalID().String(),
			resourceAuthorityChangeRequestOperation, proof.DigestKeyID(), digest[:], hashBytes[:],
			evaluatedAt, expiresAt,
		),
		true,
	)
	if err != nil {
		return authority.ChangeRequestResolution{}, fmt.Errorf(
			"claim Resource authority change request idempotency: %w", err,
		)
	}
	idempotencyResolution, err := resolveAuthorityChangeRequestIdempotency(
		record, command, ids, evaluatedAt,
	)
	if err != nil {
		return authority.ChangeRequestResolution{}, err
	}
	if idempotencyResolution.IsValid() {
		return idempotencyResolution, nil
	}
	networkRevision, subsystemRevision, err := lockAuthorityChangeHeads(
		ctx, transaction.database, preview.SubjectKind(), &transaction.audit,
	)
	if err != nil {
		return authority.ChangeRequestResolution{}, err
	}
	query := lockResourceAuthorityChangeSQL
	if preview.SubjectKind() == authority.AuthoritySubjectGroup {
		query = lockResourceGroupAuthorityChangeSQL
	}
	impact, err := scanResourceAuthorityChangeImpact(
		transaction.database.QueryRow(
			ctx, query, preview.SubjectPublicID().String(), preview.Action().String(),
			preview.TargetPrincipalID().String(),
		),
		preview,
	)
	if err != nil {
		return authority.ChangeRequestResolution{}, err
	}
	if impact.Hash() != command.ImpactHash() {
		return authority.ChangeRequestResolution{},
			authority.ErrAuthorityChangeImpactChanged
	}
	recordID, err := publicid.Parse(record.publicID)
	if err != nil {
		return authority.ChangeRequestResolution{}, ErrResourceAuthorityEvidence
	}
	resolution, err := authority.NewAuthorityChangeRequestResolution(
		transaction.scope, networkRevision, subsystemRevision, recordID, requestHash, impact,
	)
	if err != nil {
		return authority.ChangeRequestResolution{}, ErrResourceAuthorityEvidence
	}
	return resolution, nil
}

func (transaction *resourceAuthorityChangeRequestTransaction) Apply(
	ctx context.Context,
	change authority.ChangeRequestChange,
) (result authority.ChangeRequestResult, resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationResourceAuthorityApply, startedAt, resultErr)
	}()
	if ctx == nil || transaction == nil || !change.IsValid() {
		return authority.ChangeRequestResult{}, ErrResourceAuthorityState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != resourceAuthorityTransactionResolved ||
		!change.Resolution().Equal(transaction.resolution) ||
		change.Command().Scope() != transaction.scope {
		return authority.ChangeRequestResult{}, ErrResourceAuthorityState
	}
	result, err := transaction.applyLocked(ctx, change)
	if err != nil {
		return authority.ChangeRequestResult{}, errors.Join(
			ErrApplyResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	transaction.state = resourceAuthorityTransactionApplied
	return result, nil
}

func (transaction *resourceAuthorityChangeRequestTransaction) applyLocked(
	ctx context.Context,
	change authority.ChangeRequestChange,
) (authority.ChangeRequestResult, error) {
	if err := transaction.database.Exec(
		ctx, setResourceAuthorityChangeSQL, change.MutationIDs().ChangeID().String(),
	); err != nil {
		return authority.ChangeRequestResult{}, fmt.Errorf(
			"set Resource authority request change context: %w", err,
		)
	}
	command := change.Command()
	preview := command.Preview()
	impactHash := command.ImpactHash().Bytes()
	var networkRevision, subsystemRevision, requestVersion int64
	if err := transaction.database.QueryRow(
		ctx, requestResourceAuthorityChangeSQL,
		change.MutationIDs().RequestID().String(),
		change.MutationIDs().StepUpEvidenceID().String(),
		preview.SubjectKind().String(), preview.SubjectPublicID().String(),
		preview.Action().String(), preview.ExpectedVersion(),
		preview.TargetPrincipalID().String(),
		preview.AccountSession().PrincipalID().String(),
		preview.AccountSession().ID().String(), impactHash[:],
		change.OccurredAt(), change.RequestExpiresAt(),
	).Scan(&networkRevision, &subsystemRevision, &requestVersion); err != nil {
		return authority.ChangeRequestResult{}, fmt.Errorf(
			"request Resource authority change: %w", err,
		)
	}
	result, err := authority.NewAuthorityChangeRequestResult(
		change.MutationIDs().RequestID(), preview, requestVersion,
		networkRevision, subsystemRevision, command.ImpactHash(), change.RequestExpiresAt(),
	)
	if err != nil {
		return authority.ChangeRequestResult{}, ErrResourceAuthorityEvidence
	}
	if err := transaction.appendAuthorityChangeRequestEvidence(ctx, change, result); err != nil {
		return authority.ChangeRequestResult{}, err
	}
	return result, nil
}

func (transaction *resourceAuthorityChangeRequestTransaction) Commit(
	ctx context.Context,
) (resultErr error) {
	return transaction.finish(ctx, true)
}

func (transaction *resourceAuthorityChangeRequestTransaction) Rollback(
	ctx context.Context,
) (resultErr error) {
	return transaction.finish(ctx, false)
}

func (transaction *resourceAuthorityChangeRequestTransaction) finish(
	ctx context.Context,
	commit bool,
) (resultErr error) {
	operation := postgresOperationResourceAuthorityRollback
	if commit {
		operation = postgresOperationResourceAuthorityCommit
	}
	startedAt := time.Now()
	defer func() { transaction.observe(operation, startedAt, resultErr) }()
	if ctx == nil || transaction == nil {
		return ErrResourceAuthorityState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil {
		return ErrResourceAuthorityState
	}
	if !commit && transaction.state == resourceAuthorityTransactionClosed {
		return nil
	}
	if commit && transaction.state != resourceAuthorityTransactionApplied {
		return ErrResourceAuthorityState
	}
	transaction.state = resourceAuthorityTransactionClosed
	if commit {
		if err := transaction.database.Commit(ctx); err != nil {
			return errors.Join(
				ErrCommitResourceAuthority, classifyResourceAuthorityCommitError(ctx, err),
			)
		}
		return nil
	}
	if err := transaction.database.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return errors.Join(ErrRollbackResourceAuthority, err)
	}
	return nil
}

func (transaction *resourceAuthorityChangeRequestTransaction) observe(
	operation postgresOperation,
	startedAt time.Time,
	err error,
) {
	if transaction != nil {
		transaction.metrics.observeOperation(operation, time.Since(startedAt), err)
	}
}

func lockAuthorityChangeHeads(
	ctx context.Context,
	database resourceAuthorityDatabaseTransaction,
	kind authority.SubjectKind,
	audit *resourceAuthorityAuditHead,
) (int64, int64, error) {
	var networkRevision, inventoryRevision, groupRevision, policyRevision int64
	var dnsRevision, routeRevision, sharingRevision, isolationGeneration int64
	if err := database.QueryRow(ctx, lockResourceAuthorityRevisionSQL).Scan(
		&networkRevision, &inventoryRevision, &groupRevision, &policyRevision,
		&dnsRevision, &routeRevision, &sharingRevision, &isolationGeneration,
	); err != nil {
		return 0, 0, fmt.Errorf("lock Network revision: %w", err)
	}
	if networkRevision <= 0 || inventoryRevision <= 0 || groupRevision <= 0 ||
		policyRevision <= 0 || dnsRevision <= 0 || routeRevision <= 0 ||
		sharingRevision <= 0 || isolationGeneration <= 0 {
		return 0, 0, ErrResourceAuthorityEvidence
	}
	var previousHash []byte
	if err := database.QueryRow(ctx, lockResourceAuthorityAuditStreamSQL).Scan(
		&audit.streamInternalID, &audit.nextSequence, &previousHash,
	); err != nil {
		return 0, 0, fmt.Errorf("lock audit stream: %w", err)
	}
	if audit.streamInternalID <= 0 || audit.nextSequence <= 0 ||
		len(previousHash) != len(audit.previousHash) {
		return 0, 0, ErrResourceAuthorityEvidence
	}
	copy(audit.previousHash[:], previousHash)
	if kind == authority.AuthoritySubjectGroup {
		return networkRevision, groupRevision, nil
	}
	return networkRevision, inventoryRevision, nil
}
