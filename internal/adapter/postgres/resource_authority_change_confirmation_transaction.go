package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/resource"
	authority "github.com/meshtransit/meshtransit/internal/resource/authority"
)

type resourceAuthorityChangeConfirmationTransaction struct {
	mu sync.Mutex

	database      resourceAuthorityDatabaseTransaction
	scope         network.Scope
	metrics       *postgresPoolMetrics
	state         resourceAuthorityTransactionState
	resolution    authority.ChangeConfirmationResolution
	audit         resourceAuthorityAuditHead
	authorization resourceAuthorityAuthorizationEvidence
}

var _ authority.ChangeConfirmationTransaction = (*resourceAuthorityChangeConfirmationTransaction)(nil)

func (transaction *resourceAuthorityChangeConfirmationTransaction) Resolve(
	ctx context.Context,
	command authority.ChangeConfirmationCommand,
	ids authority.ChangeConfirmationMutationIDs,
	evaluatedAt, expiresAt time.Time,
) (resolution authority.ChangeConfirmationResolution, resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationResourceAuthorityResolve, startedAt, resultErr)
	}()
	if ctx == nil || transaction == nil || !command.IsValid() || !ids.IsValid() ||
		evaluatedAt.IsZero() || !expiresAt.After(evaluatedAt) {
		return authority.ChangeConfirmationResolution{}, ErrResourceAuthorityState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != resourceAuthorityTransactionOpen ||
		command.Scope() != transaction.scope {
		return authority.ChangeConfirmationResolution{}, ErrResourceAuthorityState
	}
	authorizationEvidence, err := authorizeResourceAuthorityChange(
		ctx, transaction.database, transaction.scope, command.AccountSession(),
		authorityChangePermission(command.SubjectKind()), evaluatedAt,
	)
	if err != nil {
		return authority.ChangeConfirmationResolution{}, errors.Join(
			ErrResolveResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	transaction.authorization = authorizationEvidence
	resolution, err = transaction.resolveLocked(ctx, command, ids, evaluatedAt, expiresAt)
	if err != nil {
		return authority.ChangeConfirmationResolution{}, errors.Join(
			ErrResolveResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	transaction.resolution = resolution
	transaction.state = resourceAuthorityTransactionResolved
	return resolution, nil
}

func (transaction *resourceAuthorityChangeConfirmationTransaction) resolveLocked(
	ctx context.Context,
	command authority.ChangeConfirmationCommand,
	ids authority.ChangeConfirmationMutationIDs,
	evaluatedAt, expiresAt time.Time,
) (authority.ChangeConfirmationResolution, error) {
	requestHash, err := command.RequestHash()
	if err != nil {
		return authority.ChangeConfirmationResolution{},
			authority.ErrInvalidAuthorityChangeConfirmationCommand
	}
	proof := command.IdempotencyEvidence()
	digest := proof.Digest()
	hashBytes := requestHash.Bytes()
	record, err := scanResourceAuthorityIdempotencyRecord(
		transaction.database.QueryRow(
			ctx, claimResourceAuthorityIdempotencySQL,
			ids.IdempotencyRecordID().String(), command.AccountSession().PrincipalID().String(),
			resourceAuthorityChangeConfirmationOperation, proof.DigestKeyID(), digest[:], hashBytes[:],
			evaluatedAt, expiresAt,
		),
		true,
	)
	if err != nil {
		return authority.ChangeConfirmationResolution{}, fmt.Errorf(
			"claim Resource authority change confirmation idempotency: %w", err,
		)
	}
	idempotencyResolution, err := resolveAuthorityChangeConfirmationIdempotency(
		record, command, ids, evaluatedAt,
	)
	if err != nil {
		return authority.ChangeConfirmationResolution{}, err
	}
	if idempotencyResolution.IsValid() {
		return idempotencyResolution, nil
	}
	networkRevision, subsystemRevision, err := lockAuthorityChangeHeads(
		ctx, transaction.database, command.SubjectKind(), &transaction.audit,
	)
	if err != nil {
		return authority.ChangeConfirmationResolution{}, err
	}
	requestRecord, err := scanResourceAuthorityChangeRequest(
		transaction.database.QueryRow(
			ctx, lockResourceAuthorityChangeRequestSQL, command.RequestID().String(),
		),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return authority.ChangeConfirmationResolution{},
			authority.ErrAuthorityChangeNotFound
	}
	if err != nil {
		return authority.ChangeConfirmationResolution{}, err
	}
	impact, err := transaction.resolveImpact(ctx, command, requestRecord, evaluatedAt)
	if err != nil {
		return authority.ChangeConfirmationResolution{}, err
	}
	recordID, err := publicid.Parse(record.publicID)
	if err != nil {
		return authority.ChangeConfirmationResolution{}, ErrResourceAuthorityEvidence
	}
	resolution, err := authority.NewAuthorityChangeConfirmationResolution(
		transaction.scope, command.RequestID(), requestRecord.requestVersion,
		requestRecord.expiresAt, networkRevision, subsystemRevision,
		recordID, requestHash, impact,
	)
	if err != nil {
		return authority.ChangeConfirmationResolution{}, ErrResourceAuthorityEvidence
	}
	return resolution, nil
}

func (transaction *resourceAuthorityChangeConfirmationTransaction) resolveImpact(
	ctx context.Context,
	command authority.ChangeConfirmationCommand,
	record resourceAuthorityChangeRequestRecord,
	evaluatedAt time.Time,
) (authority.ChangeImpact, error) {
	kind, err := authority.ParseAuthoritySubjectKind(record.subjectKind)
	if err != nil || kind != command.SubjectKind() ||
		record.subjectPublicID != command.SubjectPublicID().String() {
		return authority.ChangeImpact{}, ErrResourceAuthorityEvidence
	}
	action, err := authority.ParseAuthorityChangeAction(record.action)
	if err != nil {
		return authority.ChangeImpact{}, ErrResourceAuthorityEvidence
	}
	targetID, err := identity.ParsePrincipalID(record.targetPrincipalID)
	if err != nil || targetID != command.AccountSession().PrincipalID() {
		return authority.ChangeImpact{}, authority.ErrForbidden
	}
	storedImpactHash, err := authorityChangeImpactHash(record.impactHash)
	if err != nil || storedImpactHash != command.ImpactHash() {
		return authority.ChangeImpact{}, authority.ErrAuthorityChangeImpactChanged
	}
	if record.requestVersion != command.ExpectedRequestVersion() {
		return authority.ChangeImpact{}, authority.ErrAuthorityChangeRequestVersionConflict
	}
	if record.requestState != "pending" {
		return authority.ChangeImpact{}, authority.ErrAuthorityChangeRequestStateConflict
	}
	if !record.expiresAt.After(evaluatedAt) {
		return authority.ChangeImpact{}, authority.ErrAuthorityChangeRequestExpired
	}
	var preview authority.ChangePreview
	if kind == authority.AuthoritySubjectResource {
		resourceID, parseErr := resource.ParseID(record.subjectPublicID)
		if parseErr != nil || resourceID != command.ResourceID() {
			return authority.ChangeImpact{}, ErrResourceAuthorityEvidence
		}
		preview, err = authority.NewResourceAuthorityChangePreview(
			transaction.scope, resourceID, record.expectedSubjectVersion,
			action, targetID, record.requesterSession,
		)
	} else {
		groupID, parseErr := resource.ParseGroupID(record.subjectPublicID)
		if parseErr != nil || groupID != command.GroupID() {
			return authority.ChangeImpact{}, ErrResourceAuthorityEvidence
		}
		preview, err = authority.NewGroupAuthorityChangePreview(
			transaction.scope, groupID, record.expectedSubjectVersion,
			action, targetID, record.requesterSession,
		)
	}
	if err != nil {
		return authority.ChangeImpact{}, ErrResourceAuthorityEvidence
	}
	query := lockResourceAuthorityChangeSQL
	if kind == authority.AuthoritySubjectGroup {
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
		return authority.ChangeImpact{}, err
	}
	if impact.Hash() != storedImpactHash {
		return authority.ChangeImpact{}, authority.ErrAuthorityChangeImpactChanged
	}
	return impact, nil
}

func (transaction *resourceAuthorityChangeConfirmationTransaction) Apply(
	ctx context.Context,
	change authority.ChangeConfirmationChange,
) (result authority.ChangeConfirmationResult, resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationResourceAuthorityApply, startedAt, resultErr)
	}()
	if ctx == nil || transaction == nil || !change.IsValid() {
		return authority.ChangeConfirmationResult{}, ErrResourceAuthorityState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != resourceAuthorityTransactionResolved ||
		!change.Resolution().Equal(transaction.resolution) ||
		change.Command().Scope() != transaction.scope {
		return authority.ChangeConfirmationResult{}, ErrResourceAuthorityState
	}
	result, err := transaction.applyLocked(ctx, change)
	if err != nil {
		return authority.ChangeConfirmationResult{}, errors.Join(
			ErrApplyResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	transaction.state = resourceAuthorityTransactionApplied
	return result, nil
}

func (transaction *resourceAuthorityChangeConfirmationTransaction) applyLocked(
	ctx context.Context,
	change authority.ChangeConfirmationChange,
) (authority.ChangeConfirmationResult, error) {
	if err := transaction.database.Exec(
		ctx, setResourceAuthorityChangeSQL, change.MutationIDs().ChangeID().String(),
	); err != nil {
		return authority.ChangeConfirmationResult{}, fmt.Errorf(
			"set Resource authority confirmation change context: %w", err,
		)
	}
	command := change.Command()
	impact := change.Resolution().Impact()
	impactHash := command.ImpactHash().Bytes()
	proposedSemanticHash := impact.ProposedSemanticHash().Bytes()
	var networkRevision, subsystemRevision, subjectVersion, requestVersion int64
	var ownerIDValue, custodianIDValue string
	var semanticHashValue []byte
	if err := transaction.database.QueryRow(
		ctx, confirmResourceAuthorityChangeSQL,
		change.MutationIDs().StepUpEvidenceID().String(), command.RequestID().String(),
		command.ExpectedRequestVersion(), command.AccountSession().PrincipalID().String(),
		command.AccountSession().ID().String(), impactHash[:], proposedSemanticHash[:],
		change.OccurredAt(),
	).Scan(
		&networkRevision, &subsystemRevision, &subjectVersion, &requestVersion,
		&ownerIDValue, &custodianIDValue, &semanticHashValue,
	); err != nil {
		return authority.ChangeConfirmationResult{}, fmt.Errorf(
			"confirm Resource authority change: %w", err,
		)
	}
	ownerID, err := identity.ParsePrincipalID(ownerIDValue)
	if err != nil {
		return authority.ChangeConfirmationResult{}, ErrResourceAuthorityEvidence
	}
	custodianID, err := identity.ParsePrincipalID(custodianIDValue)
	if err != nil {
		return authority.ChangeConfirmationResult{}, ErrResourceAuthorityEvidence
	}
	semanticHash, err := resourceSemanticHash(semanticHashValue)
	if err != nil {
		return authority.ChangeConfirmationResult{}, err
	}
	preview := impact.Preview()
	var resourceID resource.ID
	var groupID resource.GroupID
	if command.SubjectKind() == authority.AuthoritySubjectResource {
		resourceID = command.ResourceID()
	} else {
		groupID = command.GroupID()
	}
	result, err := authority.NewAuthorityChangeConfirmationResult(
		command.RequestID(), transaction.scope, command.SubjectKind(), resourceID, groupID,
		preview.Action(), subjectVersion, requestVersion, networkRevision, subsystemRevision,
		ownerID, custodianID, semanticHash, command.ImpactHash(),
	)
	if err != nil {
		return authority.ChangeConfirmationResult{}, ErrResourceAuthorityEvidence
	}
	if err := transaction.appendAuthorityChangeConfirmationEvidence(ctx, change, result); err != nil {
		return authority.ChangeConfirmationResult{}, err
	}
	return result, nil
}

func (transaction *resourceAuthorityChangeConfirmationTransaction) Commit(
	ctx context.Context,
) (resultErr error) {
	return transaction.finish(ctx, true)
}

func (transaction *resourceAuthorityChangeConfirmationTransaction) Rollback(
	ctx context.Context,
) (resultErr error) {
	return transaction.finish(ctx, false)
}

func (transaction *resourceAuthorityChangeConfirmationTransaction) finish(
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

func (transaction *resourceAuthorityChangeConfirmationTransaction) observe(
	operation postgresOperation,
	startedAt time.Time,
	err error,
) {
	if transaction != nil {
		transaction.metrics.observeOperation(operation, time.Since(startedAt), err)
	}
}
