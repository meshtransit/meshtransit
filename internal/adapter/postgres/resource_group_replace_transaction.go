package postgres

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/authorization"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/resource"
	authority "github.com/meshtransit/meshtransit/internal/resource/authority"
)

type resourceGroupReplaceTransaction struct {
	mu sync.Mutex

	database      resourceAuthorityDatabaseTransaction
	scope         network.Scope
	metrics       *postgresPoolMetrics
	state         resourceAuthorityTransactionState
	resolution    authority.GroupReplaceResolution
	audit         resourceAuthorityAuditHead
	authorization resourceAuthorityAuthorizationEvidence
}

var _ authority.GroupReplaceTransaction = (*resourceGroupReplaceTransaction)(nil)

func (transaction *resourceGroupReplaceTransaction) authorize(
	ctx context.Context,
	session accountsession.Session,
	evaluatedAt time.Time,
) (resourceAuthorityAuthorizationEvidence, error) {
	var bindingIDValue, roleIDValue string
	var scopeGeneration, membershipGeneration, bindingGeneration, roleGeneration int64
	var hasExpiry bool
	var expiresAt time.Time
	err := transaction.database.QueryRow(
		ctx,
		authorizeResourceAuthoritySQL,
		session.ID().String(), session.DeploymentID().String(), session.PrincipalID().String(),
		session.IdentitySubjectID().String(), session.Version(),
		session.PrincipalAuthorityGeneration(), session.AccountSessionGeneration(),
		session.ProviderGeneration(), session.DeploymentRecoveryEpoch(),
		transaction.scope.WorkspaceID().String(), transaction.scope.NetworkID().String(),
		string(authorization.PermissionResourceGroupManage), evaluatedAt,
	).Scan(
		&bindingIDValue, &roleIDValue, &scopeGeneration, &membershipGeneration,
		&bindingGeneration, &roleGeneration, &hasExpiry, &expiresAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return resourceAuthorityAuthorizationEvidence{}, authority.ErrForbidden
	}
	if err != nil {
		return resourceAuthorityAuthorizationEvidence{}, fmt.Errorf(
			"authorize Resource Group replacement: %w", err,
		)
	}
	if hasExpiry && !expiresAt.After(evaluatedAt) {
		return resourceAuthorityAuthorizationEvidence{}, authority.ErrForbidden
	}
	bindingID, err := publicid.Parse(bindingIDValue)
	if err != nil {
		return resourceAuthorityAuthorizationEvidence{}, ErrResourceAuthorityEvidence
	}
	roleID, err := publicid.Parse(roleIDValue)
	if err != nil {
		return resourceAuthorityAuthorizationEvidence{}, ErrResourceAuthorityEvidence
	}
	evidence := resourceAuthorityAuthorizationEvidence{
		accountSessionID: publicid.ID(session.ID()), roleBindingID: bindingID,
		roleDefinitionID: roleID, scopeAuthorityGeneration: scopeGeneration,
		membershipAuthorityGeneration: membershipGeneration,
		bindingAuthorityGeneration:    bindingGeneration, roleAuthorityGeneration: roleGeneration,
	}
	if !evidence.isValid() {
		return resourceAuthorityAuthorizationEvidence{}, ErrResourceAuthorityEvidence
	}
	return evidence, nil
}

func scanResourceGroupReplaceImpact(
	row resourceAuthorityRow,
	preview authority.GroupReplacePreview,
) (authority.GroupReplaceImpact, error) {
	var displayNameValue, ownerIDValue, custodianIDValue, stateValue string
	var groupVersion, definitionVersion int64
	var currentSemanticHashValue, currentMembersValue []byte
	var approvalRequired bool
	if err := row.Scan(
		&displayNameValue, &ownerIDValue, &custodianIDValue, &stateValue,
		&groupVersion, &definitionVersion, &currentSemanticHashValue,
		&currentMembersValue, &approvalRequired,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return authority.GroupReplaceImpact{}, authority.ErrGroupReplaceNotFound
		}
		return authority.GroupReplaceImpact{}, err
	}
	if groupVersion != preview.ExpectedVersion() {
		return authority.GroupReplaceImpact{}, authority.ErrGroupReplaceVersionConflict
	}
	if stateValue == "deleted" || definitionVersion <= 0 || definitionVersion == math.MaxInt64 {
		return authority.GroupReplaceImpact{}, authority.ErrGroupReplaceStateConflict
	}
	displayName, err := resource.ParseDisplayName(displayNameValue)
	if err != nil {
		return authority.GroupReplaceImpact{}, ErrResourceAuthorityEvidence
	}
	ownerID, err := identity.ParsePrincipalID(ownerIDValue)
	if err != nil {
		return authority.GroupReplaceImpact{}, ErrResourceAuthorityEvidence
	}
	custodianID, err := identity.ParsePrincipalID(custodianIDValue)
	if err != nil {
		return authority.GroupReplaceImpact{}, ErrResourceAuthorityEvidence
	}
	currentSemanticHash, err := resourceSemanticHash(currentSemanticHashValue)
	if err != nil {
		return authority.GroupReplaceImpact{}, ErrResourceAuthorityEvidence
	}
	currentMembers, err := parseResourceGroupReferences(currentMembersValue, preview.Scope())
	if err != nil {
		return authority.GroupReplaceImpact{}, err
	}
	current, err := resource.NewGroupRevision(resource.GroupRevisionParams{
		Scope: preview.Scope(), DisplayName: displayName,
		OwnerPrincipalID: ownerID, CustodianPrincipalID: custodianID,
		DefinitionVersion: definitionVersion, Members: currentMembers,
	})
	if err != nil || current.SemanticHash() != currentSemanticHash {
		return authority.GroupReplaceImpact{}, ErrResourceAuthorityEvidence
	}
	proposed, err := resource.NewGroupRevision(resource.GroupRevisionParams{
		Scope: preview.Scope(), DisplayName: displayName,
		OwnerPrincipalID: ownerID, CustodianPrincipalID: custodianID,
		DefinitionVersion: definitionVersion + 1, Members: preview.Members(),
	})
	if err != nil {
		return authority.GroupReplaceImpact{}, ErrResourceAuthorityEvidence
	}
	if proposed.SemanticHash() == current.SemanticHash() {
		return authority.GroupReplaceImpact{}, authority.ErrGroupReplaceNoChange
	}
	impact, err := authority.NewGroupReplaceImpact(authority.GroupReplaceImpactParams{
		GroupID: preview.GroupID(), ExpectedVersion: preview.ExpectedVersion(),
		CurrentRevision: current, ProposedRevision: proposed,
		ApprovalRequired: approvalRequired,
	})
	if err != nil {
		return authority.GroupReplaceImpact{}, ErrResourceAuthorityEvidence
	}
	return impact, nil
}

func (transaction *resourceGroupReplaceTransaction) Resolve(
	ctx context.Context,
	command authority.GroupReplaceCommand,
	ids authority.GroupReplaceMutationIDs,
	evaluatedAt, expiresAt time.Time,
) (resolution authority.GroupReplaceResolution, resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationResourceAuthorityResolve, startedAt, resultErr)
	}()
	if ctx == nil || transaction == nil || !command.IsValid() || !ids.IsValidFor(command) ||
		evaluatedAt.IsZero() || !expiresAt.After(evaluatedAt) {
		return authority.GroupReplaceResolution{}, ErrResourceAuthorityState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != resourceAuthorityTransactionOpen ||
		command.Scope() != transaction.scope {
		return authority.GroupReplaceResolution{}, ErrResourceAuthorityState
	}
	authorizationEvidence, err := transaction.authorize(
		ctx, command.AccountSession(), evaluatedAt,
	)
	if err != nil {
		return authority.GroupReplaceResolution{}, errors.Join(
			ErrResolveResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	transaction.authorization = authorizationEvidence
	resolution, err = transaction.resolveLocked(ctx, command, ids, evaluatedAt, expiresAt)
	if err != nil {
		return authority.GroupReplaceResolution{}, errors.Join(
			ErrResolveResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	transaction.resolution = resolution
	transaction.state = resourceAuthorityTransactionResolved
	return resolution, nil
}

func (transaction *resourceGroupReplaceTransaction) resolveLocked(
	ctx context.Context,
	command authority.GroupReplaceCommand,
	ids authority.GroupReplaceMutationIDs,
	evaluatedAt, expiresAt time.Time,
) (authority.GroupReplaceResolution, error) {
	requestHash, err := command.RequestHash()
	if err != nil {
		return authority.GroupReplaceResolution{}, authority.ErrInvalidGroupReplaceCommand
	}
	proof := command.IdempotencyEvidence()
	digest := proof.Digest()
	hashBytes := requestHash.Bytes()
	record, err := scanResourceAuthorityIdempotencyRecord(
		transaction.database.QueryRow(
			ctx, claimResourceAuthorityIdempotencySQL,
			ids.IdempotencyRecordID().String(), command.AccountSession().PrincipalID().String(),
			"resource_group.replace", proof.DigestKeyID(), digest[:], hashBytes[:],
			evaluatedAt, expiresAt,
		),
		true,
	)
	if err != nil {
		return authority.GroupReplaceResolution{}, fmt.Errorf(
			"claim Resource Group replacement idempotency: %w", err,
		)
	}
	idempotencyResolution, err := resolveResourceGroupReplaceIdempotency(
		record, command, ids, evaluatedAt,
	)
	if err != nil {
		return authority.GroupReplaceResolution{}, err
	}
	if idempotencyResolution.IsValid() {
		return idempotencyResolution, nil
	}

	var networkRevision, inventoryRevision, groupRevision, policyRevision int64
	var dnsRevision, routeRevision, sharingRevision, isolationGeneration int64
	if err := transaction.database.QueryRow(ctx, lockResourceAuthorityRevisionSQL).Scan(
		&networkRevision, &inventoryRevision, &groupRevision, &policyRevision,
		&dnsRevision, &routeRevision, &sharingRevision, &isolationGeneration,
	); err != nil {
		return authority.GroupReplaceResolution{}, fmt.Errorf("lock Network revision: %w", err)
	}
	if inventoryRevision <= 0 || policyRevision <= 0 || dnsRevision <= 0 || routeRevision <= 0 ||
		sharingRevision <= 0 || isolationGeneration <= 0 {
		return authority.GroupReplaceResolution{}, ErrResourceAuthorityEvidence
	}
	var previousHash []byte
	if err := transaction.database.QueryRow(ctx, lockResourceAuthorityAuditStreamSQL).Scan(
		&transaction.audit.streamInternalID, &transaction.audit.nextSequence, &previousHash,
	); err != nil {
		return authority.GroupReplaceResolution{}, fmt.Errorf("lock audit stream: %w", err)
	}
	if transaction.audit.streamInternalID <= 0 || transaction.audit.nextSequence <= 0 ||
		len(previousHash) != len(transaction.audit.previousHash) {
		return authority.GroupReplaceResolution{}, ErrResourceAuthorityEvidence
	}
	copy(transaction.audit.previousHash[:], previousHash)
	members, err := encodeResourceGroupReferences(command.Members())
	if err != nil {
		return authority.GroupReplaceResolution{}, err
	}
	impact, err := scanResourceGroupReplaceImpact(
		transaction.database.QueryRow(
			ctx, lockResourceGroupReplaceImpactSQL, command.GroupID().String(), members,
		),
		command.Preview(),
	)
	if err != nil {
		return authority.GroupReplaceResolution{}, err
	}
	if impact.Hash() != command.ImpactHash() {
		return authority.GroupReplaceResolution{}, authority.ErrGroupReplaceImpactChanged
	}
	if impact.ApprovalRequired() {
		return authority.GroupReplaceResolution{}, authority.ErrGroupReplaceApprovalRequired
	}
	recordID, err := publicid.Parse(record.publicID)
	if err != nil {
		return authority.GroupReplaceResolution{}, ErrResourceAuthorityEvidence
	}
	resolution, err := authority.NewGroupReplaceResolution(
		transaction.scope, networkRevision, groupRevision, recordID, requestHash, impact,
	)
	if err != nil {
		return authority.GroupReplaceResolution{}, ErrResourceAuthorityEvidence
	}
	return resolution, nil
}

func (transaction *resourceGroupReplaceTransaction) Apply(
	ctx context.Context,
	change authority.GroupReplaceChange,
) (result authority.GroupReplaceResult, resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationResourceAuthorityApply, startedAt, resultErr)
	}()
	if ctx == nil || transaction == nil || !change.IsValid() {
		return authority.GroupReplaceResult{}, ErrResourceAuthorityState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != resourceAuthorityTransactionResolved ||
		!change.Resolution().Equal(transaction.resolution) ||
		change.Command().Scope() != transaction.scope {
		return authority.GroupReplaceResult{}, ErrResourceAuthorityState
	}
	result, err := transaction.applyLocked(ctx, change)
	if err != nil {
		return authority.GroupReplaceResult{}, errors.Join(
			ErrApplyResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	transaction.state = resourceAuthorityTransactionApplied
	return result, nil
}

func (transaction *resourceGroupReplaceTransaction) applyLocked(
	ctx context.Context,
	change authority.GroupReplaceChange,
) (authority.GroupReplaceResult, error) {
	if err := transaction.database.Exec(
		ctx, setResourceAuthorityChangeSQL, change.MutationIDs().ChangeID().String(),
	); err != nil {
		return authority.GroupReplaceResult{}, fmt.Errorf(
			"set Resource Group replacement change context: %w", err,
		)
	}
	command := change.Command()
	proposed := change.Resolution().Impact().ProposedRevision()
	semanticHash := proposed.SemanticHash().Bytes()
	members, err := encodeResourceGroupReplacementMembers(change)
	if err != nil {
		return authority.GroupReplaceResult{}, err
	}
	var networkRevision, groupRevision, groupVersion, definitionVersion int64
	var semanticHashValue []byte
	if err := transaction.database.QueryRow(
		ctx,
		replaceResourceGroupDefinitionSQL,
		command.GroupID().String(), command.ExpectedVersion(),
		change.MutationIDs().GroupVersionID().String(),
		command.AccountSession().PrincipalID().String(), semanticHash[:],
		change.OccurredAt(), members,
	).Scan(
		&networkRevision, &groupRevision, &groupVersion,
		&definitionVersion, &semanticHashValue,
	); err != nil {
		return authority.GroupReplaceResult{}, fmt.Errorf(
			"replace Resource Group definition: %w", err,
		)
	}
	committedHash, err := resourceSemanticHash(semanticHashValue)
	if err != nil || groupVersion != command.ExpectedVersion()+1 ||
		definitionVersion != proposed.DefinitionVersion() || committedHash != proposed.SemanticHash() ||
		networkRevision != transaction.resolution.NetworkRevision()+1 ||
		groupRevision != transaction.resolution.GroupRevision()+1 {
		return authority.GroupReplaceResult{}, ErrResourceAuthorityEvidence
	}
	result, err := authority.NewGroupReplaceResult(
		command.GroupID(), transaction.scope, definitionVersion, groupVersion,
		networkRevision, groupRevision, committedHash, command.ImpactHash(),
	)
	if err != nil {
		return authority.GroupReplaceResult{}, ErrResourceAuthorityEvidence
	}
	if err := transaction.appendGroupReplaceEvidence(ctx, change, result); err != nil {
		return authority.GroupReplaceResult{}, err
	}
	return result, nil
}

func (transaction *resourceGroupReplaceTransaction) Commit(ctx context.Context) (resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationResourceAuthorityCommit, startedAt, resultErr)
	}()
	if ctx == nil || transaction == nil {
		return ErrResourceAuthorityState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != resourceAuthorityTransactionApplied {
		return ErrResourceAuthorityState
	}
	transaction.state = resourceAuthorityTransactionClosed
	if err := transaction.database.Commit(ctx); err != nil {
		return errors.Join(ErrCommitResourceAuthority, classifyResourceAuthorityCommitError(ctx, err))
	}
	return nil
}

func (transaction *resourceGroupReplaceTransaction) Rollback(ctx context.Context) (resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationResourceAuthorityRollback, startedAt, resultErr)
	}()
	if ctx == nil || transaction == nil {
		return ErrResourceAuthorityState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil {
		return ErrResourceAuthorityState
	}
	if transaction.state == resourceAuthorityTransactionClosed {
		return nil
	}
	transaction.state = resourceAuthorityTransactionClosed
	if err := transaction.database.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return errors.Join(ErrRollbackResourceAuthority, err)
	}
	return nil
}

func (transaction *resourceGroupReplaceTransaction) observe(
	operation postgresOperation,
	startedAt time.Time,
	err error,
) {
	if transaction != nil {
		transaction.metrics.observeOperation(operation, time.Since(startedAt), err)
	}
}
