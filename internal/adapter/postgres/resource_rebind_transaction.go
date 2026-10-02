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
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/resource"
	authority "github.com/meshtransit/meshtransit/internal/resource/authority"
)

type resourceRebindTransaction struct {
	mu sync.Mutex

	database      resourceAuthorityDatabaseTransaction
	scope         network.Scope
	metrics       *postgresPoolMetrics
	state         resourceAuthorityTransactionState
	resolution    authority.RebindResolution
	audit         resourceAuthorityAuditHead
	authorization resourceAuthorityAuthorizationEvidence
}

var _ authority.RebindTransaction = (*resourceRebindTransaction)(nil)

func (transaction *resourceRebindTransaction) authorize(
	ctx context.Context,
	session accountsession.Session,
	evaluatedAt time.Time,
) (resourceAuthorityAuthorizationEvidence, error) {
	var bindingIDValue, roleIDValue string
	var scopeGeneration, membershipGeneration, bindingGeneration, roleGeneration int64
	var ownerGeneration int64
	var hasExpiry bool
	var expiresAt time.Time
	err := transaction.database.QueryRow(
		ctx,
		authorizeResourceAuthoritySQL,
		session.ID().String(),
		session.DeploymentID().String(),
		session.PrincipalID().String(),
		session.IdentitySubjectID().String(),
		session.Version(),
		session.PrincipalAuthorityGeneration(),
		session.AccountSessionGeneration(),
		session.ProviderGeneration(),
		session.DeploymentRecoveryEpoch(),
		transaction.scope.WorkspaceID().String(),
		transaction.scope.NetworkID().String(),
		string(authorization.PermissionResourceManage),
		evaluatedAt,
	).Scan(
		&bindingIDValue, &roleIDValue, &scopeGeneration, &membershipGeneration,
		&bindingGeneration, &roleGeneration, &hasExpiry, &expiresAt, &ownerGeneration,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return resourceAuthorityAuthorizationEvidence{}, authority.ErrForbidden
	}
	if err != nil {
		return resourceAuthorityAuthorizationEvidence{}, fmt.Errorf("authorize Resource rebind: %w", err)
	}
	if hasExpiry && !expiresAt.After(evaluatedAt) {
		return resourceAuthorityAuthorizationEvidence{}, authority.ErrForbidden
	}
	bindingID, roleID, err := parseNetworkPermissionAuthority(bindingIDValue, roleIDValue, ownerGeneration)
	if err != nil {
		return resourceAuthorityAuthorizationEvidence{}, ErrResourceAuthorityEvidence
	}
	evidence := resourceAuthorityAuthorizationEvidence{
		accountSessionID: publicid.ID(session.ID()), roleBindingID: bindingID,
		roleDefinitionID: roleID, scopeAuthorityGeneration: scopeGeneration,
		membershipAuthorityGeneration:     membershipGeneration,
		bindingAuthorityGeneration:        bindingGeneration,
		roleAuthorityGeneration:           roleGeneration,
		workspaceOwnerAuthorityGeneration: ownerGeneration,
	}
	if !evidence.isValid() {
		return resourceAuthorityAuthorizationEvidence{}, ErrResourceAuthorityEvidence
	}
	return evidence, nil
}

func scanResourceRebindImpact(
	row resourceAuthorityRow,
	preview authority.RebindPreview,
) (authority.RebindImpact, error) {
	var displayNameValue, ownerIDValue, custodianIDValue, stateValue string
	var currentDeviceIDValue, proposedDeviceIDValue, proposedDeviceState string
	var version, targetGeneration int64
	var currentSemanticHashValue, affectedGroupsValue []byte
	var alreadyBound, approvalRequired bool
	if err := row.Scan(
		&displayNameValue, &ownerIDValue, &custodianIDValue, &stateValue,
		&version, &targetGeneration, &currentSemanticHashValue, &currentDeviceIDValue,
		&proposedDeviceIDValue, &proposedDeviceState, &alreadyBound,
		&affectedGroupsValue, &approvalRequired,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return authority.RebindImpact{}, authority.ErrRebindNotFound
		}
		return authority.RebindImpact{}, err
	}
	if version != preview.ExpectedVersion() {
		return authority.RebindImpact{}, authority.ErrRebindVersionConflict
	}
	if stateValue == "deleted" || proposedDeviceState != "active" {
		return authority.RebindImpact{}, authority.ErrRebindStateConflict
	}
	if targetGeneration <= 0 || targetGeneration == math.MaxInt64 {
		return authority.RebindImpact{}, ErrResourceAuthorityEvidence
	}
	currentDeviceID, err := node.ParseID(currentDeviceIDValue)
	if err != nil {
		return authority.RebindImpact{}, ErrResourceAuthorityEvidence
	}
	proposedDeviceID, err := node.ParseID(proposedDeviceIDValue)
	if err != nil || proposedDeviceID != preview.DeviceID() {
		return authority.RebindImpact{}, ErrResourceAuthorityEvidence
	}
	if currentDeviceID == proposedDeviceID || alreadyBound {
		return authority.RebindImpact{}, authority.ErrRebindTargetConflict
	}
	displayName, err := resource.ParseDisplayName(displayNameValue)
	if err != nil {
		return authority.RebindImpact{}, ErrResourceAuthorityEvidence
	}
	ownerID, err := identity.ParsePrincipalID(ownerIDValue)
	if err != nil {
		return authority.RebindImpact{}, ErrResourceAuthorityEvidence
	}
	custodianID, err := identity.ParsePrincipalID(custodianIDValue)
	if err != nil {
		return authority.RebindImpact{}, ErrResourceAuthorityEvidence
	}
	currentSemanticHash, err := resourceSemanticHash(currentSemanticHashValue)
	if err != nil {
		return authority.RebindImpact{}, ErrResourceAuthorityEvidence
	}
	currentRevision, err := resource.NewDeviceRevision(resource.DeviceRevisionParams{
		Scope: preview.Scope(), DisplayName: displayName,
		OwnerPrincipalID: ownerID, CustodianPrincipalID: custodianID,
		DeviceID: currentDeviceID, TargetGeneration: targetGeneration,
	})
	if err != nil || currentRevision.SemanticHash() != currentSemanticHash {
		return authority.RebindImpact{}, ErrResourceAuthorityEvidence
	}
	revision, err := resource.NewDeviceRevision(resource.DeviceRevisionParams{
		Scope: preview.Scope(), DisplayName: displayName,
		OwnerPrincipalID: ownerID, CustodianPrincipalID: custodianID,
		DeviceID: proposedDeviceID, TargetGeneration: targetGeneration + 1,
	})
	if err != nil {
		return authority.RebindImpact{}, ErrResourceAuthorityEvidence
	}
	groupIDs, err := parseRebindAffectedGroups(affectedGroupsValue)
	if err != nil {
		return authority.RebindImpact{}, err
	}
	impact, err := authority.NewRebindImpact(authority.RebindImpactParams{
		ResourceID: preview.ResourceID(), ExpectedVersion: preview.ExpectedVersion(),
		CurrentDeviceID: currentDeviceID, CurrentTargetGeneration: targetGeneration,
		CurrentSemanticHash: currentSemanticHash,
		ProposedRevision:    revision, AffectedGroupIDs: groupIDs,
		ApprovalRequired: approvalRequired,
	})
	if err != nil {
		return authority.RebindImpact{}, ErrResourceAuthorityEvidence
	}
	return impact, nil
}

func (transaction *resourceRebindTransaction) Resolve(
	ctx context.Context,
	command authority.RebindCommand,
	ids authority.RebindMutationIDs,
	evaluatedAt, expiresAt time.Time,
) (resolution authority.RebindResolution, resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationResourceAuthorityResolve, startedAt, resultErr)
	}()
	if ctx == nil || transaction == nil || !command.IsValid() || !ids.IsValid() ||
		evaluatedAt.IsZero() || !expiresAt.After(evaluatedAt) {
		return authority.RebindResolution{}, ErrResourceAuthorityState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != resourceAuthorityTransactionOpen ||
		command.Scope() != transaction.scope {
		return authority.RebindResolution{}, ErrResourceAuthorityState
	}
	authorizationEvidence, err := transaction.authorize(ctx, command.AccountSession(), evaluatedAt)
	if err != nil {
		return authority.RebindResolution{}, errors.Join(
			ErrResolveResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	transaction.authorization = authorizationEvidence
	resolution, err = transaction.resolveLocked(ctx, command, ids, evaluatedAt, expiresAt)
	if err != nil {
		return authority.RebindResolution{}, errors.Join(
			ErrResolveResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	transaction.resolution = resolution
	transaction.state = resourceAuthorityTransactionResolved
	return resolution, nil
}

func (transaction *resourceRebindTransaction) resolveLocked(
	ctx context.Context,
	command authority.RebindCommand,
	ids authority.RebindMutationIDs,
	evaluatedAt, expiresAt time.Time,
) (authority.RebindResolution, error) {
	requestHash, err := command.RequestHash()
	if err != nil {
		return authority.RebindResolution{}, authority.ErrInvalidRebindCommand
	}
	proof := command.IdempotencyEvidence()
	digest := proof.Digest()
	hashBytes := requestHash.Bytes()
	record, err := scanResourceAuthorityIdempotencyRecord(
		transaction.database.QueryRow(
			ctx,
			claimResourceAuthorityIdempotencySQL,
			ids.IdempotencyRecordID().String(),
			command.AccountSession().PrincipalID().String(),
			"resource.rebind",
			proof.DigestKeyID(),
			digest[:],
			hashBytes[:],
			evaluatedAt,
			expiresAt,
		),
		true,
	)
	if err != nil {
		return authority.RebindResolution{}, fmt.Errorf("claim rebind idempotency: %w", err)
	}
	idempotencyResolution, err := resolveResourceRebindIdempotency(
		record, command, ids, evaluatedAt,
	)
	if err != nil {
		return authority.RebindResolution{}, err
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
		return authority.RebindResolution{}, fmt.Errorf("lock Network revision: %w", err)
	}
	if policyRevision <= 0 || dnsRevision <= 0 || routeRevision <= 0 ||
		sharingRevision <= 0 || isolationGeneration <= 0 {
		return authority.RebindResolution{}, ErrResourceAuthorityEvidence
	}
	var previousHash []byte
	if err := transaction.database.QueryRow(ctx, lockResourceAuthorityAuditStreamSQL).Scan(
		&transaction.audit.streamInternalID,
		&transaction.audit.nextSequence,
		&previousHash,
	); err != nil {
		return authority.RebindResolution{}, fmt.Errorf("lock audit stream: %w", err)
	}
	if transaction.audit.streamInternalID <= 0 || transaction.audit.nextSequence <= 0 ||
		len(previousHash) != len(transaction.audit.previousHash) {
		return authority.RebindResolution{}, ErrResourceAuthorityEvidence
	}
	copy(transaction.audit.previousHash[:], previousHash)
	impact, err := scanResourceRebindImpact(
		transaction.database.QueryRow(
			ctx, lockResourceRebindImpactSQL,
			command.ResourceID().String(), command.DeviceID().String(),
		),
		command.Preview(),
	)
	if err != nil {
		return authority.RebindResolution{}, err
	}
	if impact.Hash() != command.ImpactHash() {
		return authority.RebindResolution{}, authority.ErrRebindImpactChanged
	}
	if impact.ApprovalRequired() {
		return authority.RebindResolution{}, authority.ErrRebindApprovalRequired
	}
	recordID, err := publicid.Parse(record.publicID)
	if err != nil {
		return authority.RebindResolution{}, ErrResourceAuthorityEvidence
	}
	resolution, err := authority.NewRebindResolution(
		transaction.scope, networkRevision, inventoryRevision, groupRevision,
		recordID, requestHash, impact,
	)
	if err != nil {
		return authority.RebindResolution{}, ErrResourceAuthorityEvidence
	}
	return resolution, nil
}

func (transaction *resourceRebindTransaction) Apply(
	ctx context.Context,
	change authority.RebindChange,
) (result authority.RebindResult, resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationResourceAuthorityApply, startedAt, resultErr)
	}()
	if ctx == nil || transaction == nil || !change.IsValid() {
		return authority.RebindResult{}, ErrResourceAuthorityState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != resourceAuthorityTransactionResolved ||
		!change.Resolution().Equal(transaction.resolution) || change.Command().Scope() != transaction.scope {
		return authority.RebindResult{}, ErrResourceAuthorityState
	}
	result, err := transaction.applyLocked(ctx, change)
	if err != nil {
		return authority.RebindResult{}, errors.Join(
			ErrApplyResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	transaction.state = resourceAuthorityTransactionApplied
	return result, nil
}

func (transaction *resourceRebindTransaction) applyLocked(
	ctx context.Context,
	change authority.RebindChange,
) (authority.RebindResult, error) {
	if err := transaction.database.Exec(
		ctx, setResourceAuthorityChangeSQL, change.MutationIDs().ChangeID().String(),
	); err != nil {
		return authority.RebindResult{}, fmt.Errorf("set rebind change context: %w", err)
	}
	command := change.Command()
	impact := change.Resolution().Impact()
	proposed := impact.ProposedRevision()
	semanticHash := proposed.SemanticHash().Bytes()
	var networkRevision, inventoryRevision, resourceVersion, targetGeneration int64
	var semanticHashValue []byte
	if err := transaction.database.QueryRow(
		ctx,
		rebindDeviceResourceSQL,
		command.ResourceID().String(),
		command.ExpectedVersion(),
		change.MutationIDs().TargetID().String(),
		command.DeviceID().String(),
		command.AccountSession().PrincipalID().String(),
		semanticHash[:],
		change.OccurredAt(),
	).Scan(
		&networkRevision, &inventoryRevision, &resourceVersion,
		&targetGeneration, &semanticHashValue,
	); err != nil {
		return authority.RebindResult{}, fmt.Errorf("replace Device target: %w", err)
	}
	committedHash, err := resourceSemanticHash(semanticHashValue)
	if err != nil || resourceVersion != command.ExpectedVersion()+1 ||
		targetGeneration != proposed.TargetGeneration() || committedHash != proposed.SemanticHash() ||
		networkRevision != transaction.resolution.NetworkRevision()+1 ||
		inventoryRevision != transaction.resolution.InventoryRevision()+1 {
		return authority.RebindResult{}, ErrResourceAuthorityEvidence
	}
	result, err := authority.NewRebindResult(
		command.ResourceID(), transaction.scope, command.DeviceID(), targetGeneration,
		resourceVersion, networkRevision, inventoryRevision, committedHash, command.ImpactHash(),
	)
	if err != nil {
		return authority.RebindResult{}, ErrResourceAuthorityEvidence
	}
	if err := transaction.appendRebindEvidence(ctx, change, result); err != nil {
		return authority.RebindResult{}, err
	}
	return result, nil
}

func (transaction *resourceRebindTransaction) Commit(ctx context.Context) (resultErr error) {
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

func (transaction *resourceRebindTransaction) Rollback(ctx context.Context) (resultErr error) {
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

func (transaction *resourceRebindTransaction) observe(
	operation postgresOperation,
	startedAt time.Time,
	err error,
) {
	if transaction != nil {
		transaction.metrics.observeOperation(operation, time.Since(startedAt), err)
	}
}
