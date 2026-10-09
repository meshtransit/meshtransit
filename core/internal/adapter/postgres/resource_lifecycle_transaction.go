package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/core/internal/domain/authorization"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	authority "github.com/meshtransit/meshtransit/core/internal/domain/resource/authority"
)

type resourceLifecycleTransaction struct {
	mu sync.Mutex

	database      resourceAuthorityDatabaseTransaction
	scope         network.Scope
	metrics       *postgresPoolMetrics
	state         resourceAuthorityTransactionState
	resolution    authority.LifecycleResolution
	audit         resourceAuthorityAuditHead
	authorization resourceAuthorityAuthorizationEvidence
}

var _ authority.LifecycleTransaction = (*resourceLifecycleTransaction)(nil)

func (transaction *resourceLifecycleTransaction) Resolve(
	ctx context.Context,
	command authority.LifecycleCommand,
	ids authority.LifecycleMutationIDs,
	evaluatedAt, expiresAt time.Time,
) (resolution authority.LifecycleResolution, resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationResourceAuthorityResolve, startedAt, resultErr)
	}()
	if ctx == nil || transaction == nil || !command.IsValid() || !ids.IsValid() ||
		evaluatedAt.IsZero() || !expiresAt.After(evaluatedAt) {
		return authority.LifecycleResolution{}, ErrResourceAuthorityState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != resourceAuthorityTransactionOpen ||
		command.Scope() != transaction.scope {
		return authority.LifecycleResolution{}, ErrResourceAuthorityState
	}
	authorizationEvidence, err := transaction.resolveAuthorization(ctx, command, evaluatedAt)
	if err != nil {
		return authority.LifecycleResolution{}, errors.Join(
			ErrResolveResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	transaction.authorization = authorizationEvidence
	resolution, err = transaction.resolveLocked(ctx, command, ids, evaluatedAt, expiresAt)
	if err != nil {
		return authority.LifecycleResolution{}, errors.Join(
			ErrResolveResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	transaction.resolution = resolution
	transaction.state = resourceAuthorityTransactionResolved
	return resolution, nil
}

func (transaction *resourceLifecycleTransaction) resolveAuthorization(
	ctx context.Context,
	command authority.LifecycleCommand,
	evaluatedAt time.Time,
) (resourceAuthorityAuthorizationEvidence, error) {
	session := command.AccountSession()
	permission := authorization.PermissionResourceManage
	if command.Operation().IsGroup() {
		permission = authorization.PermissionResourceGroupManage
	}
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
		command.Scope().WorkspaceID().String(),
		command.Scope().NetworkID().String(),
		string(permission),
		evaluatedAt,
	).Scan(
		&bindingIDValue, &roleIDValue, &scopeGeneration, &membershipGeneration,
		&bindingGeneration, &roleGeneration, &hasExpiry, &expiresAt, &ownerGeneration,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return resourceAuthorityAuthorizationEvidence{}, authority.ErrForbidden
	}
	if err != nil {
		return resourceAuthorityAuthorizationEvidence{}, fmt.Errorf("authorize lifecycle mutation: %w", err)
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

func (transaction *resourceLifecycleTransaction) resolveLocked(
	ctx context.Context,
	command authority.LifecycleCommand,
	ids authority.LifecycleMutationIDs,
	evaluatedAt, expiresAt time.Time,
) (authority.LifecycleResolution, error) {
	requestHash, err := command.RequestHash()
	if err != nil {
		return authority.LifecycleResolution{}, authority.ErrInvalidLifecycleCommand
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
			resourceLifecycleOperation(command),
			proof.DigestKeyID(),
			digest[:],
			hashBytes[:],
			evaluatedAt,
			expiresAt,
		),
		true,
	)
	if err != nil {
		return authority.LifecycleResolution{}, fmt.Errorf("claim lifecycle idempotency: %w", err)
	}
	idempotencyResolution, err := resolveResourceLifecycleIdempotency(
		record, command, ids, evaluatedAt,
	)
	if err != nil {
		return authority.LifecycleResolution{}, err
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
		return authority.LifecycleResolution{}, fmt.Errorf("lock Network revision: %w", err)
	}
	if policyRevision <= 0 || dnsRevision <= 0 || routeRevision <= 0 ||
		sharingRevision <= 0 || isolationGeneration <= 0 {
		return authority.LifecycleResolution{}, ErrResourceAuthorityEvidence
	}
	var previousHash []byte
	if err := transaction.database.QueryRow(ctx, lockResourceAuthorityAuditStreamSQL).Scan(
		&transaction.audit.streamInternalID,
		&transaction.audit.nextSequence,
		&previousHash,
	); err != nil {
		return authority.LifecycleResolution{}, fmt.Errorf("lock audit stream: %w", err)
	}
	if transaction.audit.streamInternalID <= 0 || transaction.audit.nextSequence <= 0 ||
		len(previousHash) != len(transaction.audit.previousHash) {
		return authority.LifecycleResolution{}, ErrResourceAuthorityEvidence
	}
	copy(transaction.audit.previousHash[:], previousHash)
	recordID, err := publicid.Parse(record.publicID)
	if err != nil {
		return authority.LifecycleResolution{}, ErrResourceAuthorityEvidence
	}
	resolution, err := authority.NewLifecycleResolution(
		transaction.scope, networkRevision, inventoryRevision, groupRevision,
		recordID, requestHash,
	)
	if err != nil {
		return authority.LifecycleResolution{}, ErrResourceAuthorityEvidence
	}
	return resolution, nil
}

func (transaction *resourceLifecycleTransaction) Apply(
	ctx context.Context,
	change authority.LifecycleChange,
) (result authority.LifecycleResult, resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationResourceAuthorityApply, startedAt, resultErr)
	}()
	if ctx == nil || transaction == nil || !change.IsValid() {
		return authority.LifecycleResult{}, ErrResourceAuthorityState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != resourceAuthorityTransactionResolved ||
		change.Resolution() != transaction.resolution || change.Command().Scope() != transaction.scope {
		return authority.LifecycleResult{}, ErrResourceAuthorityState
	}
	result, err := transaction.applyLocked(ctx, change)
	if err != nil {
		return authority.LifecycleResult{}, errors.Join(
			ErrApplyResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	transaction.state = resourceAuthorityTransactionApplied
	return result, nil
}

func (transaction *resourceLifecycleTransaction) applyLocked(
	ctx context.Context,
	change authority.LifecycleChange,
) (authority.LifecycleResult, error) {
	if err := transaction.database.Exec(
		ctx, setResourceAuthorityChangeSQL, change.MutationIDs().ChangeID().String(),
	); err != nil {
		return authority.LifecycleResult{}, fmt.Errorf("set lifecycle change context: %w", err)
	}
	command := change.Command()
	query := transitionResourceLifecycleSQL
	if command.Operation().IsGroup() {
		query = transitionResourceGroupLifecycleSQL
	}
	var networkRevision, subsystemRevision, aggregateVersion int64
	var stateValue string
	var semanticHashValue []byte
	if err := transaction.database.QueryRow(
		ctx,
		query,
		command.AggregateID().String(),
		command.ExpectedVersion(),
		resourceLifecycleState(command.Operation().TargetState()),
		command.AccountSession().PrincipalID().String(),
		change.OccurredAt(),
	).Scan(
		&networkRevision, &subsystemRevision, &aggregateVersion, &stateValue, &semanticHashValue,
	); err != nil {
		return authority.LifecycleResult{}, fmt.Errorf("transition lifecycle state: %w", err)
	}
	state := parseResourceLifecycleState(stateValue)
	semanticHash, err := resourceSemanticHash(semanticHashValue)
	if err != nil || state != command.Operation().TargetState() ||
		aggregateVersion != command.ExpectedVersion()+1 ||
		networkRevision != transaction.resolution.NetworkRevision()+1 {
		return authority.LifecycleResult{}, ErrResourceAuthorityEvidence
	}
	expectedSubsystemRevision := transaction.resolution.InventoryRevision() + 1
	if command.Operation().IsGroup() {
		expectedSubsystemRevision = transaction.resolution.GroupRevision() + 1
	}
	if subsystemRevision != expectedSubsystemRevision {
		return authority.LifecycleResult{}, ErrResourceAuthorityEvidence
	}
	result, err := authority.NewLifecycleResult(
		command.Operation(), command.ResourceID(), command.GroupID(), transaction.scope,
		state, aggregateVersion, networkRevision, subsystemRevision, semanticHash,
	)
	if err != nil {
		return authority.LifecycleResult{}, ErrResourceAuthorityEvidence
	}
	if err := transaction.appendLifecycleEvidence(ctx, change, result); err != nil {
		return authority.LifecycleResult{}, err
	}
	return result, nil
}

func (transaction *resourceLifecycleTransaction) Commit(ctx context.Context) (resultErr error) {
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

func (transaction *resourceLifecycleTransaction) Rollback(ctx context.Context) (resultErr error) {
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

func (transaction *resourceLifecycleTransaction) observe(
	operation postgresOperation,
	startedAt time.Time,
	err error,
) {
	if transaction != nil {
		transaction.metrics.observeOperation(operation, time.Since(startedAt), err)
	}
}
