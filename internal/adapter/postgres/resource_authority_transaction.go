package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/authorization"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/publicid"
	authority "github.com/meshtransit/meshtransit/internal/resource/authority"
)

type resourceAuthorityTransactionState uint8

const (
	resourceAuthorityTransactionOpen resourceAuthorityTransactionState = iota
	resourceAuthorityTransactionResolved
	resourceAuthorityTransactionApplied
	resourceAuthorityTransactionClosed
)

type resourceAuthorityAuditHead struct {
	streamInternalID int64
	nextSequence     int64
	previousHash     [32]byte
}

type resourceAuthorityAuthorizationEvidence struct {
	accountSessionID                  publicid.ID
	roleBindingID                     publicid.ID
	roleDefinitionID                  publicid.ID
	scopeAuthorityGeneration          int64
	membershipAuthorityGeneration     int64
	bindingAuthorityGeneration        int64
	roleAuthorityGeneration           int64
	workspaceOwnerAuthorityGeneration int64
}

func (evidence resourceAuthorityAuthorizationEvidence) isValid() bool {
	return evidence.accountSessionID.IsValid() && evidence.scopeAuthorityGeneration > 0 &&
		evidence.membershipAuthorityGeneration > 0 && validNetworkPermissionAuthority(
		evidence.roleBindingID, evidence.roleDefinitionID,
		evidence.bindingAuthorityGeneration, evidence.roleAuthorityGeneration,
		evidence.workspaceOwnerAuthorityGeneration,
	)
}

type resourceAuthorityTransaction struct {
	mu sync.Mutex

	database      resourceAuthorityDatabaseTransaction
	scope         network.Scope
	metrics       *postgresPoolMetrics
	state         resourceAuthorityTransactionState
	resolution    authority.Resolution
	audit         resourceAuthorityAuditHead
	authorization resourceAuthorityAuthorizationEvidence
}

var _ authority.Transaction = (*resourceAuthorityTransaction)(nil)

func (transaction *resourceAuthorityTransaction) Resolve(
	ctx context.Context,
	command authority.Command,
	ids authority.MutationIDs,
	evaluatedAt time.Time,
	expiresAt time.Time,
) (resolution authority.Resolution, resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationResourceAuthorityResolve, startedAt, resultErr)
	}()
	if ctx == nil || transaction == nil || !command.IsValid() || !ids.IsValidFor(command) ||
		evaluatedAt.IsZero() || !expiresAt.After(evaluatedAt) {
		return authority.Resolution{}, ErrResourceAuthorityState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != resourceAuthorityTransactionOpen ||
		command.Scope() != transaction.scope {
		return authority.Resolution{}, ErrResourceAuthorityState
	}
	authorizationEvidence, err := transaction.resolveAuthorization(ctx, command, evaluatedAt)
	if err != nil {
		return authority.Resolution{}, errors.Join(
			ErrResolveResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	transaction.authorization = authorizationEvidence
	resolution, err = transaction.resolveLocked(ctx, command, ids, evaluatedAt, expiresAt)
	if err != nil {
		return authority.Resolution{}, errors.Join(
			ErrResolveResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	transaction.resolution = resolution
	transaction.state = resourceAuthorityTransactionResolved
	return resolution, nil
}

func (transaction *resourceAuthorityTransaction) resolveAuthorization(
	ctx context.Context,
	command authority.Command,
	evaluatedAt time.Time,
) (resourceAuthorityAuthorizationEvidence, error) {
	session := command.AccountSession()
	permission := authorization.PermissionResourceManage
	if command.Operation() == authority.OperationCreateGroup {
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
		return resourceAuthorityAuthorizationEvidence{}, fmt.Errorf("authorize Resource mutation: %w", err)
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
		membershipAuthorityGeneration: membershipGeneration,
		bindingAuthorityGeneration:    bindingGeneration, roleAuthorityGeneration: roleGeneration,
		workspaceOwnerAuthorityGeneration: ownerGeneration,
	}
	if !evidence.isValid() {
		return resourceAuthorityAuthorizationEvidence{}, ErrResourceAuthorityEvidence
	}
	return evidence, nil
}

func (transaction *resourceAuthorityTransaction) resolveLocked(
	ctx context.Context,
	command authority.Command,
	ids authority.MutationIDs,
	evaluatedAt time.Time,
	expiresAt time.Time,
) (authority.Resolution, error) {
	requestHash, err := command.RequestHash()
	if err != nil {
		return authority.Resolution{}, authority.ErrInvalidCommand
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
			resourceAuthorityOperation(command),
			proof.DigestKeyID(),
			digest[:],
			hashBytes[:],
			evaluatedAt,
			expiresAt,
		),
		true,
	)
	if err != nil {
		return authority.Resolution{}, fmt.Errorf("claim idempotency evidence: %w", err)
	}
	idempotencyResolution, err := resolveResourceAuthorityIdempotency(
		record, command, ids, evaluatedAt,
	)
	if err != nil {
		return authority.Resolution{}, err
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
		return authority.Resolution{}, fmt.Errorf("lock Network revision: %w", err)
	}
	if policyRevision <= 0 || dnsRevision <= 0 || routeRevision <= 0 ||
		sharingRevision <= 0 || isolationGeneration <= 0 {
		return authority.Resolution{}, ErrResourceAuthorityEvidence
	}
	var previousHash []byte
	if err := transaction.database.QueryRow(ctx, lockResourceAuthorityAuditStreamSQL).Scan(
		&transaction.audit.streamInternalID,
		&transaction.audit.nextSequence,
		&previousHash,
	); err != nil {
		return authority.Resolution{}, fmt.Errorf("lock audit stream: %w", err)
	}
	if transaction.audit.streamInternalID <= 0 || transaction.audit.nextSequence <= 0 ||
		len(previousHash) != len(transaction.audit.previousHash) {
		return authority.Resolution{}, ErrResourceAuthorityEvidence
	}
	copy(transaction.audit.previousHash[:], previousHash)
	recordID, err := publicid.Parse(record.publicID)
	if err != nil {
		return authority.Resolution{}, ErrResourceAuthorityEvidence
	}
	resolution, err := authority.NewResolution(
		transaction.scope, networkRevision, inventoryRevision, groupRevision,
		recordID, requestHash,
	)
	if err != nil {
		return authority.Resolution{}, ErrResourceAuthorityEvidence
	}
	return resolution, nil
}

func (transaction *resourceAuthorityTransaction) Apply(
	ctx context.Context,
	change authority.Change,
) (result authority.Result, resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationResourceAuthorityApply, startedAt, resultErr)
	}()
	if ctx == nil || transaction == nil || !change.IsValid() {
		return authority.Result{}, ErrResourceAuthorityState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != resourceAuthorityTransactionResolved ||
		change.Resolution() != transaction.resolution || change.Command().Scope() != transaction.scope {
		return authority.Result{}, ErrResourceAuthorityState
	}
	result, err := transaction.applyLocked(ctx, change)
	if err != nil {
		return authority.Result{}, errors.Join(
			ErrApplyResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	transaction.state = resourceAuthorityTransactionApplied
	return result, nil
}

func (transaction *resourceAuthorityTransaction) applyLocked(
	ctx context.Context,
	change authority.Change,
) (authority.Result, error) {
	if err := transaction.database.Exec(
		ctx, setResourceAuthorityChangeSQL, change.MutationIDs().ChangeID().String(),
	); err != nil {
		return authority.Result{}, fmt.Errorf("set authority change context: %w", err)
	}
	command := change.Command()
	semanticHash := command.SemanticHash().Bytes()
	var networkRevision, subsystemRevision, aggregateVersion, definitionOrGeneration int64
	if command.Operation() == authority.OperationCreateDevice {
		projectionIDs := change.MutationIDs().ProjectionIDs()
		definition := command.Device()
		if err := transaction.database.QueryRow(
			ctx,
			createDeviceResourceSQL,
			change.MutationIDs().ResourceID().String(),
			projectionIDs[0].String(),
			command.ExpectedSubsystemRevision(),
			definition.DeviceID().String(),
			command.AccountSession().PrincipalID().String(),
			definition.DisplayName().String(),
			semanticHash[:],
			change.OccurredAt(),
		).Scan(
			&networkRevision, &subsystemRevision, &aggregateVersion, &definitionOrGeneration,
		); err != nil {
			return authority.Result{}, fmt.Errorf("create Device Resource: %w", err)
		}
	} else {
		members, err := encodeResourceGroupMembers(change)
		if err != nil {
			return authority.Result{}, err
		}
		projectionIDs := change.MutationIDs().ProjectionIDs()
		definition := command.Group()
		if err := transaction.database.QueryRow(
			ctx,
			createResourceGroupSQL,
			change.MutationIDs().GroupID().String(),
			projectionIDs[0].String(),
			command.ExpectedSubsystemRevision(),
			command.AccountSession().PrincipalID().String(),
			definition.DisplayName().String(),
			semanticHash[:],
			change.OccurredAt(),
			members,
		).Scan(
			&networkRevision, &subsystemRevision, &aggregateVersion, &definitionOrGeneration,
		); err != nil {
			return authority.Result{}, fmt.Errorf("create Resource Group: %w", err)
		}
	}
	if networkRevision != transaction.resolution.NetworkRevision()+1 ||
		subsystemRevision != command.ExpectedSubsystemRevision()+1 ||
		aggregateVersion != 1 || definitionOrGeneration != 1 {
		return authority.Result{}, ErrResourceAuthorityEvidence
	}
	if err := transaction.appendEvidence(
		ctx, change, aggregateVersion, networkRevision, subsystemRevision,
	); err != nil {
		return authority.Result{}, err
	}
	result, err := authority.NewResult(
		command.Operation(), change.MutationIDs().ResourceID(), change.MutationIDs().GroupID(),
		transaction.scope, networkRevision, subsystemRevision, aggregateVersion,
		command.SemanticHash(),
	)
	if err != nil {
		return authority.Result{}, ErrResourceAuthorityEvidence
	}
	return result, nil
}

func (transaction *resourceAuthorityTransaction) Commit(ctx context.Context) (resultErr error) {
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

func (transaction *resourceAuthorityTransaction) Rollback(ctx context.Context) (resultErr error) {
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

func (transaction *resourceAuthorityTransaction) observe(
	operation postgresOperation,
	startedAt time.Time,
	err error,
) {
	if transaction != nil {
		transaction.metrics.observeOperation(operation, time.Since(startedAt), err)
	}
}
