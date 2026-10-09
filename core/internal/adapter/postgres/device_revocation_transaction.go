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
	"github.com/meshtransit/meshtransit/core/internal/domain/node/revocation"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

type deviceRevocationTransactionState uint8

const (
	deviceRevocationTransactionOpen deviceRevocationTransactionState = iota
	deviceRevocationTransactionResolved
	deviceRevocationTransactionApplied
	deviceRevocationTransactionClosed
)

type deviceRevocationAuditHead struct {
	streamInternalID int64
	nextSequence     int64
	previousHash     [32]byte
}

type deviceRevocationLockedIDs struct {
	deviceInternalID     int64
	machineKeyInternalID int64
	nodeKeyInternalID    int64
}

type deviceRevocationTransaction struct {
	mu sync.Mutex

	database            deviceRevocationDatabaseTransaction
	scope               network.Scope
	workspaceInternalID int64
	networkInternalID   int64
	metrics             *postgresPoolMetrics
	state               deviceRevocationTransactionState
	resolution          revocation.Resolution
	locked              deviceRevocationLockedIDs
	audit               deviceRevocationAuditHead
}

var _ revocation.Transaction = (*deviceRevocationTransaction)(nil)

func (transaction *deviceRevocationTransaction) Resolve(
	ctx context.Context,
	command revocation.Command,
	attempt revocation.Attempt,
) (resolution revocation.Resolution, resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationDeviceRevocationResolve, startedAt, resultErr)
	}()

	if ctx == nil || transaction == nil || !command.IsValid() || !attempt.IsValid() {
		return revocation.Resolution{}, ErrDeviceRevocationState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != deviceRevocationTransactionOpen ||
		command.Scope() != transaction.scope || transaction.workspaceInternalID <= 0 ||
		transaction.networkInternalID <= 0 {
		return revocation.Resolution{}, ErrDeviceRevocationState
	}

	resolution, err := transaction.resolveLocked(ctx, command, attempt)
	if err != nil {
		return revocation.Resolution{}, errors.Join(
			ErrResolveDeviceRevocation,
			classifyDeviceRevocationDatabaseError(ctx, err),
		)
	}
	transaction.resolution = resolution
	transaction.state = deviceRevocationTransactionResolved
	return resolution, nil
}

func (transaction *deviceRevocationTransaction) resolveLocked(
	ctx context.Context,
	command revocation.Command,
	attempt revocation.Attempt,
) (revocation.Resolution, error) {
	requestHash, err := command.RequestHash()
	if err != nil {
		return revocation.Resolution{}, revocation.ErrInvalidCommand
	}
	authorizationEvidence, err := resolveDeviceRevocationAuthorization(
		ctx,
		transaction.database,
		command,
		attempt.OccurredAt(),
	)
	if err != nil {
		return revocation.Resolution{}, err
	}
	proof := command.IdempotencyEvidence()
	digest := proof.Digest()
	hashBytes := requestHash.Bytes()
	record, err := scanDeviceRevocationIdempotencyRecord(
		transaction.database.QueryRow(
			ctx,
			claimDeviceRevocationIdempotencySQL,
			attempt.MutationIDs().IdempotencyRecordID().String(),
			command.ActorPrincipalID().String(),
			deviceRevocationOperation,
			proof.DigestKeyID(),
			digest[:],
			hashBytes[:],
			attempt.OccurredAt(),
			attempt.ExpiresAt(),
		),
		true,
	)
	if err != nil {
		return revocation.Resolution{}, fmt.Errorf("claim idempotency evidence: %w", err)
	}
	idempotencyResolution, err := resolveDeviceRevocationIdempotency(record, command, attempt)
	if err != nil {
		return revocation.Resolution{}, err
	}
	if idempotencyResolution.IsValid() {
		return idempotencyResolution, nil
	}

	var networkRevision, inventoryRevision, groupRevision, policyRevision int64
	var dnsRevision, routeRevision, sharingRevision, isolationGeneration int64
	if err := transaction.database.QueryRow(ctx, lockDeviceRevocationRevisionSQL).Scan(
		&networkRevision,
		&inventoryRevision,
		&groupRevision,
		&policyRevision,
		&dnsRevision,
		&routeRevision,
		&sharingRevision,
		&isolationGeneration,
	); err != nil {
		return revocation.Resolution{}, fmt.Errorf("lock Network revision: %w", err)
	}
	if networkRevision <= 0 || inventoryRevision <= 0 || groupRevision <= 0 || policyRevision <= 0 ||
		dnsRevision <= 0 || routeRevision <= 0 || sharingRevision <= 0 || isolationGeneration <= 0 {
		return revocation.Resolution{}, ErrDeviceRevocationEvidence
	}

	var deviceVersion, sessionGeneration, machineEpoch, machineVersion int64
	var nodeEpoch, nodeVersion int64
	var deviceStateValue, machineStateValue, nodeStateValue string
	var machineValidFrom, nodeValidFrom time.Time
	if err := transaction.database.QueryRow(
		ctx,
		lockDeviceRevocationTargetSQL,
		transaction.workspaceInternalID,
		transaction.networkInternalID,
		command.NodeID().String(),
	).Scan(
		&transaction.locked.deviceInternalID,
		&deviceVersion,
		&sessionGeneration,
		&deviceStateValue,
		&machineEpoch,
		&transaction.locked.machineKeyInternalID,
		&machineVersion,
		&machineStateValue,
		&machineValidFrom,
		&nodeEpoch,
		&transaction.locked.nodeKeyInternalID,
		&nodeVersion,
		&nodeStateValue,
		&nodeValidFrom,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return revocation.Resolution{}, revocation.ErrNotFound
		}
		return revocation.Resolution{}, fmt.Errorf("lock Device and current key epochs: %w", err)
	}
	if transaction.locked.deviceInternalID <= 0 || transaction.locked.machineKeyInternalID <= 0 ||
		transaction.locked.nodeKeyInternalID <= 0 {
		return revocation.Resolution{}, ErrDeviceRevocationEvidence
	}
	deviceState, err := deviceRevocationState(deviceStateValue)
	if err != nil {
		return revocation.Resolution{}, err
	}
	machineState, err := deviceRevocationKeyState(machineStateValue)
	if err != nil {
		return revocation.Resolution{}, err
	}
	nodeState, err := deviceRevocationKeyState(nodeStateValue)
	if err != nil {
		return revocation.Resolution{}, err
	}

	var previousHash []byte
	if err := transaction.database.QueryRow(ctx, lockDeviceRevocationAuditStreamSQL).Scan(
		&transaction.audit.streamInternalID,
		&transaction.audit.nextSequence,
		&previousHash,
	); err != nil {
		return revocation.Resolution{}, fmt.Errorf("lock audit stream: %w", err)
	}
	if transaction.audit.streamInternalID <= 0 || transaction.audit.nextSequence <= 0 ||
		len(previousHash) != len(transaction.audit.previousHash) {
		return revocation.Resolution{}, ErrDeviceRevocationEvidence
	}
	copy(transaction.audit.previousHash[:], previousHash)

	recordID, err := publicid.Parse(record.publicID)
	if err != nil {
		return revocation.Resolution{}, ErrDeviceRevocationEvidence
	}
	resolution, err := revocation.NewOpenResolution(revocation.OpenResolutionParams{
		IdempotencyRecordID: recordID,
		RequestHash:         requestHash,
		Authorization:       authorizationEvidence,
		Scope:               transaction.scope,
		NodeID:              command.NodeID(),
		NetworkRevision:     networkRevision,
		InventoryRevision:   inventoryRevision,
		DeviceVersion:       deviceVersion,
		SessionGeneration:   sessionGeneration,
		DeviceState:         deviceState,
		MachineKeyEpoch:     machineEpoch,
		MachineKeyVersion:   machineVersion,
		MachineKeyState:     machineState,
		MachineKeyValidFrom: machineValidFrom,
		NodeKeyEpoch:        nodeEpoch,
		NodeKeyVersion:      nodeVersion,
		NodeKeyState:        nodeState,
		NodeKeyValidFrom:    nodeValidFrom,
	})
	if err != nil {
		return revocation.Resolution{}, ErrDeviceRevocationEvidence
	}
	return resolution, nil
}

func resolveDeviceRevocationAuthorization(
	ctx context.Context,
	database deviceRevocationDatabaseTransaction,
	command revocation.Command,
	evaluatedAt time.Time,
) (revocation.AuthorizationEvidence, error) {
	session := command.AccountSession()
	var bindingIDValue, roleIDValue string
	var scopeGeneration, membershipGeneration, bindingGeneration, roleGeneration int64
	var ownerGeneration int64
	var hasExpiry bool
	var expiresAt time.Time
	err := database.QueryRow(
		ctx,
		authorizeDeviceRevocationSQL,
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
		string(authorization.PermissionDeviceManage),
		evaluatedAt,
	).Scan(
		&bindingIDValue,
		&roleIDValue,
		&scopeGeneration,
		&membershipGeneration,
		&bindingGeneration,
		&roleGeneration,
		&hasExpiry,
		&expiresAt,
		&ownerGeneration,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return revocation.AuthorizationEvidence{}, revocation.ErrForbidden
	}
	if err != nil {
		return revocation.AuthorizationEvidence{}, fmt.Errorf("authorize device.manage: %w", err)
	}
	bindingID, roleID, err := parseNetworkPermissionAuthority(bindingIDValue, roleIDValue, ownerGeneration)
	if err != nil || scopeGeneration <= 0 || membershipGeneration <= 0 ||
		bindingGeneration < 0 || roleGeneration < 0 || ownerGeneration < 0 ||
		!validNetworkPermissionAuthority(bindingID, roleID, bindingGeneration, roleGeneration, ownerGeneration) {
		return revocation.AuthorizationEvidence{}, ErrDeviceRevocationEvidence
	}
	target, err := authorization.NewNetworkScope(
		session.DeploymentID(),
		command.Scope().WorkspaceID(),
		command.Scope().NetworkID(),
	)
	if err != nil {
		return revocation.AuthorizationEvidence{}, ErrDeviceRevocationEvidence
	}
	expiry := time.Time{}
	if hasExpiry {
		expiry = expiresAt
	}
	grant, err := authorization.NewGrant(authorization.GrantOptions{
		PrincipalID:         authorization.PrincipalID(session.PrincipalID()),
		Permission:          authorization.PermissionDeviceManage,
		Scope:               target,
		AuthorityGeneration: authorization.AuthorityGeneration(scopeGeneration),
		State:               authorization.GrantActive,
		ExpiresAt:           expiry,
	})
	if err != nil {
		return revocation.AuthorizationEvidence{}, ErrDeviceRevocationEvidence
	}
	request, err := authorization.NewRequest(authorization.RequestOptions{
		PrincipalID:         authorization.PrincipalID(session.PrincipalID()),
		Permission:          authorization.PermissionDeviceManage,
		Target:              target,
		AuthorityGeneration: authorization.AuthorityGeneration(scopeGeneration),
		EvaluatedAt:         evaluatedAt,
	})
	if err != nil || !authorization.Evaluate(request, []authorization.Grant{grant}).IsAllowed() {
		return revocation.AuthorizationEvidence{}, revocation.ErrForbidden
	}
	evidence, err := revocation.NewAuthorizationEvidence(revocation.AuthorizationEvidenceParams{
		AccountSessionID:                  session.ID(),
		RoleBindingID:                     bindingID,
		RoleDefinitionID:                  roleID,
		ScopeAuthorityGeneration:          authorization.AuthorityGeneration(scopeGeneration),
		MembershipAuthorityGeneration:     authorization.AuthorityGeneration(membershipGeneration),
		BindingAuthorityGeneration:        authorization.AuthorityGeneration(bindingGeneration),
		RoleAuthorityGeneration:           authorization.AuthorityGeneration(roleGeneration),
		WorkspaceOwnerAuthorityGeneration: authorization.AuthorityGeneration(ownerGeneration),
	})
	if err != nil {
		return revocation.AuthorizationEvidence{}, ErrDeviceRevocationEvidence
	}
	return evidence, nil
}

func (transaction *deviceRevocationTransaction) Apply(
	ctx context.Context,
	change revocation.Change,
) (result revocation.Result, resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationDeviceRevocationApply, startedAt, resultErr)
	}()

	if ctx == nil || transaction == nil || !change.IsValid() {
		return revocation.Result{}, ErrDeviceRevocationState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != deviceRevocationTransactionResolved ||
		change.Resolution() != transaction.resolution ||
		change.Command().Scope() != transaction.scope {
		return revocation.Result{}, ErrDeviceRevocationState
	}

	result, err := transaction.applyLocked(ctx, change)
	if err != nil {
		return revocation.Result{}, errors.Join(
			ErrApplyDeviceRevocation,
			classifyDeviceRevocationDatabaseError(ctx, err),
		)
	}
	transaction.state = deviceRevocationTransactionApplied
	return result, nil
}

func (transaction *deviceRevocationTransaction) applyLocked(
	ctx context.Context,
	change revocation.Change,
) (revocation.Result, error) {
	if err := transaction.database.Exec(
		ctx,
		setDeviceRevocationChangeSQL,
		change.Attempt().MutationIDs().ChangeID().String(),
	); err != nil {
		return revocation.Result{}, fmt.Errorf("set authority change context: %w", err)
	}

	command := change.Command()
	resolution := change.Resolution()
	occurredAt := change.Attempt().OccurredAt()
	var deviceVersion, sessionGeneration int64
	if err := transaction.database.QueryRow(
		ctx,
		revokeDeviceSQL,
		transaction.locked.deviceInternalID,
		transaction.workspaceInternalID,
		transaction.networkInternalID,
		command.NodeID().String(),
		resolution.DeviceVersion(),
		resolution.SessionGeneration(),
		occurredAt,
	).Scan(&deviceVersion, &sessionGeneration); err != nil {
		return revocation.Result{}, fmt.Errorf("revoke Device: %w", err)
	}
	if deviceVersion != resolution.DeviceVersion()+1 ||
		sessionGeneration != resolution.SessionGeneration()+1 {
		return revocation.Result{}, ErrDeviceRevocationEvidence
	}

	var machineVersion int64
	if err := transaction.database.QueryRow(
		ctx,
		revokeMachineKeyEpochSQL,
		transaction.locked.machineKeyInternalID,
		transaction.workspaceInternalID,
		transaction.networkInternalID,
		transaction.locked.deviceInternalID,
		resolution.MachineKeyEpoch(),
		resolution.MachineKeyVersion(),
		occurredAt,
		occurredAt,
		command.Reason().String(),
	).Scan(&machineVersion); err != nil {
		return revocation.Result{}, fmt.Errorf("revoke current machine-key epoch: %w", err)
	}
	if machineVersion != resolution.MachineKeyVersion()+1 {
		return revocation.Result{}, ErrDeviceRevocationEvidence
	}

	var nodeVersion int64
	if err := transaction.database.QueryRow(
		ctx,
		revokeNodeKeyEpochSQL,
		transaction.locked.nodeKeyInternalID,
		transaction.workspaceInternalID,
		transaction.networkInternalID,
		transaction.locked.deviceInternalID,
		resolution.NodeKeyEpoch(),
		resolution.NodeKeyVersion(),
		occurredAt,
		occurredAt,
		command.Reason().String(),
	).Scan(&nodeVersion); err != nil {
		return revocation.Result{}, fmt.Errorf("revoke current Node-key epoch: %w", err)
	}
	if nodeVersion != resolution.NodeKeyVersion()+1 {
		return revocation.Result{}, ErrDeviceRevocationEvidence
	}

	var networkRevision, inventoryRevision int64
	if err := transaction.database.QueryRow(ctx, advanceDeviceRevocationRevisionSQL).Scan(
		&networkRevision,
		&inventoryRevision,
	); err != nil {
		return revocation.Result{}, fmt.Errorf("advance Network inventory revision: %w", err)
	}
	if networkRevision != resolution.NetworkRevision()+1 ||
		inventoryRevision != resolution.InventoryRevision()+1 {
		return revocation.Result{}, ErrDeviceRevocationEvidence
	}

	if err := transaction.appendDeviceRevocationEvidence(
		ctx,
		change,
		deviceVersion,
		sessionGeneration,
		networkRevision,
		inventoryRevision,
	); err != nil {
		return revocation.Result{}, err
	}
	result, err := revocation.NewResult(revocation.ResultParams{
		IdempotencyRecordID: resolution.IdempotencyRecordID(),
		Scope:               transaction.scope,
		NodeID:              command.NodeID(),
		DeviceVersion:       deviceVersion,
		SessionGeneration:   sessionGeneration,
		NetworkRevision:     networkRevision,
		InventoryRevision:   inventoryRevision,
	})
	if err != nil {
		return revocation.Result{}, ErrDeviceRevocationEvidence
	}
	return result, nil
}

func (transaction *deviceRevocationTransaction) Commit(ctx context.Context) (resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationDeviceRevocationCommit, startedAt, resultErr)
	}()

	if ctx == nil || transaction == nil {
		return ErrDeviceRevocationState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != deviceRevocationTransactionApplied {
		return ErrDeviceRevocationState
	}
	transaction.state = deviceRevocationTransactionClosed
	if err := transaction.database.Commit(ctx); err != nil {
		return errors.Join(
			ErrCommitDeviceRevocation,
			classifyDeviceRevocationCommitError(ctx, err),
		)
	}
	return nil
}

func (transaction *deviceRevocationTransaction) Rollback(ctx context.Context) (resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationDeviceRevocationRollback, startedAt, resultErr)
	}()

	if ctx == nil || transaction == nil {
		return ErrDeviceRevocationState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil {
		return ErrDeviceRevocationState
	}
	if transaction.state == deviceRevocationTransactionClosed {
		return nil
	}
	transaction.state = deviceRevocationTransactionClosed
	if err := transaction.database.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return errors.Join(
			ErrRollbackDeviceRevocation,
			fmt.Errorf("roll back database transaction: %w", err),
		)
	}
	return nil
}

func (transaction *deviceRevocationTransaction) observe(
	operation postgresOperation,
	startedAt time.Time,
	err error,
) {
	if transaction == nil {
		return
	}
	transaction.metrics.observeOperation(operation, time.Since(startedAt), err)
}
