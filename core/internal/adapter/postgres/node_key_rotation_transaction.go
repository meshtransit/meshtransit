package postgres

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/keyrotation"
	"meshtransit.net/core/internal/domain/publicid"
)

type nodeKeyRotationTransactionState uint8

const (
	nodeKeyRotationTransactionOpen nodeKeyRotationTransactionState = iota
	nodeKeyRotationTransactionResolved
	nodeKeyRotationTransactionApplied
	nodeKeyRotationTransactionClosed
)

type nodeKeyRotationLockedIDs struct {
	deviceInternalID  int64
	nodeKeyInternalID int64
	// gateway: the Device is a Kubernetes gateway (its own budget).
	gateway bool
}

type nodeKeyRotationAuditHead struct {
	streamInternalID int64
	nextSequence     int64
	previousHash     [32]byte
}

type nodeKeyRotationTransaction struct {
	mu sync.Mutex

	decisionAt          time.Time
	database            deviceRevocationDatabaseTransaction
	scope               network.Scope
	workspaceInternalID int64
	networkInternalID   int64
	metrics             *postgresPoolMetrics
	state               nodeKeyRotationTransactionState
	resolution          keyrotation.Resolution
	locked              nodeKeyRotationLockedIDs
	audit               nodeKeyRotationAuditHead
}

// DecisionTime is this transaction's time on the database clock.
func (transaction *nodeKeyRotationTransaction) DecisionTime() time.Time {
	return transaction.decisionAt
}

var _ keyrotation.Transaction = (*nodeKeyRotationTransaction)(nil)

func (transaction *nodeKeyRotationTransaction) Resolve(
	ctx context.Context,
	command keyrotation.Command,
) (resolution keyrotation.Resolution, resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationNodeKeyRotationResolve, startedAt, resultErr)
	}()

	if ctx == nil || transaction == nil || !command.IsValid() {
		return keyrotation.Resolution{}, ErrNodeKeyRotationState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != nodeKeyRotationTransactionOpen ||
		!transaction.scope.IsValid() || transaction.workspaceInternalID <= 0 ||
		transaction.networkInternalID <= 0 {
		return keyrotation.Resolution{}, ErrNodeKeyRotationState
	}

	resolution, err := transaction.resolveLocked(ctx, command)
	if err != nil {
		return keyrotation.Resolution{}, errors.Join(
			ErrResolveNodeKeyRotation,
			classifyNodeKeyRotationDatabaseError(ctx, err),
		)
	}
	transaction.resolution = resolution
	transaction.state = nodeKeyRotationTransactionResolved
	return resolution, nil
}

func (transaction *nodeKeyRotationTransaction) resolveLocked(
	ctx context.Context,
	command keyrotation.Command,
) (keyrotation.Resolution, error) {
	var networkRevision, inventoryRevision, groupRevision, policyRevision int64
	var dnsRevision, routeRevision, sharingRevision, isolationGeneration int64
	if err := transaction.database.QueryRow(ctx, lockNodeKeyRotationRevisionSQL).Scan(
		&networkRevision,
		&inventoryRevision,
		&groupRevision,
		&policyRevision,
		&dnsRevision,
		&routeRevision,
		&sharingRevision,
		&isolationGeneration,
	); err != nil {
		return keyrotation.Resolution{}, fmt.Errorf("lock Network revision: %w", err)
	}
	if networkRevision <= 0 || inventoryRevision <= 0 || groupRevision <= 0 ||
		policyRevision <= 0 || dnsRevision <= 0 || routeRevision <= 0 ||
		sharingRevision <= 0 || isolationGeneration <= 0 {
		return keyrotation.Resolution{}, ErrNodeKeyRotationEvidence
	}

	var nodePublicID, hostnameValue string
	var deviceVersion, sessionGeneration, nodeKeyEpoch, nodeKeyVersion int64
	var machineKeyBytes, currentNodeKeyBytes []byte
	var nodeKeyValidFrom time.Time
	machineKey := command.MachineKey().Bytes()
	machineFingerprint := command.MachineKey().Fingerprint()
	if err := transaction.database.QueryRow(
		ctx,
		lockNodeKeyRotationTargetSQL,
		transaction.workspaceInternalID,
		transaction.networkInternalID,
		machineFingerprint[:],
		machineKey[:],
	).Scan(
		&transaction.locked.deviceInternalID,
		&nodePublicID,
		&hostnameValue,
		&deviceVersion,
		&sessionGeneration,
		&nodeKeyEpoch,
		&machineKeyBytes,
		&transaction.locked.nodeKeyInternalID,
		&nodeKeyVersion,
		&currentNodeKeyBytes,
		&nodeKeyValidFrom,
		&transaction.locked.gateway,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return keyrotation.Resolution{}, keyrotation.ErrNotFound
		}
		return keyrotation.Resolution{}, fmt.Errorf("lock Device and current key epochs: %w", err)
	}
	if transaction.locked.deviceInternalID <= 0 || transaction.locked.nodeKeyInternalID <= 0 ||
		deviceVersion <= 0 || sessionGeneration <= 0 || nodeKeyEpoch <= 0 ||
		nodeKeyVersion <= 0 || len(machineKeyBytes) != len(machineKey) ||
		len(currentNodeKeyBytes) != 32 ||
		subtle.ConstantTimeCompare(machineKeyBytes, machineKey[:]) != 1 {
		return keyrotation.Resolution{}, ErrNodeKeyRotationEvidence
	}
	nodeID, err := node.ParseID(nodePublicID)
	if err != nil {
		return keyrotation.Resolution{}, ErrNodeKeyRotationEvidence
	}
	hostname, err := node.ParseHostname(hostnameValue)
	if err != nil {
		return keyrotation.Resolution{}, ErrNodeKeyRotationEvidence
	}
	var currentRaw [32]byte
	copy(currentRaw[:], currentNodeKeyBytes)
	currentNodeKey, err := node.NewKey(currentRaw)
	if err != nil {
		return keyrotation.Resolution{}, ErrNodeKeyRotationEvidence
	}

	switch currentNodeKey {
	case command.OldNodeKey():
		// Schema 232: a gateway's rotation records its verified pod token
		// here, under the Device lock and before the audit head, so the
		// epoch trigger admits the new key. A repeat (the replay branch)
		// committed its use already. A gateway without a token goes on and
		// the trigger refuses its new epoch.
		if token, ok := command.GatewayToken(); ok && transaction.locked.gateway {
			currentKey := currentNodeKey.Bytes()
			if err := transaction.database.Exec(ctx, consumeGatewayRotationTokenSQL,
				publicid.ID(token.DeviceID).String(), machineFingerprint[:], currentKey[:], token.TrustVersion,
				token.JTI, token.ExpiresAt); err != nil {
				return keyrotation.Resolution{}, classifyNodeKeyRotationDatabaseError(ctx, err)
			}
		}
		budgetStart, err := transaction.readBudgetStart(ctx, nodeKeyEpoch)
		if err != nil {
			return keyrotation.Resolution{}, err
		}
		if err := transaction.lockAuditHead(ctx); err != nil {
			return keyrotation.Resolution{}, err
		}
		resolution, err := keyrotation.NewOpenResolution(keyrotation.OpenResolutionParams{
			Scope:             transaction.scope,
			NodeID:            nodeID,
			Hostname:          hostname,
			MachineKey:        command.MachineKey(),
			CurrentNodeKey:    currentNodeKey,
			NetworkRevision:   networkRevision,
			InventoryRevision: inventoryRevision,
			DeviceVersion:     deviceVersion,
			SessionGeneration: sessionGeneration,
			NodeKeyEpoch:      nodeKeyEpoch,
			NodeKeyVersion:    nodeKeyVersion,
			NodeKeyValidFrom:  nodeKeyValidFrom,
			BudgetWindowStart: budgetStart,
			Gateway:           transaction.locked.gateway,
		})
		if err != nil {
			return keyrotation.Resolution{}, ErrNodeKeyRotationEvidence
		}
		return resolution, nil
	case command.NewNodeKey():
		return transaction.resolveReplay(
			ctx,
			command,
			nodeID,
			hostname,
			deviceVersion,
			sessionGeneration,
			nodeKeyEpoch,
			networkRevision,
			inventoryRevision,
		)
	default:
		return keyrotation.Resolution{}, keyrotation.ErrConflict
	}
}

// readBudgetStart returns when the epoch the rotation budget compares
// against began, zero while the Device has changed its key too few times.
func (transaction *nodeKeyRotationTransaction) readBudgetStart(ctx context.Context, current int64) (time.Time, error) {
	epoch, counts := keyrotation.BudgetEpoch(current, transaction.locked.gateway)
	if !counts {
		return time.Time{}, nil
	}
	var validFrom time.Time
	if err := transaction.database.QueryRow(
		ctx,
		readNodeKeyRotationBudgetSQL,
		transaction.workspaceInternalID,
		transaction.networkInternalID,
		transaction.locked.deviceInternalID,
		epoch,
	).Scan(&validFrom); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return time.Time{}, ErrNodeKeyRotationEvidence // epochs are never deleted
		}
		return time.Time{}, fmt.Errorf("read Node-key rotation budget: %w", err)
	}
	if validFrom.IsZero() {
		return time.Time{}, ErrNodeKeyRotationEvidence
	}
	return validFrom, nil
}

func (transaction *nodeKeyRotationTransaction) resolveReplay(
	ctx context.Context,
	command keyrotation.Command,
	nodeID node.ID,
	hostname node.Hostname,
	deviceVersion int64,
	sessionGeneration int64,
	nodeKeyEpoch int64,
	networkRevision int64,
	inventoryRevision int64,
) (keyrotation.Resolution, error) {
	if nodeKeyEpoch <= 1 {
		return keyrotation.Resolution{}, keyrotation.ErrConflict
	}
	var previousKeyBytes, proofBytes []byte
	var previousState string
	var previousValidUntil sql.NullTime
	if err := transaction.database.QueryRow(
		ctx,
		lockNodeKeyRotationReplaySQL,
		transaction.workspaceInternalID,
		transaction.networkInternalID,
		transaction.locked.deviceInternalID,
		nodeKeyEpoch,
	).Scan(
		&previousKeyBytes,
		&proofBytes,
		&previousState,
		&previousValidUntil,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return keyrotation.Resolution{}, keyrotation.ErrConflict
		}
		return keyrotation.Resolution{}, fmt.Errorf("lock Node-key rotation replay evidence: %w", err)
	}
	proof, err := command.RotationProofHash()
	if err != nil {
		return keyrotation.Resolution{}, keyrotation.ErrConflict
	}
	oldKey := command.OldNodeKey().Bytes()
	if previousState != "expired" || !previousValidUntil.Valid ||
		len(previousKeyBytes) != len(oldKey) || len(proofBytes) != len(proof) ||
		subtle.ConstantTimeCompare(previousKeyBytes, oldKey[:]) != 1 ||
		subtle.ConstantTimeCompare(proofBytes, proof[:]) != 1 {
		return keyrotation.Resolution{}, keyrotation.ErrConflict
	}
	result, err := keyrotation.NewResult(keyrotation.ResultParams{
		OperationID:       command.OperationID(),
		Scope:             transaction.scope,
		NodeID:            nodeID,
		Hostname:          hostname,
		DeviceVersion:     deviceVersion,
		NodeKeyEpoch:      nodeKeyEpoch,
		SessionGeneration: sessionGeneration,
		NetworkRevision:   networkRevision,
		InventoryRevision: inventoryRevision,
	})
	if err != nil {
		return keyrotation.Resolution{}, ErrNodeKeyRotationEvidence
	}
	resolution, err := keyrotation.NewCompletedResolution(result)
	if err != nil {
		return keyrotation.Resolution{}, ErrNodeKeyRotationEvidence
	}
	return resolution, nil
}

func (transaction *nodeKeyRotationTransaction) lockAuditHead(ctx context.Context) error {
	var previousHash []byte
	if err := transaction.database.QueryRow(ctx, lockNodeKeyRotationAuditStreamSQL).Scan(
		&transaction.audit.streamInternalID,
		&transaction.audit.nextSequence,
		&previousHash,
	); err != nil {
		return fmt.Errorf("lock audit stream: %w", err)
	}
	if transaction.audit.streamInternalID <= 0 || transaction.audit.nextSequence <= 0 ||
		len(previousHash) != len(transaction.audit.previousHash) {
		return ErrNodeKeyRotationEvidence
	}
	copy(transaction.audit.previousHash[:], previousHash)
	return nil
}

func (transaction *nodeKeyRotationTransaction) Apply(
	ctx context.Context,
	change keyrotation.Change,
) (result keyrotation.Result, resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationNodeKeyRotationApply, startedAt, resultErr)
	}()

	if ctx == nil || transaction == nil || !change.IsValid() {
		return keyrotation.Result{}, ErrNodeKeyRotationState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != nodeKeyRotationTransactionResolved ||
		transaction.resolution != change.Resolution() ||
		transaction.scope != change.Resolution().Scope() ||
		!change.OccurredAt().Equal(transaction.decisionAt) {
		return keyrotation.Result{}, ErrNodeKeyRotationState
	}

	result, err := transaction.applyLocked(ctx, change)
	if err != nil {
		return keyrotation.Result{}, errors.Join(
			ErrApplyNodeKeyRotation,
			classifyNodeKeyRotationDatabaseError(ctx, err),
		)
	}
	transaction.state = nodeKeyRotationTransactionApplied
	return result, nil
}

func (transaction *nodeKeyRotationTransaction) applyLocked(
	ctx context.Context,
	change keyrotation.Change,
) (keyrotation.Result, error) {
	resolution := change.Resolution()
	command := change.Command()
	if err := transaction.database.Exec(
		ctx,
		setNodeKeyRotationChangeSQL,
		change.MutationIDs().ChangeID().String(),
	); err != nil {
		return keyrotation.Result{}, fmt.Errorf("set authority change context: %w", err)
	}

	expiredVersion, err := transaction.queryInt64(
		ctx,
		"expire current Node-key epoch",
		expireNodeKeyRotationEpochSQL,
		transaction.locked.nodeKeyInternalID,
		transaction.workspaceInternalID,
		transaction.networkInternalID,
		transaction.locked.deviceInternalID,
		resolution.NodeKeyEpoch(),
		resolution.NodeKeyVersion(),
		change.OccurredAt(),
		change.OccurredAt(),
	)
	if err != nil || expiredVersion != resolution.NodeKeyVersion()+1 {
		if err == nil {
			err = ErrNodeKeyRotationEvidence
		}
		return keyrotation.Result{}, err
	}

	newNodeKey := command.NewNodeKey().Bytes()
	newFingerprint := command.NewNodeKey().Fingerprint()
	proof := change.ProofHash()
	insertedVersion, err := transaction.queryInt64(
		ctx,
		"insert next Node-key epoch",
		insertNodeKeyRotationEpochSQL,
		change.MutationIDs().NodeKeyEpochID().String(),
		transaction.workspaceInternalID,
		transaction.networkInternalID,
		transaction.locked.deviceInternalID,
		resolution.NodeKeyEpoch()+1,
		newNodeKey[:],
		newFingerprint[:],
		change.OccurredAt(),
		proof[:],
	)
	if err != nil || insertedVersion != 1 {
		if err == nil {
			err = ErrNodeKeyRotationEvidence
		}
		return keyrotation.Result{}, err
	}

	var deviceVersion, sessionGeneration, nodeKeyEpoch int64
	if err := transaction.database.QueryRow(
		ctx,
		rotateDeviceNodeKeySQL,
		transaction.locked.deviceInternalID,
		transaction.workspaceInternalID,
		transaction.networkInternalID,
		resolution.NodeID().String(),
		resolution.DeviceVersion(),
		resolution.SessionGeneration(),
		resolution.NodeKeyEpoch()+1,
		change.OccurredAt(),
	).Scan(&deviceVersion, &sessionGeneration, &nodeKeyEpoch); err != nil {
		return keyrotation.Result{}, fmt.Errorf("advance Device Node-key authority: %w", err)
	}
	if deviceVersion != resolution.DeviceVersion()+1 ||
		sessionGeneration != resolution.SessionGeneration()+1 ||
		nodeKeyEpoch != resolution.NodeKeyEpoch()+1 {
		return keyrotation.Result{}, ErrNodeKeyRotationEvidence
	}

	var networkRevision, inventoryRevision int64
	if err := transaction.database.QueryRow(ctx, advanceNodeKeyRotationRevisionSQL).Scan(
		&networkRevision,
		&inventoryRevision,
	); err != nil {
		return keyrotation.Result{}, fmt.Errorf("advance Network inventory revision: %w", err)
	}
	if networkRevision != resolution.NetworkRevision()+1 ||
		inventoryRevision != resolution.InventoryRevision()+1 {
		return keyrotation.Result{}, ErrNodeKeyRotationEvidence
	}
	if err := transaction.appendNodeKeyRotationEvidence(
		ctx,
		change,
		deviceVersion,
		sessionGeneration,
		networkRevision,
		inventoryRevision,
	); err != nil {
		return keyrotation.Result{}, err
	}
	result, err := keyrotation.NewResult(keyrotation.ResultParams{
		OperationID:       command.OperationID(),
		Scope:             resolution.Scope(),
		NodeID:            resolution.NodeID(),
		Hostname:          resolution.Hostname(),
		DeviceVersion:     deviceVersion,
		NodeKeyEpoch:      nodeKeyEpoch,
		SessionGeneration: sessionGeneration,
		NetworkRevision:   networkRevision,
		InventoryRevision: inventoryRevision,
	})
	if err != nil {
		return keyrotation.Result{}, ErrNodeKeyRotationEvidence
	}
	return result, nil
}

func (transaction *nodeKeyRotationTransaction) queryInt64(
	ctx context.Context,
	description string,
	query string,
	arguments ...any,
) (int64, error) {
	var value int64
	if err := transaction.database.QueryRow(ctx, query, arguments...).Scan(&value); err != nil {
		return 0, fmt.Errorf("%s: %w", description, err)
	}
	return value, nil
}

func (transaction *nodeKeyRotationTransaction) Commit(
	ctx context.Context,
) (resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationNodeKeyRotationCommit, startedAt, resultErr)
	}()
	if ctx == nil || transaction == nil {
		return ErrNodeKeyRotationState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state != nodeKeyRotationTransactionApplied {
		return ErrNodeKeyRotationState
	}
	if err := transaction.database.Commit(ctx); err != nil {
		return errors.Join(
			ErrCommitNodeKeyRotation,
			classifyNodeKeyRotationCommitError(ctx, err),
		)
	}
	transaction.state = nodeKeyRotationTransactionClosed
	transaction.database = nil
	return nil
}

func (transaction *nodeKeyRotationTransaction) Rollback(
	ctx context.Context,
) (resultErr error) {
	startedAt := time.Now()
	defer func() {
		transaction.observe(postgresOperationNodeKeyRotationRollback, startedAt, resultErr)
	}()
	if ctx == nil || transaction == nil {
		return ErrNodeKeyRotationState
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.database == nil || transaction.state == nodeKeyRotationTransactionClosed {
		return nil
	}
	err := transaction.database.Rollback(ctx)
	transaction.state = nodeKeyRotationTransactionClosed
	transaction.database = nil
	if err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return errors.Join(ErrRollbackNodeKeyRotation, err)
	}
	return nil
}

func (transaction *nodeKeyRotationTransaction) observe(
	operation postgresOperation,
	startedAt time.Time,
	err error,
) {
	if transaction == nil {
		return
	}
	transaction.metrics.observeOperation(operation, time.Since(startedAt), err)
}
