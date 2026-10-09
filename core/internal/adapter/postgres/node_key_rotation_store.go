package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node/keyrotation"
	"meshtransit.net/core/internal/domain/workspace"
)

const (
	maxNodeKeyRotationStatementTimeout = time.Minute
	maxNodeKeyRotationLockTimeout      = 30 * time.Second
	maxNodeKeyRotationIdleTimeout      = time.Minute
	nodeKeyRotationSetupRollbackWindow = 2 * time.Second
)

var (
	// ErrInvalidNodeKeyRotationStore reports an unsafe runtime dependency or option.
	ErrInvalidNodeKeyRotationStore = errors.New("invalid postgres Node-key rotation store")
	// ErrBeginNodeKeyRotation classifies transaction setup failure.
	ErrBeginNodeKeyRotation = errors.New("begin postgres Node-key rotation")
	// ErrNodeKeyRotationState reports invalid transaction method ordering.
	ErrNodeKeyRotationState = errors.New("postgres Node-key rotation state is invalid")
	// ErrNodeKeyRotationEvidence reports malformed durable identity authority.
	ErrNodeKeyRotationEvidence = errors.New("postgres Node-key rotation evidence is invalid")
	// ErrResolveNodeKeyRotation classifies locked-state resolution failure.
	ErrResolveNodeKeyRotation = errors.New("resolve postgres Node-key rotation")
	// ErrApplyNodeKeyRotation classifies atomic mutation failure.
	ErrApplyNodeKeyRotation = errors.New("apply postgres Node-key rotation")
	// ErrCommitNodeKeyRotation classifies commit failure.
	ErrCommitNodeKeyRotation = errors.New("commit postgres Node-key rotation")
	// ErrRollbackNodeKeyRotation classifies rollback failure.
	ErrRollbackNodeKeyRotation = errors.New("rollback postgres Node-key rotation")
)

// NodeKeyRotationOptions bounds every database wait in a rotation transaction.
type NodeKeyRotationOptions struct {
	StatementTimeout time.Duration
	LockTimeout      time.Duration
	IdleTimeout      time.Duration
}

// NodeKeyRotationStore owns short runtime-scoped rotation transactions.
type NodeKeyRotationStore struct {
	database deviceRevocationDatabase
	options  NodeKeyRotationOptions
	metrics  *postgresPoolMetrics
}

var _ keyrotation.Transactions = (*NodeKeyRotationStore)(nil)

// NewNodeKeyRotationStore constructs a store from a runtime-authenticated pool.
func NewNodeKeyRotationStore(
	pool *Pool,
	options NodeKeyRotationOptions,
) (*NodeKeyRotationStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.deviceRevocationDatabase == nil {
		return nil, ErrInvalidNodeKeyRotationStore
	}
	return newNodeKeyRotationStore(pool.deviceRevocationDatabase, options, pool.metrics)
}

func newNodeKeyRotationStore(
	database deviceRevocationDatabase,
	options NodeKeyRotationOptions,
	metrics *postgresPoolMetrics,
) (*NodeKeyRotationStore, error) {
	if database == nil || !validNodeKeyRotationOptions(options) {
		return nil, ErrInvalidNodeKeyRotationStore
	}
	return &NodeKeyRotationStore{database: database, options: options, metrics: metrics}, nil
}

// Begin resolves machine continuity before fixing exact Network RLS scope.
func (store *NodeKeyRotationStore) Begin(
	ctx context.Context,
	command keyrotation.Command,
) (_ keyrotation.Transaction, resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.observe(postgresOperationNodeKeyRotationBegin, startedAt, resultErr)
	}()

	if ctx == nil || store == nil || store.database == nil || !command.IsValid() ||
		!validNodeKeyRotationOptions(store.options) {
		return nil, ErrInvalidNodeKeyRotationStore
	}
	databaseTransaction, err := store.database.Begin(ctx, false)
	if err != nil {
		return nil, errors.Join(
			ErrBeginNodeKeyRotation,
			classifyNodeKeyRotationDatabaseError(ctx, err),
		)
	}
	owned := false
	defer func() {
		if owned {
			return
		}
		resultErr = errors.Join(resultErr, rollbackNodeKeyRotationSetup(databaseTransaction))
	}()

	options := store.options
	if err := databaseTransaction.Exec(
		ctx,
		configureNodeKeyRotationTransactionSQL,
		postgresTimeout(options.StatementTimeout),
		postgresTimeout(options.LockTimeout),
		postgresTimeout(options.IdleTimeout),
	); err != nil {
		return nil, errors.Join(ErrBeginNodeKeyRotation, classifyNodeKeyRotationDatabaseError(ctx, err))
	}
	machineKey := command.MachineKey().Bytes()
	machineFingerprint := command.MachineKey().Fingerprint()
	oldNodeKey := command.OldNodeKey().Bytes()
	newNodeKey := command.NewNodeKey().Bytes()
	var workspaceValue, networkValue string
	if err := databaseTransaction.QueryRow(
		ctx,
		resolveNodeKeyRotationScopeSQL,
		machineFingerprint[:],
		machineKey[:],
		oldNodeKey[:],
		newNodeKey[:],
	).Scan(&workspaceValue, &networkValue); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.Join(ErrBeginNodeKeyRotation, keyrotation.ErrNotFound)
		}
		return nil, errors.Join(ErrBeginNodeKeyRotation, classifyNodeKeyRotationDatabaseError(ctx, err))
	}
	workspaceID, err := workspace.ParseID(workspaceValue)
	if err != nil {
		return nil, errors.Join(ErrBeginNodeKeyRotation, ErrNodeKeyRotationEvidence)
	}
	networkID, err := network.ParseID(networkValue)
	if err != nil {
		return nil, errors.Join(ErrBeginNodeKeyRotation, ErrNodeKeyRotationEvidence)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		return nil, errors.Join(ErrBeginNodeKeyRotation, ErrNodeKeyRotationEvidence)
	}
	var workspaceInternalID, networkInternalID int64
	if err := databaseTransaction.QueryRow(
		ctx,
		setNodeKeyRotationScopeSQL,
		workspaceValue,
		networkValue,
	).Scan(&workspaceInternalID, &networkInternalID); err != nil {
		return nil, errors.Join(ErrBeginNodeKeyRotation, classifyNodeKeyRotationDatabaseError(ctx, err))
	}
	if workspaceInternalID <= 0 || networkInternalID <= 0 {
		return nil, errors.Join(ErrBeginNodeKeyRotation, ErrNodeKeyRotationEvidence)
	}

	owned = true
	return &nodeKeyRotationTransaction{
		database:            databaseTransaction,
		scope:               scope,
		workspaceInternalID: workspaceInternalID,
		networkInternalID:   networkInternalID,
		metrics:             store.metrics,
	}, nil
}

func validNodeKeyRotationOptions(options NodeKeyRotationOptions) bool {
	return options.StatementTimeout > 0 &&
		options.StatementTimeout <= maxNodeKeyRotationStatementTimeout &&
		options.LockTimeout > 0 && options.LockTimeout <= maxNodeKeyRotationLockTimeout &&
		options.IdleTimeout > 0 && options.IdleTimeout <= maxNodeKeyRotationIdleTimeout
}

func rollbackNodeKeyRotationSetup(transaction deviceRevocationDatabaseTransaction) error {
	ctx, cancel := context.WithTimeout(context.Background(), nodeKeyRotationSetupRollbackWindow)
	defer cancel()
	if err := transaction.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return fmt.Errorf("roll back Node-key rotation setup: %w", err)
	}
	return nil
}

func (store *NodeKeyRotationStore) observe(
	operation postgresOperation,
	startedAt time.Time,
	err error,
) {
	if store == nil {
		return
	}
	store.metrics.observeOperation(operation, time.Since(startedAt), err)
}
