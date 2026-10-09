package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node/revocation"
)

const (
	maxDeviceRevocationStatementTimeout = time.Minute
	maxDeviceRevocationLockTimeout      = 30 * time.Second
	maxDeviceRevocationIdleTimeout      = time.Minute
	deviceRevocationSetupRollbackWindow = 2 * time.Second
)

var (
	// ErrInvalidDeviceRevocationStore reports an unsafe runtime dependency or option.
	ErrInvalidDeviceRevocationStore = errors.New("invalid postgres device revocation store")
	// ErrBeginDeviceRevocation classifies transaction setup failure.
	ErrBeginDeviceRevocation = errors.New("begin postgres device revocation")
	// ErrDeviceRevocationState reports invalid transaction method ordering.
	ErrDeviceRevocationState = errors.New("postgres device revocation state is invalid")
	// ErrDeviceRevocationEvidence reports malformed durable revocation authority.
	ErrDeviceRevocationEvidence = errors.New("postgres device revocation evidence is invalid")
	// ErrResolveDeviceRevocation classifies locked-state resolution failure.
	ErrResolveDeviceRevocation = errors.New("resolve postgres device revocation")
	// ErrApplyDeviceRevocation classifies atomic mutation failure.
	ErrApplyDeviceRevocation = errors.New("apply postgres device revocation")
	// ErrCommitDeviceRevocation classifies commit failure.
	ErrCommitDeviceRevocation = errors.New("commit postgres device revocation")
	// ErrRollbackDeviceRevocation classifies rollback failure.
	ErrRollbackDeviceRevocation = errors.New("rollback postgres device revocation")
	// ErrResolveCommittedDeviceRevocation classifies replay lookup failure.
	ErrResolveCommittedDeviceRevocation = errors.New("resolve committed postgres device revocation")
)

// DeviceRevocationOptions bounds every database wait in a revocation transaction.
type DeviceRevocationOptions struct {
	StatementTimeout time.Duration
	LockTimeout      time.Duration
	IdleTimeout      time.Duration
}

// DeviceRevocationStore owns short runtime-scoped Device revocation transactions.
type DeviceRevocationStore struct {
	database deviceRevocationDatabase
	options  DeviceRevocationOptions
	metrics  *postgresPoolMetrics
}

var (
	_ revocation.Transactions            = (*DeviceRevocationStore)(nil)
	_ revocation.CommittedResultResolver = (*DeviceRevocationStore)(nil)
)

// NewDeviceRevocationStore constructs a revoker from a runtime-authenticated pool.
func NewDeviceRevocationStore(
	pool *Pool,
	options DeviceRevocationOptions,
) (*DeviceRevocationStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.deviceRevocationDatabase == nil {
		return nil, ErrInvalidDeviceRevocationStore
	}
	return newDeviceRevocationStore(pool.deviceRevocationDatabase, options, pool.metrics)
}

func newDeviceRevocationStore(
	database deviceRevocationDatabase,
	options DeviceRevocationOptions,
	metrics *postgresPoolMetrics,
) (*DeviceRevocationStore, error) {
	if database == nil || !validDeviceRevocationOptions(options) {
		return nil, ErrInvalidDeviceRevocationStore
	}
	return &DeviceRevocationStore{database: database, options: options, metrics: metrics}, nil
}

// Begin fixes the exact Network scope in one READ COMMITTED read-write transaction.
func (store *DeviceRevocationStore) Begin(
	ctx context.Context,
	scope network.Scope,
) (_ revocation.Transaction, resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.observe(postgresOperationDeviceRevocationBegin, startedAt, resultErr)
	}()

	if ctx == nil || store == nil || store.database == nil || !scope.IsValid() ||
		!validDeviceRevocationOptions(store.options) {
		return nil, ErrInvalidDeviceRevocationStore
	}
	databaseTransaction, err := store.database.Begin(ctx, false)
	if err != nil {
		return nil, errors.Join(
			ErrBeginDeviceRevocation,
			classifyDeviceRevocationDatabaseError(ctx, err),
		)
	}
	owned := false
	defer func() {
		if owned {
			return
		}
		resultErr = errors.Join(resultErr, rollbackDeviceRevocationSetup(databaseTransaction))
	}()

	workspaceInternalID, networkInternalID, err := store.configureAndScope(
		ctx,
		databaseTransaction,
		scope,
	)
	if err != nil {
		return nil, errors.Join(ErrBeginDeviceRevocation, err)
	}
	owned = true
	return &deviceRevocationTransaction{
		database:            databaseTransaction,
		scope:               scope,
		workspaceInternalID: workspaceInternalID,
		networkInternalID:   networkInternalID,
		metrics:             store.metrics,
	}, nil
}

// ResolveCommitted identifies a possibly committed revocation without mutation replay.
func (store *DeviceRevocationStore) ResolveCommitted(
	ctx context.Context,
	command revocation.Command,
	attempt revocation.Attempt,
) (_ revocation.Result, found bool, resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.observe(postgresOperationDeviceRevocationReplay, startedAt, resultErr)
	}()

	if ctx == nil || store == nil || store.database == nil || !command.IsValid() || !attempt.IsValid() ||
		!validDeviceRevocationOptions(store.options) {
		return revocation.Result{}, false, ErrInvalidDeviceRevocationStore
	}
	databaseTransaction, err := store.database.Begin(ctx, false)
	if err != nil {
		return revocation.Result{}, false, errors.Join(
			ErrResolveCommittedDeviceRevocation,
			classifyDeviceRevocationDatabaseError(ctx, err),
		)
	}
	closed := false
	defer func() {
		if closed {
			return
		}
		resultErr = errors.Join(resultErr, rollbackDeviceRevocationSetup(databaseTransaction))
	}()

	if _, _, err := store.configureAndScope(
		ctx,
		databaseTransaction,
		command.Scope(),
	); err != nil {
		return revocation.Result{}, false, errors.Join(ErrResolveCommittedDeviceRevocation, err)
	}
	if _, err := resolveDeviceRevocationAuthorization(
		ctx,
		databaseTransaction,
		command,
		attempt.OccurredAt(),
	); err != nil {
		return revocation.Result{}, false, errors.Join(ErrResolveCommittedDeviceRevocation, err)
	}
	proof := command.IdempotencyEvidence()
	digest := proof.Digest()
	record, err := scanDeviceRevocationIdempotencyRecord(
		databaseTransaction.QueryRow(
			ctx,
			loadDeviceRevocationIdempotencySQL,
			command.ActorPrincipalID().String(),
			deviceRevocationOperation,
			proof.DigestKeyID(),
			digest[:],
		),
		false,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := databaseTransaction.Commit(ctx); err != nil {
			return revocation.Result{}, false, errors.Join(
				ErrResolveCommittedDeviceRevocation,
				classifyDeviceRevocationCommitError(ctx, err),
			)
		}
		closed = true
		return revocation.Result{}, false, nil
	}
	if err != nil {
		return revocation.Result{}, false, errors.Join(
			ErrResolveCommittedDeviceRevocation,
			classifyDeviceRevocationDatabaseError(ctx, err),
		)
	}
	result, found, err := deviceRevocationCommittedRecord(record, command, attempt.OccurredAt())
	if err != nil {
		return revocation.Result{}, false, errors.Join(ErrResolveCommittedDeviceRevocation, err)
	}
	if err := databaseTransaction.Commit(ctx); err != nil {
		return revocation.Result{}, false, errors.Join(
			ErrResolveCommittedDeviceRevocation,
			classifyDeviceRevocationCommitError(ctx, err),
		)
	}
	closed = true
	return result, found, nil
}

func (store *DeviceRevocationStore) configureAndScope(
	ctx context.Context,
	transaction deviceRevocationDatabaseTransaction,
	scope network.Scope,
) (int64, int64, error) {
	options := store.options
	if err := transaction.Exec(
		ctx,
		configureDeviceRevocationTransactionSQL,
		postgresTimeout(options.StatementTimeout),
		postgresTimeout(options.LockTimeout),
		postgresTimeout(options.IdleTimeout),
	); err != nil {
		return 0, 0, fmt.Errorf(
			"configure transaction timeouts: %w",
			classifyDeviceRevocationDatabaseError(ctx, err),
		)
	}
	var workspaceInternalID, networkInternalID int64
	if err := transaction.QueryRow(
		ctx,
		setDeviceRevocationScopeSQL,
		scope.WorkspaceID().String(),
		scope.NetworkID().String(),
	).Scan(&workspaceInternalID, &networkInternalID); err != nil {
		return 0, 0, fmt.Errorf(
			"set exact Network scope: %w",
			classifyDeviceRevocationDatabaseError(ctx, err),
		)
	}
	if workspaceInternalID <= 0 || networkInternalID <= 0 {
		return 0, 0, ErrDeviceRevocationEvidence
	}
	return workspaceInternalID, networkInternalID, nil
}

func validDeviceRevocationOptions(options DeviceRevocationOptions) bool {
	return options.StatementTimeout > 0 &&
		options.StatementTimeout <= maxDeviceRevocationStatementTimeout &&
		options.LockTimeout > 0 && options.LockTimeout <= maxDeviceRevocationLockTimeout &&
		options.IdleTimeout > 0 && options.IdleTimeout <= maxDeviceRevocationIdleTimeout
}

func rollbackDeviceRevocationSetup(transaction deviceRevocationDatabaseTransaction) error {
	ctx, cancel := context.WithTimeout(context.Background(), deviceRevocationSetupRollbackWindow)
	defer cancel()
	if err := transaction.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return fmt.Errorf("roll back Device revocation setup: %w", err)
	}
	return nil
}

func (store *DeviceRevocationStore) observe(
	operation postgresOperation,
	startedAt time.Time,
	err error,
) {
	if store == nil {
		return
	}
	store.metrics.observeOperation(operation, time.Since(startedAt), err)
}
