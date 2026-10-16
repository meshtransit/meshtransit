package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/resource"
	authority "meshtransit.net/core/internal/domain/resource/authority"
)

const (
	maximumResourceAuthorityStatementTimeout = time.Minute
	maximumResourceAuthorityLockTimeout      = 30 * time.Second
	maximumResourceAuthorityIdleTimeout      = time.Minute
	resourceAuthoritySetupRollbackWindow     = 2 * time.Second
)

var (
	// ErrInvalidResourceAuthorityStore reports an unsafe dependency or option.
	ErrInvalidResourceAuthorityStore = errors.New("invalid postgres Resource authority store")
	// ErrBeginResourceAuthority classifies transaction setup failure.
	ErrBeginResourceAuthority = errors.New("begin postgres Resource authority")
	// ErrResourceAuthorityState reports invalid transaction method ordering.
	ErrResourceAuthorityState = errors.New("postgres Resource authority state is invalid")
	// ErrResourceAuthorityEvidence reports malformed durable authority.
	ErrResourceAuthorityEvidence = errors.New("postgres Resource authority evidence is invalid")
	// ErrResolveResourceAuthority classifies locked-state resolution failure.
	ErrResolveResourceAuthority = errors.New("resolve postgres Resource authority")
	// ErrApplyResourceAuthority classifies atomic mutation failure.
	ErrApplyResourceAuthority = errors.New("apply postgres Resource authority")
	// ErrCommitResourceAuthority classifies commit failure.
	ErrCommitResourceAuthority = errors.New("commit postgres Resource authority")
	// ErrRollbackResourceAuthority classifies rollback failure.
	ErrRollbackResourceAuthority = errors.New("rollback postgres Resource authority")
	// ErrResolveCommittedResourceAuthority classifies stable-ID replay failure.
	ErrResolveCommittedResourceAuthority = errors.New("resolve committed postgres Resource authority")
)

// ResourceAuthorityOptions bounds every database wait in an authority transaction.
type ResourceAuthorityOptions struct {
	StatementTimeout time.Duration
	LockTimeout      time.Duration
	IdleTimeout      time.Duration
}

// ResourceAuthorityStore owns short, exact-scope authority transactions.
type ResourceAuthorityStore struct {
	database resourceAuthorityDatabase
	options  ResourceAuthorityOptions
	metrics  *postgresPoolMetrics
}

var (
	_ authority.Transactions            = (*ResourceAuthorityStore)(nil)
	_ authority.CommittedResultResolver = (*ResourceAuthorityStore)(nil)
)

// NewResourceAuthorityStore constructs a store from a runtime-authenticated pool.
func NewResourceAuthorityStore(
	pool *Pool,
	options ResourceAuthorityOptions,
) (*ResourceAuthorityStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.resourceAuthorityDatabase == nil {
		return nil, ErrInvalidResourceAuthorityStore
	}
	return newResourceAuthorityStore(pool.resourceAuthorityDatabase, options, pool.metrics)
}

func newResourceAuthorityStore(
	database resourceAuthorityDatabase,
	options ResourceAuthorityOptions,
	metrics *postgresPoolMetrics,
) (*ResourceAuthorityStore, error) {
	if database == nil || !validResourceAuthorityOptions(options) {
		return nil, ErrInvalidResourceAuthorityStore
	}
	return &ResourceAuthorityStore{database: database, options: options, metrics: metrics}, nil
}

// Begin fixes exact Network scope in one READ COMMITTED read-write transaction.
func (store *ResourceAuthorityStore) Begin(
	ctx context.Context,
	scope network.Scope,
) (_ authority.Transaction, resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.observe(postgresOperationResourceAuthorityBegin, startedAt, resultErr)
	}()
	if ctx == nil || store == nil || store.database == nil || !scope.IsValid() ||
		!validResourceAuthorityOptions(store.options) {
		return nil, ErrInvalidResourceAuthorityStore
	}
	databaseTransaction, err := store.database.Begin(ctx, false)
	if err != nil {
		return nil, errors.Join(
			ErrBeginResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	owned := false
	defer func() {
		if !owned {
			resultErr = errors.Join(resultErr, rollbackResourceAuthoritySetup(databaseTransaction))
		}
	}()
	decisionAt, err := store.configureAndScope(ctx, databaseTransaction, scope)
	if err != nil {
		return nil, errors.Join(ErrBeginResourceAuthority, err)
	}
	owned = true
	return &resourceAuthorityTransaction{
		decisionAt: decisionAt, database: databaseTransaction, scope: scope, metrics: store.metrics,
	}, nil
}

// ResolveCommitted identifies a possibly committed aggregate without replaying mutation.
func (store *ResourceAuthorityStore) ResolveCommitted(
	ctx context.Context,
	command authority.Command,
	ids authority.MutationIDs,
) (_ authority.Result, found bool, resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.observe(postgresOperationResourceAuthorityReplay, startedAt, resultErr)
	}()
	if ctx == nil || store == nil || store.database == nil || !command.IsValid() ||
		!ids.IsValidFor(command) || !validResourceAuthorityOptions(store.options) {
		return authority.Result{}, false, ErrInvalidResourceAuthorityStore
	}
	transaction, err := store.database.Begin(ctx, false)
	if err != nil {
		return authority.Result{}, false, errors.Join(
			ErrResolveCommittedResourceAuthority,
			classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackResourceAuthoritySetup(transaction))
		}
	}()
	decisionAt, err := store.configureAndScope(ctx, transaction, command.Scope())
	if err != nil {
		return authority.Result{}, false, errors.Join(ErrResolveCommittedResourceAuthority, err)
	}
	evaluatedAt := decisionAt
	authorizationTransaction := resourceAuthorityTransaction{
		database: transaction,
		scope:    command.Scope(),
	}
	if _, err := authorizationTransaction.resolveAuthorization(ctx, command, evaluatedAt); err != nil {
		return authority.Result{}, false, errors.Join(
			ErrResolveCommittedResourceAuthority,
			classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	proof := command.IdempotencyEvidence()
	digest := proof.Digest()
	record, err := scanResourceAuthorityIdempotencyRecord(
		transaction.QueryRow(
			ctx,
			loadResourceAuthorityIdempotencySQL,
			command.AccountSession().PrincipalID().String(),
			resourceAuthorityOperation(command),
			proof.DigestKeyID(),
			digest[:],
		),
		false,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := transaction.Commit(ctx); err != nil {
			return authority.Result{}, false, errors.Join(
				ErrResolveCommittedResourceAuthority,
				classifyResourceAuthorityCommitError(ctx, err),
			)
		}
		closed = true
		return authority.Result{}, false, nil
	}
	if err != nil {
		return authority.Result{}, false, errors.Join(
			ErrResolveCommittedResourceAuthority,
			classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	result, found, err := resourceAuthorityCommittedRecord(record, command, evaluatedAt)
	if err != nil {
		return authority.Result{}, false, errors.Join(ErrResolveCommittedResourceAuthority, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return authority.Result{}, false, errors.Join(
			ErrResolveCommittedResourceAuthority,
			classifyResourceAuthorityCommitError(ctx, err),
		)
	}
	closed = true
	return result, found, nil
}

//nolint:unused // Retained as a compatibility verifier for pre-M2 aggregate replay evidence.
func resolveCommittedResourceAuthority(
	ctx context.Context,
	transaction resourceAuthorityDatabaseTransaction,
	command authority.Command,
	ids authority.MutationIDs,
) (authority.Result, bool, error) {
	var version, targetOrDefinition, networkRevision, subsystemRevision int64
	var semanticHashValue []byte
	var state string
	if command.Operation() == authority.OperationCreateDevice {
		var resourceIDValue, displayName, ownerID, custodianID, deviceID string
		err := transaction.QueryRow(
			ctx, resolveCommittedDeviceResourceSQL, ids.ResourceID().String(),
		).Scan(
			&resourceIDValue, &displayName, &ownerID, &custodianID, &deviceID,
			&version, &targetOrDefinition, &semanticHashValue, &state,
			&networkRevision, &subsystemRevision,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return authority.Result{}, false, nil
		}
		if err != nil {
			return authority.Result{}, false, classifyResourceAuthorityDatabaseError(ctx, err)
		}
		definition := command.Device()
		if resourceIDValue != ids.ResourceID().String() ||
			displayName != definition.DisplayName().String() ||
			ownerID != definition.OwnerPrincipalID().String() ||
			custodianID != definition.CustodianPrincipalID().String() ||
			deviceID != definition.DeviceID().String() || targetOrDefinition != 1 {
			return authority.Result{}, false, ErrResourceAuthorityEvidence
		}
	} else {
		var groupIDValue, displayName, ownerID, custodianID string
		var membersValue []byte
		err := transaction.QueryRow(
			ctx, resolveCommittedResourceGroupSQL, ids.GroupID().String(),
		).Scan(
			&groupIDValue, &displayName, &ownerID, &custodianID,
			&version, &targetOrDefinition, &semanticHashValue, &state,
			&networkRevision, &subsystemRevision, &membersValue,
		)
		if errors.Is(err, pgx.ErrNoRows) {
			return authority.Result{}, false, nil
		}
		if err != nil {
			return authority.Result{}, false, classifyResourceAuthorityDatabaseError(ctx, err)
		}
		definition := command.Group()
		if groupIDValue != ids.GroupID().String() ||
			displayName != definition.DisplayName().String() ||
			ownerID != definition.OwnerPrincipalID().String() ||
			custodianID != definition.CustodianPrincipalID().String() ||
			targetOrDefinition != definition.DefinitionVersion() ||
			!resourceGroupMembersMatch(membersValue, definition.Members()) {
			return authority.Result{}, false, ErrResourceAuthorityEvidence
		}
	}
	semanticHash, err := resourceSemanticHash(semanticHashValue)
	if err != nil || version != 1 || state != "active" || semanticHash != command.SemanticHash() {
		return authority.Result{}, false, errors.Join(ErrResourceAuthorityEvidence, err)
	}
	result, err := authority.NewResult(
		command.Operation(), ids.ResourceID(), ids.GroupID(), command.Scope(),
		networkRevision, subsystemRevision, version, semanticHash,
	)
	if err != nil {
		return authority.Result{}, false, errors.Join(ErrResourceAuthorityEvidence, err)
	}
	return result, true, nil
}

//nolint:unused // Retained with the compatibility aggregate replay verifier.
type resolvedResourceGroupMember struct {
	ResourcePublicID string `json:"resource_public_id"`
	ResourceVersion  int64  `json:"resource_version"`
	TargetGeneration int64  `json:"target_generation"`
}

//nolint:unused // Retained with the compatibility aggregate replay verifier.
func resourceGroupMembersMatch(encoded []byte, expected []resource.Reference) bool {
	var actual []resolvedResourceGroupMember
	if len(encoded) == 0 || json.Unmarshal(encoded, &actual) != nil || len(actual) != len(expected) {
		return false
	}
	for index := range expected {
		if actual[index].ResourcePublicID != expected[index].ResourceID().String() ||
			actual[index].ResourceVersion != expected[index].ResourceVersion() ||
			actual[index].TargetGeneration != expected[index].TargetGeneration() {
			return false
		}
	}
	return true
}

func resourceSemanticHash(value []byte) (resource.SemanticHash, error) {
	var fixed [sha256.Size]byte
	if len(value) != len(fixed) {
		return resource.SemanticHash{}, ErrResourceAuthorityEvidence
	}
	copy(fixed[:], value)
	hash, err := resource.NewSemanticHash(fixed)
	if err != nil {
		return resource.SemanticHash{}, ErrResourceAuthorityEvidence
	}
	return hash, nil
}

// configureAndScope configures one unit of work, fixes its exact Network
// scope and returns its time on the database clock, which every
// authorization, idempotency deadline and persisted time in it uses.
func (store *ResourceAuthorityStore) configureAndScope(
	ctx context.Context,
	transaction resourceAuthorityDatabaseTransaction,
	scope network.Scope,
) (time.Time, error) {
	if err := transaction.Exec(
		ctx,
		configureResourceAuthoritySQL,
		postgresTimeout(store.options.StatementTimeout),
		postgresTimeout(store.options.LockTimeout),
		postgresTimeout(store.options.IdleTimeout),
	); err != nil {
		return time.Time{}, fmt.Errorf("configure transaction timeouts: %w", classifyResourceAuthorityDatabaseError(ctx, err))
	}
	var workspaceInternalID, networkInternalID int64
	if err := transaction.QueryRow(
		ctx, setResourceAuthorityScopeSQL,
		scope.WorkspaceID().String(), scope.NetworkID().String(),
	).Scan(&workspaceInternalID, &networkInternalID); err != nil {
		return time.Time{}, fmt.Errorf("set exact Network scope: %w", classifyResourceAuthorityDatabaseError(ctx, err))
	}
	if workspaceInternalID <= 0 || networkInternalID <= 0 {
		return time.Time{}, ErrResourceAuthorityEvidence
	}
	decisionAt, err := readTransactionTime(ctx, transaction.QueryRow)
	if err != nil {
		return time.Time{}, fmt.Errorf("read database time: %w", classifyResourceAuthorityDatabaseError(ctx, err))
	}
	return decisionAt, nil
}

func validResourceAuthorityOptions(options ResourceAuthorityOptions) bool {
	return options.StatementTimeout > 0 &&
		options.StatementTimeout <= maximumResourceAuthorityStatementTimeout &&
		options.LockTimeout > 0 && options.LockTimeout <= maximumResourceAuthorityLockTimeout &&
		options.IdleTimeout > 0 && options.IdleTimeout <= maximumResourceAuthorityIdleTimeout
}

func rollbackResourceAuthoritySetup(transaction resourceAuthorityDatabaseTransaction) error {
	ctx, cancel := context.WithTimeout(context.Background(), resourceAuthoritySetupRollbackWindow)
	defer cancel()
	if err := transaction.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return fmt.Errorf("roll back Resource authority setup: %w", err)
	}
	return nil
}

func (store *ResourceAuthorityStore) observe(
	operation postgresOperation,
	startedAt time.Time,
	err error,
) {
	if store != nil {
		store.metrics.observeOperation(operation, time.Since(startedAt), err)
	}
}
