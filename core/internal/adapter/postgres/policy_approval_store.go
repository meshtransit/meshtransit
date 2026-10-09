package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	approval "github.com/meshtransit/meshtransit/core/internal/domain/policy/approval"
)

const (
	maxPolicyApprovalStatementTimeout = time.Minute
	maxPolicyApprovalLockTimeout      = 30 * time.Second
	maxPolicyApprovalIdleTimeout      = time.Minute
	policyApprovalSetupRollbackWindow = 2 * time.Second
)

var (
	// ErrInvalidPolicyApprovalStore reports an unsafe runtime dependency or option.
	ErrInvalidPolicyApprovalStore = errors.New("invalid postgres policy approval store")
	// ErrBeginPolicyApproval classifies transaction setup failure.
	ErrBeginPolicyApproval = errors.New("begin postgres policy approval")
	// ErrPolicyApprovalState reports invalid transaction method ordering.
	ErrPolicyApprovalState = errors.New("postgres policy approval state is invalid")
	// ErrPolicyApprovalEvidence reports malformed durable workflow evidence.
	ErrPolicyApprovalEvidence = errors.New("postgres policy approval evidence is invalid")
	// ErrResolvePolicyApproval classifies locked-state resolution failure.
	ErrResolvePolicyApproval = errors.New("resolve postgres policy approval")
	// ErrApplyPolicyApproval classifies atomic mutation failure.
	ErrApplyPolicyApproval = errors.New("apply postgres policy approval")
	// ErrCommitPolicyApproval classifies commit failure.
	ErrCommitPolicyApproval = errors.New("commit postgres policy approval")
	// ErrRollbackPolicyApproval classifies rollback failure.
	ErrRollbackPolicyApproval = errors.New("rollback postgres policy approval")
	// ErrResolveCommittedPolicyApproval classifies immutable replay lookup failure.
	ErrResolveCommittedPolicyApproval = errors.New("resolve committed postgres policy approval")
)

// PolicyApprovalOptions bounds every database wait in approval workflow transactions.
type PolicyApprovalOptions struct {
	StatementTimeout time.Duration
	LockTimeout      time.Duration
	IdleTimeout      time.Duration
}

// PolicyApprovalStore owns exact-scope proposal and independent-approval transactions.
type PolicyApprovalStore struct {
	database policyApprovalDatabase
	options  PolicyApprovalOptions
	metrics  *postgresPoolMetrics
}

var (
	_ approval.RequestTransactions       = (*PolicyApprovalStore)(nil)
	_ approval.Transactions              = (*PolicyApprovalStore)(nil)
	_ approval.CommittedRequestResolver  = (*PolicyApprovalStore)(nil)
	_ approval.CommittedApprovalResolver = (*PolicyApprovalStore)(nil)
)

// NewPolicyApprovalStore constructs durable policy approval persistence.
func NewPolicyApprovalStore(
	pool *Pool,
	options PolicyApprovalOptions,
) (*PolicyApprovalStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.policyApprovalDatabase == nil {
		return nil, ErrInvalidPolicyApprovalStore
	}
	return newPolicyApprovalStore(pool.policyApprovalDatabase, options, pool.metrics)
}

func newPolicyApprovalStore(
	database policyApprovalDatabase,
	options PolicyApprovalOptions,
	metrics *postgresPoolMetrics,
) (*PolicyApprovalStore, error) {
	if database == nil || !validPolicyApprovalOptions(options) {
		return nil, ErrInvalidPolicyApprovalStore
	}
	return &PolicyApprovalStore{database: database, options: options, metrics: metrics}, nil
}

// BeginApprovalRequest starts one short proposal transaction.
func (store *PolicyApprovalStore) BeginApprovalRequest(
	ctx context.Context,
	scope network.Scope,
) (_ approval.RequestTransaction, resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.observe(postgresOperationPolicyApprovalRequestBegin, startedAt, resultErr)
	}()
	database, err := store.begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	return &policyApprovalRequestTransaction{
		core: policyApprovalTransactionCore{
			database: database, scope: scope, metrics: store.metrics,
		},
	}, nil
}

// BeginPolicyApproval starts one short independent-human decision transaction.
func (store *PolicyApprovalStore) BeginPolicyApproval(
	ctx context.Context,
	scope network.Scope,
) (_ approval.Transaction, resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.observe(postgresOperationPolicyApprovalDecisionBegin, startedAt, resultErr)
	}()
	database, err := store.begin(ctx, scope)
	if err != nil {
		return nil, err
	}
	return &policyApprovalDecisionTransaction{
		core: policyApprovalTransactionCore{
			database: database, scope: scope, metrics: store.metrics,
		},
	}, nil
}

func (store *PolicyApprovalStore) begin(
	ctx context.Context,
	scope network.Scope,
) (_ policyApprovalDatabaseTransaction, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !scope.IsValid() ||
		!validPolicyApprovalOptions(store.options) {
		return nil, ErrInvalidPolicyApprovalStore
	}
	database, err := store.database.Begin(ctx, false)
	if err != nil {
		return nil, errors.Join(ErrBeginPolicyApproval, classifyPolicyApprovalDatabaseError(ctx, err))
	}
	owned := false
	defer func() {
		if !owned {
			resultErr = errors.Join(resultErr, rollbackPolicyApprovalSetup(database))
		}
	}()
	if _, _, err := store.configureAndScope(ctx, database, scope); err != nil {
		return nil, errors.Join(ErrBeginPolicyApproval, err)
	}
	owned = true
	return database, nil
}

// ResolveCommittedApprovalRequest resolves an uncertain proposal commit by stable ID.
func (store *PolicyApprovalStore) ResolveCommittedApprovalRequest(
	ctx context.Context,
	command approval.RequestCommand,
	mutationIDs approval.RequestMutationIDs,
) (_ approval.RequestResult, found bool, resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.observe(postgresOperationPolicyApprovalRequestReplay, startedAt, resultErr)
	}()
	if ctx == nil || store == nil || !command.IsValid() || !mutationIDs.IsValid() {
		return approval.RequestResult{}, false, ErrInvalidPolicyApprovalStore
	}
	database, err := store.beginReadOnly(ctx, command.Scope())
	if err != nil {
		return approval.RequestResult{}, false, err
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackPolicyApprovalSetup(database))
		}
	}()
	record, err := scanPolicyApprovalRequest(database.QueryRow(
		ctx, loadPolicyApprovalRequestSQL, mutationIDs.RequestID().String(),
	))
	if errors.Is(err, pgx.ErrNoRows) {
		if err := database.Commit(ctx); err != nil {
			return approval.RequestResult{}, false, errors.Join(
				ErrResolveCommittedPolicyApproval,
				classifyPolicyApprovalCommitError(ctx, err),
			)
		}
		closed = true
		return approval.RequestResult{}, false, nil
	}
	if err != nil {
		return approval.RequestResult{}, false, errors.Join(
			ErrResolveCommittedPolicyApproval,
			classifyPolicyApprovalDatabaseError(ctx, err),
		)
	}
	result, err := record.result(command.Scope(), mutationIDs.RequestID())
	if err != nil {
		return approval.RequestResult{}, false, errors.Join(ErrResolveCommittedPolicyApproval, err)
	}
	if err := database.Commit(ctx); err != nil {
		return approval.RequestResult{}, false, errors.Join(
			ErrResolveCommittedPolicyApproval,
			classifyPolicyApprovalCommitError(ctx, err),
		)
	}
	closed = true
	return result, true, nil
}

// ResolveCommittedPolicyApproval resolves an uncertain approval commit by stable ID.
func (store *PolicyApprovalStore) ResolveCommittedPolicyApproval(
	ctx context.Context,
	command approval.Command,
	mutationIDs approval.MutationIDs,
) (_ approval.Result, found bool, resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.observe(postgresOperationPolicyApprovalDecisionReplay, startedAt, resultErr)
	}()
	if ctx == nil || store == nil || !command.IsValid() || !mutationIDs.IsValid() {
		return approval.Result{}, false, ErrInvalidPolicyApprovalStore
	}
	database, err := store.beginReadOnly(ctx, command.Scope())
	if err != nil {
		return approval.Result{}, false, err
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackPolicyApprovalSetup(database))
		}
	}()
	record, err := scanPolicyApprovalEvidence(database.QueryRow(
		ctx, loadPolicyApprovalEvidenceSQL, mutationIDs.EvidenceID().String(),
	))
	if errors.Is(err, pgx.ErrNoRows) {
		if err := database.Commit(ctx); err != nil {
			return approval.Result{}, false, errors.Join(
				ErrResolveCommittedPolicyApproval,
				classifyPolicyApprovalCommitError(ctx, err),
			)
		}
		closed = true
		return approval.Result{}, false, nil
	}
	if err != nil {
		return approval.Result{}, false, errors.Join(
			ErrResolveCommittedPolicyApproval,
			classifyPolicyApprovalDatabaseError(ctx, err),
		)
	}
	result, err := record.result(command.Scope(), mutationIDs.EvidenceID())
	if err != nil {
		return approval.Result{}, false, errors.Join(ErrResolveCommittedPolicyApproval, err)
	}
	if err := database.Commit(ctx); err != nil {
		return approval.Result{}, false, errors.Join(
			ErrResolveCommittedPolicyApproval,
			classifyPolicyApprovalCommitError(ctx, err),
		)
	}
	closed = true
	return result, true, nil
}

func (store *PolicyApprovalStore) beginReadOnly(
	ctx context.Context,
	scope network.Scope,
) (_ policyApprovalDatabaseTransaction, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !scope.IsValid() ||
		!validPolicyApprovalOptions(store.options) {
		return nil, ErrInvalidPolicyApprovalStore
	}
	database, err := store.database.Begin(ctx, true)
	if err != nil {
		return nil, errors.Join(
			ErrResolveCommittedPolicyApproval,
			classifyPolicyApprovalDatabaseError(ctx, err),
		)
	}
	owned := false
	defer func() {
		if !owned {
			resultErr = errors.Join(resultErr, rollbackPolicyApprovalSetup(database))
		}
	}()
	if _, _, err := store.configureAndScope(ctx, database, scope); err != nil {
		return nil, errors.Join(ErrResolveCommittedPolicyApproval, err)
	}
	owned = true
	return database, nil
}

func (store *PolicyApprovalStore) configureAndScope(
	ctx context.Context,
	database policyApprovalDatabaseTransaction,
	scope network.Scope,
) (int64, int64, error) {
	if err := database.Exec(
		ctx,
		configurePolicyApprovalTransactionSQL,
		postgresTimeout(store.options.StatementTimeout),
		postgresTimeout(store.options.LockTimeout),
		postgresTimeout(store.options.IdleTimeout),
	); err != nil {
		return 0, 0, fmt.Errorf(
			"configure Policy approval transaction: %w",
			classifyPolicyApprovalDatabaseError(ctx, err),
		)
	}
	var workspaceInternalID, networkInternalID int64
	if err := database.QueryRow(
		ctx,
		setPolicyApprovalScopeSQL,
		scope.WorkspaceID().String(),
		scope.NetworkID().String(),
	).Scan(&workspaceInternalID, &networkInternalID); err != nil {
		return 0, 0, fmt.Errorf(
			"set Policy approval Network scope: %w",
			classifyPolicyApprovalDatabaseError(ctx, err),
		)
	}
	if workspaceInternalID <= 0 || networkInternalID <= 0 {
		return 0, 0, ErrPolicyApprovalEvidence
	}
	return workspaceInternalID, networkInternalID, nil
}

func validPolicyApprovalOptions(options PolicyApprovalOptions) bool {
	return options.StatementTimeout > 0 &&
		options.StatementTimeout <= maxPolicyApprovalStatementTimeout &&
		options.LockTimeout > 0 && options.LockTimeout <= maxPolicyApprovalLockTimeout &&
		options.IdleTimeout > 0 && options.IdleTimeout <= maxPolicyApprovalIdleTimeout
}

func rollbackPolicyApprovalSetup(database policyApprovalDatabaseTransaction) error {
	ctx, cancel := context.WithTimeout(context.Background(), policyApprovalSetupRollbackWindow)
	defer cancel()
	if err := database.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return fmt.Errorf("roll back Policy approval setup: %w", err)
	}
	return nil
}

func (store *PolicyApprovalStore) observe(
	operation postgresOperation,
	startedAt time.Time,
	err error,
) {
	if store != nil {
		store.metrics.observeOperation(operation, time.Since(startedAt), err)
	}
}
