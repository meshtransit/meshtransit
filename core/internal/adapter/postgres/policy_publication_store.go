package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/network"
	publication "meshtransit.net/core/internal/domain/policy/publication"
)

const (
	maxPolicyPublicationStatementTimeout = time.Minute
	maxPolicyPublicationLockTimeout      = 30 * time.Second
	maxPolicyPublicationIdleTimeout      = time.Minute
	policyPublicationSetupRollbackWindow = 2 * time.Second
)

var (
	// ErrInvalidPolicyPublicationStore reports an unsafe runtime dependency or option.
	ErrInvalidPolicyPublicationStore = errors.New("invalid postgres policy publication store")
	// ErrBeginPolicyPublication classifies transaction setup failure.
	ErrBeginPolicyPublication = errors.New("begin postgres policy publication")
	// ErrPolicyPublicationState reports invalid transaction method ordering.
	ErrPolicyPublicationState = errors.New("postgres policy publication state is invalid")
	// ErrPolicyPublicationEvidence reports malformed durable publication authority.
	ErrPolicyPublicationEvidence = errors.New("postgres policy publication evidence is invalid")
	// ErrResolvePolicyPublication classifies locked-state resolution failure.
	ErrResolvePolicyPublication = errors.New("resolve postgres policy publication")
	// ErrApplyPolicyPublication classifies atomic mutation failure.
	ErrApplyPolicyPublication = errors.New("apply postgres policy publication")
	// ErrCommitPolicyPublication classifies commit failure.
	ErrCommitPolicyPublication = errors.New("commit postgres policy publication")
	// ErrRollbackPolicyPublication classifies rollback failure.
	ErrRollbackPolicyPublication = errors.New("rollback postgres policy publication")
	// ErrResolveCommittedPolicyPublication classifies immutable release replay failure.
	ErrResolveCommittedPolicyPublication = errors.New("resolve committed postgres policy publication")
)

// PolicyPublicationApprovalMode makes approval enforcement explicit at composition time.
type PolicyPublicationApprovalMode uint8

const (
	// PolicyPublicationApprovalModeUnknown is invalid and prevents fail-open composition.
	PolicyPublicationApprovalModeUnknown PolicyPublicationApprovalMode = iota
	// PolicyPublicationApprovalModeRequired enforces durable, single-use human approval.
	PolicyPublicationApprovalModeRequired
	// PolicyPublicationApprovalModeQualificationBypass is only for offline compatibility tests.
	PolicyPublicationApprovalModeQualificationBypass
	// PolicyPublicationApprovalModePublisherAuthorized permits direct publication
	// only after fresh exact-scope policy.publish AccountSession authorization.
	// Any supplied approval evidence still invokes the durable approval gate.
	PolicyPublicationApprovalModePublisherAuthorized
)

// PolicyPublicationOptions bounds every database wait in a publication transaction.
type PolicyPublicationOptions struct {
	StatementTimeout time.Duration
	LockTimeout      time.Duration
	IdleTimeout      time.Duration
	ApprovalMode     PolicyPublicationApprovalMode
	// AllowTrustedActor permits the offline qualification path to publish without
	// an Account Session. Runtime management composition must leave this false.
	AllowTrustedActor bool
}

// PolicyPublicationStore owns short runtime-scoped publication transactions.
type PolicyPublicationStore struct {
	database policyPublicationDatabase
	options  PolicyPublicationOptions
	metrics  *postgresPoolMetrics
}

var (
	_ publication.Transactions            = (*PolicyPublicationStore)(nil)
	_ publication.CommittedResultResolver = (*PolicyPublicationStore)(nil)
)

// NewPolicyPublicationStore constructs a publisher from a runtime-authenticated pool.
func NewPolicyPublicationStore(
	pool *Pool,
	options PolicyPublicationOptions,
) (*PolicyPublicationStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.policyPublicationDatabase == nil {
		return nil, ErrInvalidPolicyPublicationStore
	}
	return newPolicyPublicationStore(pool.policyPublicationDatabase, options, pool.metrics)
}

func newPolicyPublicationStore(
	database policyPublicationDatabase,
	options PolicyPublicationOptions,
	metrics *postgresPoolMetrics,
) (*PolicyPublicationStore, error) {
	if database == nil || !validPolicyPublicationOptions(options) {
		return nil, ErrInvalidPolicyPublicationStore
	}
	return &PolicyPublicationStore{database: database, options: options, metrics: metrics}, nil
}

// Begin fixes the exact Network scope in one READ COMMITTED read-write transaction.
func (store *PolicyPublicationStore) Begin(
	ctx context.Context,
	scope network.Scope,
) (_ publication.Transaction, resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.observe(postgresOperationPolicyPublicationBegin, startedAt, resultErr)
	}()

	if ctx == nil || store == nil || store.database == nil || !scope.IsValid() ||
		!validPolicyPublicationOptions(store.options) {
		return nil, ErrInvalidPolicyPublicationStore
	}
	databaseTransaction, err := store.database.Begin(ctx, false)
	if err != nil {
		return nil, errors.Join(
			ErrBeginPolicyPublication,
			classifyPolicyPublicationDatabaseError(ctx, err),
		)
	}
	owned := false
	defer func() {
		if owned {
			return
		}
		resultErr = errors.Join(resultErr, rollbackPolicyPublicationSetup(databaseTransaction))
	}()

	_, _, err = store.configureAndScope(
		ctx,
		databaseTransaction,
		scope,
	)
	if err != nil {
		return nil, errors.Join(ErrBeginPolicyPublication, err)
	}
	owned = true
	return &policyPublicationTransaction{
		database:              databaseTransaction,
		scope:                 scope,
		metrics:               store.metrics,
		requireAccountSession: !store.options.AllowTrustedActor,
		requireApproval:       store.options.ApprovalMode == PolicyPublicationApprovalModeRequired,
	}, nil
}

// ResolveCommitted identifies a possibly committed release without replaying mutation.
func (store *PolicyPublicationStore) ResolveCommitted(
	ctx context.Context,
	command publication.Command,
	releaseID publication.ReleaseID,
) (_ publication.Result, found bool, resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.observe(postgresOperationPolicyPublicationReplay, startedAt, resultErr)
	}()

	if ctx == nil || store == nil || store.database == nil || !command.IsValid() ||
		!releaseID.IsValid() || !validPolicyPublicationOptions(store.options) {
		return publication.Result{}, false, ErrInvalidPolicyPublicationStore
	}
	databaseTransaction, err := store.database.Begin(ctx, true)
	if err != nil {
		return publication.Result{}, false, errors.Join(
			ErrResolveCommittedPolicyPublication,
			classifyPolicyPublicationDatabaseError(ctx, err),
		)
	}
	closed := false
	defer func() {
		if closed {
			return
		}
		resultErr = errors.Join(resultErr, rollbackPolicyPublicationSetup(databaseTransaction))
	}()

	scope := command.Candidate().Snapshot().Scope()
	workspaceInternalID, networkInternalID, err := store.configureAndScope(
		ctx,
		databaseTransaction,
		scope,
	)
	if err != nil {
		return publication.Result{}, false, errors.Join(ErrResolveCommittedPolicyPublication, err)
	}
	var networkRevision, policyRevision int64
	var semanticHashValue []byte
	var approvalEvidenceID *string
	err = databaseTransaction.QueryRow(
		ctx,
		loadCommittedPolicyReleaseSQL,
		workspaceInternalID,
		networkInternalID,
		releaseID.String(),
	).Scan(&networkRevision, &policyRevision, &semanticHashValue, &approvalEvidenceID)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := databaseTransaction.Commit(ctx); err != nil {
			return publication.Result{}, false, errors.Join(
				ErrResolveCommittedPolicyPublication,
				classifyPolicyPublicationCommitError(ctx, err),
			)
		}
		closed = true
		return publication.Result{}, false, nil
	}
	if err != nil {
		return publication.Result{}, false, errors.Join(
			ErrResolveCommittedPolicyPublication,
			classifyPolicyPublicationDatabaseError(ctx, err),
		)
	}
	semanticHash, err := policyPublicationSemanticHash(semanticHashValue)
	if err != nil {
		return publication.Result{}, false, errors.Join(ErrResolveCommittedPolicyPublication, err)
	}
	result, err := publication.NewResult(publication.ResultParams{
		ReleaseID:       releaseID,
		Scope:           scope,
		NetworkRevision: networkRevision,
		PolicyRevision:  policyRevision,
		SemanticHash:    semanticHash,
	})
	if err != nil || policyRevision != command.Candidate().Snapshot().Revision() ||
		semanticHash != command.Candidate().SemanticHash() {
		return publication.Result{}, false, errors.Join(
			ErrResolveCommittedPolicyPublication,
			ErrPolicyPublicationEvidence,
			err,
		)
	}
	if command.HasApprovalEvidence() {
		if approvalEvidenceID == nil || *approvalEvidenceID != command.ApprovalEvidenceID().String() {
			return publication.Result{}, false, errors.Join(
				ErrResolveCommittedPolicyPublication,
				publication.ErrApprovalUnavailable,
			)
		}
	} else if approvalEvidenceID != nil {
		return publication.Result{}, false, errors.Join(
			ErrResolveCommittedPolicyPublication,
			ErrPolicyPublicationEvidence,
		)
	}
	if err := databaseTransaction.Commit(ctx); err != nil {
		return publication.Result{}, false, errors.Join(
			ErrResolveCommittedPolicyPublication,
			classifyPolicyPublicationCommitError(ctx, err),
		)
	}
	closed = true
	return result, true, nil
}

func (store *PolicyPublicationStore) configureAndScope(
	ctx context.Context,
	transaction policyPublicationDatabaseTransaction,
	scope network.Scope,
) (int64, int64, error) {
	options := store.options
	if err := transaction.Exec(
		ctx,
		configurePolicyPublicationTransactionSQL,
		postgresTimeout(options.StatementTimeout),
		postgresTimeout(options.LockTimeout),
		postgresTimeout(options.IdleTimeout),
	); err != nil {
		return 0, 0, fmt.Errorf(
			"configure transaction timeouts: %w",
			classifyPolicyPublicationDatabaseError(ctx, err),
		)
	}
	var workspaceInternalID, networkInternalID int64
	if err := transaction.QueryRow(
		ctx,
		setPolicyPublicationScopeSQL,
		scope.WorkspaceID().String(),
		scope.NetworkID().String(),
	).Scan(&workspaceInternalID, &networkInternalID); err != nil {
		return 0, 0, fmt.Errorf(
			"set exact Network scope: %w",
			classifyPolicyPublicationDatabaseError(ctx, err),
		)
	}
	if workspaceInternalID <= 0 || networkInternalID <= 0 {
		return 0, 0, ErrPolicyPublicationEvidence
	}
	return workspaceInternalID, networkInternalID, nil
}

func validPolicyPublicationOptions(options PolicyPublicationOptions) bool {
	if options.ApprovalMode == PolicyPublicationApprovalModePublisherAuthorized && options.AllowTrustedActor {
		return false
	}
	return options.StatementTimeout > 0 &&
		options.StatementTimeout <= maxPolicyPublicationStatementTimeout &&
		options.LockTimeout > 0 && options.LockTimeout <= maxPolicyPublicationLockTimeout &&
		options.IdleTimeout > 0 && options.IdleTimeout <= maxPolicyPublicationIdleTimeout &&
		(options.ApprovalMode == PolicyPublicationApprovalModeRequired ||
			options.ApprovalMode == PolicyPublicationApprovalModeQualificationBypass ||
			options.ApprovalMode == PolicyPublicationApprovalModePublisherAuthorized)
}

func rollbackPolicyPublicationSetup(transaction policyPublicationDatabaseTransaction) error {
	ctx, cancel := context.WithTimeout(context.Background(), policyPublicationSetupRollbackWindow)
	defer cancel()
	if err := transaction.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return fmt.Errorf("roll back policy publication setup: %w", err)
	}
	return nil
}

func (store *PolicyPublicationStore) observe(
	operation postgresOperation,
	startedAt time.Time,
	err error,
) {
	if store == nil {
		return
	}
	store.metrics.observeOperation(operation, time.Since(startedAt), err)
}
