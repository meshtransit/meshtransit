package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/ipam"
	"meshtransit.net/core/internal/domain/network"
)

const (
	maxRegistrationStatementTimeout = time.Minute
	maxRegistrationLockTimeout      = 30 * time.Second
	maxRegistrationIdleTimeout      = time.Minute
	maxRegistrationPrefixCount      = 8
	registrationSetupRollbackWindow = 2 * time.Second
)

var (
	// ErrInvalidRegistrationTransactions reports an unsafe runtime dependency or option.
	ErrInvalidRegistrationTransactions = errors.New("invalid postgres registration transactions")
	// ErrBeginRegistrationTransaction classifies transaction setup failure.
	ErrBeginRegistrationTransaction = errors.New("begin postgres registration transaction")
	// ErrRegistrationTransactionState reports invalid transaction method ordering.
	ErrRegistrationTransactionState = errors.New("postgres registration transaction state is invalid")
	// ErrRegistrationEvidence reports malformed durable registration authority.
	ErrRegistrationEvidence = errors.New("postgres registration evidence is invalid")
	// ErrRegistrationAllocation reports an unavailable bounded hostname or address allocation.
	ErrRegistrationAllocation = errors.New("postgres registration allocation is unavailable")
	// ErrResolveRegistrationTransaction classifies locked-state resolution failure.
	ErrResolveRegistrationTransaction = errors.New("resolve postgres registration transaction")
	// ErrApplyRegistrationTransaction classifies atomic mutation failure.
	ErrApplyRegistrationTransaction = errors.New("apply postgres registration transaction")
	// ErrCommitRegistrationTransaction classifies commit failure.
	ErrCommitRegistrationTransaction = errors.New("commit postgres registration transaction")
	// ErrRollbackRegistrationTransaction classifies rollback failure.
	ErrRollbackRegistrationTransaction = errors.New("rollback postgres registration transaction")
)

// RegistrationTransactionOptions bounds every database wait and allocation snapshot.
type RegistrationTransactionOptions struct {
	StatementTimeout      time.Duration
	LockTimeout           time.Duration
	IdleTimeout           time.Duration
	AddressCandidateLimit int
}

// RegistrationTransactions creates runtime-scoped registration units of work.
// It owns no goroutine or process-local correctness state.
type RegistrationTransactions struct {
	database registrationTransactionDatabase
	options  RegistrationTransactionOptions
	metrics  *postgresPoolMetrics
}

var _ registration.Transactions = (*RegistrationTransactions)(nil)

// NewRegistrationTransactions constructs an adapter from a runtime-authenticated pool.
func NewRegistrationTransactions(
	pool *Pool,
	options RegistrationTransactionOptions,
) (*RegistrationTransactions, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.registrationTransactionDatabase == nil {
		return nil, ErrInvalidRegistrationTransactions
	}
	return newRegistrationTransactions(pool.registrationTransactionDatabase, options, pool.metrics)
}

func newRegistrationTransactions(
	database registrationTransactionDatabase,
	options RegistrationTransactionOptions,
	metrics *postgresPoolMetrics,
) (*RegistrationTransactions, error) {
	if database == nil || !validRegistrationTransactionOptions(options) {
		return nil, ErrInvalidRegistrationTransactions
	}
	return &RegistrationTransactions{database: database, options: options, metrics: metrics}, nil
}

// Begin opens one READ COMMITTED transaction, installs finite database timeouts,
// and fixes the exact Network scope before returning it to the application.
func (transactions *RegistrationTransactions) Begin(
	ctx context.Context,
	scope network.Scope,
) (_ registration.Transaction, resultErr error) {
	if ctx == nil || transactions == nil || transactions.database == nil ||
		!validRegistrationTransactionOptions(transactions.options) || !scope.IsValid() {
		return nil, ErrInvalidRegistrationTransactions
	}
	startedAt := time.Now()
	defer func() {
		transactions.metrics.observeOperation(
			postgresOperationRegistrationBegin,
			time.Since(startedAt),
			resultErr,
		)
	}()

	databaseTransaction, err := transactions.database.Begin(ctx)
	if err != nil {
		return nil, errors.Join(
			ErrBeginRegistrationTransaction,
			classifyRegistrationDatabaseError(ctx, err),
		)
	}
	owned := false
	defer func() {
		if owned {
			return
		}
		rollbackErr := rollbackRegistrationSetup(databaseTransaction)
		resultErr = errors.Join(resultErr, rollbackErr)
	}()

	options := transactions.options
	if _, err := databaseTransaction.Exec(
		ctx,
		configureRegistrationTransactionSQL,
		postgresTimeout(options.StatementTimeout),
		postgresTimeout(options.LockTimeout),
		postgresTimeout(options.IdleTimeout),
	); err != nil {
		return nil, errors.Join(
			ErrBeginRegistrationTransaction,
			fmt.Errorf("configure transaction timeouts: %w", classifyRegistrationDatabaseError(ctx, err)),
		)
	}

	var workspaceInternalID, networkInternalID int64
	if err := databaseTransaction.QueryRow(
		ctx,
		setRegistrationTransactionScopeSQL,
		scope.WorkspaceID().String(),
		scope.NetworkID().String(),
	).Scan(&workspaceInternalID, &networkInternalID); err != nil {
		return nil, errors.Join(
			ErrBeginRegistrationTransaction,
			fmt.Errorf("set exact network scope: %w", classifyRegistrationDatabaseError(ctx, err)),
		)
	}
	if workspaceInternalID <= 0 || networkInternalID <= 0 {
		return nil, errors.Join(ErrBeginRegistrationTransaction, ErrRegistrationEvidence)
	}

	decisionAt, err := readTransactionTime(ctx, databaseTransaction.QueryRow)
	if err != nil {
		return nil, errors.Join(ErrBeginRegistrationTransaction, classifyRegistrationDatabaseError(ctx, err))
	}

	owned = true
	return &registrationTransaction{
		decisionAt:          decisionAt,
		database:            databaseTransaction,
		scope:               scope,
		workspaceInternalID: workspaceInternalID,
		networkInternalID:   networkInternalID,
		candidateLimit:      options.AddressCandidateLimit,
		metrics:             transactions.metrics,
	}, nil
}

func validRegistrationTransactionOptions(options RegistrationTransactionOptions) bool {
	return options.StatementTimeout > 0 &&
		options.StatementTimeout <= maxRegistrationStatementTimeout &&
		options.LockTimeout > 0 && options.LockTimeout <= maxRegistrationLockTimeout &&
		options.IdleTimeout > 0 && options.IdleTimeout <= maxRegistrationIdleTimeout &&
		options.AddressCandidateLimit > 0 && options.AddressCandidateLimit <= ipam.MaxCandidateLimit
}

func postgresTimeout(value time.Duration) string {
	return strconv.FormatInt(value.Milliseconds(), 10) + "ms"
}

func rollbackRegistrationSetup(transaction registrationDatabaseTransaction) error {
	ctx, cancel := context.WithTimeout(context.Background(), registrationSetupRollbackWindow)
	defer cancel()
	if err := transaction.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return fmt.Errorf("roll back registration transaction setup: %w", err)
	}
	return nil
}
