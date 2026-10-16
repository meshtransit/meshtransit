package registrationintake

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"meshtransit.net/core/internal/adapter/postgres/dbclock"
	"meshtransit.net/core/internal/domain/deployment"
	appintake "meshtransit.net/core/internal/domain/enrollment/registration/intake"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/workspace"
)

const (
	maxStatementTimeout = time.Minute
	maxLockTimeout      = 30 * time.Second
	maxIdleTimeout      = time.Minute
	setupRollbackWindow = 2 * time.Second
)

var (
	// ErrInvalidTransactions reports a missing database or unsafe timeout configuration.
	ErrInvalidTransactions = errors.New("invalid postgres registration intake transactions")
	// ErrBeginTransaction classifies transaction setup failure.
	ErrBeginTransaction = errors.New("begin postgres registration intake transaction")
	// ErrTransactionState reports invalid transaction method ordering.
	ErrTransactionState = errors.New("postgres registration intake transaction state is invalid")
	// ErrEvidence reports malformed durable registration-intake authority.
	ErrEvidence = errors.New("postgres registration intake evidence is invalid")
	// ErrResolveTransaction classifies locked-state resolution failure.
	ErrResolveTransaction = errors.New("resolve postgres registration intake transaction")
	// ErrApplyTransaction classifies pending-intent mutation failure.
	ErrApplyTransaction = errors.New("apply postgres registration intake transaction")
	// ErrCommitTransaction classifies commit failure.
	ErrCommitTransaction = errors.New("commit postgres registration intake transaction")
	// ErrRollbackTransaction classifies rollback failure.
	ErrRollbackTransaction = errors.New("rollback postgres registration intake transaction")
	// ErrResolvePrepared classifies uncertain-commit resolution failure.
	ErrResolvePrepared = errors.New("resolve prepared postgres registration intent")
)

// Options bounds every database wait owned by the adapter.
type Options struct {
	StatementTimeout time.Duration
	LockTimeout      time.Duration
	IdleTimeout      time.Duration
}

// Transactions creates scoped registration-intake units of work and resolves
// uncertain commits. It owns no goroutine or process-local correctness state.
type Transactions struct {
	database database
	options  Options
	observer Observer
}

var (
	_ appintake.Transactions           = (*Transactions)(nil)
	_ appintake.PreparedIntentResolver = (*Transactions)(nil)
)

// NewTransactions constructs a bounded PostgreSQL registration-intake adapter.
func NewTransactions(
	pool *pgxpool.Pool,
	options Options,
	observers ...Observer,
) (*Transactions, error) {
	return newTransactions(newPGXDatabase(pool), options, observers...)
}

func newTransactions(
	database database,
	options Options,
	observers ...Observer,
) (*Transactions, error) {
	if database == nil || !validOptions(options) || len(observers) > 1 ||
		(len(observers) == 1 && observers[0] == nil) {
		return nil, ErrInvalidTransactions
	}
	var observer Observer
	if len(observers) == 1 {
		observer = observers[0]
	}
	return &Transactions{database: database, options: options, observer: observer}, nil
}

// Begin opens READ COMMITTED, resolves server-owned scope from the credential,
// installs exact RLS scope, and returns an application-owned transaction.
func (transactions *Transactions) Begin(
	ctx context.Context,
	lookup appintake.Lookup,
) (_ appintake.Transaction, resultErr error) {
	if ctx == nil || transactions == nil || transactions.database == nil ||
		!validOptions(transactions.options) || !lookup.IsValid() {
		return nil, ErrInvalidTransactions
	}
	startedAt := time.Now()
	defer func() {
		observe(transactions.observer, OperationBegin, startedAt, resultErr)
	}()
	databaseTransaction, err := transactions.database.Begin(ctx)
	if err != nil {
		return nil, errors.Join(ErrBeginTransaction, classifyDatabaseError(ctx, err))
	}
	owned := false
	defer func() {
		if owned {
			return
		}
		resultErr = errors.Join(resultErr, rollbackSetup(databaseTransaction))
	}()
	if err := configure(ctx, databaseTransaction, transactions.options); err != nil {
		return nil, errors.Join(ErrBeginTransaction, classifyDatabaseError(ctx, err))
	}

	resolved, err := resolveScope(ctx, databaseTransaction, lookup)
	if err != nil {
		return nil, errors.Join(ErrBeginTransaction, classifyDatabaseError(ctx, err))
	}
	var workspaceInternalID, networkInternalID int64
	if err := databaseTransaction.QueryRow(
		ctx,
		setScopeSQL,
		resolved.scope.WorkspaceID().String(),
		resolved.scope.NetworkID().String(),
	).Scan(&workspaceInternalID, &networkInternalID); err != nil {
		return nil, errors.Join(ErrBeginTransaction, classifyDatabaseError(ctx, err))
	}
	if workspaceInternalID <= 0 || networkInternalID <= 0 {
		return nil, errors.Join(ErrBeginTransaction, ErrEvidence)
	}

	decisionAt, err := dbclock.Read(ctx, databaseTransaction.QueryRow)
	if err != nil {
		return nil, errors.Join(ErrBeginTransaction, classifyDatabaseError(ctx, err))
	}

	owned = true
	return &transaction{
		decisionAt:          decisionAt,
		database:            databaseTransaction,
		lookup:              lookup,
		deploymentID:        resolved.deploymentID,
		scope:               resolved.scope,
		recoveryEpoch:       resolved.recoveryEpoch,
		workspaceInternalID: workspaceInternalID,
		networkInternalID:   networkInternalID,
		observer:            transactions.observer,
	}, nil
}

type resolvedScope struct {
	deploymentID  deployment.ID
	scope         network.Scope
	recoveryEpoch int64
}

func resolveScope(
	ctx context.Context,
	transaction databaseTransaction,
	lookup appintake.Lookup,
) (resolvedScope, error) {
	var deploymentValue, workspaceValue, networkValue string
	var recoveryEpoch int64
	if err := transaction.QueryRow(ctx, resolveScopeSQL, lookup.CredentialID.String()).Scan(
		&deploymentValue,
		&workspaceValue,
		&networkValue,
		&recoveryEpoch,
	); err != nil {
		return resolvedScope{}, fmt.Errorf("resolve credential scope: %w", err)
	}
	deploymentID, err := deployment.ParseID(deploymentValue)
	if err != nil {
		return resolvedScope{}, ErrEvidence
	}
	workspaceID, err := workspace.ParseID(workspaceValue)
	if err != nil {
		return resolvedScope{}, ErrEvidence
	}
	networkID, err := network.ParseID(networkValue)
	if err != nil {
		return resolvedScope{}, ErrEvidence
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil || recoveryEpoch <= 0 {
		return resolvedScope{}, ErrEvidence
	}
	return resolvedScope{
		deploymentID:  deploymentID,
		scope:         scope,
		recoveryEpoch: recoveryEpoch,
	}, nil
}

func configure(ctx context.Context, transaction databaseTransaction, options Options) error {
	if _, err := transaction.Exec(
		ctx,
		configureTransactionSQL,
		postgresTimeout(options.StatementTimeout),
		postgresTimeout(options.LockTimeout),
		postgresTimeout(options.IdleTimeout),
	); err != nil {
		return fmt.Errorf("configure transaction timeouts: %w", err)
	}
	return nil
}

func validOptions(options Options) bool {
	return options.StatementTimeout >= time.Millisecond &&
		options.StatementTimeout <= maxStatementTimeout &&
		options.LockTimeout >= time.Millisecond && options.LockTimeout <= maxLockTimeout &&
		options.IdleTimeout >= time.Millisecond && options.IdleTimeout <= maxIdleTimeout
}

func postgresTimeout(value time.Duration) string {
	return strconv.FormatInt(value.Milliseconds(), 10) + "ms"
}

func rollbackSetup(transaction databaseTransaction) error {
	ctx, cancel := context.WithTimeout(context.Background(), setupRollbackWindow)
	defer cancel()
	if err := transaction.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return fmt.Errorf("roll back registration intake setup: %w", err)
	}
	return nil
}
