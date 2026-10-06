package postgres

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

const (
	maxAuthTransactionStatementTimeout = time.Minute
	maxAuthTransactionLockTimeout      = 30 * time.Second
	maxAuthTransactionIdleTimeout      = time.Minute
	authTransactionSetupRollbackWindow = 2 * time.Second
)

var (
	// ErrInvalidAuthTransactionStore reports an unsafe runtime dependency or option.
	ErrInvalidAuthTransactionStore = errors.New("invalid postgres auth transaction store")
	// ErrBeginAuthTransaction classifies transaction setup failure.
	ErrBeginAuthTransaction = errors.New("begin postgres auth transaction")
	// ErrAuthTransactionState reports invalid transaction method ordering.
	ErrAuthTransactionState = errors.New("postgres auth transaction state is invalid")
	// ErrAuthTransactionEvidence reports malformed durable creation authority.
	ErrAuthTransactionEvidence = errors.New("postgres auth transaction evidence is invalid")
	// ErrAuthTransactionRouteUnavailable reports stale or inactive login authority.
	ErrAuthTransactionRouteUnavailable = errors.New("postgres auth transaction route is unavailable")
	// ErrAuthTransactionConflict reports an existing durable transaction identity.
	ErrAuthTransactionConflict = errors.New("postgres auth transaction conflicts with durable state")
	// ErrAuthTransactionRetryable reports a transient serialization or lock failure.
	ErrAuthTransactionRetryable = errors.New("postgres auth transaction is retryable")
	// ErrCreateAuthTransaction classifies atomic creation failure.
	ErrCreateAuthTransaction = errors.New("create postgres auth transaction")
	// ErrCommitAuthTransaction classifies commit failure.
	ErrCommitAuthTransaction = errors.New("commit postgres auth transaction")
	// ErrAuthTransactionCommitOutcomeUnknown reports an uncertain commit outcome.
	ErrAuthTransactionCommitOutcomeUnknown = oidcauth.ErrCommitOutcomeUnknown
	// ErrRollbackAuthTransaction classifies rollback failure.
	ErrRollbackAuthTransaction = errors.New("rollback postgres auth transaction")
	// ErrResolveCommittedAuthTransaction classifies exact creation replay failure.
	ErrResolveCommittedAuthTransaction = errors.New("resolve committed postgres auth transaction")
)

// AuthTransactionOptions bounds every database wait in a login transaction.
type AuthTransactionOptions struct {
	StatementTimeout time.Duration
	LockTimeout      time.Duration
	IdleTimeout      time.Duration
}

// AuthTransactionStore owns short runtime-scoped login creation transactions.
type AuthTransactionStore struct {
	database authTransactionDatabase
	options  AuthTransactionOptions
	metrics  *postgresPoolMetrics
}

var (
	_ oidcauth.Transactions              = (*AuthTransactionStore)(nil)
	_ oidcauth.CommittedCreationResolver = (*AuthTransactionStore)(nil)
)

// NewAuthTransactionStore constructs a store from a runtime-authenticated pool.
func NewAuthTransactionStore(
	pool *Pool,
	options AuthTransactionOptions,
) (*AuthTransactionStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.authTransactionDatabase == nil {
		return nil, ErrInvalidAuthTransactionStore
	}
	return newAuthTransactionStore(pool.authTransactionDatabase, options, pool.metrics)
}

func newAuthTransactionStore(
	database authTransactionDatabase,
	options AuthTransactionOptions,
	metrics *postgresPoolMetrics,
) (*AuthTransactionStore, error) {
	if database == nil || !validAuthTransactionOptions(options) {
		return nil, ErrInvalidAuthTransactionStore
	}
	return &AuthTransactionStore{database: database, options: options, metrics: metrics}, nil
}

// Begin fixes one exact login route in a READ COMMITTED read-write transaction.
func (store *AuthTransactionStore) Begin(
	ctx context.Context,
	route oidcauth.Route,
) (_ oidcauth.Transaction, resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.observe(postgresOperationAuthTransactionBegin, startedAt, resultErr)
	}()

	if ctx == nil || store == nil || store.database == nil || !route.IsValid() ||
		!validAuthTransactionOptions(store.options) {
		return nil, ErrInvalidAuthTransactionStore
	}
	databaseTransaction, err := store.database.Begin(ctx, false)
	if err != nil {
		return nil, errors.Join(
			ErrBeginAuthTransaction,
			classifyAuthTransactionDatabaseError(ctx, err),
		)
	}
	owned := false
	defer func() {
		if owned {
			return
		}
		resultErr = errors.Join(resultErr, rollbackAuthTransactionSetup(databaseTransaction))
	}()
	if err := store.configure(ctx, databaseTransaction); err != nil {
		return nil, errors.Join(ErrBeginAuthTransaction, err)
	}
	owned = true
	return &authTransactionTransaction{
		database: databaseTransaction,
		route:    route,
		metrics:  store.metrics,
	}, nil
}

// ResolveCommitted identifies exact durable creation after an uncertain commit.
func (store *AuthTransactionStore) ResolveCommitted(
	ctx context.Context,
	pending oidcauth.Pending,
) (_ oidcauth.Created, found bool, resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.observe(postgresOperationAuthTransactionReplay, startedAt, resultErr)
	}()

	if ctx == nil || store == nil || store.database == nil || !pending.IsValid() ||
		!validAuthTransactionOptions(store.options) {
		return oidcauth.Created{}, false, ErrInvalidAuthTransactionStore
	}
	databaseTransaction, err := store.database.Begin(ctx, true)
	if err != nil {
		return oidcauth.Created{}, false, errors.Join(
			ErrResolveCommittedAuthTransaction,
			classifyAuthTransactionDatabaseError(ctx, err),
		)
	}
	closed := false
	defer func() {
		if closed {
			return
		}
		resultErr = errors.Join(resultErr, rollbackAuthTransactionSetup(databaseTransaction))
	}()
	if err := store.configure(ctx, databaseTransaction); err != nil {
		return oidcauth.Created{}, false, errors.Join(ErrResolveCommittedAuthTransaction, err)
	}
	semanticHash := pending.SemanticHash()
	created, err := scanAuthTransactionCreated(databaseTransaction.QueryRow(
		ctx,
		loadCommittedAuthTransactionSQL,
		pending.Route().DeploymentID().String(),
		pending.TransactionID().String(),
		semanticHash[:],
	))
	if errors.Is(err, pgx.ErrNoRows) {
		if err := databaseTransaction.Commit(ctx); err != nil {
			return oidcauth.Created{}, false, errors.Join(
				ErrResolveCommittedAuthTransaction,
				classifyAuthTransactionCommitError(ctx, err),
			)
		}
		closed = true
		return oidcauth.Created{}, false, nil
	}
	if err != nil {
		return oidcauth.Created{}, false, errors.Join(
			ErrResolveCommittedAuthTransaction,
			classifyAuthTransactionDatabaseError(ctx, err),
		)
	}
	if created.TransactionID() != pending.TransactionID() ||
		!created.CreatedAt().Equal(pending.CreatedAt()) ||
		!created.ExpiresAt().Equal(pending.ExpiresAt()) {
		return oidcauth.Created{}, false, errors.Join(
			ErrResolveCommittedAuthTransaction,
			ErrAuthTransactionEvidence,
		)
	}
	if err := databaseTransaction.Commit(ctx); err != nil {
		return oidcauth.Created{}, false, errors.Join(
			ErrResolveCommittedAuthTransaction,
			classifyAuthTransactionCommitError(ctx, err),
		)
	}
	closed = true
	return created, true, nil
}

func (store *AuthTransactionStore) configure(
	ctx context.Context,
	transaction authTransactionDatabaseTransaction,
) error {
	if err := transaction.Exec(
		ctx,
		configureAuthTransactionSQL,
		postgresTimeout(store.options.StatementTimeout),
		postgresTimeout(store.options.LockTimeout),
		postgresTimeout(store.options.IdleTimeout),
	); err != nil {
		return fmt.Errorf(
			"configure transaction timeouts: %w",
			classifyAuthTransactionDatabaseError(ctx, err),
		)
	}
	return nil
}

func validAuthTransactionOptions(options AuthTransactionOptions) bool {
	return options.StatementTimeout > 0 &&
		options.StatementTimeout <= maxAuthTransactionStatementTimeout &&
		options.LockTimeout > 0 && options.LockTimeout <= maxAuthTransactionLockTimeout &&
		options.IdleTimeout > 0 && options.IdleTimeout <= maxAuthTransactionIdleTimeout
}

func sameAuthTransactionRoute(left, right oidcauth.Route) bool {
	return left.DeploymentID() == right.DeploymentID() &&
		left.ProviderID() == right.ProviderID() &&
		left.ClientID() == right.ClientID() &&
		left.ProviderGeneration() == right.ProviderGeneration() &&
		left.RecoveryEpoch() == right.RecoveryEpoch() &&
		left.Issuer() == right.Issuer() &&
		left.DiscoveryURI() == right.DiscoveryURI() &&
		left.AuthorizationEndpoint() == right.AuthorizationEndpoint() &&
		left.TokenEndpoint() == right.TokenEndpoint() &&
		left.JWKSURI() == right.JWKSURI() &&
		left.OIDCClientID() == right.OIDCClientID() &&
		left.ClientAuthMethod() == right.ClientAuthMethod() &&
		slices.Equal(left.Scopes(), right.Scopes()) &&
		slices.Equal(left.AllowedAlgorithms(), right.AllowedAlgorithms()) &&
		left.RedirectID() == right.RedirectID() &&
		left.RedirectURI() == right.RedirectURI() &&
		left.ReturnRouteID() == right.ReturnRouteID()
}

func rollbackAuthTransactionSetup(transaction authTransactionDatabaseTransaction) error {
	ctx, cancel := context.WithTimeout(context.Background(), authTransactionSetupRollbackWindow)
	defer cancel()
	if err := transaction.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return fmt.Errorf("roll back auth transaction setup: %w", err)
	}
	return nil
}

func (store *AuthTransactionStore) observe(
	operation postgresOperation,
	startedAt time.Time,
	err error,
) {
	if store == nil {
		return
	}
	store.metrics.observeOperation(operation, time.Since(startedAt), err)
}
