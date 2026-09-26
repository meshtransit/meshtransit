package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
)

const (
	maximumAccountSessionLogoutStatementTimeout = 30 * time.Second
	maximumAccountSessionLogoutLockTimeout      = 30 * time.Second
	maximumAccountSessionLogoutIdleTimeout      = time.Minute
	accountSessionLogoutRollbackTimeout         = 2 * time.Second
)

var (
	// ErrInvalidAccountSessionLogoutStore reports an unsafe dependency or option.
	ErrInvalidAccountSessionLogoutStore = errors.New("invalid postgres account session logout store")
	// ErrLogoutAccountSession classifies a durable local logout failure.
	ErrLogoutAccountSession = errors.New("logout postgres account session")
	// ErrAccountSessionLogoutEvidence reports malformed mutation evidence.
	ErrAccountSessionLogoutEvidence = errors.New("postgres account session logout evidence is invalid")
)

// AccountSessionLogoutOptions bounds every database wait during local logout.
type AccountSessionLogoutOptions struct {
	StatementTimeout time.Duration
	LockTimeout      time.Duration
	IdleTimeout      time.Duration
}

// AccountSessionLogoutStore atomically revokes one Deployment-bound Session.
type AccountSessionLogoutStore struct {
	database accountSessionLogoutDatabase
	options  AccountSessionLogoutOptions
	metrics  *postgresPoolMetrics
}

var _ accountsession.Revoker = (*AccountSessionLogoutStore)(nil)

// NewAccountSessionLogoutStore constructs a revoker from a runtime pool.
func NewAccountSessionLogoutStore(
	pool *Pool,
	options AccountSessionLogoutOptions,
) (*AccountSessionLogoutStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.accountSessionLogoutDatabase == nil {
		return nil, ErrInvalidAccountSessionLogoutStore
	}
	return newAccountSessionLogoutStore(pool.accountSessionLogoutDatabase, options, pool.metrics)
}

func newAccountSessionLogoutStore(
	database accountSessionLogoutDatabase,
	options AccountSessionLogoutOptions,
	metrics *postgresPoolMetrics,
) (*AccountSessionLogoutStore, error) {
	if database == nil || !validAccountSessionLogoutOptions(options) {
		return nil, ErrInvalidAccountSessionLogoutStore
	}
	return &AccountSessionLogoutStore{database: database, options: options, metrics: metrics}, nil
}

// Revoke ends one active Session and returns an idempotent no-match otherwise.
func (store *AccountSessionLogoutStore) Revoke(
	ctx context.Context,
	deploymentID deployment.ID,
	recoveryEpoch int64,
	digest accountsession.Digest,
) (_ accountsession.ID, _ int64, found bool, resultErr error) {
	startedAt := time.Now()
	defer func() {
		if store != nil && store.metrics != nil {
			store.metrics.observeOperation(postgresOperationAccountSessionLogout, time.Since(startedAt), resultErr)
		}
	}()
	if ctx == nil || store == nil || store.database == nil || !validAccountSessionLogoutOptions(store.options) ||
		!deploymentID.IsValid() || recoveryEpoch <= 0 || !digest.IsValid() {
		return accountsession.ID{}, 0, false, ErrInvalidAccountSessionLogoutStore
	}
	transaction, err := store.database.Begin(ctx)
	if err != nil || transaction == nil {
		if err == nil {
			err = ErrInvalidAccountSessionLogoutStore
		}
		return accountsession.ID{}, 0, false, errors.Join(ErrLogoutAccountSession, err)
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackAccountSessionLogout(transaction))
		}
	}()
	options := store.options
	if err := transaction.Exec(
		ctx,
		configureAccountSessionLogoutSQL,
		postgresTimeout(options.StatementTimeout),
		postgresTimeout(options.LockTimeout),
		postgresTimeout(options.IdleTimeout),
	); err != nil {
		return accountsession.ID{}, 0, false, errors.Join(ErrLogoutAccountSession, err)
	}
	digestBytes := digest.Bytes()
	var publicID string
	var version int64
	err = transaction.QueryRow(
		ctx,
		logoutAccountSessionSQL,
		deploymentID.String(),
		recoveryEpoch,
		digest.Algorithm(),
		digest.KeyID().String(),
		digestBytes[:],
	).Scan(&publicID, &version)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := transaction.Commit(ctx); err != nil {
			return accountsession.ID{}, 0, false, errors.Join(ErrLogoutAccountSession, err)
		}
		closed = true
		return accountsession.ID{}, 0, false, nil
	}
	if err != nil {
		return accountsession.ID{}, 0, false, errors.Join(ErrLogoutAccountSession, err)
	}
	id, err := accountsession.ParseID(publicID)
	if err != nil || version < 2 {
		return accountsession.ID{}, 0, false, errors.Join(
			ErrLogoutAccountSession,
			ErrAccountSessionLogoutEvidence,
		)
	}
	if err := transaction.Commit(ctx); err != nil {
		return accountsession.ID{}, 0, false, errors.Join(ErrLogoutAccountSession, err)
	}
	closed = true
	return id, version, true, nil
}

func validAccountSessionLogoutOptions(options AccountSessionLogoutOptions) bool {
	return options.StatementTimeout > 0 &&
		options.StatementTimeout <= maximumAccountSessionLogoutStatementTimeout &&
		options.LockTimeout > 0 && options.LockTimeout <= maximumAccountSessionLogoutLockTimeout &&
		options.IdleTimeout > 0 && options.IdleTimeout <= maximumAccountSessionLogoutIdleTimeout
}

func rollbackAccountSessionLogout(transaction accountSessionLogoutTransaction) error {
	ctx, cancel := context.WithTimeout(context.Background(), accountSessionLogoutRollbackTimeout)
	defer cancel()
	if err := transaction.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return fmt.Errorf("roll back Account Session logout: %w", err)
	}
	return nil
}
