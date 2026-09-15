package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const (
	maximumAccountSessionStatementTimeout = 30 * time.Second
	maximumAccountSessionIdleTimeout      = time.Minute
	accountSessionRollbackTimeout         = 2 * time.Second
)

var (
	// ErrInvalidAccountSessionStore reports an unsafe dependency or option.
	ErrInvalidAccountSessionStore = errors.New("invalid postgres account session store")
	// ErrResolveAccountSession classifies durable Account Session resolution failure.
	ErrResolveAccountSession = errors.New("resolve postgres account session")
	// ErrAccountSessionEvidence reports malformed authority returned by PostgreSQL.
	ErrAccountSessionEvidence = errors.New("postgres account session evidence is invalid")
)

// AccountSessionOptions bounds every database wait during session resolution.
type AccountSessionOptions struct {
	StatementTimeout time.Duration
	IdleTimeout      time.Duration
}

// AccountSessionStore resolves current session authority through a narrow function.
type AccountSessionStore struct {
	database accountSessionDatabase
	options  AccountSessionOptions
	metrics  *postgresPoolMetrics
}

var _ accountsession.Resolver = (*AccountSessionStore)(nil)

// NewAccountSessionStore constructs a resolver from a runtime-authenticated pool.
func NewAccountSessionStore(
	pool *Pool,
	options AccountSessionOptions,
) (*AccountSessionStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.accountSessionDatabase == nil {
		return nil, ErrInvalidAccountSessionStore
	}
	return newAccountSessionStore(pool.accountSessionDatabase, options, pool.metrics)
}

func newAccountSessionStore(
	database accountSessionDatabase,
	options AccountSessionOptions,
	metrics *postgresPoolMetrics,
) (*AccountSessionStore, error) {
	if database == nil || !validAccountSessionOptions(options) {
		return nil, ErrInvalidAccountSessionStore
	}
	return &AccountSessionStore{database: database, options: options, metrics: metrics}, nil
}

// Resolve returns current authority for one exact Deployment, recovery epoch, and digest.
func (store *AccountSessionStore) Resolve(
	ctx context.Context,
	deploymentID deployment.ID,
	recoveryEpoch int64,
	digest accountsession.Digest,
) (_ accountsession.Session, found bool, resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.observe(startedAt, resultErr)
	}()

	if ctx == nil || store == nil || store.database == nil ||
		!validAccountSessionOptions(store.options) || !deploymentID.IsValid() ||
		recoveryEpoch <= 0 || !digest.IsValid() {
		return accountsession.Session{}, false, ErrInvalidAccountSessionStore
	}
	transaction, err := store.database.Begin(ctx)
	if err != nil || transaction == nil {
		if err == nil {
			err = ErrInvalidAccountSessionStore
		}
		return accountsession.Session{}, false, errors.Join(ErrResolveAccountSession, err)
	}
	closed := false
	defer func() {
		if closed {
			return
		}
		resultErr = errors.Join(resultErr, rollbackAccountSessionTransaction(transaction))
	}()

	if err := transaction.Exec(
		ctx,
		configureAccountSessionTransactionSQL,
		postgresTimeout(store.options.StatementTimeout),
		postgresTimeout(store.options.IdleTimeout),
	); err != nil {
		return accountsession.Session{}, false, errors.Join(ErrResolveAccountSession, err)
	}
	digestBytes := digest.Bytes()
	session, err := scanAccountSession(transaction.QueryRow(
		ctx,
		resolveAccountSessionSQL,
		deploymentID.String(),
		recoveryEpoch,
		digest.Algorithm(),
		digest.KeyID().String(),
		digestBytes[:],
	))
	if errors.Is(err, pgx.ErrNoRows) {
		if err := transaction.Commit(ctx); err != nil {
			return accountsession.Session{}, false, errors.Join(ErrResolveAccountSession, err)
		}
		closed = true
		return accountsession.Session{}, false, nil
	}
	if err != nil {
		return accountsession.Session{}, false, errors.Join(ErrResolveAccountSession, err)
	}
	if session.DeploymentID() != deploymentID ||
		session.DeploymentRecoveryEpoch() != recoveryEpoch {
		return accountsession.Session{}, false, errors.Join(
			ErrResolveAccountSession,
			ErrAccountSessionEvidence,
		)
	}
	if err := transaction.Commit(ctx); err != nil {
		return accountsession.Session{}, false, errors.Join(ErrResolveAccountSession, err)
	}
	closed = true
	return session, true, nil
}

func scanAccountSession(row accountSessionRow) (accountsession.Session, error) {
	var sessionPublicID, deploymentPublicID, principalPublicID, subjectPublicID string
	var loginWorkspacePublicID *string
	var authenticationTime, idleExpiresAt, absoluteExpiresAt time.Time
	var acr *string
	var amr []string
	var sessionVersion, principalGeneration, accountGeneration int64
	var providerGeneration, recoveryEpoch int64
	if err := row.Scan(
		&sessionPublicID,
		&deploymentPublicID,
		&principalPublicID,
		&subjectPublicID,
		&loginWorkspacePublicID,
		&authenticationTime,
		&acr,
		&amr,
		&sessionVersion,
		&principalGeneration,
		&accountGeneration,
		&providerGeneration,
		&recoveryEpoch,
		&idleExpiresAt,
		&absoluteExpiresAt,
	); err != nil {
		return accountsession.Session{}, err
	}
	sessionID, err := accountsession.ParseID(sessionPublicID)
	if err != nil {
		return accountsession.Session{}, ErrAccountSessionEvidence
	}
	deploymentID, err := deployment.ParseID(deploymentPublicID)
	if err != nil {
		return accountsession.Session{}, ErrAccountSessionEvidence
	}
	principalID, err := identity.ParsePrincipalID(principalPublicID)
	if err != nil {
		return accountsession.Session{}, ErrAccountSessionEvidence
	}
	subjectID, err := accountsession.ParseIdentitySubjectID(subjectPublicID)
	if err != nil {
		return accountsession.Session{}, ErrAccountSessionEvidence
	}
	var loginWorkspaceID workspace.ID
	if loginWorkspacePublicID != nil {
		loginWorkspaceID, err = workspace.ParseID(*loginWorkspacePublicID)
		if err != nil {
			return accountsession.Session{}, ErrAccountSessionEvidence
		}
	}
	acrValue := ""
	if acr != nil {
		acrValue = *acr
	}
	session, err := accountsession.NewSession(accountsession.Params{
		ID:                           sessionID,
		DeploymentID:                 deploymentID,
		PrincipalID:                  principalID,
		IdentitySubjectID:            subjectID,
		LoginWorkspaceID:             loginWorkspaceID,
		HasLoginWorkspace:            loginWorkspacePublicID != nil,
		AuthenticationTime:           authenticationTime,
		ACR:                          acrValue,
		AMR:                          amr,
		Version:                      sessionVersion,
		PrincipalAuthorityGeneration: principalGeneration,
		AccountSessionGeneration:     accountGeneration,
		ProviderGeneration:           providerGeneration,
		DeploymentRecoveryEpoch:      recoveryEpoch,
		IdleExpiresAt:                idleExpiresAt,
		AbsoluteExpiresAt:            absoluteExpiresAt,
	})
	if err != nil {
		return accountsession.Session{}, ErrAccountSessionEvidence
	}
	return session, nil
}

func validAccountSessionOptions(options AccountSessionOptions) bool {
	return options.StatementTimeout > 0 &&
		options.StatementTimeout <= maximumAccountSessionStatementTimeout &&
		options.IdleTimeout > 0 && options.IdleTimeout <= maximumAccountSessionIdleTimeout
}

func rollbackAccountSessionTransaction(transaction accountSessionTransaction) error {
	ctx, cancel := context.WithTimeout(context.Background(), accountSessionRollbackTimeout)
	defer cancel()
	if err := transaction.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return fmt.Errorf("roll back Account Session transaction: %w", err)
	}
	return nil
}

func (store *AccountSessionStore) observe(startedAt time.Time, err error) {
	if store != nil && store.metrics != nil {
		store.metrics.observeOperation(
			postgresOperationAccountSessionResolve,
			time.Since(startedAt),
			err,
		)
	}
}
