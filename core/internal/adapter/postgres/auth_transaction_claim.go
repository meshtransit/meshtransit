package postgres

import (
	"context"
	"crypto/hmac"
	"errors"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/oidcauth"
)

// ErrClaimAuthTransaction classifies failed atomic browser consumption.
var ErrClaimAuthTransaction = errors.New("claim postgres browser auth transaction")

const (
	authClaimOpen uint32 = iota + 1
	authClaimBusy
	authClaimReady
	authClaimCleanup
	authClaimClosed
)

// The CAS owns all mutable database work. Contenders fail immediately; neither
// a mutex nor a queued goroutine may overlap Claim/Commit/Rollback I/O.
type authClaimTransaction struct {
	state    atomic.Uint32
	database authTransactionDatabaseTransaction
	route    oidcauth.Route
	metrics  *postgresPoolMetrics
}

var (
	_ oidcauth.ClaimTransactions = (*AuthTransactionStore)(nil)
	_ oidcauth.ClaimTransaction  = (*authClaimTransaction)(nil)
)

func newAuthClaimTransaction(database authTransactionDatabaseTransaction, route oidcauth.Route, metrics *postgresPoolMetrics) *authClaimTransaction {
	unit := &authClaimTransaction{database: database, route: route, metrics: metrics}
	unit.state.Store(authClaimOpen)
	return unit
}

// BeginClaim owns a READ COMMITTED write unit and bounds database setup/cleanup.
// Route/auth locks are acquired by Claim, not a lease from earlier read admission.
func (store *AuthTransactionStore) BeginClaim(ctx context.Context, route oidcauth.Route) (result oidcauth.ClaimTransaction, resultErr error) {
	startedAt := time.Now()
	defer func() { store.observe(postgresOperationAuthClaimBegin, startedAt, resultErr) }()
	if ctx == nil || store == nil || store.database == nil || !route.IsValid() || !validAuthTransactionOptions(store.options) {
		return nil, ErrInvalidAuthTransactionStore
	}
	if ctx.Err() != nil {
		return nil, errors.Join(ErrBeginAuthTransaction, ctx.Err())
	}
	database, beginErr := store.database.Begin(ctx, false)
	if database == nil {
		return nil, errors.Join(ErrBeginAuthTransaction, classifyAuthTransactionDatabaseError(ctx, beginErr), ErrAuthTransactionEvidence)
	}
	owned := false
	defer func() {
		if owned {
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), authTransactionSetupRollbackWindow)
		defer cancel()
		if err := database.Rollback(cleanup); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			resultErr = errors.Join(resultErr, ErrRollbackAuthTransaction, classifyAuthTransactionDatabaseError(cleanup, err))
		}
		resultErr = errors.Join(resultErr, cleanup.Err(), ctx.Err())
	}()
	if beginErr != nil {
		return nil, errors.Join(ErrBeginAuthTransaction, classifyAuthTransactionDatabaseError(ctx, beginErr))
	}
	if err := store.configure(ctx, database); err != nil {
		return nil, errors.Join(ErrBeginAuthTransaction, err)
	}
	if ctx.Err() != nil {
		return nil, errors.Join(ErrBeginAuthTransaction, ctx.Err())
	}
	owned = true
	return newAuthClaimTransaction(database, route, store.metrics), nil
}

func (unit *authClaimTransaction) Claim(ctx context.Context, command oidcauth.ClaimCommand) (result oidcauth.Claimed, resultErr error) {
	startedAt := time.Now()
	defer func() { unit.observe(postgresOperationAuthClaimApply, startedAt, resultErr) }()
	if ctx == nil || unit == nil || unit.database == nil || !command.IsValid() || !sameAuthTransactionRoute(unit.route, command.Snapshot().Route()) || !unit.state.CompareAndSwap(authClaimOpen, authClaimBusy) {
		return result, ErrAuthTransactionState
	}
	defer func() {
		if resultErr != nil {
			unit.state.Store(authClaimCleanup)
		} else {
			unit.state.Store(authClaimReady)
		}
	}()
	if ctx.Err() != nil {
		return result, errors.Join(ErrClaimAuthTransaction, ctx.Err())
	}
	if err := unit.database.Exec(ctx, setAuthTransactionChangeSQL, command.MutationIDs().ChangeID().String()); err != nil {
		return result, errors.Join(ErrClaimAuthTransaction, classifyAuthTransactionDatabaseError(ctx, err))
	}
	snapshot, route := command.Snapshot(), command.Snapshot().Route()
	digest, hash := snapshot.StateDigest().Bytes(), snapshot.SemanticHash()
	row := unit.database.QueryRow(ctx, claimAuthTransactionSQL,
		route.DeploymentID().String(), route.ProviderID().String(), route.ClientID().String(), route.ProviderGeneration(), route.RecoveryEpoch(),
		route.Issuer(), route.DiscoveryURI(), route.AuthorizationEndpoint(), route.TokenEndpoint(), route.JWKSURI(), route.OIDCClientID(), route.ClientAuthMethod(), route.Scopes(), route.AllowedAlgorithms(), route.RedirectURI(),
		snapshot.StateDigest().Algorithm(), snapshot.StateDigest().KeyID().String(), digest[:], route.RedirectID(), route.ReturnRouteID(), snapshot.TransactionID().String(), snapshot.Version(), hash[:],
	)
	claimed, err := scanAuthClaim(row, snapshot)
	if err != nil {
		return result, errors.Join(ErrClaimAuthTransaction, classifyAuthTransactionDatabaseError(ctx, err))
	}
	var head authTransactionAuditHead
	var previousHash []byte
	if err := unit.database.QueryRow(ctx, lockAuthTransactionAuditStreamSQL, route.DeploymentID().String()).Scan(&head.streamInternalID, &head.nextSequence, &previousHash); err != nil {
		return result, errors.Join(ErrClaimAuthTransaction, classifyAuthTransactionDatabaseError(ctx, err))
	}
	if head.streamInternalID <= 0 || head.nextSequence <= 0 || len(previousHash) != 32 {
		return result, ErrAuthTransactionEvidence
	}
	copy(head.previousHash[:], previousHash)
	// Audit-head acquisition is also a lock wait: frozen transaction time is not
	// sufficient. Reject and roll back the transition if its deadline passed.
	var now time.Time
	if err := unit.database.QueryRow(ctx, authClaimClockSQL).Scan(&now); err != nil {
		return result, errors.Join(ErrClaimAuthTransaction, classifyAuthTransactionDatabaseError(ctx, err))
	}
	if now.Before(claimed.ConsumedAt()) || !now.Before(snapshot.ExpiresAt()) || ctx.Err() != nil {
		return result, errors.Join(ErrClaimAuthTransaction, ErrAuthTransactionEvidence, ctx.Err())
	}
	if err := unit.appendClaimEvidence(ctx, command, claimed, head); err != nil {
		return result, errors.Join(ErrClaimAuthTransaction, classifyAuthTransactionDatabaseError(ctx, err))
	}
	if ctx.Err() != nil {
		return result, errors.Join(ErrClaimAuthTransaction, ctx.Err())
	}
	return claimed, nil
}

func scanAuthClaim(row authTransactionRow, snapshot oidcauth.PendingSnapshot) (oidcauth.Claimed, error) {
	var id string
	var version int64
	var createdAt, expiresAt, consumedAt time.Time
	var hash []byte
	if err := row.Scan(&id, &version, &createdAt, &expiresAt, &consumedAt, &hash); err != nil {
		return oidcauth.Claimed{}, err
	}
	expected := snapshot.SemanticHash()
	if id != snapshot.TransactionID().String() || len(hash) != 32 || !hmac.Equal(hash, expected[:]) || !createdAt.Equal(snapshot.CreatedAt()) || !expiresAt.Equal(snapshot.ExpiresAt()) {
		return oidcauth.Claimed{}, ErrAuthTransactionEvidence
	}
	claimed, err := oidcauth.NewClaimed(snapshot, version, consumedAt)
	if err != nil {
		return oidcauth.Claimed{}, ErrAuthTransactionEvidence
	}
	return claimed, nil
}

func (unit *authClaimTransaction) Commit(ctx context.Context) (resultErr error) {
	startedAt := time.Now()
	defer func() { unit.observe(postgresOperationAuthClaimCommit, startedAt, resultErr) }()
	if ctx == nil || unit == nil || unit.database == nil || !unit.state.CompareAndSwap(authClaimReady, authClaimBusy) {
		return ErrAuthTransactionState
	}
	if ctx.Err() != nil {
		unit.state.Store(authClaimCleanup)
		return errors.Join(ErrCommitAuthTransaction, ctx.Err())
	}
	err := unit.database.Commit(ctx)
	if err != nil {
		unit.state.Store(authClaimCleanup)
		return errors.Join(ErrCommitAuthTransaction, classifyAuthTransactionCommitError(ctx, err))
	}
	unit.state.Store(authClaimClosed)
	return nil
}

func (unit *authClaimTransaction) Rollback(ctx context.Context) (resultErr error) {
	startedAt := time.Now()
	defer func() { unit.observe(postgresOperationAuthClaimRollback, startedAt, resultErr) }()
	if ctx == nil || unit == nil || unit.database == nil {
		return ErrAuthTransactionState
	}
	state := unit.state.Load()
	if state == authClaimClosed {
		return nil
	}
	if (state != authClaimOpen && state != authClaimReady && state != authClaimCleanup) || !unit.state.CompareAndSwap(state, authClaimBusy) {
		return ErrAuthTransactionState
	}
	defer unit.state.Store(authClaimClosed)
	if err := unit.database.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return errors.Join(ErrRollbackAuthTransaction, classifyAuthTransactionDatabaseError(ctx, err))
	}
	return ctx.Err()
}
func (unit *authClaimTransaction) observe(operation postgresOperation, startedAt time.Time, err error) {
	if unit != nil {
		unit.metrics.observeOperation(operation, time.Since(startedAt), err)
	}
}
