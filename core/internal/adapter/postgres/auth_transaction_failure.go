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

// ErrFailAuthTransaction classifies a rejected atomic terminal transition.
var ErrFailAuthTransaction = errors.New("terminate postgres browser auth transaction")

type authFailureTransaction struct {
	state    atomic.Uint32
	database authTransactionDatabaseTransaction
	route    oidcauth.Route
	metrics  *postgresPoolMetrics
}

var (
	_ oidcauth.FailureTransactions = (*AuthTransactionStore)(nil)
	_ oidcauth.FailureTransaction  = (*authFailureTransaction)(nil)
)

func newAuthFailureTransaction(
	database authTransactionDatabaseTransaction,
	route oidcauth.Route,
	metrics *postgresPoolMetrics,
) *authFailureTransaction {
	unit := &authFailureTransaction{database: database, route: route, metrics: metrics}
	unit.state.Store(authClaimOpen)
	return unit
}

// BeginFailure opens one bounded write unit. It performs no current-route admission.
func (store *AuthTransactionStore) BeginFailure(
	ctx context.Context,
	route oidcauth.Route,
) (result oidcauth.FailureTransaction, resultErr error) {
	startedAt := time.Now()
	defer func() { store.observe(postgresOperationAuthFailureBegin, startedAt, resultErr) }()
	if ctx == nil || store == nil {
		return nil, ErrInvalidAuthTransactionStore
	}
	configured := store.database != nil && validAuthTransactionOptions(store.options)
	if !configured || !route.IsValid() {
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
			resultErr = errors.Join(
				resultErr,
				ErrRollbackAuthTransaction,
				classifyAuthTransactionDatabaseError(cleanup, err),
			)
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
	return newAuthFailureTransaction(database, route, store.metrics), nil
}
func (unit *authFailureTransaction) Fail(
	ctx context.Context,
	command oidcauth.FailureCommand,
) (result oidcauth.Terminated, resultErr error) {
	startedAt := time.Now()
	defer func() { unit.observe(postgresOperationAuthFailureApply, startedAt, resultErr) }()
	if ctx == nil || unit == nil {
		return result, ErrAuthTransactionState
	}
	validCommand := command.IsValid() && sameAuthTransactionRoute(unit.route, command.Snapshot().Route())
	if unit.database == nil || !validCommand || !unit.state.CompareAndSwap(authClaimOpen, authClaimBusy) {
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
		return result, errors.Join(ErrFailAuthTransaction, ctx.Err())
	}
	if err := unit.database.Exec(ctx, setAuthTransactionChangeSQL, command.MutationIDs().ChangeID().String()); err != nil {
		return result, errors.Join(ErrFailAuthTransaction, classifyAuthTransactionDatabaseError(ctx, err))
	}
	snapshot, route := command.Snapshot(), command.Snapshot().Route()
	hash := snapshot.SemanticHash()
	row := unit.database.QueryRow(
		ctx,
		failAuthTransactionSQL,
		route.DeploymentID().String(),
		route.ProviderID().String(),
		route.ClientID().String(),
		route.ProviderGeneration(),
		route.RecoveryEpoch(),
		snapshot.TransactionID().String(),
		command.Claimed().Version(),
		hash[:],
		command.Claimed().ConsumedAt(),
	)
	terminal, head, err := scanAuthFailure(row, command)
	if err != nil {
		return result, errors.Join(ErrFailAuthTransaction, classifyAuthTransactionDatabaseError(ctx, err))
	}
	if ctx.Err() != nil {
		return result, errors.Join(ErrFailAuthTransaction, ctx.Err())
	}
	if err := unit.appendFailureEvidence(ctx, command, terminal, head); err != nil {
		return result, errors.Join(ErrFailAuthTransaction, classifyAuthTransactionDatabaseError(ctx, err))
	}
	if ctx.Err() != nil {
		return result, errors.Join(ErrFailAuthTransaction, ctx.Err())
	}
	return terminal, nil
}
func scanAuthFailure(
	row authTransactionRow,
	command oidcauth.FailureCommand,
) (oidcauth.Terminated, authTransactionAuditHead, error) {
	var id, state, class string
	var version int64
	var createdAt, expiresAt, consumedAt, at time.Time
	// Scan destinations intentionally start nil; only exact validated bytes may
	// become evidence. They are never directly serialized as JSON collections.
	var hash, previousHash []byte
	var head authTransactionAuditHead
	if err := row.Scan(
		&id,
		&version,
		&createdAt,
		&expiresAt,
		&consumedAt,
		&hash,
		&state,
		&class,
		&at,
		&head.streamInternalID,
		&head.nextSequence,
		&previousHash,
	); err != nil {
		return oidcauth.Terminated{}, head, err
	}
	snapshot := command.Snapshot()
	expected := snapshot.SemanticHash()
	boundIdentity := id == snapshot.TransactionID().String() && len(hash) == 32 && hmac.Equal(hash, expected[:])
	boundTimes := createdAt.Equal(snapshot.CreatedAt()) && expiresAt.Equal(snapshot.ExpiresAt()) &&
		consumedAt.Equal(command.Claimed().ConsumedAt())
	safeHead := head.streamInternalID > 0 && head.nextSequence > 0 && len(previousHash) == 32
	if !boundIdentity || !boundTimes || !safeHead {
		return oidcauth.Terminated{}, authTransactionAuditHead{}, ErrAuthTransactionEvidence
	}
	terminal, err := oidcauth.NewTerminated(
		command.Claimed(),
		version,
		state,
		class,
		at,
	)
	if err != nil {
		return oidcauth.Terminated{}, authTransactionAuditHead{}, ErrAuthTransactionEvidence
	}
	copy(head.previousHash[:], previousHash)
	return terminal, head, nil
}
func (unit *authFailureTransaction) Commit(ctx context.Context) (resultErr error) {
	startedAt := time.Now()
	defer func() { unit.observe(postgresOperationAuthFailureCommit, startedAt, resultErr) }()
	if ctx == nil || unit == nil || unit.database == nil || !unit.state.CompareAndSwap(authClaimReady, authClaimBusy) {
		return ErrAuthTransactionState
	}
	if ctx.Err() != nil {
		unit.state.Store(authClaimCleanup)
		return errors.Join(ErrCommitAuthTransaction, ctx.Err())
	}
	if err := unit.database.Commit(ctx); err != nil {
		unit.state.Store(authClaimCleanup)
		return errors.Join(ErrCommitAuthTransaction, classifyAuthTransactionCommitError(ctx, err))
	}
	unit.state.Store(authClaimClosed)
	return nil
}
func (unit *authFailureTransaction) Rollback(ctx context.Context) (resultErr error) {
	startedAt := time.Now()
	defer func() { unit.observe(postgresOperationAuthFailureRollback, startedAt, resultErr) }()
	if ctx == nil || unit == nil || unit.database == nil {
		return ErrAuthTransactionState
	}
	state := unit.state.Load()
	if state == authClaimClosed {
		return nil
	}
	canRollback := state == authClaimOpen || state == authClaimReady || state == authClaimCleanup
	if !canRollback || !unit.state.CompareAndSwap(state, authClaimBusy) {
		return ErrAuthTransactionState
	}
	defer unit.state.Store(authClaimClosed)
	if err := unit.database.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return errors.Join(ErrRollbackAuthTransaction, classifyAuthTransactionDatabaseError(ctx, err))
	}
	return ctx.Err()
}
func (unit *authFailureTransaction) observe(operation postgresOperation, startedAt time.Time, err error) {
	if unit != nil {
		unit.metrics.observeOperation(operation, time.Since(startedAt), err)
	}
}
