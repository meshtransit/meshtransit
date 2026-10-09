package postgres

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/oidcauth"
)

type authExpiryTransaction struct {
	state        atomic.Uint32
	database     authTransactionDatabaseTransaction
	deploymentID deployment.ID
	metrics      *postgresPoolMetrics
}

var _ oidcauth.ExpiryTransaction = (*authExpiryTransaction)(nil)

func newAuthExpiryTransaction(
	database authTransactionDatabaseTransaction,
	dep deployment.ID,
	metrics *postgresPoolMetrics,
) *authExpiryTransaction {
	unit := &authExpiryTransaction{database: database, deploymentID: dep, metrics: metrics}
	unit.state.Store(authClaimOpen)
	return unit
}

func (unit *authExpiryTransaction) Expire(
	ctx context.Context,
	command oidcauth.ExpiryCommand,
) (result oidcauth.Expired, resultErr error) {
	startedAt := time.Now()
	defer func() { unit.observe(postgresOperationAuthExpiryApply, startedAt, resultErr) }()
	if ctx == nil || unit == nil || unit.database == nil || !command.IsValid() ||
		command.Snapshot().DeploymentID() != unit.deploymentID || !unit.state.CompareAndSwap(authClaimOpen, authClaimBusy) {
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
		return result, ctx.Err()
	}
	if err := unit.database.Exec(ctx, setAuthTransactionChangeSQL, command.MutationIDs().ChangeID().String()); err != nil {
		return result, classifyAuthExpiryError(ctx, err)
	}
	snapshot := command.Snapshot()
	hash := snapshot.SemanticHash()
	var consumed any
	if !snapshot.ConsumedAt().IsZero() {
		consumed = snapshot.ConsumedAt()
	}
	var version int64
	var at, consumedAt time.Time
	var head authTransactionAuditHead
	var previousHash []byte
	if err := unit.database.QueryRow(
		ctx,
		expireAuthSQL,
		unit.deploymentID.String(),
		snapshot.TransactionID().String(),
		snapshot.Version(),
		snapshot.CreatedAt(),
		snapshot.ExpiresAt(),
		consumed,
		hash[:],
	).Scan(
		&version,
		&consumedAt,
		&at,
		&head.streamInternalID,
		&head.nextSequence,
		&previousHash,
	); err != nil {
		return result, classifyAuthExpiryError(ctx, err)
	}
	terminal, err := oidcauth.NewExpired(snapshot, at)
	if err != nil || version != terminal.Version() || !consumedAt.Equal(terminal.ConsumedAt()) ||
		head.streamInternalID <= 0 || head.nextSequence <= 0 ||
		head.nextSequence == 9223372036854775807 || len(previousHash) != 32 {
		return result, ErrAuthTransactionEvidence
	}
	copy(head.previousHash[:], previousHash)
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if err := unit.appendExpiryEvidence(
		ctx,
		command,
		terminal,
		head,
	); err != nil {
		return result, classifyAuthExpiryError(ctx, err)
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	return terminal, nil
}

func (unit *authExpiryTransaction) Commit(ctx context.Context) (resultErr error) {
	startedAt := time.Now()
	defer func() { unit.observe(postgresOperationAuthExpiryCommit, startedAt, resultErr) }()
	if ctx == nil || unit == nil || unit.database == nil || !unit.state.CompareAndSwap(authClaimReady, authClaimBusy) {
		return ErrAuthTransactionState
	}
	if ctx.Err() != nil {
		unit.state.Store(authClaimCleanup)
		return ctx.Err()
	}
	if err := unit.database.Commit(ctx); err != nil {
		unit.state.Store(authClaimCleanup)
		return classifyAuthExpiryError(ctx, classifyAuthTransactionCommitError(ctx, err))
	}
	unit.state.Store(authClaimClosed)
	return nil
}

func (unit *authExpiryTransaction) Rollback(ctx context.Context) (resultErr error) {
	startedAt := time.Now()
	defer func() { unit.observe(postgresOperationAuthExpiryRollback, startedAt, resultErr) }()
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
		return classifyAuthExpiryError(ctx, err)
	}
	return ctx.Err()
}

func (unit *authExpiryTransaction) observe(operation postgresOperation, startedAt time.Time, err error) {
	if unit != nil {
		unit.metrics.observeOperation(operation, time.Since(startedAt), err)
	}
}
