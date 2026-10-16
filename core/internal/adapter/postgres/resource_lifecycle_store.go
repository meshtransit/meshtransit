package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/network"
	authority "meshtransit.net/core/internal/domain/resource/authority"
)

var (
	_ authority.LifecycleTransactions            = (*ResourceAuthorityStore)(nil)
	_ authority.CommittedLifecycleResultResolver = (*ResourceAuthorityStore)(nil)
)

// BeginLifecycle fixes exact Network scope in one read-write transaction.
func (store *ResourceAuthorityStore) BeginLifecycle(
	ctx context.Context,
	scope network.Scope,
) (_ authority.LifecycleTransaction, resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.observe(postgresOperationResourceAuthorityBegin, startedAt, resultErr)
	}()
	if ctx == nil || store == nil || store.database == nil || !scope.IsValid() ||
		!validResourceAuthorityOptions(store.options) {
		return nil, ErrInvalidResourceAuthorityStore
	}
	databaseTransaction, err := store.database.Begin(ctx, false)
	if err != nil {
		return nil, errors.Join(
			ErrBeginResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	owned := false
	defer func() {
		if !owned {
			resultErr = errors.Join(resultErr, rollbackResourceAuthoritySetup(databaseTransaction))
		}
	}()
	decisionAt, err := store.configureAndScope(ctx, databaseTransaction, scope)
	if err != nil {
		return nil, errors.Join(ErrBeginResourceAuthority, err)
	}
	owned = true
	return &resourceLifecycleTransaction{
		decisionAt: decisionAt, database: databaseTransaction, scope: scope, metrics: store.metrics,
	}, nil
}

// ResolveCommittedLifecycle identifies a possibly committed transition.
func (store *ResourceAuthorityStore) ResolveCommittedLifecycle(
	ctx context.Context,
	command authority.LifecycleCommand,
	ids authority.LifecycleMutationIDs,
) (_ authority.LifecycleResult, found bool, resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.observe(postgresOperationResourceAuthorityReplay, startedAt, resultErr)
	}()
	if ctx == nil || store == nil || store.database == nil || !command.IsValid() ||
		!ids.IsValid() || !validResourceAuthorityOptions(store.options) {
		return authority.LifecycleResult{}, false, ErrInvalidResourceAuthorityStore
	}
	transaction, err := store.database.Begin(ctx, false)
	if err != nil {
		return authority.LifecycleResult{}, false, errors.Join(
			ErrResolveCommittedResourceAuthority,
			classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackResourceAuthoritySetup(transaction))
		}
	}()
	decisionAt, err := store.configureAndScope(ctx, transaction, command.Scope())
	if err != nil {
		return authority.LifecycleResult{}, false, errors.Join(
			ErrResolveCommittedResourceAuthority, err,
		)
	}
	evaluatedAt := decisionAt
	lifecycleTransaction := resourceLifecycleTransaction{
		database: transaction, scope: command.Scope(),
	}
	if _, err := lifecycleTransaction.resolveAuthorization(ctx, command, evaluatedAt); err != nil {
		return authority.LifecycleResult{}, false, errors.Join(
			ErrResolveCommittedResourceAuthority,
			classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	proof := command.IdempotencyEvidence()
	digest := proof.Digest()
	record, err := scanResourceAuthorityIdempotencyRecord(
		transaction.QueryRow(
			ctx,
			loadResourceAuthorityIdempotencySQL,
			command.AccountSession().PrincipalID().String(),
			resourceLifecycleOperation(command),
			proof.DigestKeyID(),
			digest[:],
		),
		false,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := transaction.Commit(ctx); err != nil {
			return authority.LifecycleResult{}, false, errors.Join(
				ErrResolveCommittedResourceAuthority,
				classifyResourceAuthorityCommitError(ctx, err),
			)
		}
		closed = true
		return authority.LifecycleResult{}, false, nil
	}
	if err != nil {
		return authority.LifecycleResult{}, false, errors.Join(
			ErrResolveCommittedResourceAuthority,
			classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	result, found, err := resourceLifecycleCommittedRecord(record, command, evaluatedAt)
	if err != nil {
		return authority.LifecycleResult{}, false, errors.Join(
			ErrResolveCommittedResourceAuthority, err,
		)
	}
	if err := transaction.Commit(ctx); err != nil {
		return authority.LifecycleResult{}, false, errors.Join(
			ErrResolveCommittedResourceAuthority,
			classifyResourceAuthorityCommitError(ctx, err),
		)
	}
	closed = true
	return result, found, nil
}
