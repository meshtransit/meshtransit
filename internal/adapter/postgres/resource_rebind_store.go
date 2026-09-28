package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/network"
	authority "github.com/meshtransit/meshtransit/internal/resource/authority"
)

var (
	_ authority.RebindImpactReader            = (*ResourceAuthorityStore)(nil)
	_ authority.RebindTransactions            = (*ResourceAuthorityStore)(nil)
	_ authority.CommittedRebindResultResolver = (*ResourceAuthorityStore)(nil)
)

// PreviewRebind returns a freshly authorized, snapshot-consistent impact preview.
func (store *ResourceAuthorityStore) PreviewRebind(
	ctx context.Context,
	preview authority.RebindPreview,
	evaluatedAt time.Time,
) (_ authority.RebindImpact, resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.observe(postgresOperationResourceAuthorityResolve, startedAt, resultErr)
	}()
	if ctx == nil || store == nil || store.database == nil || !preview.IsValid() ||
		evaluatedAt.IsZero() || !validResourceAuthorityOptions(store.options) {
		return authority.RebindImpact{}, ErrInvalidResourceAuthorityStore
	}
	database, err := store.database.BeginRepeatableRead(ctx)
	if err != nil {
		return authority.RebindImpact{}, errors.Join(
			ErrResolveResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackResourceAuthoritySetup(database))
		}
	}()
	if err := store.configureAndScope(ctx, database, preview.Scope()); err != nil {
		return authority.RebindImpact{}, errors.Join(ErrResolveResourceAuthority, err)
	}
	transaction := resourceRebindTransaction{database: database, scope: preview.Scope()}
	if _, err := transaction.authorize(ctx, preview.AccountSession(), evaluatedAt); err != nil {
		return authority.RebindImpact{}, errors.Join(
			ErrResolveResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	impact, err := scanResourceRebindImpact(
		database.QueryRow(
			ctx, previewResourceRebindImpactSQL,
			preview.ResourceID().String(), preview.DeviceID().String(),
		),
		preview,
	)
	if err != nil {
		return authority.RebindImpact{}, errors.Join(
			ErrResolveResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	if err := database.Commit(ctx); err != nil {
		return authority.RebindImpact{}, errors.Join(
			ErrResolveResourceAuthority, classifyResourceAuthorityCommitError(ctx, err),
		)
	}
	closed = true
	return impact, nil
}

// BeginRebind fixes exact Network scope in one read-write transaction.
func (store *ResourceAuthorityStore) BeginRebind(
	ctx context.Context,
	scope network.Scope,
) (_ authority.RebindTransaction, resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.observe(postgresOperationResourceAuthorityBegin, startedAt, resultErr)
	}()
	if ctx == nil || store == nil || store.database == nil || !scope.IsValid() ||
		!validResourceAuthorityOptions(store.options) {
		return nil, ErrInvalidResourceAuthorityStore
	}
	database, err := store.database.Begin(ctx, false)
	if err != nil {
		return nil, errors.Join(
			ErrBeginResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	owned := false
	defer func() {
		if !owned {
			resultErr = errors.Join(resultErr, rollbackResourceAuthoritySetup(database))
		}
	}()
	if err := store.configureAndScope(ctx, database, scope); err != nil {
		return nil, errors.Join(ErrBeginResourceAuthority, err)
	}
	owned = true
	return &resourceRebindTransaction{database: database, scope: scope, metrics: store.metrics}, nil
}

// ResolveCommittedRebind identifies a possibly committed replacement.
func (store *ResourceAuthorityStore) ResolveCommittedRebind(
	ctx context.Context,
	command authority.RebindCommand,
	ids authority.RebindMutationIDs,
) (_ authority.RebindResult, found bool, resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.observe(postgresOperationResourceAuthorityReplay, startedAt, resultErr)
	}()
	if ctx == nil || store == nil || store.database == nil || !command.IsValid() ||
		!ids.IsValid() || !validResourceAuthorityOptions(store.options) {
		return authority.RebindResult{}, false, ErrInvalidResourceAuthorityStore
	}
	database, err := store.database.Begin(ctx, false)
	if err != nil {
		return authority.RebindResult{}, false, errors.Join(
			ErrResolveCommittedResourceAuthority,
			classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackResourceAuthoritySetup(database))
		}
	}()
	if err := store.configureAndScope(ctx, database, command.Scope()); err != nil {
		return authority.RebindResult{}, false, errors.Join(ErrResolveCommittedResourceAuthority, err)
	}
	evaluatedAt := time.Now().UTC()
	transaction := resourceRebindTransaction{database: database, scope: command.Scope()}
	if _, err := transaction.authorize(ctx, command.AccountSession(), evaluatedAt); err != nil {
		return authority.RebindResult{}, false, errors.Join(
			ErrResolveCommittedResourceAuthority,
			classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	proof := command.IdempotencyEvidence()
	digest := proof.Digest()
	record, err := scanResourceAuthorityIdempotencyRecord(
		database.QueryRow(
			ctx,
			loadResourceAuthorityIdempotencySQL,
			command.AccountSession().PrincipalID().String(),
			"resource.rebind",
			proof.DigestKeyID(),
			digest[:],
		),
		false,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := database.Commit(ctx); err != nil {
			return authority.RebindResult{}, false, errors.Join(
				ErrResolveCommittedResourceAuthority,
				classifyResourceAuthorityCommitError(ctx, err),
			)
		}
		closed = true
		return authority.RebindResult{}, false, nil
	}
	if err != nil {
		return authority.RebindResult{}, false, errors.Join(
			ErrResolveCommittedResourceAuthority,
			classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	result, found, err := resourceRebindCommittedRecord(record, command, evaluatedAt)
	if err != nil {
		return authority.RebindResult{}, false, errors.Join(ErrResolveCommittedResourceAuthority, err)
	}
	if err := database.Commit(ctx); err != nil {
		return authority.RebindResult{}, false, errors.Join(
			ErrResolveCommittedResourceAuthority,
			classifyResourceAuthorityCommitError(ctx, err),
		)
	}
	closed = true
	return result, found, nil
}
