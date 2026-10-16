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
	_ authority.GroupReplaceImpactReader            = (*ResourceAuthorityStore)(nil)
	_ authority.GroupReplaceTransactions            = (*ResourceAuthorityStore)(nil)
	_ authority.CommittedGroupReplaceResultResolver = (*ResourceAuthorityStore)(nil)
)

// PreviewGroupReplace returns freshly authorized, snapshot-consistent impact.
func (store *ResourceAuthorityStore) PreviewGroupReplace(
	ctx context.Context,
	preview authority.GroupReplacePreview,
) (_ authority.GroupReplaceImpact, resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.observe(postgresOperationResourceAuthorityResolve, startedAt, resultErr)
	}()
	if ctx == nil || store == nil || store.database == nil || !preview.IsValid() ||
		!validResourceAuthorityOptions(store.options) {
		return authority.GroupReplaceImpact{}, ErrInvalidResourceAuthorityStore
	}
	database, err := store.database.BeginRepeatableRead(ctx)
	if err != nil {
		return authority.GroupReplaceImpact{}, errors.Join(
			ErrResolveResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackResourceAuthoritySetup(database))
		}
	}()
	evaluatedAt, err := store.configureAndScope(ctx, database, preview.Scope())
	if err != nil {
		return authority.GroupReplaceImpact{}, errors.Join(ErrResolveResourceAuthority, err)
	}
	transaction := resourceGroupReplaceTransaction{database: database, scope: preview.Scope()}
	if _, err := transaction.authorize(ctx, preview.AccountSession(), evaluatedAt); err != nil {
		return authority.GroupReplaceImpact{}, errors.Join(
			ErrResolveResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	members, err := encodeResourceGroupReferences(preview.Members())
	if err != nil {
		return authority.GroupReplaceImpact{}, errors.Join(ErrResolveResourceAuthority, err)
	}
	impact, err := scanResourceGroupReplaceImpact(
		database.QueryRow(
			ctx, previewResourceGroupReplaceImpactSQL, preview.GroupID().String(), members,
		),
		preview,
	)
	if err != nil {
		return authority.GroupReplaceImpact{}, errors.Join(
			ErrResolveResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	if err := database.Commit(ctx); err != nil {
		return authority.GroupReplaceImpact{}, errors.Join(
			ErrResolveResourceAuthority, classifyResourceAuthorityCommitError(ctx, err),
		)
	}
	closed = true
	return impact, nil
}

// BeginGroupReplace fixes exact Network scope in one read-write transaction.
func (store *ResourceAuthorityStore) BeginGroupReplace(
	ctx context.Context,
	scope network.Scope,
) (_ authority.GroupReplaceTransaction, resultErr error) {
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
	decisionAt, err := store.configureAndScope(ctx, database, scope)
	if err != nil {
		return nil, errors.Join(ErrBeginResourceAuthority, err)
	}
	owned = true
	return &resourceGroupReplaceTransaction{
		decisionAt: decisionAt, database: database, scope: scope, metrics: store.metrics,
	}, nil
}

// ResolveCommittedGroupReplace identifies a possibly committed replacement.
func (store *ResourceAuthorityStore) ResolveCommittedGroupReplace(
	ctx context.Context,
	command authority.GroupReplaceCommand,
	ids authority.GroupReplaceMutationIDs,
) (_ authority.GroupReplaceResult, found bool, resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.observe(postgresOperationResourceAuthorityReplay, startedAt, resultErr)
	}()
	if ctx == nil || store == nil || store.database == nil || !command.IsValid() ||
		!ids.IsValidFor(command) || !validResourceAuthorityOptions(store.options) {
		return authority.GroupReplaceResult{}, false, ErrInvalidResourceAuthorityStore
	}
	database, err := store.database.Begin(ctx, false)
	if err != nil {
		return authority.GroupReplaceResult{}, false, errors.Join(
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
	decisionAt, err := store.configureAndScope(ctx, database, command.Scope())
	if err != nil {
		return authority.GroupReplaceResult{}, false, errors.Join(
			ErrResolveCommittedResourceAuthority, err,
		)
	}
	evaluatedAt := decisionAt
	transaction := resourceGroupReplaceTransaction{database: database, scope: command.Scope()}
	if _, err := transaction.authorize(ctx, command.AccountSession(), evaluatedAt); err != nil {
		return authority.GroupReplaceResult{}, false, errors.Join(
			ErrResolveCommittedResourceAuthority,
			classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	proof := command.IdempotencyEvidence()
	digest := proof.Digest()
	record, err := scanResourceAuthorityIdempotencyRecord(
		database.QueryRow(
			ctx, loadResourceAuthorityIdempotencySQL,
			command.AccountSession().PrincipalID().String(),
			"resource_group.replace", proof.DigestKeyID(), digest[:],
		),
		false,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := database.Commit(ctx); err != nil {
			return authority.GroupReplaceResult{}, false, errors.Join(
				ErrResolveCommittedResourceAuthority,
				classifyResourceAuthorityCommitError(ctx, err),
			)
		}
		closed = true
		return authority.GroupReplaceResult{}, false, nil
	}
	if err != nil {
		return authority.GroupReplaceResult{}, false, errors.Join(
			ErrResolveCommittedResourceAuthority,
			classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	result, found, err := resourceGroupReplaceCommittedRecord(record, command, evaluatedAt)
	if err != nil {
		return authority.GroupReplaceResult{}, false, errors.Join(
			ErrResolveCommittedResourceAuthority, err,
		)
	}
	if err := database.Commit(ctx); err != nil {
		return authority.GroupReplaceResult{}, false, errors.Join(
			ErrResolveCommittedResourceAuthority,
			classifyResourceAuthorityCommitError(ctx, err),
		)
	}
	closed = true
	return result, found, nil
}
