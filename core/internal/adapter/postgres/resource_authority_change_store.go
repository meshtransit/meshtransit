package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/authorization"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	authority "meshtransit.net/core/internal/domain/resource/authority"
)

var (
	_ authority.ChangeImpactReader                           = (*ResourceAuthorityStore)(nil)
	_ authority.ChangeRequestTransactions                    = (*ResourceAuthorityStore)(nil)
	_ authority.CommittedAuthorityChangeRequestResolver      = (*ResourceAuthorityStore)(nil)
	_ authority.ChangeConfirmationTransactions               = (*ResourceAuthorityStore)(nil)
	_ authority.CommittedAuthorityChangeConfirmationResolver = (*ResourceAuthorityStore)(nil)
)

func authorityChangePermission(
	kind authority.SubjectKind,
) authorization.Permission {
	if kind == authority.AuthoritySubjectGroup {
		return authorization.PermissionResourceGroupTransfer
	}
	return authorization.PermissionResourceTransfer
}

func authorizeResourceAuthorityChange(
	ctx context.Context,
	database resourceAuthorityDatabaseTransaction,
	scope network.Scope,
	session accountsession.Session,
	permission authorization.Permission,
	evaluatedAt time.Time,
) (resourceAuthorityAuthorizationEvidence, error) {
	var bindingIDValue, roleIDValue string
	var scopeGeneration, membershipGeneration, bindingGeneration, roleGeneration int64
	var ownerGeneration int64
	var hasExpiry bool
	var expiresAt time.Time
	err := database.QueryRow(
		ctx, authorizeResourceAuthoritySQL,
		session.ID().String(), session.DeploymentID().String(), session.PrincipalID().String(),
		session.IdentitySubjectID().String(), session.Version(),
		session.PrincipalAuthorityGeneration(), session.AccountSessionGeneration(),
		session.ProviderGeneration(), session.DeploymentRecoveryEpoch(),
		scope.WorkspaceID().String(), scope.NetworkID().String(), string(permission), evaluatedAt,
	).Scan(
		&bindingIDValue, &roleIDValue, &scopeGeneration, &membershipGeneration,
		&bindingGeneration, &roleGeneration, &hasExpiry, &expiresAt, &ownerGeneration,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return resourceAuthorityAuthorizationEvidence{}, authority.ErrForbidden
	}
	if err != nil {
		return resourceAuthorityAuthorizationEvidence{}, fmt.Errorf(
			"authorize Resource authority change: %w", err,
		)
	}
	if hasExpiry && !expiresAt.After(evaluatedAt) {
		return resourceAuthorityAuthorizationEvidence{}, authority.ErrForbidden
	}
	bindingID, roleID, err := parseNetworkPermissionAuthority(bindingIDValue, roleIDValue, ownerGeneration)
	if err != nil {
		return resourceAuthorityAuthorizationEvidence{}, ErrResourceAuthorityEvidence
	}
	evidence := resourceAuthorityAuthorizationEvidence{
		accountSessionID: publicid.ID(session.ID()), roleBindingID: bindingID,
		roleDefinitionID: roleID, scopeAuthorityGeneration: scopeGeneration,
		membershipAuthorityGeneration: membershipGeneration,
		bindingAuthorityGeneration:    bindingGeneration, roleAuthorityGeneration: roleGeneration,
		workspaceOwnerAuthorityGeneration: ownerGeneration,
	}
	if !evidence.isValid() {
		return resourceAuthorityAuthorizationEvidence{}, ErrResourceAuthorityEvidence
	}
	return evidence, nil
}

// PreviewAuthorityChange returns freshly authorized, snapshot-consistent impact.
func (store *ResourceAuthorityStore) PreviewAuthorityChange(
	ctx context.Context,
	preview authority.ChangePreview,
	evaluatedAt time.Time,
) (_ authority.ChangeImpact, resultErr error) {
	startedAt := time.Now()
	defer func() {
		store.observe(postgresOperationResourceAuthorityResolve, startedAt, resultErr)
	}()
	if ctx == nil || store == nil || store.database == nil || !preview.IsValid() ||
		evaluatedAt.IsZero() || !validResourceAuthorityOptions(store.options) {
		return authority.ChangeImpact{}, ErrInvalidResourceAuthorityStore
	}
	database, err := store.database.BeginRepeatableRead(ctx)
	if err != nil {
		return authority.ChangeImpact{}, errors.Join(
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
		return authority.ChangeImpact{}, errors.Join(ErrResolveResourceAuthority, err)
	}
	if _, err := authorizeResourceAuthorityChange(
		ctx, database, preview.Scope(), preview.AccountSession(),
		authorityChangePermission(preview.SubjectKind()), evaluatedAt,
	); err != nil {
		return authority.ChangeImpact{}, errors.Join(
			ErrResolveResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	query := previewResourceAuthorityChangeSQL
	if preview.SubjectKind() == authority.AuthoritySubjectGroup {
		query = previewResourceGroupAuthorityChangeSQL
	}
	impact, err := scanResourceAuthorityChangeImpact(
		database.QueryRow(
			ctx, query, preview.SubjectPublicID().String(), preview.Action().String(),
			preview.TargetPrincipalID().String(),
		),
		preview,
	)
	if err != nil {
		return authority.ChangeImpact{}, errors.Join(
			ErrResolveResourceAuthority, classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	if err := database.Commit(ctx); err != nil {
		return authority.ChangeImpact{}, errors.Join(
			ErrResolveResourceAuthority, classifyResourceAuthorityCommitError(ctx, err),
		)
	}
	closed = true
	return impact, nil
}

// BeginAuthorityChangeRequest fixes exact Network scope for proposal creation.
func (store *ResourceAuthorityStore) BeginAuthorityChangeRequest(
	ctx context.Context,
	scope network.Scope,
) (_ authority.ChangeRequestTransaction, resultErr error) {
	database, err := store.beginAuthorityChange(ctx, scope)
	if err != nil {
		return nil, err
	}
	return &resourceAuthorityChangeRequestTransaction{
		database: database, scope: scope, metrics: store.metrics,
	}, nil
}

// BeginAuthorityChangeConfirmation fixes exact Network scope for final application.
func (store *ResourceAuthorityStore) BeginAuthorityChangeConfirmation(
	ctx context.Context,
	scope network.Scope,
) (_ authority.ChangeConfirmationTransaction, resultErr error) {
	database, err := store.beginAuthorityChange(ctx, scope)
	if err != nil {
		return nil, err
	}
	return &resourceAuthorityChangeConfirmationTransaction{
		database: database, scope: scope, metrics: store.metrics,
	}, nil
}

func (store *ResourceAuthorityStore) beginAuthorityChange(
	ctx context.Context,
	scope network.Scope,
) (_ resourceAuthorityDatabaseTransaction, resultErr error) {
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
	return database, nil
}

// ResolveCommittedAuthorityChangeRequest resolves an uncertain proposal commit.
func (store *ResourceAuthorityStore) ResolveCommittedAuthorityChangeRequest(
	ctx context.Context,
	command authority.ChangeRequestCommand,
	ids authority.ChangeRequestMutationIDs,
) (_ authority.ChangeRequestResult, found bool, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !command.IsValid() ||
		!ids.IsValid() || !validResourceAuthorityOptions(store.options) {
		return authority.ChangeRequestResult{}, false, ErrInvalidResourceAuthorityStore
	}
	database, closeDatabase, err := store.beginAuthorityChangeReplay(ctx, command.Scope())
	if err != nil {
		return authority.ChangeRequestResult{}, false, err
	}
	defer func() { closeDatabase(&resultErr) }()
	evaluatedAt := time.Now().UTC()
	preview := command.Preview()
	if _, err := authorizeResourceAuthorityChange(
		ctx, database, command.Scope(), preview.AccountSession(),
		authorityChangePermission(preview.SubjectKind()), evaluatedAt,
	); err != nil {
		return authority.ChangeRequestResult{}, false, errors.Join(
			ErrResolveCommittedResourceAuthority,
			classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	record, err := loadAuthorityChangeIdempotency(
		ctx, database, preview.AccountSession().PrincipalID().String(),
		resourceAuthorityChangeRequestOperation, command.IdempotencyEvidence(),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := database.Commit(ctx); err != nil {
			return authority.ChangeRequestResult{}, false, errors.Join(
				ErrResolveCommittedResourceAuthority,
				classifyResourceAuthorityCommitError(ctx, err),
			)
		}
		closeDatabase = func(*error) {}
		return authority.ChangeRequestResult{}, false, nil
	}
	if err != nil {
		return authority.ChangeRequestResult{}, false, errors.Join(
			ErrResolveCommittedResourceAuthority,
			classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	result, found, err := authorityChangeRequestCommittedRecord(record, command, evaluatedAt)
	if err != nil {
		return authority.ChangeRequestResult{}, false,
			errors.Join(ErrResolveCommittedResourceAuthority, err)
	}
	if err := database.Commit(ctx); err != nil {
		return authority.ChangeRequestResult{}, false, errors.Join(
			ErrResolveCommittedResourceAuthority,
			classifyResourceAuthorityCommitError(ctx, err),
		)
	}
	closeDatabase = func(*error) {}
	return result, found, nil
}

// ResolveCommittedAuthorityChangeConfirmation resolves an uncertain final commit.
func (store *ResourceAuthorityStore) ResolveCommittedAuthorityChangeConfirmation(
	ctx context.Context,
	command authority.ChangeConfirmationCommand,
	ids authority.ChangeConfirmationMutationIDs,
) (_ authority.ChangeConfirmationResult, found bool, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !command.IsValid() ||
		!ids.IsValid() || !validResourceAuthorityOptions(store.options) {
		return authority.ChangeConfirmationResult{}, false,
			ErrInvalidResourceAuthorityStore
	}
	database, closeDatabase, err := store.beginAuthorityChangeReplay(ctx, command.Scope())
	if err != nil {
		return authority.ChangeConfirmationResult{}, false, err
	}
	defer func() { closeDatabase(&resultErr) }()
	evaluatedAt := time.Now().UTC()
	if _, err := authorizeResourceAuthorityChange(
		ctx, database, command.Scope(), command.AccountSession(),
		authorityChangePermission(command.SubjectKind()), evaluatedAt,
	); err != nil {
		return authority.ChangeConfirmationResult{}, false, errors.Join(
			ErrResolveCommittedResourceAuthority,
			classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	record, err := loadAuthorityChangeIdempotency(
		ctx, database, command.AccountSession().PrincipalID().String(),
		resourceAuthorityChangeConfirmationOperation, command.IdempotencyEvidence(),
	)
	if errors.Is(err, pgx.ErrNoRows) {
		if err := database.Commit(ctx); err != nil {
			return authority.ChangeConfirmationResult{}, false, errors.Join(
				ErrResolveCommittedResourceAuthority,
				classifyResourceAuthorityCommitError(ctx, err),
			)
		}
		closeDatabase = func(*error) {}
		return authority.ChangeConfirmationResult{}, false, nil
	}
	if err != nil {
		return authority.ChangeConfirmationResult{}, false, errors.Join(
			ErrResolveCommittedResourceAuthority,
			classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	result, found, err := authorityChangeConfirmationCommittedRecord(record, command, evaluatedAt)
	if err != nil {
		return authority.ChangeConfirmationResult{}, false,
			errors.Join(ErrResolveCommittedResourceAuthority, err)
	}
	if err := database.Commit(ctx); err != nil {
		return authority.ChangeConfirmationResult{}, false, errors.Join(
			ErrResolveCommittedResourceAuthority,
			classifyResourceAuthorityCommitError(ctx, err),
		)
	}
	closeDatabase = func(*error) {}
	return result, found, nil
}

func (store *ResourceAuthorityStore) beginAuthorityChangeReplay(
	ctx context.Context,
	scope network.Scope,
) (resourceAuthorityDatabaseTransaction, func(*error), error) {
	database, err := store.database.Begin(ctx, false)
	if err != nil {
		return nil, nil, errors.Join(
			ErrResolveCommittedResourceAuthority,
			classifyResourceAuthorityDatabaseError(ctx, err),
		)
	}
	closeDatabase := func(resultErr *error) {
		*resultErr = errors.Join(*resultErr, rollbackResourceAuthoritySetup(database))
	}
	if err := store.configureAndScope(ctx, database, scope); err != nil {
		closeDatabase(&err)
		return nil, nil, errors.Join(ErrResolveCommittedResourceAuthority, err)
	}
	return database, closeDatabase, nil
}

func loadAuthorityChangeIdempotency(
	ctx context.Context,
	database resourceAuthorityDatabaseTransaction,
	principalID, operation string,
	proof interface {
		DigestKeyID() string
		Digest() [32]byte
	},
) (resourceAuthorityIdempotencyRecord, error) {
	digest := proof.Digest()
	return scanResourceAuthorityIdempotencyRecord(
		database.QueryRow(
			ctx, loadResourceAuthorityIdempotencySQL,
			principalID, operation, proof.DigestKeyID(), digest[:],
		),
		false,
	)
}
