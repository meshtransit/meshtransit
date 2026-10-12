package postgres

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"meshtransit.net/core/internal/domain/authorization"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/sharing"
)

const maximumResourceSharingIdempotencyTTL = 24 * time.Hour

// ResourceSharingOptions bounds every database wait and replay record lifetime.
type ResourceSharingOptions struct {
	StatementTimeout time.Duration
	LockTimeout      time.Duration
	IdleTimeout      time.Duration
	IdempotencyTTL   time.Duration
}

// ResourceSharingStore owns exact-scope sharing reads and atomic bilateral mutations.
type ResourceSharingStore struct {
	database resourceAuthorityDatabase
	options  ResourceSharingOptions
}

var _ sharing.Repository = (*ResourceSharingStore)(nil)

// NewResourceSharingStore constructs a least-privilege store from the runtime pool.
func NewResourceSharingStore(
	pool *Pool,
	options ResourceSharingOptions,
) (*ResourceSharingStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.resourceAuthorityDatabase == nil ||
		!validResourceSharingOptions(options) {
		return nil, sharing.ErrUnavailable
	}
	return &ResourceSharingStore{database: pool.resourceAuthorityDatabase, options: options}, nil
}

func validResourceSharingOptions(options ResourceSharingOptions) bool {
	return options.StatementTimeout > 0 &&
		options.StatementTimeout <= maximumResourceAuthorityStatementTimeout &&
		options.LockTimeout > 0 && options.LockTimeout <= maximumResourceAuthorityLockTimeout &&
		options.IdleTimeout > 0 && options.IdleTimeout <= maximumResourceAuthorityIdleTimeout &&
		options.IdempotencyTTL > 0 && options.IdempotencyTTL <= maximumResourceSharingIdempotencyTTL
}

// GetOffer returns one current projection after exact-scope share.read authorization.
func (store *ResourceSharingStore) GetOffer(
	ctx context.Context,
	session accountsession.Session,
	scope network.Scope,
	id sharing.OfferID,
	evaluatedAt time.Time,
) (_ sharing.OfferSnapshot, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !session.IsValid() ||
		!scope.IsValid() || !id.IsValid() || evaluatedAt.IsZero() ||
		!validResourceSharingOptions(store.options) {
		return sharing.OfferSnapshot{}, sharing.ErrInvalidManagementRequest
	}
	transaction, err := store.begin(ctx)
	if err != nil {
		return sharing.OfferSnapshot{}, err
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackResourceSharing(transaction))
		}
	}()
	if _, err := setResourceSharingScope(ctx, transaction, scope); err != nil {
		return sharing.OfferSnapshot{}, err
	}
	if _, err := authorizeResourceSharing(
		ctx, transaction, session, scope, authorization.PermissionShareRead, evaluatedAt,
	); err != nil {
		return sharing.OfferSnapshot{}, err
	}
	projection, err := readResourceSharingOffer(ctx, transaction, id)
	if err != nil {
		return sharing.OfferSnapshot{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return sharing.OfferSnapshot{}, resourceSharingDatabaseError(ctx, err)
	}
	closed = true
	return projection.offer, nil
}

// ListOffers returns one UUID-keyset page pinned to the local sharing revision.
func (store *ResourceSharingStore) ListOffers(
	ctx context.Context,
	session accountsession.Session,
	scope network.Scope,
	direction sharing.Direction,
	state sharing.OfferState,
	limit int,
	cursor sharing.PageCursor,
	evaluatedAt time.Time,
) (_ sharing.OfferPage, resultErr error) {
	if ctx == nil || store == nil || store.database == nil || !session.IsValid() ||
		!scope.IsValid() || !direction.IsValid() || limit < 1 ||
		limit > sharing.MaximumManagementPageSize || evaluatedAt.IsZero() ||
		(cursor != (sharing.PageCursor{}) && !cursor.IsValid()) ||
		!validResourceSharingOptions(store.options) {
		return sharing.OfferPage{}, sharing.ErrInvalidManagementRequest
	}
	stateFilter, validState := resourceSharingStateFilter(state)
	if !validState {
		return sharing.OfferPage{}, sharing.ErrInvalidManagementRequest
	}
	transaction, err := store.begin(ctx)
	if err != nil {
		return sharing.OfferPage{}, err
	}
	closed := false
	defer func() {
		if !closed {
			resultErr = errors.Join(resultErr, rollbackResourceSharing(transaction))
		}
	}()
	networkState, err := setResourceSharingScope(ctx, transaction, scope)
	if err != nil {
		return sharing.OfferPage{}, err
	}
	if _, err := authorizeResourceSharing(
		ctx, transaction, session, scope, authorization.PermissionShareRead, evaluatedAt,
	); err != nil {
		return sharing.OfferPage{}, err
	}
	if cursor.IsValid() && cursor.Revision() != networkState.sharingRevision {
		return sharing.OfferPage{}, sharing.ErrConflict
	}
	var after any
	if cursor.IsValid() {
		after = cursor.After().String()
	}
	var encoded string
	if err := transaction.QueryRow(
		ctx,
		listResourceSharingOffersSQL,
		resourceSharingDirection(direction),
		stateFilter,
		after,
		limit+1,
	).Scan(&encoded); err != nil {
		return sharing.OfferPage{}, resourceSharingDatabaseError(ctx, err)
	}
	projections, err := decodeResourceSharingOffers(encoded)
	if err != nil {
		return sharing.OfferPage{}, err
	}
	next := sharing.EmptyPageCursor()
	if len(projections) > limit {
		last := projections[limit-1].offer.Offer().ID()
		next, err = sharing.NewPageCursor(networkState.sharingRevision, last)
		if err != nil {
			return sharing.OfferPage{}, sharing.ErrUnavailable
		}
		projections = projections[:limit]
	}
	items := make([]sharing.OfferSnapshot, len(projections))
	for index, projection := range projections {
		items[index] = projection.offer
	}
	page, err := sharing.NewOfferPage(items, networkState.sharingRevision, next)
	if err != nil {
		return sharing.OfferPage{}, sharing.ErrUnavailable
	}
	if err := transaction.Commit(ctx); err != nil {
		return sharing.OfferPage{}, resourceSharingDatabaseError(ctx, err)
	}
	closed = true
	return page, nil
}

func (store *ResourceSharingStore) begin(
	ctx context.Context,
) (resourceAuthorityDatabaseTransaction, error) {
	transaction, err := store.database.BeginRepeatableRead(ctx)
	if err != nil {
		return nil, resourceSharingDatabaseError(ctx, err)
	}
	if err := transaction.Exec(
		ctx,
		configureResourceAuthoritySQL,
		postgresTimeout(store.options.StatementTimeout),
		postgresTimeout(store.options.LockTimeout),
		postgresTimeout(store.options.IdleTimeout),
	); err != nil {
		_ = rollbackResourceSharing(transaction)
		return nil, resourceSharingDatabaseError(ctx, err)
	}
	return transaction, nil
}

type resourceSharingNetworkState struct {
	scope               network.Scope
	workspaceInternal   int64
	networkInternal     int64
	authorityGeneration int64
	networkRevision     int64
	sharingRevision     int64
}

func setResourceSharingScope(
	ctx context.Context,
	transaction resourceAuthorityDatabaseTransaction,
	scope network.Scope,
) (resourceSharingNetworkState, error) {
	var workspaceInternalID, networkInternalID int64
	if err := transaction.QueryRow(
		ctx,
		setResourceAuthorityScopeSQL,
		scope.WorkspaceID().String(),
		scope.NetworkID().String(),
	).Scan(&workspaceInternalID, &networkInternalID); err != nil {
		return resourceSharingNetworkState{}, resourceSharingDatabaseError(ctx, err)
	}
	return readResourceSharingNetworkState(
		ctx, transaction, scope, workspaceInternalID, networkInternalID,
	)
}

func readResourceSharingNetworkState(
	ctx context.Context,
	transaction resourceAuthorityDatabaseTransaction,
	scope network.Scope,
	workspaceInternalID, networkInternalID int64,
) (resourceSharingNetworkState, error) {
	var authorityGeneration, networkRevision, sharingRevision int64
	if err := transaction.QueryRow(ctx, readResourceSharingNetworkStateSQL).Scan(
		&authorityGeneration, &networkRevision, &sharingRevision,
	); err != nil {
		return resourceSharingNetworkState{}, resourceSharingDatabaseError(ctx, err)
	}
	state := resourceSharingNetworkState{
		scope: scope, workspaceInternal: workspaceInternalID, networkInternal: networkInternalID,
		authorityGeneration: authorityGeneration,
		networkRevision:     networkRevision, sharingRevision: sharingRevision,
	}
	if !state.isValid() {
		return resourceSharingNetworkState{}, sharing.ErrUnavailable
	}
	return state, nil
}

func (state resourceSharingNetworkState) isValid() bool {
	return state.scope.IsValid() && state.workspaceInternal > 0 && state.networkInternal > 0 &&
		state.authorityGeneration > 0 && state.networkRevision > 0 && state.sharingRevision > 0 &&
		state.networkRevision >= state.sharingRevision
}

func authorizeResourceSharing(
	ctx context.Context,
	transaction resourceAuthorityDatabaseTransaction,
	session accountsession.Session,
	scope network.Scope,
	permission authorization.Permission,
	evaluatedAt time.Time,
) (resourceAuthorityAuthorizationEvidence, error) {
	var evidence resourceAuthorityAuthorizationEvidence
	var bindingIDValue, roleIDValue string
	var hasExpiry bool
	var expiresAt time.Time
	err := transaction.QueryRow(
		ctx,
		authorizeResourceAuthoritySQL,
		session.ID().String(),
		session.DeploymentID().String(),
		session.PrincipalID().String(),
		session.IdentitySubjectID().String(),
		session.Version(),
		session.PrincipalAuthorityGeneration(),
		session.AccountSessionGeneration(),
		session.ProviderGeneration(),
		session.DeploymentRecoveryEpoch(),
		scope.WorkspaceID().String(),
		scope.NetworkID().String(),
		string(permission),
		evaluatedAt,
	).Scan(
		&bindingIDValue,
		&roleIDValue,
		&evidence.scopeAuthorityGeneration,
		&evidence.membershipAuthorityGeneration,
		&evidence.bindingAuthorityGeneration,
		&evidence.roleAuthorityGeneration,
		&hasExpiry,
		&expiresAt,
		&evidence.workspaceOwnerAuthorityGeneration,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return resourceAuthorityAuthorizationEvidence{}, sharing.ErrForbidden
	}
	if err != nil {
		return resourceAuthorityAuthorizationEvidence{}, resourceSharingDatabaseError(ctx, err)
	}
	bindingID, roleID, authorityErr := parseNetworkPermissionAuthority(bindingIDValue, roleIDValue, evidence.workspaceOwnerAuthorityGeneration)
	evidence.accountSessionID = publicid.ID(session.ID())
	evidence.roleBindingID = bindingID
	evidence.roleDefinitionID = roleID
	if authorityErr != nil || !evidence.isValid() ||
		(hasExpiry && !expiresAt.After(evaluatedAt)) {
		return resourceAuthorityAuthorizationEvidence{}, sharing.ErrForbidden
	}
	return evidence, nil
}

func readResourceSharingOffer(
	ctx context.Context,
	transaction resourceAuthorityDatabaseTransaction,
	id sharing.OfferID,
) (resourceSharingProjection, error) {
	var encoded string
	err := transaction.QueryRow(ctx, readResourceSharingOfferSQL, id.String()).Scan(&encoded)
	if errors.Is(err, pgx.ErrNoRows) {
		return resourceSharingProjection{}, sharing.ErrNotFound
	}
	if err != nil {
		return resourceSharingProjection{}, resourceSharingDatabaseError(ctx, err)
	}
	return decodeResourceSharingOffer(encoded)
}

func resourceSharingStateFilter(state sharing.OfferState) (any, bool) {
	value := resourceSharingOfferStateFilter(state)
	if err, invalid := value.(error); invalid {
		_ = err
		return nil, false
	}
	return value, true
}

func resourceSharingDatabaseError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return errors.Join(sharing.ErrUnavailable, ctx.Err(), err)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return sharing.ErrNotFound
	}
	postgresError, ok := errors.AsType[*pgconn.PgError](err)
	if !ok {
		return errors.Join(sharing.ErrUnavailable, err)
	}
	switch postgresError.Code {
	case "22023":
		return errors.Join(sharing.ErrInvalidManagementRequest, err)
	case "23505":
		switch postgresError.ConstraintName {
		case "imported_resource_network_name_current_uidx":
			return errors.Join(sharing.ErrImportedNameTaken, sharing.ErrConflict, err)
		case "imported_resource_access_name_current_uidx":
			return errors.Join(sharing.ErrAccessNameTaken, sharing.ErrConflict, err)
		}
		return errors.Join(sharing.ErrConflict, err)
	case "MT001", "40001", "40P01", "55P03":
		return errors.Join(sharing.ErrConflict, err)
	case "42501":
		return errors.Join(sharing.ErrForbidden, err)
	default:
		return errors.Join(sharing.ErrUnavailable, err)
	}
}

func rollbackResourceSharing(transaction resourceAuthorityDatabaseTransaction) error {
	if transaction == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), resourceAuthoritySetupRollbackWindow)
	defer cancel()
	if err := transaction.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return fmt.Errorf("rollback Resource Sharing transaction: %w", err)
	}
	return nil
}

type resourceSharingIdempotencyPayload struct {
	Operation               string `json:"operation"`
	OfferID                 string `json:"offer_id"`
	ContractID              string `json:"contract_id,omitempty"`
	ProviderNetworkRevision int64  `json:"provider_network_revision"`
	ProviderSharingRevision int64  `json:"provider_sharing_revision"`
	ConsumerNetworkRevision int64  `json:"consumer_network_revision"`
	ConsumerSharingRevision int64  `json:"consumer_sharing_revision"`
	ImportedResourceVersion int64  `json:"imported_resource_version,omitempty"`
}

func decodeResourceSharingIdempotencyPayload(
	record resourceAuthorityIdempotencyRecord,
	operation string,
	requestHash [32]byte,
	now time.Time,
) (resourceSharingIdempotencyPayload, bool, error) {
	if subtle.ConstantTimeCompare(record.requestSemanticHash, requestHash[:]) != 1 {
		return resourceSharingIdempotencyPayload{}, false, sharing.ErrConflict
	}
	if !record.expiresAt.After(now) {
		return resourceSharingIdempotencyPayload{}, false, sharing.ErrConflict
	}
	if record.created {
		if record.state != "pending" || record.resultKind != "" || record.resultPublicID != "" ||
			record.resultVersion != 0 || record.resultNetworkRevision != 0 ||
			record.resultPayload != "{}" {
			return resourceSharingIdempotencyPayload{}, false, sharing.ErrUnavailable
		}
		return resourceSharingIdempotencyPayload{}, false, nil
	}
	if record.state != "completed" || record.resultKind != "resource_sharing_mutation" ||
		record.resultPublicID == "" || record.resultVersion <= 0 ||
		record.resultNetworkRevision <= 0 {
		return resourceSharingIdempotencyPayload{}, false, sharing.ErrUnavailable
	}
	var payload resourceSharingIdempotencyPayload
	if err := json.Unmarshal([]byte(record.resultPayload), &payload); err != nil ||
		payload.Operation != operation || payload.OfferID == "" ||
		payload.ProviderNetworkRevision <= 0 || payload.ProviderSharingRevision <= 0 ||
		payload.ConsumerNetworkRevision <= 0 || payload.ConsumerSharingRevision <= 0 {
		return resourceSharingIdempotencyPayload{}, false, sharing.ErrUnavailable
	}
	return payload, true, nil
}
