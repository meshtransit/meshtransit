package postgres

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/core/internal/domain/authorization"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	"github.com/meshtransit/meshtransit/core/internal/domain/resource"
	"github.com/meshtransit/meshtransit/core/internal/domain/resource/catalog"
)

// ResourceCatalogOptions bounds each authorized catalog transaction.
type ResourceCatalogOptions struct {
	StatementTimeout time.Duration
	LockTimeout      time.Duration
	IdleTimeout      time.Duration
}

// ResourceCatalogStore exposes least-privilege, exact-scope Resource reads.
type ResourceCatalogStore struct {
	database resourceAuthorityDatabase
	options  ResourceCatalogOptions
}

var _ catalog.Transactions = (*ResourceCatalogStore)(nil)

// NewResourceCatalogStore creates an exact-scope catalog store for the runtime role.
func NewResourceCatalogStore(
	pool *Pool,
	options ResourceCatalogOptions,
) (*ResourceCatalogStore, error) {
	if pool == nil || pool.role != PoolRoleRuntime || pool.resourceAuthorityDatabase == nil ||
		!validResourceCatalogOptions(options) {
		return nil, catalog.ErrUnavailable
	}
	return &ResourceCatalogStore{database: pool.resourceAuthorityDatabase, options: options}, nil
}

func validResourceCatalogOptions(options ResourceCatalogOptions) bool {
	return options.StatementTimeout > 0 &&
		options.StatementTimeout <= maximumResourceAuthorityStatementTimeout &&
		options.LockTimeout > 0 && options.LockTimeout <= maximumResourceAuthorityLockTimeout &&
		options.IdleTimeout > 0 && options.IdleTimeout <= maximumResourceAuthorityIdleTimeout
}

// Begin starts a snapshot-consistent, exact-scope catalog transaction.
func (store *ResourceCatalogStore) Begin(
	ctx context.Context,
	scope network.Scope,
) (catalog.Transaction, error) {
	if ctx == nil || store == nil || store.database == nil || !scope.IsValid() ||
		!validResourceCatalogOptions(store.options) {
		return nil, catalog.ErrUnavailable
	}
	database, err := store.database.BeginRepeatableRead(ctx)
	if err != nil {
		return nil, resourceCatalogDatabaseError(ctx, err)
	}
	owned := false
	defer func() {
		if !owned {
			_ = rollbackResourceAuthoritySetup(database)
		}
	}()
	if err := database.Exec(
		ctx,
		configureResourceAuthoritySQL,
		postgresTimeout(store.options.StatementTimeout),
		postgresTimeout(store.options.LockTimeout),
		postgresTimeout(store.options.IdleTimeout),
	); err != nil {
		return nil, resourceCatalogDatabaseError(ctx, err)
	}
	var workspaceInternalID, networkInternalID int64
	if err := database.QueryRow(
		ctx, setResourceAuthorityScopeSQL,
		scope.WorkspaceID().String(), scope.NetworkID().String(),
	).Scan(&workspaceInternalID, &networkInternalID); err != nil {
		return nil, resourceCatalogDatabaseError(ctx, err)
	}
	if workspaceInternalID <= 0 || networkInternalID <= 0 {
		return nil, catalog.ErrUnavailable
	}
	owned = true
	return &resourceCatalogTransaction{database: database, scope: scope}, nil
}

type resourceCatalogTransaction struct {
	mu                 sync.Mutex
	database           resourceAuthorityDatabaseTransaction
	scope              network.Scope
	closed             bool
	resourceAuthorized bool
	groupAuthorized    bool
}

var _ catalog.Transaction = (*resourceCatalogTransaction)(nil)

func (transaction *resourceCatalogTransaction) Authorize(
	ctx context.Context,
	session accountsession.Session,
	permission authorization.Permission,
	evaluatedAt time.Time,
) error {
	if ctx == nil || transaction == nil || !session.IsValid() || !transaction.scope.IsValid() ||
		(permission != authorization.PermissionResourceRead &&
			permission != authorization.PermissionResourceGroupRead) || evaluatedAt.IsZero() {
		return catalog.ErrUnavailable
	}
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if transaction.closed || transaction.database == nil {
		return catalog.ErrUnavailable
	}
	var bindingID, roleID string
	var scopeGeneration, membershipGeneration, bindingGeneration, roleGeneration int64
	var ownerGeneration int64
	var hasExpiry bool
	var expiresAt time.Time
	err := transaction.database.QueryRow(
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
		transaction.scope.WorkspaceID().String(),
		transaction.scope.NetworkID().String(),
		string(permission),
		evaluatedAt,
	).Scan(
		&bindingID, &roleID, &scopeGeneration, &membershipGeneration,
		&bindingGeneration, &roleGeneration, &hasExpiry, &expiresAt, &ownerGeneration,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return catalog.ErrForbidden
	}
	if err != nil {
		return resourceCatalogDatabaseError(ctx, err)
	}
	binding, role, authorityErr := parseNetworkPermissionAuthority(bindingID, roleID, ownerGeneration)
	if authorityErr != nil || scopeGeneration <= 0 || membershipGeneration <= 0 ||
		!validNetworkPermissionAuthority(binding, role, bindingGeneration, roleGeneration, ownerGeneration) ||
		(hasExpiry && !expiresAt.After(evaluatedAt)) {
		return catalog.ErrForbidden
	}
	if permission == authorization.PermissionResourceRead {
		transaction.resourceAuthorized = true
	} else {
		transaction.groupAuthorized = true
	}
	return nil
}

func (transaction *resourceCatalogTransaction) Revisions(
	ctx context.Context,
) (int64, int64, error) {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if ctx == nil || transaction == nil || transaction.closed || transaction.database == nil ||
		(!transaction.resourceAuthorized && !transaction.groupAuthorized) {
		return 0, 0, catalog.ErrUnavailable
	}
	var networkRevision, inventoryRevision, groupRevision, policyRevision int64
	var dnsRevision, routeRevision, sharingRevision, isolationGeneration int64
	if err := transaction.database.QueryRow(ctx, readResourceCatalogRevisionSQL).Scan(
		&networkRevision, &inventoryRevision, &groupRevision, &policyRevision,
		&dnsRevision, &routeRevision, &sharingRevision, &isolationGeneration,
	); err != nil {
		return 0, 0, resourceCatalogDatabaseError(ctx, err)
	}
	if networkRevision <= 0 || inventoryRevision <= 0 || groupRevision <= 0 ||
		networkRevision < inventoryRevision || networkRevision < groupRevision || policyRevision <= 0 ||
		dnsRevision <= 0 || routeRevision <= 0 || sharingRevision <= 0 || isolationGeneration <= 0 {
		return 0, 0, catalog.ErrUnavailable
	}
	return inventoryRevision, groupRevision, nil
}

func (transaction *resourceCatalogTransaction) Resource(
	ctx context.Context,
	id resource.ID,
) (catalog.Resource, error) {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if ctx == nil || transaction == nil || transaction.closed || transaction.database == nil ||
		!transaction.resourceAuthorized || !id.IsValid() {
		return catalog.Resource{}, catalog.ErrInvalidRequest
	}
	var record resourceCatalogRecord
	var semanticHash []byte
	err := transaction.database.QueryRow(ctx, readResourceCatalogSQL, id.String()).Scan(
		&record.ID, &record.DisplayName, &record.OwnerID, &record.CustodianID,
		&record.DeviceID, &record.State, &record.Kind, &record.Provenance,
		&record.Version, &record.TargetGeneration, &semanticHash,
		&record.ActivatedNetworkRevision, &record.InventoryRevision,
		&record.CreatedAt, &record.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return catalog.Resource{}, catalog.ErrNotFound
	}
	if err != nil {
		return catalog.Resource{}, resourceCatalogDatabaseError(ctx, err)
	}
	record.SemanticHash = hex.EncodeToString(semanticHash)
	return record.value(transaction.scope)
}

func (transaction *resourceCatalogTransaction) Resources(
	ctx context.Context,
	state resource.State,
	after publicid.ID,
	limit int,
) ([]catalog.Resource, error) {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if ctx == nil || transaction == nil || transaction.closed || transaction.database == nil ||
		!transaction.resourceAuthorized || limit < 1 || limit > catalog.MaximumPageSize+1 {
		return nil, catalog.ErrInvalidRequest
	}
	var afterValue any
	if after.IsValid() {
		afterValue = after.String()
	}
	var stateValue any
	if parsed := catalog.StateString(state); parsed != "" {
		stateValue = parsed
	} else if state != resource.StateUnknown {
		return nil, catalog.ErrInvalidRequest
	}
	var encoded string
	if err := transaction.database.QueryRow(
		ctx, listResourceCatalogSQL, afterValue, stateValue, limit,
	).Scan(&encoded); err != nil {
		return nil, resourceCatalogDatabaseError(ctx, err)
	}
	var records []resourceCatalogRecord
	if err := json.Unmarshal([]byte(encoded), &records); err != nil {
		return nil, catalog.ErrInvalidResult
	}
	values := make([]catalog.Resource, len(records))
	for index, record := range records {
		value, err := record.value(transaction.scope)
		if err != nil {
			return nil, err
		}
		values[index] = value
	}
	return values, nil
}

func (transaction *resourceCatalogTransaction) Group(
	ctx context.Context,
	id resource.GroupID,
) (catalog.Group, error) {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if ctx == nil || transaction == nil || transaction.closed || transaction.database == nil ||
		!transaction.groupAuthorized || !id.IsValid() {
		return catalog.Group{}, catalog.ErrInvalidRequest
	}
	var record resourceGroupCatalogRecord
	var semanticHash []byte
	var members string
	err := transaction.database.QueryRow(ctx, readResourceGroupCatalogSQL, id.String()).Scan(
		&record.ID, &record.DisplayName, &record.OwnerID, &record.CustodianID,
		&record.State, &record.Version, &record.DefinitionVersion, &semanticHash,
		&record.ActivatedNetworkRevision, &record.GroupRevision,
		&record.CreatedAt, &record.UpdatedAt, &members,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return catalog.Group{}, catalog.ErrNotFound
	}
	if err != nil {
		return catalog.Group{}, resourceCatalogDatabaseError(ctx, err)
	}
	record.SemanticHash = hex.EncodeToString(semanticHash)
	if err := json.Unmarshal([]byte(members), &record.Members); err != nil {
		return catalog.Group{}, catalog.ErrInvalidResult
	}
	return record.value(transaction.scope)
}

func (transaction *resourceCatalogTransaction) Groups(
	ctx context.Context,
	state resource.State,
	after publicid.ID,
	limit int,
) ([]catalog.Group, error) {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if ctx == nil || transaction == nil || transaction.closed || transaction.database == nil ||
		!transaction.groupAuthorized || limit < 1 || limit > catalog.MaximumPageSize+1 {
		return nil, catalog.ErrInvalidRequest
	}
	var afterValue any
	if after.IsValid() {
		afterValue = after.String()
	}
	var stateValue any
	if parsed := catalog.StateString(state); parsed != "" {
		stateValue = parsed
	} else if state != resource.StateUnknown {
		return nil, catalog.ErrInvalidRequest
	}
	var encoded string
	if err := transaction.database.QueryRow(
		ctx, listResourceGroupCatalogSQL, afterValue, stateValue, limit,
	).Scan(&encoded); err != nil {
		return nil, resourceCatalogDatabaseError(ctx, err)
	}
	var records []resourceGroupCatalogRecord
	if err := json.Unmarshal([]byte(encoded), &records); err != nil {
		return nil, catalog.ErrInvalidResult
	}
	values := make([]catalog.Group, len(records))
	for index, record := range records {
		value, err := record.value(transaction.scope)
		if err != nil {
			return nil, err
		}
		values[index] = value
	}
	return values, nil
}

func (transaction *resourceCatalogTransaction) Commit(ctx context.Context) error {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if ctx == nil || transaction == nil || transaction.closed || transaction.database == nil {
		return catalog.ErrUnavailable
	}
	if err := transaction.database.Commit(ctx); err != nil {
		return resourceCatalogDatabaseError(ctx, err)
	}
	transaction.closed = true
	return nil
}

func (transaction *resourceCatalogTransaction) Rollback(ctx context.Context) error {
	transaction.mu.Lock()
	defer transaction.mu.Unlock()
	if ctx == nil || transaction == nil || transaction.closed || transaction.database == nil {
		return catalog.ErrUnavailable
	}
	transaction.closed = true
	if err := transaction.database.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
		return resourceCatalogDatabaseError(ctx, err)
	}
	return nil
}

type resourceCatalogRecord struct {
	ID                       string    `json:"resource_public_id"`
	DisplayName              string    `json:"display_name"`
	OwnerID                  string    `json:"owner_principal_public_id"`
	CustodianID              string    `json:"custodian_principal_public_id"`
	DeviceID                 string    `json:"device_public_id"`
	State                    string    `json:"state"`
	Kind                     string    `json:"kind"`
	Provenance               string    `json:"provenance_kind"`
	Version                  int64     `json:"version"`
	TargetGeneration         int64     `json:"target_generation"`
	SemanticHash             string    `json:"semantic_hash"`
	ActivatedNetworkRevision int64     `json:"activated_network_revision"`
	InventoryRevision        int64     `json:"inventory_revision"`
	CreatedAt                time.Time `json:"created_at"`
	UpdatedAt                time.Time `json:"updated_at"`
}

func (record resourceCatalogRecord) value(scope network.Scope) (catalog.Resource, error) {
	id, err := resource.ParseID(record.ID)
	if err != nil || record.Kind != "device" || record.Provenance != "manual" {
		return catalog.Resource{}, catalog.ErrInvalidResult
	}
	name, err := resource.ParseDisplayName(record.DisplayName)
	if err != nil {
		return catalog.Resource{}, catalog.ErrInvalidResult
	}
	ownerID, err := identity.ParsePrincipalID(record.OwnerID)
	if err != nil {
		return catalog.Resource{}, catalog.ErrInvalidResult
	}
	custodianID, err := identity.ParsePrincipalID(record.CustodianID)
	if err != nil {
		return catalog.Resource{}, catalog.ErrInvalidResult
	}
	deviceID, err := node.ParseID(record.DeviceID)
	if err != nil {
		return catalog.Resource{}, catalog.ErrInvalidResult
	}
	state, err := catalog.ParseState(record.State)
	if err != nil || state == resource.StateUnknown {
		return catalog.Resource{}, catalog.ErrInvalidResult
	}
	semanticHash, err := parseCatalogSemanticHash(record.SemanticHash)
	if err != nil {
		return catalog.Resource{}, err
	}
	return catalog.NewResource(catalog.ResourceParams{
		ID: id, Scope: scope, DisplayName: name, OwnerPrincipalID: ownerID,
		CustodianPrincipalID: custodianID, DeviceID: deviceID, State: state,
		Provenance: resource.ProvenanceManual, Version: record.Version,
		TargetGeneration: record.TargetGeneration, SemanticHash: semanticHash,
		ActivatedNetworkRevision: record.ActivatedNetworkRevision,
		InventoryRevision:        record.InventoryRevision,
		CreatedAt:                record.CreatedAt, UpdatedAt: record.UpdatedAt,
	})
}

type resourceGroupMemberRecord struct {
	ResourceID       string `json:"resource_public_id"`
	ResourceVersion  int64  `json:"resource_version"`
	TargetGeneration int64  `json:"target_generation"`
}

type resourceGroupCatalogRecord struct {
	ID                       string                      `json:"group_public_id"`
	DisplayName              string                      `json:"display_name"`
	OwnerID                  string                      `json:"owner_principal_public_id"`
	CustodianID              string                      `json:"custodian_principal_public_id"`
	State                    string                      `json:"state"`
	Version                  int64                       `json:"version"`
	DefinitionVersion        int64                       `json:"definition_version"`
	SemanticHash             string                      `json:"semantic_hash"`
	ActivatedNetworkRevision int64                       `json:"activated_network_revision"`
	GroupRevision            int64                       `json:"group_revision"`
	CreatedAt                time.Time                   `json:"created_at"`
	UpdatedAt                time.Time                   `json:"updated_at"`
	Members                  []resourceGroupMemberRecord `json:"members"`
}

func (record resourceGroupCatalogRecord) value(scope network.Scope) (catalog.Group, error) {
	id, err := resource.ParseGroupID(record.ID)
	if err != nil {
		return catalog.Group{}, catalog.ErrInvalidResult
	}
	name, err := resource.ParseDisplayName(record.DisplayName)
	if err != nil {
		return catalog.Group{}, catalog.ErrInvalidResult
	}
	ownerID, err := identity.ParsePrincipalID(record.OwnerID)
	if err != nil {
		return catalog.Group{}, catalog.ErrInvalidResult
	}
	custodianID, err := identity.ParsePrincipalID(record.CustodianID)
	if err != nil {
		return catalog.Group{}, catalog.ErrInvalidResult
	}
	state, err := catalog.ParseState(record.State)
	if err != nil || state == resource.StateUnknown {
		return catalog.Group{}, catalog.ErrInvalidResult
	}
	semanticHash, err := parseCatalogSemanticHash(record.SemanticHash)
	if err != nil {
		return catalog.Group{}, err
	}
	members := make([]resource.Reference, len(record.Members))
	for index, member := range record.Members {
		memberID, err := resource.ParseID(member.ResourceID)
		if err != nil {
			return catalog.Group{}, catalog.ErrInvalidResult
		}
		reference, err := resource.NewReference(
			scope, memberID, member.ResourceVersion, member.TargetGeneration,
		)
		if err != nil {
			return catalog.Group{}, catalog.ErrInvalidResult
		}
		members[index] = reference
	}
	return catalog.NewGroup(catalog.GroupParams{
		ID: id, Scope: scope, DisplayName: name, OwnerPrincipalID: ownerID,
		CustodianPrincipalID: custodianID, State: state, Version: record.Version,
		DefinitionVersion: record.DefinitionVersion, SemanticHash: semanticHash,
		ActivatedNetworkRevision: record.ActivatedNetworkRevision,
		GroupRevision:            record.GroupRevision, Members: members,
		CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt,
	})
}

func parseCatalogSemanticHash(value string) (resource.SemanticHash, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 32 {
		return resource.SemanticHash{}, catalog.ErrInvalidResult
	}
	var fixed [32]byte
	copy(fixed[:], decoded)
	hash, err := resource.NewSemanticHash(fixed)
	if err != nil {
		return resource.SemanticHash{}, catalog.ErrInvalidResult
	}
	return hash, nil
}

func resourceCatalogDatabaseError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if ctx != nil && ctx.Err() != nil {
		return errors.Join(catalog.ErrUnavailable, ctx.Err())
	}
	return errors.Join(catalog.ErrUnavailable, fmt.Errorf("resource catalog database: %w", err))
}
