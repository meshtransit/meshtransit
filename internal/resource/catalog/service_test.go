package catalog

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/authorization"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/resource"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

func TestServiceListsResourcesWithFreshPermissionAndPinnedRevision(t *testing.T) {
	t.Parallel()
	transaction := &catalogTransactionFixture{inventoryRevision: 7, groupRevision: 4}
	service := catalogServiceFixture(t, transaction)

	page, err := service.ListResources(
		t.Context(), catalogSessionFixture(t), catalogScopeFixture(t),
		resource.StateActive, 25, PageCursor{},
	)
	if err != nil {
		t.Fatalf("ListResources() error = %v", err)
	}
	if page.Revision != 7 || page.Items == nil || len(page.Items) != 0 ||
		transaction.permission != authorization.PermissionResourceRead ||
		transaction.limit != 26 || transaction.commits != 1 || transaction.rollbacks != 0 {
		t.Fatalf("page=%+v transaction=%+v", page, transaction)
	}
}

func TestServiceRejectsCursorAfterCollectionRevisionChanges(t *testing.T) {
	t.Parallel()
	transaction := &catalogTransactionFixture{inventoryRevision: 8, groupRevision: 4}
	service := catalogServiceFixture(t, transaction)
	after, err := publicid.Parse("01890f00-0000-7000-8000-000000000501")
	if err != nil {
		t.Fatal(err)
	}
	cursor, err := NewPageCursor(7, after)
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.ListResources(
		t.Context(), catalogSessionFixture(t), catalogScopeFixture(t),
		resource.StateUnknown, 50, cursor,
	)
	if !errors.Is(err, ErrConflict) || transaction.commits != 0 || transaction.rollbacks != 1 ||
		transaction.listCalls != 0 {
		t.Fatalf("error=%v transaction=%+v", err, transaction)
	}
}

func TestServicePreservesOpaqueNotFoundAndRollsBack(t *testing.T) {
	t.Parallel()
	transaction := &catalogTransactionFixture{
		inventoryRevision: 7, groupRevision: 4, resourceErr: ErrNotFound,
	}
	service := catalogServiceFixture(t, transaction)
	id, err := resource.ParseID("01890f00-0000-7000-8000-000000000501")
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.GetResource(
		t.Context(), catalogSessionFixture(t), catalogScopeFixture(t), id,
	)
	if !errors.Is(err, ErrNotFound) || transaction.commits != 0 || transaction.rollbacks != 1 ||
		transaction.permission != authorization.PermissionResourceRead {
		t.Fatalf("error=%v transaction=%+v", err, transaction)
	}
}

func TestServiceRejectsDuplicatePolicyResourceResolutionBeforeTransaction(t *testing.T) {
	t.Parallel()
	transaction := &catalogTransactionFixture{}
	service := catalogServiceFixture(t, transaction)
	id, err := resource.ParseID("01890f00-0000-7000-8000-000000000501")
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.ResolvePolicyResources(
		t.Context(), catalogSessionFixture(t), catalogScopeFixture(t), []resource.ID{id, id},
	)
	if !errors.Is(err, ErrInvalidRequest) || transaction.permission != authorization.Permission("") {
		t.Fatalf("error=%v transaction=%+v", err, transaction)
	}
}

func TestServiceResolvesPolicyResourceGroupsInOneAuthorizedSnapshot(t *testing.T) {
	t.Parallel()
	value := catalogPolicyResourceFixture(t, 1, 1)
	group := catalogPolicyGroupFixture(t, value, 1, 1)
	transaction := &catalogTransactionFixture{
		resources: map[resource.ID]Resource{value.ID(): value},
		groups:    map[resource.GroupID]Group{group.ID(): group},
	}
	service := catalogServiceFixture(t, transaction)

	resources, groups, err := service.ResolvePolicyDestinations(
		t.Context(), catalogSessionFixture(t), catalogScopeFixture(t), nil,
		[]resource.GroupID{group.ID()},
	)
	if err != nil {
		t.Fatalf("ResolvePolicyDestinations() error = %v", err)
	}
	if len(resources) != 1 || resources[0].ID() != value.ID() || len(groups) != 1 ||
		groups[0].ID() != group.ID() || len(transaction.permissions) != 2 ||
		transaction.permissions[0] != authorization.PermissionResourceGroupRead ||
		transaction.permissions[1] != authorization.PermissionResourceRead ||
		transaction.commits != 1 || transaction.rollbacks != 0 {
		t.Fatalf("resources=%+v groups=%+v transaction=%+v", resources, groups, transaction)
	}
}

func TestServiceRejectsStaleResourceGroupMemberPin(t *testing.T) {
	t.Parallel()
	value := catalogPolicyResourceFixture(t, 2, 2)
	group := catalogPolicyGroupFixture(t, value, 1, 1)
	transaction := &catalogTransactionFixture{
		resources: map[resource.ID]Resource{value.ID(): value},
		groups:    map[resource.GroupID]Group{group.ID(): group},
	}
	service := catalogServiceFixture(t, transaction)

	_, _, err := service.ResolvePolicyDestinations(
		t.Context(), catalogSessionFixture(t), catalogScopeFixture(t), nil,
		[]resource.GroupID{group.ID()},
	)
	if !errors.Is(err, ErrConflict) || transaction.commits != 0 || transaction.rollbacks != 1 {
		t.Fatalf("error=%v transaction=%+v", err, transaction)
	}
}

type catalogTransactionsFixture struct{ transaction *catalogTransactionFixture }

func (fixture catalogTransactionsFixture) Begin(context.Context, network.Scope) (Transaction, error) {
	return fixture.transaction, nil
}

type catalogTransactionFixture struct {
	permission        authorization.Permission
	permissions       []authorization.Permission
	inventoryRevision int64
	groupRevision     int64
	resourceErr       error
	limit             int
	listCalls         int
	commits           int
	rollbacks         int
	resources         map[resource.ID]Resource
	groups            map[resource.GroupID]Group
}

func (fixture *catalogTransactionFixture) Authorize(
	_ context.Context,
	_ accountsession.Session,
	permission authorization.Permission,
	_ time.Time,
) error {
	fixture.permission = permission
	fixture.permissions = append(fixture.permissions, permission)
	return nil
}

func (fixture *catalogTransactionFixture) Revisions(context.Context) (int64, int64, error) {
	return fixture.inventoryRevision, fixture.groupRevision, nil
}

func (fixture *catalogTransactionFixture) Resource(_ context.Context, id resource.ID) (Resource, error) {
	if fixture.resourceErr != nil {
		return Resource{}, fixture.resourceErr
	}
	return fixture.resources[id], nil
}

func (fixture *catalogTransactionFixture) Resources(
	_ context.Context,
	_ resource.State,
	_ publicid.ID,
	limit int,
) ([]Resource, error) {
	fixture.listCalls++
	fixture.limit = limit
	return []Resource{}, nil
}

func (fixture *catalogTransactionFixture) Group(_ context.Context, id resource.GroupID) (Group, error) {
	if value, found := fixture.groups[id]; found {
		return value, nil
	}
	return Group{}, errors.New("unexpected Group read")
}

func (*catalogTransactionFixture) Groups(
	context.Context,
	resource.State,
	publicid.ID,
	int,
) ([]Group, error) {
	return nil, errors.New("unexpected Group list")
}

func (fixture *catalogTransactionFixture) Commit(context.Context) error {
	fixture.commits++
	return nil
}

func (fixture *catalogTransactionFixture) Rollback(context.Context) error {
	fixture.rollbacks++
	return nil
}

type catalogClockFixture struct{ now time.Time }

func (fixture catalogClockFixture) Now() time.Time { return fixture.now }

func catalogServiceFixture(t *testing.T, transaction *catalogTransactionFixture) *Service {
	t.Helper()
	service, err := NewService(Dependencies{
		Transactions: catalogTransactionsFixture{transaction: transaction},
		Clock: catalogClockFixture{
			now: time.Date(2026, time.September, 28, 1, 0, 0, 0, time.UTC),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func catalogScopeFixture(t *testing.T) network.Scope {
	t.Helper()
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	networkID, _ := network.ParseID("01890f00-0000-7000-8000-000000000201")
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func catalogSessionFixture(t *testing.T) accountsession.Session {
	t.Helper()
	deploymentID, _ := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	principalID, _ := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000401")
	sessionID, _ := accountsession.ParseID("01890f00-0000-7000-8000-000000000811")
	subjectID, _ := accountsession.ParseIdentitySubjectID("01890f00-0000-7000-8000-000000000611")
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	now := time.Date(2026, time.September, 28, 1, 0, 0, 0, time.UTC)
	session, err := accountsession.NewSession(accountsession.Params{
		ID: sessionID, DeploymentID: deploymentID, PrincipalID: principalID,
		IdentitySubjectID: subjectID, LoginWorkspaceID: workspaceID, HasLoginWorkspace: true,
		AuthenticationTime: now.Add(-time.Hour), ACR: "urn:meshtransit:test", AMR: []string{"mfa"},
		Version: 1, PrincipalAuthorityGeneration: 1, AccountSessionGeneration: 1,
		ProviderGeneration: 1, DeploymentRecoveryEpoch: 1,
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(2 * time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func catalogPolicyResourceFixture(t *testing.T, version, generation int64) Resource {
	t.Helper()
	scope := catalogScopeFixture(t)
	principalID := catalogSessionFixture(t).PrincipalID()
	id, err := resource.ParseID("01890f00-0000-7000-8000-000000000501")
	if err != nil {
		t.Fatal(err)
	}
	deviceID, err := node.ParseID("01890f00-0000-7000-8000-000000000301")
	if err != nil {
		t.Fatal(err)
	}
	name, err := resource.ParseDisplayName("Production database")
	if err != nil {
		t.Fatal(err)
	}
	revision, err := resource.NewDeviceRevision(resource.DeviceRevisionParams{
		Scope: scope, DisplayName: name, OwnerPrincipalID: principalID,
		CustodianPrincipalID: principalID, DeviceID: deviceID, TargetGeneration: generation,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 29, 4, 0, 0, 0, time.UTC)
	value, err := NewResource(ResourceParams{
		ID: id, Scope: scope, DisplayName: name, OwnerPrincipalID: principalID,
		CustodianPrincipalID: principalID, DeviceID: deviceID, State: resource.StateActive,
		Provenance: resource.ProvenanceManual, Version: version, TargetGeneration: generation,
		SemanticHash: revision.SemanticHash(), ActivatedNetworkRevision: 9, InventoryRevision: 9,
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func catalogPolicyGroupFixture(
	t *testing.T,
	value Resource,
	memberVersion,
	memberGeneration int64,
) Group {
	t.Helper()
	scope := catalogScopeFixture(t)
	principalID := catalogSessionFixture(t).PrincipalID()
	name, err := resource.ParseDisplayName("Production services")
	if err != nil {
		t.Fatal(err)
	}
	reference, err := resource.NewReference(
		scope, value.ID(), memberVersion, memberGeneration,
	)
	if err != nil {
		t.Fatal(err)
	}
	definition, err := resource.NewGroupDefinition(resource.GroupDefinitionParams{
		Scope: scope, DisplayName: name, OwnerPrincipalID: principalID,
		CustodianPrincipalID: principalID, Members: []resource.Reference{reference},
	})
	if err != nil {
		t.Fatal(err)
	}
	id, err := resource.ParseGroupID("01890f00-0000-7000-8000-000000000601")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, time.September, 29, 4, 0, 0, 0, time.UTC)
	group, err := NewGroup(GroupParams{
		ID: id, Scope: scope, DisplayName: name, OwnerPrincipalID: principalID,
		CustodianPrincipalID: principalID, State: resource.StateActive,
		Version: 1, DefinitionVersion: 1, SemanticHash: definition.SemanticHash(),
		ActivatedNetworkRevision: 9, GroupRevision: 9, Members: definition.Members(),
		CreatedAt: now, UpdatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return group
}
