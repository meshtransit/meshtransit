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

type catalogTransactionsFixture struct{ transaction *catalogTransactionFixture }

func (fixture catalogTransactionsFixture) Begin(context.Context, network.Scope) (Transaction, error) {
	return fixture.transaction, nil
}

type catalogTransactionFixture struct {
	permission        authorization.Permission
	inventoryRevision int64
	groupRevision     int64
	resourceErr       error
	limit             int
	listCalls         int
	commits           int
	rollbacks         int
}

func (fixture *catalogTransactionFixture) Authorize(
	_ context.Context,
	_ accountsession.Session,
	permission authorization.Permission,
	_ time.Time,
) error {
	fixture.permission = permission
	return nil
}

func (fixture *catalogTransactionFixture) Revisions(context.Context) (int64, int64, error) {
	return fixture.inventoryRevision, fixture.groupRevision, nil
}

func (fixture *catalogTransactionFixture) Resource(context.Context, resource.ID) (Resource, error) {
	return Resource{}, fixture.resourceErr
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

func (*catalogTransactionFixture) Group(context.Context, resource.GroupID) (Group, error) {
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
