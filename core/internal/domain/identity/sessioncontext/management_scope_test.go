package sessioncontext_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/authorization"
	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/sessioncontext"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

func TestServiceListsValidatedManagementScopes(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 29, 9, 0, 0, 0, time.UTC)
	session := testSession(t, now)
	workspaceID, _ := session.LoginWorkspaceID()
	first := testManagementScope(t, "01890f00-0000-7000-8000-000000000201", "Core")
	second := testManagementScope(t, "01890f00-0000-7000-8000-000000000202", "Edge")
	reader := &scopeReader{result: sessioncontext.ReadResult{
		WorkspaceID: workspaceID, WorkspaceDisplayName: "Production", Scopes: []sessioncontext.ManagementScope{first, second},
	}}
	service, err := sessioncontext.NewService(reader, fixedClock{now: now})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	page, err := service.List(t.Context(), session, 1, network.ID{})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	next, hasNext := page.Next()
	items := page.Items()
	if page.WorkspaceID() != workspaceID || page.WorkspaceDisplayName() != "Production" ||
		len(items) != 1 || items[0].NetworkID() != first.NetworkID() || !hasNext || next != first.NetworkID() {
		t.Fatalf("List() page = %+v, items=%+v, next=%v/%t", page, items, next, hasNext)
	}
	items[0] = sessioncontext.ManagementScope{}
	if !page.Items()[0].IsValid() {
		t.Fatal("Page.Items() exposed mutable storage")
	}
	if reader.limit != 2 || !reader.evaluatedAt.Equal(now) {
		t.Fatalf("reader limit/time = %d/%v", reader.limit, reader.evaluatedAt)
	}
}

func TestServiceRejectsOutOfSessionOrUnorderedEvidence(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 29, 9, 0, 0, 0, time.UTC)
	session := testSession(t, now)
	first := testManagementScope(t, "01890f00-0000-7000-8000-000000000202", "Edge")
	second := testManagementScope(t, "01890f00-0000-7000-8000-000000000201", "Core")
	wrongWorkspace, err := workspace.ParseID("01890f00-0000-7000-8000-000000000102")
	if err != nil {
		t.Fatalf("workspace.ParseID() error = %v", err)
	}
	for _, test := range []struct {
		name   string
		result sessioncontext.ReadResult
	}{
		{name: "wrong workspace", result: sessioncontext.ReadResult{WorkspaceID: wrongWorkspace, WorkspaceDisplayName: "Other"}},
		{name: "unordered networks", result: sessioncontext.ReadResult{
			WorkspaceID: mustLoginWorkspace(t, session), WorkspaceDisplayName: "Production",
			Scopes: []sessioncontext.ManagementScope{first, second},
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			service, err := sessioncontext.NewService(&scopeReader{result: test.result}, fixedClock{now: now})
			if err != nil {
				t.Fatalf("NewService() error = %v", err)
			}
			_, err = service.List(t.Context(), session, 50, network.ID{})
			if !errors.Is(err, sessioncontext.ErrInvalidResult) {
				t.Fatalf("List() error = %v, want ErrInvalidResult", err)
			}
		})
	}
}

func TestManagementScopeRejectsInvalidProjectionAndCursorEvidence(t *testing.T) {
	t.Parallel()
	networkID, err := network.ParseID("01890f00-0000-7000-8000-000000000201")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name        string
		displayName string
		permissions []authorization.Permission
	}{
		{name: "empty label", permissions: []authorization.Permission{authorization.PermissionPolicyApprove}},
		{name: "uncanonical label", displayName: " Core", permissions: []authorization.Permission{authorization.PermissionPolicyApprove}},
		{name: "wrong permission", displayName: "Core", permissions: []authorization.Permission{authorization.PermissionDeviceManage}},
		{name: "multiple permissions", displayName: "Core", permissions: []authorization.Permission{
			authorization.PermissionPolicyApprove, authorization.PermissionPolicyApprove,
		}},
		{name: "unsorted permissions", displayName: "Core", permissions: []authorization.Permission{
			authorization.PermissionShareRead, authorization.PermissionPolicyApprove,
		}},
		{name: "unsupported management permission", displayName: "Core", permissions: []authorization.Permission{
			authorization.PermissionDeviceManage,
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := sessioncontext.NewManagementScope(
				networkID,
				test.displayName,
				test.permissions,
			); !errors.Is(err, sessioncontext.ErrInvalidResult) {
				t.Fatalf("NewManagementScope() error = %v, want ErrInvalidResult", err)
			}
		})
	}
	canonical, err := sessioncontext.NewManagementScope(
		networkID,
		"Core",
		[]authorization.Permission{
			authorization.PermissionPolicyApprove,
			authorization.PermissionPolicyPublish,
			authorization.PermissionPolicyValidate,
			authorization.PermissionShareAccept,
			authorization.PermissionShareRead,
		},
	)
	if err != nil || len(canonical.Permissions()) != 5 {
		t.Fatalf("NewManagementScope() with policy and sharing permissions = %+v/%v", canonical, err)
	}

	now := time.Date(2026, 9, 29, 9, 0, 0, 0, time.UTC)
	session := testSession(t, now)
	after, err := network.ParseID("01890f00-0000-7000-8000-000000000202")
	if err != nil {
		t.Fatal(err)
	}
	reader := &scopeReader{result: sessioncontext.ReadResult{
		WorkspaceID: mustLoginWorkspace(t, session), WorkspaceDisplayName: "Production",
		Scopes: []sessioncontext.ManagementScope{testManagementScope(
			t,
			"01890f00-0000-7000-8000-000000000201",
			"Core",
		)},
	}}
	service, err := sessioncontext.NewService(reader, fixedClock{now: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.List(t.Context(), session, 50, after); !errors.Is(err, sessioncontext.ErrInvalidResult) {
		t.Fatalf("List() cursor evidence error = %v, want ErrInvalidResult", err)
	}
}

func testManagementScope(t *testing.T, id, name string) sessioncontext.ManagementScope {
	t.Helper()
	networkID, err := network.ParseID(id)
	if err != nil {
		t.Fatalf("network.ParseID() error = %v", err)
	}
	value, err := sessioncontext.NewManagementScope(
		networkID,
		name,
		[]authorization.Permission{authorization.PermissionPolicyApprove},
	)
	if err != nil {
		t.Fatalf("NewManagementScope() error = %v", err)
	}
	return value
}

func testSession(t *testing.T, now time.Time) accountsession.Session {
	t.Helper()
	sessionID, _ := accountsession.ParseID("01890f00-0000-7000-8000-000000000811")
	deploymentID, _ := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	principalID, _ := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000011")
	subjectID, _ := accountsession.ParseIdentitySubjectID("01890f00-0000-7000-8000-000000000711")
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	session, err := accountsession.NewSession(accountsession.Params{
		ID: sessionID, DeploymentID: deploymentID, PrincipalID: principalID, IdentitySubjectID: subjectID,
		LoginWorkspaceID: workspaceID, HasLoginWorkspace: true, AuthenticationTime: now.Add(-time.Minute),
		Version: 1, PrincipalAuthorityGeneration: 1, AccountSessionGeneration: 1,
		ProviderGeneration: 1, DeploymentRecoveryEpoch: 1,
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(8 * time.Hour),
	})
	if err != nil {
		t.Fatalf("accountsession.NewSession() error = %v", err)
	}
	return session
}

func mustLoginWorkspace(t *testing.T, session accountsession.Session) workspace.ID {
	t.Helper()
	value, ok := session.LoginWorkspaceID()
	if !ok {
		t.Fatal("test Session has no login Workspace")
	}
	return value
}

type scopeReader struct {
	result      sessioncontext.ReadResult
	err         error
	limit       int
	evaluatedAt time.Time
}

func (reader *scopeReader) ReadManagementScopes(
	_ context.Context,
	_ accountsession.Session,
	_ network.ID,
	limit int,
	evaluatedAt time.Time,
) (sessioncontext.ReadResult, error) {
	reader.limit, reader.evaluatedAt = limit, evaluatedAt
	return reader.result, reader.err
}

type fixedClock struct{ now time.Time }

func (clock fixedClock) Now() time.Time { return clock.now }
