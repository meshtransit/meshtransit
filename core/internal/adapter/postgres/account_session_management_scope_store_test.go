package postgres

import (
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/identity/sessioncontext"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/workspace"
)

func TestAccountSessionStoreReadsManagementScopes(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	encoded := `{"workspace_id":"01890f00-0000-7000-8000-000000000101",` +
		`"workspace_display_name":"Production","scopes":[` +
		`{"network_id":"01890f00-0000-7000-8000-000000000201",` +
		`"network_display_name":"Core","permissions":["policy.approve"]}]}`
	transaction := &fakeAccountSessionTransaction{
		row: fakeAccountSessionRow{values: []any{&encoded}},
	}
	store, err := newAccountSessionStore(
		&fakeAccountSessionDatabase{transaction: transaction},
		AccountSessionOptions{StatementTimeout: time.Second, IdleTimeout: 2 * time.Second},
		nil,
	)
	if err != nil {
		t.Fatalf("newAccountSessionStore() error = %v", err)
	}
	session := accountSessionManagementScopeSession(t, now)
	result, err := store.ReadManagementScopes(t.Context(), session, network.ID{}, 51)
	if err != nil {
		t.Fatalf("ReadManagementScopes() error = %v", err)
	}
	if result.WorkspaceID.String() != "01890f00-0000-7000-8000-000000000101" ||
		result.WorkspaceDisplayName != "Production" || len(result.Scopes) != 1 ||
		result.Scopes[0].NetworkID().String() != "01890f00-0000-7000-8000-000000000201" {
		t.Fatalf("ReadManagementScopes() result = %+v", result)
	}
	if transaction.commits != 1 || transaction.rollbacks != 0 ||
		len(transaction.arguments) != 13 || transaction.arguments[9] != result.WorkspaceID.String() ||
		transaction.arguments[10] != accountSessionTestDatabaseTime || transaction.timeReads != 1 ||
		transaction.arguments[11] != nil || transaction.arguments[12] != 51 {
		t.Fatalf(
			"transaction commit/rollback/arguments = %d/%d/%v",
			transaction.commits,
			transaction.rollbacks,
			transaction.arguments,
		)
	}
}

func TestAccountSessionStoreManagementScopesConcealsStaleAuthority(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	transaction := &fakeAccountSessionTransaction{
		row: fakeAccountSessionRow{values: []any{nil}},
	}
	store, err := newAccountSessionStore(
		&fakeAccountSessionDatabase{transaction: transaction},
		AccountSessionOptions{StatementTimeout: time.Second, IdleTimeout: 2 * time.Second},
		nil,
	)
	if err != nil {
		t.Fatalf("newAccountSessionStore() error = %v", err)
	}
	_, err = store.ReadManagementScopes(
		t.Context(), accountSessionManagementScopeSession(t, now), network.ID{}, 50,
	)
	if !errors.Is(err, sessioncontext.ErrUnauthenticated) {
		t.Fatalf("ReadManagementScopes() error = %v, want ErrUnauthenticated", err)
	}
	if transaction.commits != 1 || transaction.rollbacks != 0 {
		t.Fatalf("transaction commit/rollback = %d/%d, want 1/0", transaction.commits, transaction.rollbacks)
	}
}

func accountSessionManagementScopeSession(t *testing.T, now time.Time) accountsession.Session {
	t.Helper()
	sessionID, _ := accountsession.ParseID("01890f00-0000-7000-8000-000000000811")
	deploymentID, _ := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	principalID, _ := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000011")
	subjectID, _ := accountsession.ParseIdentitySubjectID("01890f00-0000-7000-8000-000000000711")
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	session, err := accountsession.NewSession(accountsession.Params{
		ID: sessionID, DeploymentID: deploymentID, PrincipalID: principalID, IdentitySubjectID: subjectID,
		LoginWorkspaceID: workspaceID, HasLoginWorkspace: true, AuthenticationTime: now.Add(-time.Minute),
		Version: 2, PrincipalAuthorityGeneration: 3, AccountSessionGeneration: 4,
		ProviderGeneration: 5, DeploymentRecoveryEpoch: 7,
		IdleExpiresAt: now.Add(time.Hour), AbsoluteExpiresAt: now.Add(8 * time.Hour),
	})
	if err != nil {
		t.Fatalf("accountsession.NewSession() error = %v", err)
	}
	return session
}
