//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	adapteroidc "github.com/meshtransit/meshtransit/core/internal/adapter/oidc"
	postgresadapter "github.com/meshtransit/meshtransit/core/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/oidcauth"
)

// assertPostgreSQLAccountSignup qualifies schema 131 through the production
// store and real claimed, exchanged sign-ins on the Cloud fixture: a
// never-seen identity gets an Account and a Workspace it owns and then
// resolves into it; signing in again creates nothing; and another new identity
// from the same source network is refused once the daily limit is reached.
func assertPostgreSQLAccountSignup(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool) {
	t.Helper()
	authStore, err := postgresadapter.NewAuthTransactionStore(runtimePool, postgresadapter.AuthTransactionOptions{
		StatementTimeout: 10 * time.Second, LockTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	signups, err := postgresadapter.NewAccountSignupStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second},
		postgresadapter.SignupLimits{SourcePerDay: 1, DeploymentPerHour: 100})
	if err != nil {
		t.Fatal(err)
	}
	source := oidcauth.NewSignupSource([32]byte{0x81, 0x81})
	signUp := func(keys *oidcauth.SubjectKeyring, suffix string) (oidcauth.ExchangeResult, error) {
		exchange, route := integrationSubjectExchangeWithProfile(ctx, t, authStore, suffix, integrationSubjectProfile{})
		digests, err := keys.Digests(route, exchange.Identity())
		if err != nil {
			t.Fatal(err)
		}
		lookup, err := oidcauth.NewSubjectLookup(exchange.Claimed(), digests)
		if err != nil {
			t.Fatal(err)
		}
		return exchange, signups.SignUp(ctx, oidcauth.AccountSignup{
			Lookup: lookup, Source: source, DisplayName: "Signup Person",
		})
	}
	first, err := oidcauth.NewSubjectKeyring(integrationSubjectKey(t, "signup-subject-v1", 0x81))
	if err != nil {
		t.Fatal(err)
	}
	exchange, err := signUp(first, "e81")
	if err != nil {
		t.Fatalf("sign up: %v", err)
	}
	var displayName, workspaceName string
	var owned, routes, signupRows int64
	if err := admin.QueryRow(ctx, `SELECT account.display_name, workspace.display_name,
    (SELECT count(*) FROM mesh.workspace AS w WHERE w.owner_principal_id = account.principal_id),
    (SELECT count(*) FROM mesh.workspace_identity_provider AS r WHERE r.workspace_id = workspace.id
       AND r.state = 'active'),
    (SELECT count(*) FROM mesh.account_signup AS s WHERE s.principal_id = account.principal_id)
FROM mesh.account_signup AS signup
JOIN mesh.account AS account ON account.principal_id = signup.principal_id
JOIN mesh.workspace AS workspace ON workspace.id = signup.workspace_id
ORDER BY signup.id DESC LIMIT 1`).Scan(&displayName, &workspaceName, &owned, &routes, &signupRows); err != nil {
		t.Fatal(err)
	}
	if displayName != "Signup Person" || workspaceName != "Signup Person" || owned != 1 || routes != 1 ||
		signupRows != 1 {
		t.Fatalf("signed up = %q %q owned=%d routes=%d rows=%d", displayName, workspaceName, owned, routes, signupRows)
	}
	resolver, err := oidcauth.NewSubjectResolutionService(
		oidcauth.SubjectResolutionOptions{RequestTimeout: 10 * time.Second, MaxConcurrent: 1},
		oidcauth.SubjectResolutionDependencies{Subjects: authStore, Keys: first, Clock: oidcauth.SystemStartClock{},
			Observer: adapteroidc.NewSubjectTelemetry()})
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver.ResolveBrowser(ctx, exchange)
	if err != nil || resolved.WorkspaceID().String() == integrationLoginWorkspacePublicID {
		t.Fatalf("the new Account must resolve into its own Workspace: %v", err)
	}
	if _, err := signUp(first, "e82"); err != nil {
		t.Fatalf("signing in again must not sign up: %v", err)
	}
	if count := countSignups(ctx, t, admin); count != 1 {
		t.Fatalf("a repeated sign-in created %d sign-ups, want 1", count)
	}
	second, err := oidcauth.NewSubjectKeyring(integrationSubjectKey(t, "signup-subject-v2", 0x82))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signUp(second, "e83"); !errors.Is(err, oidcauth.ErrSignupRejected) {
		t.Fatalf("a second sign-up from the same network must be refused: %v", err)
	}
	if count := countSignups(ctx, t, admin); count != 1 {
		t.Fatalf("a refused sign-up left %d sign-ups, want 1", count)
	}
	var events int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh_audit.audit_event WHERE action = 'account.signed_up'`).
		Scan(&events); err != nil || events != 1 {
		t.Fatalf("sign-up evidence = %d, %v; want 1", events, err)
	}
}

func countSignups(ctx context.Context, t *testing.T, admin *pgx.Conn) int64 {
	t.Helper()
	var count int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh.account_signup`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}
