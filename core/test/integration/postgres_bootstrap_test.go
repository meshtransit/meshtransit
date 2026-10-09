//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/core/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/core/internal/domain/deployment"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/oidcauth"
	"github.com/meshtransit/meshtransit/core/internal/platform/bootstrap"
	"github.com/meshtransit/meshtransit/core/internal/platform/config"
)

const (
	bootstrapProviderPublicID = "01890f00-0000-7000-8000-00000000b101"
	bootstrapClientPublicID   = "01890f00-0000-7000-8000-00000000b201"
	bootstrapIssuer           = "https://bootstrap.example.test/realms/main"
	// A Deployment that does not exist yet: the reset path on an empty
	// database creates it, its audit stream and the provider together.
	bootstrapFreshDeploymentPublicID = "01890f00-0000-7000-8000-00000000b301"
)

func bootstrapRoute(t *testing.T, issuer string) oidcauth.Route {
	t.Helper()
	return bootstrapDeploymentRoute(t, integrationDeploymentPublicID, issuer)
}

func bootstrapDeploymentRoute(t *testing.T, deploymentPublicID, issuer string) oidcauth.Route {
	t.Helper()
	deploymentID, err := deployment.ParseID(deploymentPublicID)
	if err != nil {
		t.Fatal(err)
	}
	providerID, _ := oidcauth.ParseProviderID(bootstrapProviderPublicID)
	clientID, _ := oidcauth.ParseClientID(bootstrapClientPublicID)
	// #nosec G101 -- synthetic OIDC metadata, no credentials.
	route, err := oidcauth.NewRoute(oidcauth.RouteParams{
		DeploymentID: deploymentID, ProviderID: providerID, ClientID: clientID,
		ProviderGeneration: 1, RecoveryEpoch: 1, Issuer: issuer,
		DiscoveryURI:          issuer + "/.well-known/openid-configuration",
		AuthorizationEndpoint: issuer + "/protocol/openid-connect/auth",
		TokenEndpoint:         issuer + "/protocol/openid-connect/token",
		JWKSURI:               issuer + "/protocol/openid-connect/certs",
		OIDCClientID:          "meshtransit-console", ClientKind: "confidential",
		ClientAuthMethod: "client_secret_basic", Scopes: []string{"openid", "profile"},
		AllowedAlgorithms: []string{"RS256"}, RedirectID: "console-callback",
		RedirectURI: "https://console.example.test/auth/v1/callback", ReturnRouteID: "workspace-home",
	})
	if err != nil {
		t.Fatal(err)
	}
	return route
}

func bootstrapSubjectKey(t *testing.T) oidcauth.SubjectKey {
	t.Helper()
	keyID, err := oidcauth.NewDigestKeyID("subject-bootstrap")
	if err != nil {
		t.Fatal(err)
	}
	material := make([]byte, 32)
	material[0], material[31] = 9, 4
	key, err := oidcauth.NewSubjectKey(keyID, material)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func bootstrapPlan(t *testing.T, route oidcauth.Route) bootstrap.Plan {
	t.Helper()
	key := bootstrapSubjectKey(t)
	plan, err := bootstrap.NewPlan([]byte(`{"format":"meshtransit-bootstrap/v1","profile":"cloud",
"minimum_assurance":null,"accounts":[
{"subject":"owner-subject-1","display_name":"Owner One","workspace_name":"Default"},
{"subject":"second-subject-2","display_name":"Second Person","workspace_name":"Default"}]}`), route, key)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

// assertPostgreSQLBootstrap applies an installation plan as the migration
// role on the existing integration Deployment: dry run leaves nothing,
// apply creates the provider, two Accounts and their Default Workspaces with
// audit, a second apply is a no-op, and a differing route is refused.
func assertPostgreSQLBootstrap(ctx context.Context, t *testing.T, admin *pgx.Conn, migrationConfig config.MigrationConfig) {
	t.Helper()
	options := postgresadapter.MigrationOptions{
		Address: migrationConfig.PostgreSQL.Address, Database: migrationConfig.PostgreSQL.Database,
		User: migrationConfig.PostgreSQL.User, PasswordFile: migrationConfig.PostgreSQL.PasswordFile,
		CAFile: migrationConfig.PostgreSQL.CAFile, ConnectTimeout: migrationConfig.ConnectTimeout,
		LockTimeout: migrationConfig.LockTimeout, StatementTimeout: migrationConfig.StatementTimeout,
		Actor: migrationConfig.Actor, CodeRelease: "integration-test@local",
	}
	route := bootstrapRoute(t, bootstrapIssuer)
	plan := bootstrapPlan(t, route)
	auditBefore := countAuditTarget(ctx, t, admin, "workspace")

	report, err := postgresadapter.ApplyBootstrap(ctx, options, plan, false)
	if err != nil || report.DeploymentCreated || !report.ProviderCreated || report.AccountsCreated != 2 ||
		report.WorkspacesCreated != 2 {
		t.Fatalf("dry run = %+v, %v", report, err)
	}
	if countBootstrapProviders(ctx, t, admin) != 0 {
		t.Fatal("dry run committed rows")
	}

	report, err = postgresadapter.ApplyBootstrap(ctx, options, plan, true)
	if err != nil || !report.ProviderCreated || report.AccountsCreated != 2 || report.WorkspacesCreated != 2 {
		t.Fatalf("apply = %+v, %v", report, err)
	}
	if countAuditTarget(ctx, t, admin, "workspace") != auditBefore+2 {
		t.Fatal("each Workspace needs exactly one audit event")
	}
	var workspaces, memberships, routes, realms, pools, codes int64
	if err := admin.QueryRow(ctx, `SELECT
 count(DISTINCT w.id), count(DISTINCT m.id), count(DISTINCT r.id), count(DISTINCT a.id), count(DISTINCT p.id),
 count(DISTINCT w.id) FILTER (WHERE EXISTS (
   SELECT 1 FROM mesh_ops.tenant_display_identity c WHERE c.workspace_public_id = w.public_id))
FROM mesh.identity_provider ip
JOIN mesh.workspace_identity_provider r ON r.identity_provider_id = ip.id AND r.state = 'active'
JOIN mesh.workspace w ON w.id = r.workspace_id AND w.state = 'active'
JOIN mesh.workspace_membership m ON m.workspace_id = w.id AND m.principal_id = w.owner_principal_id AND m.state = 'active'
JOIN mesh.address_realm a ON a.workspace_id = w.id AND a.kind = 'workspace_overlay'
JOIN mesh.address_pool p ON p.address_realm_id = a.id AND p.purpose = 'node_overlay'
WHERE ip.public_id = $1::UUID`, bootstrapProviderPublicID).Scan(&workspaces, &memberships, &routes, &realms, &pools, &codes); err != nil {
		t.Fatal(err)
	}
	if workspaces != 2 || memberships != 2 || routes != 2 || realms != 2 || pools != 4 || codes != 2 {
		t.Fatalf("Workspaces=%d memberships=%d routes=%d realms=%d pools=%d codes=%d",
			workspaces, memberships, routes, realms, pools, codes)
	}
	// The route names no Workspace. The first Account can sign in because its
	// subject resolves to an active membership in exactly one Workspace it owns
	// (its own Default Workspace) that routes this provider and client.
	ownerDigest := plan.Accounts[0].SubjectDigest.Bytes()
	var loginWorkspaces int64
	if err := admin.QueryRow(ctx, `SELECT count(DISTINCT w.id)
 FROM mesh.identity_subject s
 JOIN mesh.principal p ON p.id = s.principal_id AND p.kind = 'account' AND p.state = 'active'
 JOIN mesh.account a ON a.principal_id = s.principal_id AND a.recovery_state = 'verified'
 JOIN mesh.workspace w ON w.deployment_id = s.deployment_id AND w.owner_principal_id = s.principal_id
  AND w.state = 'active' AND w.deleted_at IS NULL
 JOIN mesh.workspace_membership m ON m.workspace_id = w.id AND m.principal_id = s.principal_id AND m.state = 'active'
  AND m.valid_from <= pg_catalog.clock_timestamp() AND (m.expires_at IS NULL OR m.expires_at > pg_catalog.clock_timestamp())
 JOIN mesh.identity_provider_client c ON c.identity_provider_id = s.identity_provider_id AND c.public_id = $2::UUID
 JOIN mesh.workspace_identity_provider r ON r.workspace_id = w.id AND r.identity_provider_id = s.identity_provider_id
  AND r.identity_provider_client_id = c.id AND r.state = 'active' AND r.deleted_at IS NULL AND r.organization_digest IS NULL
 WHERE s.subject_digest = $1 AND s.subject_digest_key_id = 'subject-bootstrap' AND s.state = 'active'`,
		ownerDigest[:], bootstrapClientPublicID).Scan(&loginWorkspaces); err != nil || loginWorkspaces != 1 {
		t.Fatalf("bootstrapped owner sign-in Workspaces = %d, want its own Default Workspace: %v", loginWorkspaces, err)
	}
	var distinctOwners int64
	if err := admin.QueryRow(ctx, `SELECT count(DISTINCT w.owner_principal_id)
 FROM mesh.identity_provider ip
 JOIN mesh.workspace_identity_provider r ON r.identity_provider_id = ip.id AND r.state = 'active'
 JOIN mesh.workspace w ON w.id = r.workspace_id
 WHERE ip.public_id = $1::UUID`, bootstrapProviderPublicID).Scan(&distinctOwners); err != nil || distinctOwners != 2 {
		t.Fatalf("each bootstrapped Account must own its own Default Workspace: owners=%d %v", distinctOwners, err)
	}

	report, err = postgresadapter.ApplyBootstrap(ctx, options, plan, true)
	if err != nil || report.ProviderCreated || report.AccountsCreated != 0 || report.AccountsExisting != 2 ||
		report.WorkspacesCreated != 0 {
		t.Fatalf("second apply = %+v, %v", report, err)
	}
	differing := bootstrapPlan(t, bootstrapRoute(t, "https://other.example.test/realms/main"))
	if _, err := postgresadapter.ApplyBootstrap(ctx, options, differing, true); !errors.Is(err, postgresadapter.ErrBootstrapConflict) {
		t.Fatalf("differing provider route: %v", err)
	}
	assertPostgreSQLBootstrapFreshDeployment(ctx, t, admin, migrationConfig, options)
}

// assertPostgreSQLBootstrapFreshDeployment migrates a separate empty database
// with the real runner, as the reset does, and dry-runs a plan there: the
// Deployment, its audit stream, the provider and both Accounts with their
// Workspaces are created, every deferred evidence constraint holds, and the
// transaction rolls back. A Deployment allows one active row, so the shared
// integration database cannot host this path.
func assertPostgreSQLBootstrapFreshDeployment(ctx context.Context, t *testing.T, admin *pgx.Conn,
	migrationConfig config.MigrationConfig, options postgresadapter.MigrationOptions) {
	t.Helper()
	var database string
	if err := admin.QueryRow(ctx, `SELECT 'mesh_bootstrap_fresh_'||replace(gen_random_uuid()::TEXT,'-','')`).Scan(&database); err != nil {
		t.Fatal(err)
	}
	quoted := pgx.Identifier{database}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted+" OWNER mesh_migrator TEMPLATE template0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanupCtx, "DROP DATABASE "+quoted+" WITH (FORCE)"); err != nil {
			t.Errorf("remove fresh bootstrap database: %v", err)
		}
	})
	extensionConfig := admin.Config().Copy()
	extensionConfig.Database = database
	extensionConnection, err := pgx.ConnectConfig(ctx, extensionConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := extensionConnection.Exec(ctx, "CREATE EXTENSION btree_gist"); err != nil {
		t.Fatal(err)
	}
	if err := extensionConnection.Close(ctx); err != nil {
		t.Fatal(err)
	}
	freshConfig := migrationConfig
	freshConfig.PostgreSQL.Database = database
	if _, err := openIntegrationMigrationRunner(ctx, t, freshConfig).Up(ctx); err != nil {
		t.Fatalf("migrate fresh bootstrap database: %v", err)
	}
	freshOptions := options
	freshOptions.Database = database
	route := bootstrapDeploymentRoute(t, bootstrapFreshDeploymentPublicID, bootstrapIssuer)
	// A Cloud deployment can start with no Accounts and let people sign up.
	empty, err := bootstrap.NewPlan([]byte(`{"format":"meshtransit-bootstrap/v1","profile":"cloud","accounts":[]}`),
		route, bootstrapSubjectKey(t))
	if err != nil {
		t.Fatal(err)
	}
	report, err := postgresadapter.ApplyBootstrap(ctx, freshOptions, empty, true)
	if err != nil || !report.DeploymentCreated || !report.ProviderCreated || report.AccountsCreated != 0 ||
		report.WorkspacesCreated != 0 {
		t.Fatalf("fresh Deployment without Accounts = %+v, %v", report, err)
	}
	// Schema 132: with no Workspace routing the provider yet, a Cloud
	// deployment still admits a sign-in, so the first person can sign up.
	freshAdminConfig := admin.Config().Copy()
	freshAdminConfig.Database = database
	freshAdmin, err := pgx.ConnectConfig(ctx, freshAdminConfig)
	if err != nil {
		t.Fatal(err)
	}
	var admitted bool
	if err := freshAdmin.QueryRow(ctx, `SELECT mesh_ops.admit_oidc_login_route_v2($1::UUID, $2::UUID, $3::UUID,
 $4, $5, $6, $7, $8, $9, $10, $11, $12, $13::TEXT[], $14::TEXT[], $15)`,
		route.DeploymentID().String(), route.ProviderID().String(), route.ClientID().String(),
		route.ProviderGeneration(), route.RecoveryEpoch(), route.Issuer(), route.DiscoveryURI(),
		route.AuthorizationEndpoint(), route.TokenEndpoint(), route.JWKSURI(), route.OIDCClientID(),
		route.ClientAuthMethod(), route.Scopes(), route.AllowedAlgorithms(), route.RedirectURI()).Scan(&admitted); err != nil ||
		!admitted {
		t.Fatalf("an empty Cloud deployment must admit sign-in: %t, %v", admitted, err)
	}
	if err := freshAdmin.Close(ctx); err != nil {
		t.Fatal(err)
	}
	plan := bootstrapPlan(t, route)
	report, err = postgresadapter.ApplyBootstrap(ctx, freshOptions, plan, false)
	if err != nil || report.DeploymentCreated || report.ProviderCreated || report.AccountsCreated != 2 ||
		report.WorkspacesCreated != 2 {
		t.Fatalf("fresh Deployment dry run = %+v, %v", report, err)
	}
}

func countBootstrapProviders(ctx context.Context, t *testing.T, admin *pgx.Conn) int64 {
	t.Helper()
	var count int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh.identity_provider WHERE public_id = $1::UUID`,
		bootstrapProviderPublicID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}
