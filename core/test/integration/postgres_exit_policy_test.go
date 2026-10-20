//go:build integration

package integration

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/exitpool"
	"meshtransit.net/core/internal/domain/identitygroup"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/site"
)

func exitRuleIntent(t *testing.T, scope network.Scope, source devicegroup.ID, pool exitpool.ID) compilation.RuleIntent {
	t.Helper()
	ruleID, err := policy.ParseRuleID(newCorrelationID(t).String())
	if err != nil {
		t.Fatal(err)
	}
	https, err := policy.NewPortRange(443, 443)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := compilation.NewRuleIntent(compilation.RuleIntentParams{
		ID: ruleID, Scope: scope, SourceGroupID: source, DestinationExitPoolID: pool,
		Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{https},
	})
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

func newIntegrationExitPolicyCompiler(t *testing.T, runtimePool *postgresadapter.Pool) *compilation.Service {
	t.Helper()
	pools, err := postgresadapter.NewExitPoolStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := newIntegrationSitePolicyCompiler(t, runtimePool).WithExitPools(pools)
	if err != nil {
		t.Fatal(err)
	}
	return compiler
}

// assertPostgreSQLExitPolicy qualifies schema 202 through the production
// compiler and stores: rules naming Exit Pools compile to exit rules and
// publish with the release, after its route rules; the active policy and the
// simulation baseline read them back, so republishing and simulating keep
// them; a pool, or a source group, that active rules name cannot be deleted
// until a release drops them.
func assertPostgreSQLExitPolicy(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool) {
	t.Helper()
	pools := newIntegrationExitPoolService(t, runtimePool)
	sites := newIntegrationSiteService(t, runtimePool)
	groups := newIntegrationDeviceGroupService(t, runtimePool)
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)
	owner := managementRBACAccountSessionFixture(t)
	workspaceID, _ := owner.LoginWorkspaceID()
	networkID, err := network.ParseID(guardrailFixtureNetwork)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	created, err := pools.Create(ctx, owner, scope, exitpool.Definition{Name: "Policy Singapore",
		ConntrackPerConsumer: exitpool.DefaultConntrackPerConsumer}, newCorrelationID(t))
	if err != nil {
		t.Fatal(err)
	}
	pool := created.Pool.ID
	lan, err := sites.Create(ctx, owner, scope, site.Definition{Name: "Exit policy LAN", Masquerade: true,
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.40.0.0/16")}}, newCorrelationID(t))
	if err != nil {
		t.Fatal(err)
	}
	clients, err := groups.Create(ctx, owner, scope, devicegroup.Definition{Name: "Exit clients"}, newCorrelationID(t))
	if err != nil {
		t.Fatal(err)
	}
	identityGroups, _ := newIntegrationIdentityCatalog(t, runtimePool)
	travellers, err := identityGroups.Create(ctx, owner, workspaceID,
		identitygroup.Definition{Name: "Exit travellers"}, newCorrelationID(t))
	if err != nil {
		t.Fatal(err)
	}
	fixtures := activeFixtureDevices(ctx, t, admin, 1)
	if _, err := groups.ChangeMembers(ctx, owner, scope, clients.Group.ID, 1, []node.ID{fixtures[0]}, nil,
		newCorrelationID(t)); err != nil {
		t.Fatalf("add an exit client: %v", err)
	}

	base := fixturePolicyRevision(ctx, t, admin)
	if _, err := compileSiteRules(ctx, t, newIntegrationSitePolicyCompiler(t, runtimePool), owner, scope, base+1,
		exitRuleIntent(t, scope, clients.Group.ID, pool)); !errors.Is(err, compilation.ErrExitPoolsDisabled) {
		t.Fatalf("an exit rule without Exit Pools: %v", err)
	}
	compiler := newIntegrationExitPolicyCompiler(t, runtimePool)
	// A group rule, a route rule and an exit rule in one release: each kind's
	// projections follow the kinds before it.
	ruleID, err := policy.ParseRuleID(newCorrelationID(t).String())
	if err != nil {
		t.Fatal(err)
	}
	ssh, err := policy.NewPortRange(22, 22)
	if err != nil {
		t.Fatal(err)
	}
	groupRule, err := compilation.NewRuleIntent(compilation.RuleIntentParams{ID: ruleID, Scope: scope,
		SourceGroupID: clients.Group.ID, DestinationDeviceGroupID: clients.Group.ID, Protocol: policy.ProtocolTCP,
		DestinationPortRanges: []policy.PortRange{ssh}})
	if err != nil {
		t.Fatal(err)
	}
	travellerRuleID, err := policy.ParseRuleID(newCorrelationID(t).String())
	if err != nil {
		t.Fatal(err)
	}
	travellerRule, err := compilation.NewRuleIntent(compilation.RuleIntentParams{ID: travellerRuleID, Scope: scope,
		SourceIdentityGroupID: travellers.Group.ID, DestinationExitPoolID: pool, Protocol: policy.ProtocolICMP,
		DestinationPortRanges: []policy.PortRange{}})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := compileSiteRules(ctx, t, compiler, owner, scope, base+1,
		exitRuleIntent(t, scope, clients.Group.ID, pool), siteRuleIntent(t, scope, clients.Group.ID, lan.Site.ID),
		groupRule, travellerRule)
	if err != nil || len(candidate.ExitRules()) != 2 || len(candidate.RouteRules()) != 1 || len(candidate.GroupRules()) != 1 {
		t.Fatalf("compile exit rules = %+v, error = %v", candidate, err)
	}
	reason, err := publication.NewAuditReason("integration exit rules")
	if err != nil {
		t.Fatal(err)
	}
	command, err := publication.NewManagementCommand(publication.ManagementCommandParams{
		Candidate: candidate, BasePolicyRevision: base, AccountSession: owner, AuditReason: reason,
	})
	if err != nil {
		t.Fatal(err)
	}
	published := publishPolicyOverBrowserManagement(ctx, t, runtimePool,
		newIntegrationManagementPolicyPublicationService(t, runtimePool), command)
	if published.PolicyRevision() != base+1 || published.SemanticHash() != candidate.SemanticHash() {
		t.Fatalf("exit rule publication = %+v", published)
	}
	var stored int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh.compiled_policy_exit_rule AS rule
JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id WHERE release.state = 'active'
  AND release.workspace_id = 103 AND release.network_id = 203`).Scan(&stored); err != nil || stored != 2 {
		t.Fatalf("stored exit rules = %d, error = %v", stored, err)
	}

	catalogStore, err := postgresadapter.NewActivePolicyStore(runtimePool, postgresadapter.PolicySimulationOptions{
		StatementTimeout: 5 * time.Second, LockTimeout: time.Second, IdleTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	active, err := catalogStore.ReadActivePolicy(ctx, owner, scope)
	if err != nil || len(active.Rows()) != 4 || active.DeviceRulesOnly() || active.SemanticHash() != candidate.SemanticHash() {
		t.Fatalf("catalog of exit rules = %+v, error = %v", active, err)
	}
	exits := 0
	for _, row := range active.Rows() {
		if row.Intent.DestinationExitPoolID() == pool && len(row.Intent.DestinationPrefixes()) == 0 {
			exits++
		}
	}
	if exits != 2 {
		t.Fatalf("catalog lost the exit rule: %+v", active.Rows())
	}
	// A member joining an Identity Group that only exit rules name rebuilds
	// the maps of their Network (schema 202).
	joined, err := identityGroups.ChangeMembers(ctx, owner, workspaceID, travellers.Group.ID, 1,
		[]publicid.ID{publicid.ID(owner.PrincipalID())}, nil, newCorrelationID(t))
	if err != nil || len(joined.Networks) != 1 {
		t.Fatalf("an exit rule's Identity Group gained a member = %+v, error = %v", joined, err)
	}
	// The simulation baseline rebuilds the release with its exit rules.
	empty, err := compilation.NewRequest(compilation.RequestParams{Scope: scope, Revision: base + 2,
		Rules: []compilation.RuleIntent{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newIntegrationPolicySimulator(t, runtimePool).Simulate(ctx, owner, empty); err != nil {
		t.Fatalf("simulate against a release with exit rules: %v", err)
	}

	if _, err := pools.Delete(ctx, owner, scope, pool, 1, newCorrelationID(t)); !errors.Is(err, exitpool.ErrInUse) {
		t.Fatalf("delete an Exit Pool that active rules name: %v", err)
	}
	if _, err := groups.Delete(ctx, owner, scope, clients.Group.ID, 2, newCorrelationID(t)); !errors.Is(err,
		devicegroup.ErrInUse) {
		t.Fatalf("delete the source group of active exit rules: %v", err)
	}
	denyAll, err := compiler.Compile(ctx, owner, empty)
	if err != nil {
		t.Fatal(err)
	}
	clearCommand, err := publication.NewManagementCommand(publication.ManagementCommandParams{
		Candidate: denyAll, BasePolicyRevision: base + 1, AccountSession: owner, AuditReason: reason,
	})
	if err != nil {
		t.Fatal(err)
	}
	publishPolicyOverBrowserManagement(ctx, t, runtimePool, newIntegrationManagementPolicyPublicationService(t, runtimePool),
		clearCommand)
	if _, err := pools.Delete(ctx, owner, scope, pool, 1, newCorrelationID(t)); err != nil {
		t.Fatalf("delete a released Exit Pool: %v", err)
	}
	if _, err := sites.Delete(ctx, owner, scope, lan.Site.ID, 1, newCorrelationID(t)); err != nil {
		t.Fatalf("delete a released Site: %v", err)
	}
	if _, err := groups.Delete(ctx, owner, scope, clients.Group.ID, 2, newCorrelationID(t)); err != nil {
		t.Fatalf("delete the source group: %v", err)
	}
	if _, err := identityGroups.Delete(ctx, owner, workspaceID, travellers.Group.ID, 2, newCorrelationID(t)); err != nil {
		t.Fatalf("delete the source Identity Group: %v", err)
	}
}
