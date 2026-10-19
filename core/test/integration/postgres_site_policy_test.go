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
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/site"
)

// assertPostgreSQLSitePolicy qualifies schema 189 through the production
// compiler and stores: rules naming Sites compile to route rules and publish
// with the release; the active policy and the simulation baseline read them
// back, so republishing and simulating keep them; rules of two Sites with
// overlapping prefixes are refused; a Site that active rules name cannot be
// deleted until a release drops them.
func assertPostgreSQLSitePolicy(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool) {
	t.Helper()
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
	define := func(name, prefix string) site.ID {
		created, err := sites.Create(ctx, owner, scope, site.Definition{Name: name, Masquerade: true,
			Prefixes: []netip.Prefix{netip.MustParsePrefix(prefix)}}, newCorrelationID(t))
		if err != nil {
			t.Fatalf("create Site %s: %v", name, err)
		}
		return created.Site.ID
	}
	hq, lab, twin := define("Policy HQ", "10.20.0.0/16"), define("Policy Lab", "10.30.0.0/16"),
		define("Policy Twin", "10.20.0.0/16")
	clients, err := groups.Create(ctx, owner, scope, devicegroup.Definition{Name: "Site clients"}, newCorrelationID(t))
	if err != nil {
		t.Fatal(err)
	}

	base := fixturePolicyRevision(ctx, t, admin)
	if _, err := compileSiteRules(ctx, t, newIntegrationPolicyCompiler(t, runtimePool), owner, scope, base+1,
		siteRuleIntent(t, scope, clients.Group.ID, hq)); !errors.Is(err, compilation.ErrSiteRoutesDisabled) {
		t.Fatalf("a Site rule with subnet routes off: %v", err)
	}
	compiler := newIntegrationSitePolicyCompiler(t, runtimePool)
	if _, err := compileSiteRules(ctx, t, compiler, owner, scope, base+1, siteRuleIntent(t, scope, clients.Group.ID, hq),
		siteRuleIntent(t, scope, clients.Group.ID, twin)); !errors.Is(err, compilation.ErrRouteOverlap) {
		t.Fatalf("rules of two overlapping Sites: %v", err)
	}
	if _, err := compileSiteRules(ctx, t, compiler, owner, scope, base+1,
		siteRuleIntent(t, scope, clients.Group.ID, hq, "10.21.0.0/24")); !errors.Is(err, compilation.ErrOutsideSite) {
		t.Fatalf("a prefix outside its Site: %v", err)
	}

	candidate, err := compileSiteRules(ctx, t, compiler, owner, scope, base+1,
		siteRuleIntent(t, scope, clients.Group.ID, hq, "10.20.5.0/24"), siteRuleIntent(t, scope, clients.Group.ID, lab))
	if err != nil || len(candidate.RouteRules()) != 2 {
		t.Fatalf("compile Site rules = %+v, error = %v", candidate, err)
	}
	reason, err := publication.NewAuditReason("integration Site rules")
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
		t.Fatalf("Site rule publication = %+v, base %d, candidate hash %x", published, base, candidate.SemanticHash().Bytes())
	}
	var stored int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh.compiled_policy_route_rule AS rule
JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id WHERE release.state = 'active'
  AND release.workspace_id = 103 AND release.network_id = 203`).Scan(&stored); err != nil || stored != 2 {
		t.Fatalf("stored route rules = %d, error = %v", stored, err)
	}

	catalogStore, err := postgresadapter.NewActivePolicyStore(runtimePool, postgresadapter.PolicySimulationOptions{
		StatementTimeout: 5 * time.Second, LockTimeout: time.Second, IdleTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	active, err := catalogStore.ReadActivePolicy(ctx, owner, scope)
	if err != nil || len(active.Rows()) != 2 || active.DeviceRulesOnly() || active.SemanticHash() != candidate.SemanticHash() {
		t.Fatalf("catalog of Site rules = %+v, error = %v", active, err)
	}
	narrowed := 0
	for _, row := range active.Rows() {
		if row.Intent.DestinationSiteID() == hq && len(row.Intent.DestinationPrefixes()) == 1 &&
			row.Intent.DestinationPrefixes()[0].String() == "10.20.5.0/24" {
			narrowed++
		}
	}
	if narrowed != 1 {
		t.Fatalf("catalog lost the granted prefixes: %+v", active.Rows())
	}
	// The simulation baseline rebuilds the release with its route rules.
	empty, err := compilation.NewRequest(compilation.RequestParams{Scope: scope, Revision: base + 2,
		Rules: []compilation.RuleIntent{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newIntegrationPolicySimulator(t, runtimePool).Simulate(ctx, owner, empty); err != nil {
		t.Fatalf("simulate against a release with Site rules: %v", err)
	}

	if _, err := sites.Delete(ctx, owner, scope, hq, 1, newCorrelationID(t)); !errors.Is(err, site.ErrInUse) {
		t.Fatalf("delete a Site that active rules name: %v", err)
	}
	// Sources and granted address space stay while active rules use them:
	// otherwise every later publication, which resends the rules, would fail.
	if _, err := groups.Delete(ctx, owner, scope, clients.Group.ID, 1, newCorrelationID(t)); !errors.Is(err, devicegroup.ErrInUse) {
		t.Fatalf("delete the source group of active Site rules: %v", err)
	}
	reshape := func(id site.ID, version int64, name, prefix string) error {
		_, err := sites.Update(ctx, owner, scope, id, version, site.Definition{Name: name, Masquerade: true,
			Prefixes: []netip.Prefix{netip.MustParsePrefix(prefix)}}, newCorrelationID(t))
		return err
	}
	if err := reshape(hq, 1, "Policy HQ", "10.20.0.0/17"); err != nil {
		t.Fatalf("narrow a Site around what its rules grant: %v", err)
	}
	if err := reshape(hq, 2, "Policy HQ", "10.20.128.0/17"); !errors.Is(err, site.ErrPrefixesInUse) {
		t.Fatalf("drop address space a rule grants: %v", err)
	}
	if err := reshape(lab, 1, "Policy Lab", "10.31.0.0/16"); !errors.Is(err, site.ErrPrefixesInUse) {
		t.Fatalf("move a Site its whole-Site rule grants: %v", err)
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
	if err := reshape(lab, 1, "Policy Lab", "10.31.0.0/16"); err != nil {
		t.Fatalf("move a released Site: %v", err)
	}
	for id, version := range map[site.ID]int64{hq: 2, lab: 2, twin: 1} {
		if _, err := sites.Delete(ctx, owner, scope, id, version, newCorrelationID(t)); err != nil {
			t.Fatalf("delete a released Site: %v", err)
		}
	}
	if _, err := groups.Delete(ctx, owner, scope, clients.Group.ID, 1, newCorrelationID(t)); err != nil {
		t.Fatalf("delete the source group: %v", err)
	}
}

func siteRuleIntent(t *testing.T, scope network.Scope, source devicegroup.ID, destination site.ID,
	prefixes ...string) compilation.RuleIntent {
	t.Helper()
	ruleID, err := policy.ParseRuleID(newCorrelationID(t).String())
	if err != nil {
		t.Fatal(err)
	}
	https, err := policy.NewPortRange(443, 443)
	if err != nil {
		t.Fatal(err)
	}
	params := compilation.RuleIntentParams{
		ID: ruleID, Scope: scope, SourceGroupID: source, DestinationSiteID: destination,
		Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{https},
	}
	for _, text := range prefixes {
		params.DestinationPrefixes = append(params.DestinationPrefixes, netip.MustParsePrefix(text))
	}
	intent, err := compilation.NewRuleIntent(params)
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

func compileSiteRules(ctx context.Context, t *testing.T, compiler *compilation.Service, owner accountsession.Session,
	scope network.Scope, revision int64, intents ...compilation.RuleIntent) (publication.Candidate, error) {
	t.Helper()
	request, err := compilation.NewRequest(compilation.RequestParams{Scope: scope, Revision: revision, Rules: intents})
	if err != nil {
		t.Fatal(err)
	}
	return compiler.Compile(ctx, owner, request)
}
