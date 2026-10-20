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
	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/accessgraph/ledger"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
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
func assertPostgreSQLSitePolicy(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool, workerPool *postgresadapter.Pool) {
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
	member := activeFixtureDevices(ctx, t, admin, 1)[0]
	if _, err := groups.ChangeMembers(ctx, owner, scope, clients.Group.ID, 1, []node.ID{member}, nil,
		newCorrelationID(t)); err != nil {
		t.Fatalf("add a Site client: %v", err)
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

	assertSiteExplanations(ctx, t, newIntegrationPolicyExplainer(t, runtimePool), owner, scope, member, hq)
	assertSiteGraph(ctx, t, newIntegrationPolicyExplainer(t, runtimePool), owner, scope, member, hq, lab)
	assertSiteLedger(ctx, t, admin, runtimePool, workerPool, owner, scope, member)

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
	if _, err := groups.Delete(ctx, owner, scope, clients.Group.ID, 2, newCorrelationID(t)); !errors.Is(err, devicegroup.ErrInUse) {
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
	if _, err := groups.Delete(ctx, owner, scope, clients.Group.ID, 2, newCorrelationID(t)); err != nil {
		t.Fatalf("delete the source group: %v", err)
	}
}

// assertSiteExplanations qualifies schema 197: Explain allows an address
// the source's group rule grants, names the Site and the granted prefixes,
// and denies an address of the Site outside them, another port, and an
// address no Site holds.
func assertSiteExplanations(ctx context.Context, t *testing.T, explainer *accessgraph.Service,
	owner accountsession.Session, scope network.Scope, source node.ID, hq site.ID) {
	t.Helper()
	explain := func(address string, port uint16) accessgraph.Result {
		query, err := accessgraph.NewQuery(accessgraph.QueryParams{Scope: scope, SourceNodeID: source,
			DestinationAddress: netip.MustParseAddr(address), Protocol: policy.ProtocolTCP, DestinationPort: port})
		if err != nil {
			t.Fatal(err)
		}
		result, err := explainer.Explain(ctx, owner, query)
		if err != nil {
			t.Fatalf("explain %s:%d: %v", address, port, err)
		}
		return result
	}
	allowed := explain("10.20.5.9", 443)
	if allowed.Decision() != accessgraph.DecisionAllow || len(allowed.Paths()) != 1 ||
		allowed.Snapshot().TargetSiteID() != hq || allowed.Snapshot().Target().Name() != "Policy HQ" {
		t.Fatalf("explain a granted Site address = %+v", allowed)
	}
	path := allowed.Paths()[0]
	if path.SelectorKind() != accessgraph.SelectorKindSite || path.DestinationSiteID() != hq ||
		len(path.DestinationPrefixes()) != 1 || path.DestinationPrefixes()[0].String() != "10.20.5.0/24" ||
		!path.SourceDeviceGroupID().IsValid() {
		t.Fatalf("Site path = %+v", path)
	}
	for _, denied := range []struct {
		address string
		port    uint16
		reason  accessgraph.DenyReason
		inSite  bool
	}{
		{"10.20.6.9", 443, accessgraph.DenyReasonNoMatchingActiveRule, true},
		{"10.20.5.9", 22, accessgraph.DenyReasonNoMatchingActiveRule, true},
		{"10.99.0.1", 443, accessgraph.DenyReasonTargetInactive, false},
	} {
		result := explain(denied.address, denied.port)
		reason, isDenied := result.DenyReason()
		if !isDenied || reason != denied.reason || result.Snapshot().TargetSiteID().IsValid() != denied.inSite {
			t.Fatalf("explain %s:%d = %s, %s", denied.address, denied.port, result.Decision(), reason)
		}
	}
}

// assertSiteGraph qualifies schema 198: the Access Graph lists one edge per
// Site a rule grants the member, with the Site node, both filtered to the
// member and unfiltered across small pages that merge with the other edges.
func assertSiteGraph(ctx context.Context, t *testing.T, graph *accessgraph.Service,
	owner accountsession.Session, scope network.Scope, member node.ID, hq, lab site.ID) {
	t.Helper()
	list := func(filter node.ID, pageSize int) ([]accessgraph.Path, map[site.ID]accessgraph.GraphNode) {
		var paths []accessgraph.Path
		sites := make(map[site.ID]accessgraph.GraphNode)
		var cursor accessgraph.GraphCursor
		for range 1000 {
			query, err := accessgraph.NewGraphQuery(accessgraph.GraphQueryParams{
				Scope: scope, DeviceID: filter, PageSize: pageSize, Cursor: cursor,
			})
			if err != nil {
				t.Fatal(err)
			}
			page, err := graph.Graph(ctx, owner, query)
			if err != nil {
				t.Fatalf("list Access Graph: %v", err)
			}
			paths = append(paths, page.Paths()...)
			for _, graphNode := range page.Nodes() {
				if graphNode.Kind() == accessgraph.GraphNodeKindSite {
					sites[graphNode.SiteID()] = graphNode
				}
			}
			next, more := page.Next()
			if !more {
				return paths, sites
			}
			cursor = next
		}
		t.Fatal("Access Graph pages never end")
		return nil, nil
	}
	siteEdges := func(paths []accessgraph.Path) map[site.ID]accessgraph.Path {
		edges := make(map[site.ID]accessgraph.Path)
		seen := make(map[string]bool)
		for _, path := range paths {
			if seen[path.ProjectionID().String()] {
				t.Fatalf("Access Graph repeats edge %s", path.ProjectionID())
			}
			seen[path.ProjectionID().String()] = true
			if path.SelectorKind() == accessgraph.SelectorKindSite && path.SourceNodeID() == member {
				edges[path.DestinationSiteID()] = path
			}
		}
		return edges
	}
	filtered, nodes := list(member, accessgraph.MaximumGraphPageSize)
	edges := siteEdges(filtered)
	if len(edges) != 2 || !edges[hq].SourceDeviceGroupID().IsValid() ||
		len(edges[hq].DestinationPrefixes()) != 1 || edges[hq].DestinationPrefixes()[0].String() != "10.20.5.0/24" ||
		nodes[hq].Participant().Name() != "Policy HQ" || nodes[lab].Participant().Name() != "Policy Lab" {
		t.Fatalf("Site edges of the member = %+v, Site nodes = %+v", edges, nodes)
	}
	unfiltered, _ := list(node.ID{}, 2)
	if all := siteEdges(unfiltered); len(all) != 2 || all[lab].RuleID() != edges[lab].RuleID() {
		t.Fatalf("unfiltered Site edges = %+v", all)
	}
}

// assertSiteLedger qualifies schema 199: the ledger records one edge per Site
// the member is granted, history v2 returns them with the Site and prefixes,
// and v1, which older Cores call, leaves them out.
func assertSiteLedger(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool, workerPool *postgresadapter.Pool,
	owner accountsession.Session, scope network.Scope, member node.ID) {
	t.Helper()
	var installationText string
	if err := admin.QueryRow(ctx, `SELECT installation_public_id::TEXT FROM mesh.deployment WHERE id = 1`).
		Scan(&installationText); err != nil {
		t.Fatal(err)
	}
	installation, err := deployment.ParseID(installationText)
	if err != nil {
		t.Fatal(err)
	}
	recorder, err := postgresadapter.NewAccessLedgerStore(workerPool)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recorder.Record(ctx, installation, scope); err != nil {
		t.Fatalf("record the ledger with Site rules: %v", err)
	}
	reader, err := postgresadapter.NewAccessGraphHistoryStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	result, err := reader.ReadHistory(ctx, owner, scope, ledger.Query{Source: member, Limit: 500})
	if err != nil {
		t.Fatalf("read history with Site edges: %v", err)
	}
	sites := 0
	for _, edge := range result.Edges {
		if edge.SelectorKind == ledger.SelectorSite {
			sites++
			if !edge.SiteID.IsValid() || len(edge.Prefixes) != 1 || edge.DestinationDeviceID.IsValid() {
				t.Fatalf("Site edge = %+v", edge)
			}
		}
	}
	if sites != 2 {
		t.Fatalf("history has %d Site edges of the member, want 2", sites)
	}
	var legacy int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh_ops.access_edge_history
WHERE workspace_id = 103 AND network_id = 203 AND selector_kind = 'site' AND valid_to_revision IS NULL
  AND source_device_public_id = $1::UUID`, member.String()).Scan(&legacy); err != nil || legacy != 2 {
		t.Fatalf("open Site edges = %d, error = %v", legacy, err)
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
