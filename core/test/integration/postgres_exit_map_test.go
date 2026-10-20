//go:build integration

package integration

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	postgresmapsession "meshtransit.net/core/internal/adapter/postgres/mapsession"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/accessgraph/ledger"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/devicelifecycle"
	"meshtransit.net/core/internal/domain/exitpool"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/policy/publication"
)

// assertPostgreSQLExitMaps qualifies schema 205 through the shared map
// store: a consumer whose group a rule grants an Exit Pool gets the pool
// with its offering exit node as primary and peer; the exit node serves the
// pool and admits the consumer, both as Derive rebuilds them; an exit node
// that withdraws its offer leaves the pool unserved; a store without exit
// nodes carries none.
func assertPostgreSQLExitMaps(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool, workerPool *postgresadapter.Pool) {
	t.Helper()
	pools := newIntegrationExitPoolService(t, runtimePool)
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
	devices := activeFixtureDevices(ctx, t, admin, 2)
	exitNode, consumer := devices[0], devices[1]
	exitIdentity, consumerIdentity := fixtureDeviceIdentity(ctx, t, admin, exitNode),
		fixtureDeviceIdentity(ctx, t, admin, consumer)
	if row := readIntegrationDevice(ctx, t, admin, exitNode); row.ownership != "workspace" {
		if _, err := newIntegrationDeviceLifecycle(t, runtimePool).Change(ctx, owner, devicelifecycle.Request{
			Scope: scope, DeviceID: exitNode, Action: devicelifecycle.ActionTransferWorkspace, Reason: "Exit node",
			ExpectedVersion: row.version, CorrelationID: newCorrelationID(t)}); err != nil {
			t.Fatalf("transfer the exit node to the Workspace: %v", err)
		}
	}
	offers, err := postgresadapter.NewExitOfferStore(runtimePool, postgresadapter.AccountSessionOptions{
		StatementTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := offers.ReportExitOffer(ctx, exitIdentity, true); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := fixtureRouteOffer(ctx, admin, `DELETE FROM mesh.device_exit_offer`); err != nil {
			t.Error(err)
		}
	}()
	created, err := pools.Create(ctx, owner, scope, exitpool.Definition{Name: "Map exit",
		ConntrackPerConsumer: exitpool.DefaultConntrackPerConsumer}, newCorrelationID(t))
	if err != nil {
		t.Fatal(err)
	}
	poolID := created.Pool.ID
	if _, err := pools.PutNode(ctx, owner, scope, poolID, created.Pool.Version, exitpool.NodeAssignment{
		DeviceID: exitNode, Priority: 1, State: exitpool.NodeActive}, newCorrelationID(t)); err != nil {
		t.Fatalf("assign the exit node: %v", err)
	}
	clients, err := groups.Create(ctx, owner, scope, devicegroup.Definition{Name: "Exit map clients"},
		newCorrelationID(t))
	if err != nil {
		t.Fatal(err)
	}
	// The exit node is in the group too: it never uses the pool it serves.
	if _, err := groups.ChangeMembers(ctx, owner, scope, clients.Group.ID, 1, []node.ID{consumer, exitNode}, nil,
		newCorrelationID(t)); err != nil {
		t.Fatal(err)
	}
	base := fixturePolicyRevision(ctx, t, admin)
	compiler := newIntegrationExitPolicyCompiler(t, runtimePool)
	candidate, err := compileSiteRules(ctx, t, compiler, owner, scope, base+1,
		exitRuleIntent(t, scope, clients.Group.ID, poolID))
	if err != nil {
		t.Fatal(err)
	}
	reason, err := publication.NewAuditReason("integration exit maps")
	if err != nil {
		t.Fatal(err)
	}
	publish := func(candidate publication.Candidate, base int64) {
		command, err := publication.NewManagementCommand(publication.ManagementCommandParams{
			Candidate: candidate, BasePolicyRevision: base, AccountSession: owner, AuditReason: reason,
		})
		if err != nil {
			t.Fatal(err)
		}
		publishPolicyOverBrowserManagement(ctx, t, runtimePool, newIntegrationManagementPolicyPublicationService(t, runtimePool),
			command)
	}
	publish(candidate, base)

	store := func(exits bool) *postgresmapsession.Store {
		shared, err := postgresadapter.NewMapSessionStore(runtimePool, postgresadapter.MapSessionOptions{
			StatementTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second,
			PeerCandidateLimit: mapsession.MaximumPeerCandidates, PolicyRuleLimit: mapsession.MaximumPacketPolicyRules,
			RelayDirectory: integrationRelayDirectory(t), SharedInventory: true,
			InventoryStatementTimeout: 30 * time.Second, InventoryMaxAge: 30 * time.Second,
			ExitNodes: exits, RoutePeerLimit: mapsession.DefaultPeerLimit,
		})
		if err != nil {
			t.Fatal(err)
		}
		return shared
	}
	exits := store(true)
	consumerMap, err := exits.Load(ctx, consumerIdentity)
	if err != nil {
		t.Fatal(err)
	}
	granted := consumerMap.Routes().Exits()
	if len(granted) != 1 || granted[0].Ref != poolID.String() || granted[0].Name != "Map exit" ||
		granted[0].Primary != exitNode || granted[0].Status != mapsession.RouteServed ||
		!slices.Equal(granted[0].Candidates, []node.ID{exitNode}) || len(consumerMap.Routes().Sites()) != 0 {
		t.Fatalf("consumer exits = %+v", granted)
	}
	if !slices.ContainsFunc(consumerMap.AuthorizedPeers(), func(peer mapsession.PeerCandidate) bool {
		return peer.NodeID() == exitNode
	}) {
		t.Fatal("the consumer's map lacks its exit node")
	}
	exitMap, err := exits.Load(ctx, exitIdentity)
	if err != nil {
		t.Fatal(err)
	}
	served, inbound := exitMap.Routes().ServedExits(), exitMap.Routes().ExitInbound()
	if len(served) != 1 || served[0].Ref != poolID.String() ||
		served[0].ConntrackPerConsumer != exitpool.DefaultConntrackPerConsumer || len(inbound) != 1 ||
		!slices.Equal(inbound[0].Sources, []node.ID{consumer}) || len(exitMap.Routes().Exits()) != 0 {
		t.Fatalf("exit node served %+v, inbound %+v", served, inbound)
	}
	if derived, found, err := exits.Derive(ctx, consumerMap, 0); err != nil || !found ||
		!derived.Routes().Equal(consumerMap.Routes()) {
		t.Fatalf("derived consumer exits = %+v, found %t, error %v", derived.Routes().Exits(), found, err)
	}
	if plain, err := store(false).Load(ctx, consumerIdentity); err != nil || !plain.Routes().IsEmpty() {
		t.Fatalf("exits without exit nodes on = %+v, error %v", plain.Routes().Exits(), err)
	}
	assertExitExplanations(ctx, t, newIntegrationPolicyExplainer(t, runtimePool), owner, scope, consumer, exitNode,
		poolID)
	assertExitGraph(ctx, t, newIntegrationPolicyExplainer(t, runtimePool), owner, scope, consumer, exitNode, poolID)
	assertExitLedger(ctx, t, admin, runtimePool, workerPool, owner, scope, consumer, exitNode, poolID)
	// Withdrawing the offer advances the Network: the pool stays granted,
	// with its exit node still the primary before any election, unserved.
	if _, err := offers.ReportExitOffer(ctx, exitIdentity, false); err != nil {
		t.Fatal(err)
	}
	if withdrawn, err := exits.Load(ctx, consumerIdentity); err != nil || len(withdrawn.Routes().Exits()) != 1 ||
		withdrawn.Routes().Exits()[0].Status != mapsession.RouteUnserved {
		t.Fatalf("exits after the offer was withdrawn = %+v, error %v", withdrawn.Routes().Exits(), err)
	}
	if exitMap, err := exits.Load(ctx, exitIdentity); err != nil || len(exitMap.Routes().ServedExits()) != 0 {
		t.Fatalf("an exit node without offer serves %+v, error %v", exitMap.Routes().ServedExits(), err)
	}

	// Clean up: a deny-all release frees the pool and the group.
	empty, err := compilation.NewRequest(compilation.RequestParams{Scope: scope, Revision: base + 2,
		Rules: []compilation.RuleIntent{}})
	if err != nil {
		t.Fatal(err)
	}
	denyAll, err := compiler.Compile(ctx, owner, empty)
	if err != nil {
		t.Fatal(err)
	}
	publish(denyAll, base+1)
	reading, err := pools.Read(ctx, owner, scope, poolID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pools.Delete(ctx, owner, scope, poolID, reading.Pool.Version, newCorrelationID(t)); err != nil {
		t.Fatalf("delete the pool: %v", err)
	}
	if _, err := groups.Delete(ctx, owner, scope, clients.Group.ID, 2, newCorrelationID(t)); err != nil {
		t.Fatalf("delete the group: %v", err)
	}
}

// assertExitExplanations qualifies schema 206: Explain allows an Internet
// address the source's group rule grants through the pool, names the pool
// and the rule; it denies another port with no matching rule, the pool's
// own exit node (which does not use its pool), and answers a private
// address no Site holds as a missing Site.
func assertExitExplanations(ctx context.Context, t *testing.T, explainer *accessgraph.Service,
	owner accountsession.Session, scope network.Scope, source, exitNode node.ID, pool exitpool.ID) {
	t.Helper()
	explain := func(from node.ID, address string, port uint16) accessgraph.Result {
		query, err := accessgraph.NewQuery(accessgraph.QueryParams{Scope: scope, SourceNodeID: from,
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
	allowed := explain(source, "8.8.8.8", 443)
	if allowed.Decision() != accessgraph.DecisionAllow || len(allowed.Paths()) != 1 ||
		allowed.Snapshot().TargetKind() != accessgraph.TargetKindExitPool ||
		allowed.Snapshot().TargetExitPoolID() != pool || allowed.Snapshot().Target().Name() != "Map exit" {
		t.Fatalf("explain a granted Internet address = %+v", allowed)
	}
	if path := allowed.Paths()[0]; path.SelectorKind() != accessgraph.SelectorKindExitPool ||
		path.DestinationExitPoolID() != pool || path.DestinationNodeID().IsValid() {
		t.Fatalf("exit path = %+v", path)
	}
	for name, result := range map[string]accessgraph.Result{
		"another port":        explain(source, "8.8.8.8", 80),
		"the pool's own node": explain(exitNode, "8.8.8.8", 443),
	} {
		if reason, denied := result.DenyReason(); !denied || reason != accessgraph.DenyReasonNoMatchingActiveRule ||
			result.Snapshot().TargetKind() != accessgraph.TargetKindExitPool || result.Snapshot().TargetExitPoolID().IsValid() {
			t.Fatalf("%s: deny reason %s, target %s", name, reason, result.Snapshot().TargetKind())
		}
	}
	private := explain(source, "10.99.0.1", 443)
	if reason, denied := private.DenyReason(); !denied || reason != accessgraph.DenyReasonTargetInactive ||
		private.Snapshot().TargetKind() != accessgraph.TargetKindSite {
		t.Fatalf("a private address: deny reason %s, target %s", reason, private.Snapshot().TargetKind())
	}
}

// assertExitGraph qualifies schema 207: the Access Graph lists one edge to
// the pool for the consumer its group rule grants, with the pool node, both
// filtered to the consumer and unfiltered across small pages that merge with
// the other edges; the pool's own exit node has none.
func assertExitGraph(ctx context.Context, t *testing.T, graph *accessgraph.Service,
	owner accountsession.Session, scope network.Scope, consumer, exitNode node.ID, pool exitpool.ID) {
	t.Helper()
	list := func(filter node.ID, pageSize int) ([]accessgraph.Path, map[exitpool.ID]accessgraph.GraphNode) {
		var paths []accessgraph.Path
		pools := make(map[exitpool.ID]accessgraph.GraphNode)
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
				if graphNode.Kind() == accessgraph.GraphNodeKindExitPool {
					pools[graphNode.ExitPoolID()] = graphNode
				}
			}
			next, more := page.Next()
			if !more {
				return paths, pools
			}
			cursor = next
		}
		t.Fatal("Access Graph pages never end")
		return nil, nil
	}
	exitEdges := func(paths []accessgraph.Path, source node.ID) []accessgraph.Path {
		var edges []accessgraph.Path
		seen := make(map[string]bool)
		for _, path := range paths {
			if seen[path.ProjectionID().String()] {
				t.Fatalf("Access Graph repeats edge %s", path.ProjectionID())
			}
			seen[path.ProjectionID().String()] = true
			if path.SelectorKind() == accessgraph.SelectorKindExitPool && path.SourceNodeID() == source {
				edges = append(edges, path)
			}
		}
		return edges
	}
	filtered, nodes := list(consumer, accessgraph.MaximumGraphPageSize)
	edges := exitEdges(filtered, consumer)
	if len(edges) != 1 || edges[0].DestinationExitPoolID() != pool || !edges[0].SourceDeviceGroupID().IsValid() ||
		len(edges[0].DestinationPrefixes()) != 0 || nodes[pool].Participant().Name() != "Map exit" {
		t.Fatalf("exit edges of the consumer = %+v, pool nodes = %+v", edges, nodes)
	}
	if own, _ := list(exitNode, accessgraph.MaximumGraphPageSize); len(exitEdges(own, exitNode)) != 0 {
		t.Fatal("the pool's own exit node has an edge to it")
	}
	unfiltered, _ := list(node.ID{}, 2)
	if all := exitEdges(unfiltered, consumer); len(all) != 1 || all[0].RuleID() != edges[0].RuleID() {
		t.Fatalf("unfiltered exit edges = %+v", all)
	}
}

// assertExitLedger qualifies schema 208: the ledger records one edge to the
// pool for the consumer, none for the pool's own exit node, and history v3
// returns it with the pool.
func assertExitLedger(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool, workerPool *postgresadapter.Pool,
	owner accountsession.Session, scope network.Scope, consumer, exitNode node.ID, pool exitpool.ID) {
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
		t.Fatalf("record the ledger with exit rules: %v", err)
	}
	reader, err := postgresadapter.NewAccessGraphHistoryStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	exitEdges := func(source node.ID) []ledger.Edge {
		result, err := reader.ReadHistory(ctx, owner, scope, ledger.Query{Source: source, Limit: 500})
		if err != nil {
			t.Fatalf("read history with exit edges: %v", err)
		}
		var edges []ledger.Edge
		for _, edge := range result.Edges {
			if edge.SelectorKind == ledger.SelectorExitPool {
				edges = append(edges, edge)
			}
		}
		return edges
	}
	if edges := exitEdges(consumer); len(edges) != 1 || edges[0].ExitPoolID.String() != pool.String() ||
		edges[0].DestinationDeviceID.IsValid() || len(edges[0].Prefixes) != 0 || edges[0].SiteID.IsValid() {
		t.Fatalf("exit edges of the consumer = %+v", edges)
	}
	if edges := exitEdges(exitNode); len(edges) != 0 {
		t.Fatalf("the pool's own exit node has exit edges %+v", edges)
	}
	var recorded int
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh_ops.access_edge_history
WHERE workspace_id = 103 AND network_id = 203 AND selector_kind = 'exit_pool' AND valid_to_revision IS NULL
  AND source_device_public_id = $1::UUID AND destination_exit_pool_public_id = $2::UUID`,
		consumer.String(), pool.String()).Scan(&recorded); err != nil || recorded != 1 {
		t.Fatalf("open exit edges = %d, error = %v", recorded, err)
	}
}
