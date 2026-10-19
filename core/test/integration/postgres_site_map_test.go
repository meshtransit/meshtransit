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
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/site"
)

// assertPostgreSQLSiteMaps qualifies schema 191 through the shared map
// store: a consumer whose group a rule grants part of a Site gets that part
// with the Site's router as primary and peer; the router serves the Site
// and admits the consumer, both as Derive rebuilds them; a store without
// subnet routes carries none.
func assertPostgreSQLSiteMaps(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool) {
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
	devices := activeFixtureDevices(ctx, t, admin, 2)
	router, consumer := devices[0], devices[1]
	routerIdentity, consumerIdentity := fixtureDeviceIdentity(ctx, t, admin, router), fixtureDeviceIdentity(ctx, t, admin, consumer)
	if row := readIntegrationDevice(ctx, t, admin, router); row.ownership != "workspace" {
		t.Fatalf("the router fixture is not Workspace-owned: %q", row.ownership)
	}
	offers, err := postgresadapter.NewRouteOfferStore(runtimePool, postgresadapter.AccountSessionOptions{
		StatementTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := offers.ReportRouteOffer(ctx, routerIdentity, []netip.Prefix{netip.MustParsePrefix("10.50.0.0/16")}); err != nil {
		t.Fatal(err)
	}
	created, err := sites.Create(ctx, owner, scope, site.Definition{Name: "Map HQ", Masquerade: true,
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.50.0.0/16")}}, newCorrelationID(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sites.PutRouter(ctx, owner, scope, created.Site.ID, 1,
		site.RouterAssignment{DeviceID: router, Priority: 1, State: site.RouterActive}, newCorrelationID(t)); err != nil {
		t.Fatalf("assign the router: %v", err)
	}
	clients, err := groups.Create(ctx, owner, scope, devicegroup.Definition{Name: "Map clients"}, newCorrelationID(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := groups.ChangeMembers(ctx, owner, scope, clients.Group.ID, 1, []node.ID{consumer}, nil,
		newCorrelationID(t)); err != nil {
		t.Fatal(err)
	}
	base := fixturePolicyRevision(ctx, t, admin)
	compiler := newIntegrationSitePolicyCompiler(t, runtimePool)
	candidate, err := compileSiteRules(ctx, t, compiler, owner, scope, base+1,
		siteRuleIntent(t, scope, clients.Group.ID, created.Site.ID, "10.50.5.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	reason, err := publication.NewAuditReason("integration Site maps")
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

	store := func(routes bool) *postgresmapsession.Store {
		shared, err := postgresadapter.NewMapSessionStore(runtimePool, postgresadapter.MapSessionOptions{
			StatementTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second,
			PeerCandidateLimit: mapsession.MaximumPeerCandidates, PolicyRuleLimit: mapsession.MaximumPacketPolicyRules,
			RelayDirectory: integrationRelayDirectory(t), SharedInventory: true,
			InventoryStatementTimeout: 30 * time.Second, InventoryMaxAge: 30 * time.Second,
			SubnetRoutes: routes, RoutePeerLimit: mapsession.DefaultPeerLimit,
		})
		if err != nil {
			t.Fatal(err)
		}
		return shared
	}
	routed := store(true)
	consumerMap, err := routed.Load(ctx, consumerIdentity)
	if err != nil {
		t.Fatal(err)
	}
	routes := consumerMap.Routes().Sites()
	if len(routes) != 1 || routes[0].Ref != created.Site.ID.String() || routes[0].Primary != router ||
		routes[0].Status != mapsession.RouteServed ||
		!slices.Equal(routes[0].Prefixes, []netip.Prefix{netip.MustParsePrefix("10.50.5.0/24")}) {
		t.Fatalf("consumer routes = %+v", routes)
	}
	if !slices.ContainsFunc(consumerMap.AuthorizedPeers(), func(peer mapsession.PeerCandidate) bool { return peer.NodeID() == router }) {
		t.Fatal("the consumer's map lacks its router")
	}
	routerMap, err := routed.Load(ctx, routerIdentity)
	if err != nil {
		t.Fatal(err)
	}
	served, inbound := routerMap.Routes().Served(), routerMap.Routes().Inbound()
	if len(served) != 1 || len(inbound) != 1 || !slices.Equal(inbound[0].Sources, []node.ID{consumer}) {
		t.Fatalf("router served %+v, inbound %+v", served, inbound)
	}
	if derived, found, err := routed.Derive(ctx, consumerMap, 0); err != nil || !found ||
		!derived.Routes().Equal(consumerMap.Routes()) {
		t.Fatalf("derived consumer routes = %+v, found %t, error %v", derived.Routes().Sites(), found, err)
	}
	if plain, err := store(false).Load(ctx, consumerIdentity); err != nil || !plain.Routes().IsEmpty() {
		t.Fatalf("routes without subnet routes on = %+v, error %v", plain.Routes().Sites(), err)
	}

	// Clean up: a deny-all release frees the Site and the group.
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
	if _, err := sites.Delete(ctx, owner, scope, created.Site.ID, 2, newCorrelationID(t)); err != nil {
		t.Fatalf("delete the Site: %v", err)
	}
	if _, err := groups.Delete(ctx, owner, scope, clients.Group.ID, 2, newCorrelationID(t)); err != nil {
		t.Fatalf("delete the group: %v", err)
	}
	if _, err := offers.ReportRouteOffer(ctx, routerIdentity, nil); err != nil {
		t.Fatal(err)
	}
}

// fixtureDeviceIdentity returns the authenticated identity of an active
// fixture Device's current keys.
func fixtureDeviceIdentity(ctx context.Context, t *testing.T, admin *pgx.Conn, device node.ID) control.AuthenticatedNode {
	t.Helper()
	var machine, nodeKey []byte
	if err := admin.QueryRow(ctx, `SELECT machine.public_key, node_key.public_key
FROM mesh.device AS device
JOIN mesh.device_machine_key_epoch AS machine
  ON machine.device_id = device.id AND machine.epoch = device.current_machine_key_epoch AND machine.state = 'active'
JOIN mesh.device_node_key_epoch AS node_key
  ON node_key.device_id = device.id AND node_key.epoch = device.current_node_key_epoch AND node_key.state = 'active'
WHERE device.public_id = $1::UUID`, device.String()).Scan(&machine, &nodeKey); err != nil {
		t.Fatalf("keys of %s: %v", device, err)
	}
	return identityFromKeys(t, machine, nodeKey)
}
