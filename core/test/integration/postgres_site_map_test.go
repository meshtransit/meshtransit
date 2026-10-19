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
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/devicelifecycle"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/site"
	"meshtransit.net/core/internal/domain/site/election"
)

// assertPostgreSQLSiteMaps qualifies schema 191 through the shared map
// store: a consumer whose group a rule grants part of a Site gets that part
// with the Site's router as primary and peer; the router serves the Site
// and admits the consumer, both as Derive rebuilds them; a store without
// subnet routes carries none.
func assertPostgreSQLSiteMaps(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool,
	workerPool *postgresadapter.Pool,
) {
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

	siteVersion := assertPostgreSQLSiteElection(ctx, t, admin, runtimePool, workerPool, sites, routed, owner, scope,
		created.Site.ID, router, consumer, consumerIdentity)

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
	if _, err := sites.Delete(ctx, owner, scope, created.Site.ID, siteVersion, newCorrelationID(t)); err != nil {
		t.Fatalf("delete the Site: %v", err)
	}
	if _, err := groups.Delete(ctx, owner, scope, clients.Group.ID, 2, newCorrelationID(t)); err != nil {
		t.Fatalf("delete the group: %v", err)
	}
	if _, err := offers.ReportRouteOffer(ctx, routerIdentity, nil); err != nil {
		t.Fatal(err)
	}
}

// assertPostgreSQLSiteElection qualifies schema 193 on a Site with two
// routers: maps follow the priority until the first election, then the
// elected router, and none once Core elected none; the worker store records
// each change once at its generation with one system event, and refuses a
// decision made on an older generation or for a Device that is no router.
// It returns the Site's version.
func assertPostgreSQLSiteElection(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool, workerPool *postgresadapter.Pool,
	sites *site.Service, maps *postgresmapsession.Store,
	owner accountsession.Session, scope network.Scope, siteID site.ID, router, consumer node.ID,
	consumerIdentity control.AuthenticatedNode,
) int64 {
	t.Helper()
	// Another active Device, moved to the Workspace, offering the Site as
	// the fixture writes it: it need not connect.
	standby := activeFixtureDevices(ctx, t, admin, 3)[2]
	if row := readIntegrationDevice(ctx, t, admin, standby); row.ownership != "workspace" {
		if _, err := newIntegrationDeviceLifecycle(t, runtimePool).Change(ctx, owner, devicelifecycle.Request{
			Scope: scope, DeviceID: standby, Action: devicelifecycle.ActionTransferWorkspace, Reason: "Router",
			ExpectedVersion: row.version, CorrelationID: newCorrelationID(t)}); err != nil {
			t.Fatalf("transfer the second router to the Workspace: %v", err)
		}
	}
	if err := fixtureRouteOffer(ctx, admin, `INSERT INTO mesh.device_route_advertisement
    (device_id, workspace_id, network_id, public_id, prefixes, reported_at)
SELECT id, workspace_id, network_id, public_id, '{10.50.0.0/16}'::CIDR[], now() FROM mesh.device WHERE public_id = $1::UUID
ON CONFLICT (device_id) DO UPDATE SET prefixes = EXCLUDED.prefixes, reported_at = EXCLUDED.reported_at,
    version = mesh.device_route_advertisement.version + 1`, standby.String()); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := fixtureRouteOffer(ctx, admin, `DELETE FROM mesh.device_route_advertisement
WHERE device_id = (SELECT id FROM mesh.device WHERE public_id = $1::UUID)`, standby.String()); err != nil {
			t.Error(err)
		}
	}()
	if _, err := sites.PutRouter(ctx, owner, scope, siteID, 2,
		site.RouterAssignment{DeviceID: standby, Priority: 2, State: site.RouterActive}, newCorrelationID(t)); err != nil {
		t.Fatalf("add a second router: %v", err)
	}
	primary := func() node.ID {
		t.Helper()
		loaded, err := maps.Load(ctx, consumerIdentity)
		if err != nil {
			t.Fatal(err)
		}
		routes := loaded.Routes().Sites()
		if len(routes) != 1 {
			t.Fatalf("consumer routes = %+v", routes)
		}
		return routes[0].Primary
	}
	if got := primary(); got != router {
		t.Fatalf("primary before any election = %s, want the preferred router", got)
	}
	store, err := postgresadapter.NewSitePrimaryStore(workerPool)
	if err != nil {
		t.Fatal(err)
	}
	var installationText string
	if err := admin.QueryRow(ctx, `SELECT deployment.installation_public_id::TEXT
FROM mesh.network_site AS network_site JOIN mesh.deployment AS deployment ON deployment.id = network_site.deployment_id
WHERE network_site.public_id = $1::UUID`, siteID.String()).Scan(&installationText); err != nil {
		t.Fatal(err)
	}
	installation, err := deployment.ParseID(installationText)
	if err != nil {
		t.Fatal(err)
	}
	page, err := store.List(ctx, installation, site.ID{}, election.PageSize)
	if err != nil {
		t.Fatalf("List() = %v", err)
	}
	index := slices.IndexFunc(page.Sites, func(facts election.SiteFacts) bool { return facts.Site == siteID })
	if index < 0 {
		t.Fatalf("List() lacks the Site: %+v", page)
	}
	facts := page.Sites[index]
	if facts.Generation != 0 || facts.Primary.IsValid() || len(facts.Routers) != 2 ||
		facts.Routers[0].Device != router || facts.Routers[1].Device != standby ||
		!facts.Routers[1].Live || !facts.Routers[1].Covers || facts.Routers[1].Draining {
		t.Fatalf("listed Site = %+v", facts)
	}
	record := func(expected int64, primary node.ID, reason string, want bool) {
		t.Helper()
		changed, err := store.Record(ctx, installation, election.Decision{Site: siteID, ExpectedGeneration: expected,
			Primary: primary, Reason: reason})
		if err != nil || changed != want {
			t.Fatalf("Record(%d, %s, %s) = %t, %v, want %t", expected, primary, reason, changed, err, want)
		}
	}
	record(0, standby, election.ReasonFailover, true)
	record(0, standby, election.ReasonFailover, false) // decided on an older generation
	record(1, standby, election.ReasonFailover, false) // already the primary
	record(1, consumer, election.ReasonElected, false) // no router
	if got := primary(); got != standby {
		t.Fatalf("primary after the election = %s, want the elected router", got)
	}
	record(1, node.ID{}, election.ReasonNone, true)
	if got := primary(); got.IsValid() {
		t.Fatalf("primary after electing none = %s", got)
	}
	record(2, router, election.ReasonElected, true)
	// prepare checks again that the router can serve: one that stopped
	// offering the Site since the list is not recorded.
	if err := fixtureRouteOffer(ctx, admin, `UPDATE mesh.device_route_advertisement
SET prefixes = '{10.60.0.0/16}'::CIDR[], version = version + 1
WHERE device_id = (SELECT id FROM mesh.device WHERE public_id = $1::UUID)`, standby.String()); err != nil {
		t.Fatal(err)
	}
	record(3, standby, election.ReasonFailover, false)
	var events, systemActors, outbox int
	if err := admin.QueryRow(ctx, `WITH elected AS (
    SELECT identity.change_public_id, event.actor_principal_public_id
    FROM mesh_audit.audit_event AS event
    JOIN mesh_audit.audit_event_identity AS identity
      ON identity.id = event.event_identity_id AND identity.occurred_at = event.occurred_at
    WHERE event.action = 'site.primary_changed' AND event.target_public_id = $1::UUID
)
SELECT
    (SELECT pg_catalog.count(*) FROM elected),
    (SELECT pg_catalog.count(*) FROM elected WHERE actor_principal_public_id IS NULL),
    (SELECT pg_catalog.count(*) FROM mesh_ops.outbox_event AS outbox
     WHERE outbox.change_public_id IN (SELECT change_public_id FROM elected)
       AND outbox.event_class = 'network.revision.advanced')`, siteID.String()).Scan(&events, &systemActors,
		&outbox); err != nil {
		t.Fatalf("read election evidence: %v", err)
	}
	if events != 3 || systemActors != 3 || outbox != 3 {
		t.Fatalf("election evidence: events %d, system %d, outbox %d", events, systemActors, outbox)
	}
	// Schema 194: the Site's read carries the elected primary, and its
	// history pages newest first.
	reading, err := sites.Read(ctx, owner, scope, siteID)
	if err != nil || reading.Primary == nil || reading.Primary.Device != router || reading.Primary.Generation != 3 ||
		reading.Primary.Reason != election.ReasonElected {
		t.Fatalf("Site read primary = %+v, error %v", reading.Primary, err)
	}
	first, err := sites.PrimaryChanges(ctx, owner, scope, siteID, publicid.ID{}, 2)
	if err != nil || len(first.Changes) != 2 || !first.HasMore || first.Changes[0].Device != router ||
		first.Changes[0].Previous.IsValid() || first.Changes[0].Generation != 3 ||
		first.Changes[1].Reason != election.ReasonNone || first.Changes[1].Previous != standby {
		t.Fatalf("first history page = %+v, error %v", first, err)
	}
	rest, err := sites.PrimaryChanges(ctx, owner, scope, siteID, first.Changes[1].EventID, 2)
	if err != nil || len(rest.Changes) != 1 || rest.HasMore || rest.Changes[0].Device != standby ||
		rest.Changes[0].Reason != election.ReasonFailover || rest.Changes[0].Generation != 1 {
		t.Fatalf("second history page = %+v, error %v", rest, err)
	}
	if _, err := sites.RemoveRouter(ctx, owner, scope, siteID, 3, site.RouterAssignment{DeviceID: standby},
		newCorrelationID(t)); err != nil {
		t.Fatalf("remove the second router: %v", err)
	}
	return 4
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
