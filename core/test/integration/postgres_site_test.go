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
	"meshtransit.net/core/internal/domain/devicelifecycle"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/site"
)

func newIntegrationSiteService(t *testing.T, runtimePool *postgresadapter.Pool) *site.Service {
	t.Helper()
	store, err := postgresadapter.NewSiteStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service, err := site.NewService(store, accountsession.SystemClock{}, site.SystemIDs{},
		site.Config{Limits: site.DefaultLimits()})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func countSiteAudit(ctx context.Context, t *testing.T, admin *pgx.Conn, action string) int64 {
	t.Helper()
	var count int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh_audit.audit_event
WHERE target_kind = 'network_site' AND action = $1`, action).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func siteEventWakesMaps(ctx context.Context, t *testing.T, admin *pgx.Conn, id site.ID) bool {
	t.Helper()
	var wakes bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM mesh_ops.outbox_event AS outbox
WHERE outbox.event_class = 'network.revision.advanced' AND outbox.payload->>'site_id' = $1::TEXT)`,
		id.String()).Scan(&wakes); err != nil {
		t.Fatal(err)
	}
	return wakes
}

// assertPostgreSQLSites qualifies schema 188 through the production store:
// route.read gates the list, route.approve creating and changing, and
// route.withdraw deleting and removing routers; names are unique per
// Network ignoring case; stale versions are refused; a router must be an
// active Workspace Device of the Network that offers the Site's prefixes,
// and a Site has at most one router until high availability; every change
// advances the Network revision with one audit event that wakes map sessions.
func assertPostgreSQLSites(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool) {
	t.Helper()
	service := newIntegrationSiteService(t, runtimePool)
	lifecycle := newIntegrationDeviceLifecycle(t, runtimePool)
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)
	owner := managementRBACAccountSessionFixture(t)
	member := authorityConfirmerAccountSessionFixture(t)
	workspaceID, _ := owner.LoginWorkspaceID()
	networkID, err := network.ParseID(guardrailFixtureNetwork)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}

	listing, err := service.List(ctx, owner, scope, site.ID{}, site.DefaultPage)
	if err != nil || len(listing.Sites) != 0 || !listing.CanManage || !listing.CanDelete {
		t.Fatalf("owner Sites = %+v, error = %v", listing, err)
	}
	if _, err := service.List(ctx, member, scope, site.ID{}, site.DefaultPage); !errors.Is(err, site.ErrForbidden) {
		t.Fatalf("plain member listed Sites: %v", err)
	}
	hq := site.Definition{Name: "HQ LAN", Masquerade: true,
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")},
		Probes:   []site.Probe{{Address: netip.MustParseAddr("10.20.0.1"), Kind: site.ProbeICMP}}}
	if _, err := service.Create(ctx, member, scope, hq, newCorrelationID(t)); !errors.Is(err, site.ErrForbidden) {
		t.Fatalf("plain member created a Site: %v", err)
	}
	networkBefore, _ := fixtureNetworkRevisions(ctx, t, admin)
	created, err := service.Create(ctx, owner, scope, hq, newCorrelationID(t))
	if err != nil || created.Site.Version != 1 || len(created.Site.Routers) != 0 ||
		created.Site.Probes[0].Address != hq.Probes[0].Address {
		t.Fatalf("create Site = %+v, error = %v", created, err)
	}
	if networkAfter, _ := fixtureNetworkRevisions(ctx, t, admin); networkAfter != networkBefore+1 ||
		countSiteAudit(ctx, t, admin, "network_site.created") != 1 || !siteEventWakesMaps(ctx, t, admin, created.Site.ID) {
		t.Fatal("creating a Site did not advance the Network revision with one waking audit event")
	}
	id := created.Site.ID
	if _, err := service.Create(ctx, owner, scope, site.Definition{Name: "hq lan",
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.30.0.0/16")}}, newCorrelationID(t)); !errors.Is(err, site.ErrNameTaken) {
		t.Fatalf("duplicate name differing in case: %v", err)
	}
	// Another Site may use the same prefixes: a Site is a route domain.
	twin, err := service.Create(ctx, owner, scope, site.Definition{Name: "Branch",
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.20.0.0/16")}}, newCorrelationID(t))
	if err != nil {
		t.Fatalf("a second Site with the same prefixes: %v", err)
	}

	// Paging in name order: Branch, then HQ LAN.
	first, err := service.List(ctx, owner, scope, site.ID{}, 1)
	if err != nil || len(first.Sites) != 1 || !first.HasMore || first.Sites[0].Name != "Branch" {
		t.Fatalf("first page = %+v, error = %v", first, err)
	}
	if second, err := service.List(ctx, owner, scope, first.Sites[0].ID, 1); err != nil || len(second.Sites) != 1 ||
		second.HasMore || second.Sites[0].ID != id {
		t.Fatalf("second page = %+v, error = %v", second, err)
	}
	// An update that changes nothing writes nothing.
	networkBefore, _ = fixtureNetworkRevisions(ctx, t, admin)
	if same, err := service.Update(ctx, owner, scope, id, 1, hq, newCorrelationID(t)); err != nil || same.Changed ||
		same.Site.Version != 1 {
		t.Fatalf("no-op update = %+v, error = %v", same, err)
	}
	if networkAfter, _ := fixtureNetworkRevisions(ctx, t, admin); networkAfter != networkBefore ||
		countSiteAudit(ctx, t, admin, "network_site.updated") != 0 {
		t.Fatal("a no-op update advanced the revision or wrote evidence")
	}
	renamed := hq
	renamed.Name = "branch"
	if _, err := service.Update(ctx, owner, scope, id, 1, renamed, newCorrelationID(t)); !errors.Is(err, site.ErrNameTaken) {
		t.Fatalf("rename onto another Site's name: %v", err)
	}

	hq.Prefixes = append(hq.Prefixes, netip.MustParsePrefix("2001:db8:20::/48"))
	routeBefore := fixtureRouteRevision(ctx, t, admin)
	updated, err := service.Update(ctx, owner, scope, id, 1, hq, newCorrelationID(t))
	if err != nil || !updated.Changed || updated.Site.Version != 2 || len(updated.Site.Prefixes) != 2 || updated.Previous == nil {
		t.Fatalf("update Site = %+v, error = %v", updated, err)
	}
	if fixtureRouteRevision(ctx, t, admin) != routeBefore+1 {
		t.Fatal("a Site change did not advance the route revision")
	}
	if reading, err := service.Read(ctx, owner, scope, id); err != nil || reading.Site.Version != 2 || !reading.CanDelete {
		t.Fatalf("read Site = %+v, error = %v", reading, err)
	}
	if _, err := service.Read(ctx, owner, scope, site.ID(newCorrelationID(t))); !errors.Is(err, site.ErrNotFound) {
		t.Fatalf("read an unknown Site: %v", err)
	}
	if _, err := service.Update(ctx, owner, scope, id, 1, hq, newCorrelationID(t)); !errors.Is(err, site.ErrVersionConflict) {
		t.Fatalf("stale update: %v", err)
	}

	devices := activeFixtureDevices(ctx, t, admin, 2)
	router, other := devices[0], devices[1]
	if row := readIntegrationDevice(ctx, t, admin, router); row.ownership != "workspace" {
		if _, err := lifecycle.Change(ctx, owner, devicelifecycle.Request{Scope: scope, DeviceID: router,
			Action: devicelifecycle.ActionTransferWorkspace, Reason: "Router",
			ExpectedVersion: row.version, CorrelationID: newCorrelationID(t)}); err != nil {
			t.Fatalf("transfer the router to the Workspace: %v", err)
		}
	}
	assignment := site.RouterAssignment{DeviceID: router, Priority: 10, State: site.RouterActive}
	if _, err := service.PutRouter(ctx, owner, scope, id, 2, assignment, newCorrelationID(t)); !errors.Is(err, site.ErrRouterNotOffering) {
		t.Fatalf("a router that offers nothing: %v", err)
	}
	// Offers come from nodes (schema 190); the fixture writes them directly,
	// without the evidence a node's report records.
	offer := func(device string, prefixes string) error {
		return fixtureRouteOffer(ctx, admin, `INSERT INTO mesh.device_route_advertisement
    (device_id, workspace_id, network_id, public_id, prefixes, reported_at)
SELECT id, workspace_id, network_id, public_id, $2::CIDR[], now() FROM mesh.device WHERE public_id = $1::UUID
ON CONFLICT (device_id) DO UPDATE SET prefixes = EXCLUDED.prefixes, reported_at = EXCLUDED.reported_at,
    version = mesh.device_route_advertisement.version + 1`, device, prefixes)
	}
	if err := offer(router.String(), "{0.0.0.0/0}"); err == nil {
		t.Fatal("a Device offered the default route")
	}
	if err := offer(router.String(), "{10.0.0.0/8,2001:db8::/32}"); err != nil {
		t.Fatal(err)
	}
	if row := readIntegrationDevice(ctx, t, admin, other); row.ownership != "workspace" {
		member := site.RouterAssignment{DeviceID: other, Priority: 1, State: site.RouterActive}
		if _, err := service.PutRouter(ctx, owner, scope, id, 2, member, newCorrelationID(t)); !errors.Is(err, site.ErrRouterNotEligible) {
			t.Fatalf("a member's Device as router: %v", err)
		}
	}
	withRouter, err := service.PutRouter(ctx, owner, scope, id, 2, assignment, newCorrelationID(t))
	if err != nil || withRouter.Site.Version != 3 || len(withRouter.Site.Routers) != 1 ||
		!withRouter.Site.Routers[0].Eligible || withRouter.Site.Routers[0].DeviceID != router {
		t.Fatalf("put router = %+v, error = %v", withRouter, err)
	}
	var auditedDevice string
	if err := admin.QueryRow(ctx, `SELECT payload->'router'->>'device_id' FROM mesh_audit.audit_event
WHERE target_kind = 'network_site' AND action = 'network_site.router_set' ORDER BY event_identity_id DESC LIMIT 1`).
		Scan(&auditedDevice); err != nil || auditedDevice != router.String() {
		t.Fatalf("router audit names %q, error = %v", auditedDevice, err)
	}
	if same, err := service.PutRouter(ctx, owner, scope, id, 3, assignment, newCorrelationID(t)); err != nil || same.Changed {
		t.Fatalf("no-op router put = %+v, error = %v", same, err)
	}
	assignment.Priority, assignment.State = 5, site.RouterDraining
	changed, err := service.PutRouter(ctx, owner, scope, id, 3, assignment, newCorrelationID(t))
	if err != nil || changed.Site.Routers[0].Priority != 5 || changed.Site.Routers[0].State != site.RouterDraining {
		t.Fatalf("change router = %+v, error = %v", changed, err)
	}
	// A second, eligible router of a masqueraded Site; masquerade cannot be
	// turned off while it has two.
	if row := readIntegrationDevice(ctx, t, admin, other); row.ownership != "workspace" {
		if _, err := lifecycle.Change(ctx, owner, devicelifecycle.Request{Scope: scope, DeviceID: other,
			Action: devicelifecycle.ActionTransferWorkspace, Reason: "Router",
			ExpectedVersion: row.version, CorrelationID: newCorrelationID(t)}); err != nil {
			t.Fatalf("transfer the second router to the Workspace: %v", err)
		}
	}
	if err := offer(other.String(), "{10.0.0.0/8,2001:db8::/32}"); err != nil {
		t.Fatal(err)
	}
	second := site.RouterAssignment{DeviceID: other, Priority: 1, State: site.RouterActive}
	if paired, err := service.PutRouter(ctx, owner, scope, id, 4, second, newCorrelationID(t)); err != nil ||
		len(paired.Site.Routers) != 2 || paired.Site.Routers[0].DeviceID != other {
		t.Fatalf("a second router = %+v, error = %v", paired, err)
	}
	routed := hq
	routed.Masquerade = false
	if _, err := service.Update(ctx, owner, scope, id, 5, routed, newCorrelationID(t)); !errors.Is(err, site.ErrMasqueradeRequired) {
		t.Fatalf("masquerade off with two routers: %v", err)
	}
	if single, err := service.RemoveRouter(ctx, owner, scope, id, 5, second, newCorrelationID(t)); err != nil ||
		len(single.Site.Routers) != 1 {
		t.Fatalf("remove the second router = %+v, error = %v", single, err)
	}
	// A narrower offer leaves the router listed but unable to serve.
	if err := fixtureRouteOffer(ctx, admin, `UPDATE mesh.device_route_advertisement
SET prefixes = ARRAY['10.20.0.0/16']::CIDR[], version = version + 1
WHERE device_id = (SELECT id FROM mesh.device WHERE public_id = $1::UUID)`, router.String()); err != nil {
		t.Fatal(err)
	}
	if listing, err := service.List(ctx, owner, scope, site.ID{}, site.DefaultPage); err != nil || len(listing.Sites) != 2 ||
		listing.Sites[1].Routers[0].Eligible {
		t.Fatalf("Sites after the offer narrowed = %+v, error = %v", listing, err)
	}
	removed, err := service.RemoveRouter(ctx, owner, scope, id, 6, assignment, newCorrelationID(t))
	if err != nil || len(removed.Site.Routers) != 0 {
		t.Fatalf("remove router = %+v, error = %v", removed, err)
	}
	if _, err := service.RemoveRouter(ctx, owner, scope, id, 7, assignment, newCorrelationID(t)); !errors.Is(err, site.ErrNotFound) {
		t.Fatalf("remove an absent router: %v", err)
	}
	if countSiteAudit(ctx, t, admin, "network_site.router_set") != 3 ||
		countSiteAudit(ctx, t, admin, "network_site.router_removed") != 2 {
		t.Fatal("router changes were not audited once each")
	}
	// Deleting a Site removes its routers in the same change.
	if twinRouter, err := service.PutRouter(ctx, owner, scope, twin.Site.ID, 1, second, newCorrelationID(t)); err != nil ||
		len(twinRouter.Site.Routers) != 1 {
		t.Fatalf("router for the twin Site = %+v, error = %v", twinRouter, err)
	}
	for _, target := range []struct {
		id      site.ID
		version int64
	}{{id, 7}, {twin.Site.ID, 2}} {
		if deleted, err := service.Delete(ctx, owner, scope, target.id, target.version, newCorrelationID(t)); err != nil || !deleted.Deleted {
			t.Fatalf("delete Site = %+v, error = %v", deleted, err)
		}
	}
	if listing, err := service.List(ctx, owner, scope, site.ID{}, site.DefaultPage); err != nil || len(listing.Sites) != 0 {
		t.Fatalf("Sites after delete = %+v, error = %v", listing, err)
	}
	var leftover int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh.network_site_router`).Scan(&leftover); err != nil || leftover != 0 {
		t.Fatalf("routers left after deleting their Sites: %d, %v", leftover, err)
	}
	if err := fixtureRouteOffer(ctx, admin, `DELETE FROM mesh.device_route_advertisement`); err != nil {
		t.Fatal(err)
	}
}

// fixtureRouteOffer runs one statement on route offers without the
// authority evidence triggers, as a fixture.
func fixtureRouteOffer(ctx context.Context, admin *pgx.Conn, statement string, arguments ...any) error {
	tx, err := admin.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `RESET ROLE; SET LOCAL session_replication_role = replica`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, statement, arguments...); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func fixtureRouteRevision(ctx context.Context, t *testing.T, admin *pgx.Conn) int64 {
	t.Helper()
	var revision int64
	if err := admin.QueryRow(ctx, `SELECT route_revision FROM mesh_ops.network_revision
WHERE workspace_id = 103 AND network_id = 203`).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	return revision
}
