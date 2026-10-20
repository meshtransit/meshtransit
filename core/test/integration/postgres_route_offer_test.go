//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/devicelifecycle"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/inventory"
	"meshtransit.net/core/internal/domain/site"
)

// assertPostgreSQLRouteOffers qualifies schema 190: a node stores the
// subnets it offers only for the active Device whose current keys it holds;
// an unchanged offer writes nothing; a Device that routes no Site moves no
// map, while a router's change advances the Network and route revisions
// with device.route_offer_changed and a wakeup; an empty offer removes it.
func assertPostgreSQLRouteOffers(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool) {
	t.Helper()
	store, err := postgresadapter.NewRouteOfferStore(runtimePool, postgresadapter.AccountSessionOptions{
		StatementTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	device, machineKey, nodeKey := activeFixtureDeviceKeys(ctx, t, admin)
	machine, err := control.NewAuthenticatedMachine(machineKey)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := machine.BindNodeKey(nodeKey)
	if err != nil {
		t.Fatal(err)
	}
	report := func(texts ...string) (bool, error) {
		prefixes := make([]netip.Prefix, len(texts))
		for index, text := range texts {
			prefixes[index] = netip.MustParsePrefix(text)
		}
		return store.ReportRouteOffer(ctx, identity, prefixes)
	}
	stored := func() string {
		var prefixes string
		if err := admin.QueryRow(ctx, `SELECT COALESCE((SELECT prefixes::TEXT FROM mesh.device_route_advertisement
WHERE device_id = (SELECT id FROM mesh.device WHERE public_id = $1::UUID)), '')`, device.String()).Scan(&prefixes); err != nil {
			t.Fatal(err)
		}
		return prefixes
	}
	revisions := func() (int64, int64) {
		networkRevision, _ := fixtureNetworkRevisions(ctx, t, admin)
		return networkRevision, fixtureRouteRevision(ctx, t, admin)
	}

	networkBefore, routeBefore := revisions()
	if changed, err := report("10.0.0.0/8"); err != nil || !changed || stored() != "{10.0.0.0/8}" {
		t.Fatalf("first offer changed %t, error %v, stored %q", changed, err, stored())
	}
	if changed, err := report("10.0.0.0/8"); err != nil || changed {
		t.Fatalf("the same offer changed %t, error %v", changed, err)
	}
	if networkAfter, routeAfter := revisions(); networkAfter != networkBefore || routeAfter != routeBefore {
		t.Fatal("the offer of a Device that routes no Site moved maps")
	}
	var otherKey node.Key
	copy(otherKey[:], nodeKey[:])
	otherKey[0] ^= 0xff
	if other, err := machine.BindNodeKey(otherKey); err != nil {
		t.Fatal(err)
	} else if _, err := store.ReportRouteOffer(ctx, other, nil); !errors.Is(err, postgresadapter.ErrRouteOfferNotFound) {
		t.Fatalf("an offer with another node key: %v", err)
	}

	// Make the Device a router of a Site.
	sites := newIntegrationSiteService(t, runtimePool)
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
	if row := readIntegrationDevice(ctx, t, admin, device); row.ownership != "workspace" {
		if _, err := newIntegrationDeviceLifecycle(t, runtimePool).Change(ctx, owner, devicelifecycle.Request{
			Scope: scope, DeviceID: device, Action: devicelifecycle.ActionTransferWorkspace, Reason: "Router",
			ExpectedVersion: row.version, CorrelationID: newCorrelationID(t)}); err != nil {
			t.Fatalf("transfer the router to the Workspace: %v", err)
		}
	}
	created, err := sites.Create(ctx, owner, scope, site.Definition{Name: "Offer HQ", Masquerade: true,
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.40.0.0/16")}}, newCorrelationID(t))
	if err != nil {
		t.Fatal(err)
	}
	assignment := site.RouterAssignment{DeviceID: device, Priority: 1, State: site.RouterActive}
	if _, err := sites.PutRouter(ctx, owner, scope, created.Site.ID, 1, assignment, newCorrelationID(t)); err != nil {
		t.Fatalf("make the Device a router: %v", err)
	}

	// Only a change of whether the router covers its Site moves maps.
	step := func(name string, moves bool, texts ...string) {
		t.Helper()
		networkBefore, routeBefore := revisions()
		if changed, err := report(texts...); err != nil || !changed {
			t.Fatalf("%s: changed %t, error %v", name, changed, err)
		}
		networkAfter, routeAfter := revisions()
		if moved := networkAfter == networkBefore+1 && routeAfter == routeBefore+1; moved != moves ||
			(!moves && (networkAfter != networkBefore || routeAfter != routeBefore)) {
			t.Fatalf("%s: revisions %d→%d, routes %d→%d, want moved %t", name, networkBefore, networkAfter,
				routeBefore, routeAfter, moves)
		}
		var named, wakes bool
		if err := admin.QueryRow(ctx, `SELECT outbox.aggregate_public_id = $1::UUID,
    outbox.event_class = 'network.revision.advanced'
FROM mesh_ops.outbox_event AS outbox
WHERE outbox.aggregate_kind = 'device_route_advertisement' ORDER BY outbox.id DESC LIMIT 1`,
			device.String()).Scan(&named, &wakes); err != nil || !named || wakes != moves {
			t.Fatalf("%s: evidence names the Device %t, wakes %t, error %v", name, named, wakes, err)
		}
	}
	step("drop the Site", true, "2001:db8::/32")
	step("cover the Site again", true, "10.40.0.0/16")
	step("offer more", false, "10.40.0.0/16", "172.16.0.0/24")
	assertConsoleDeviceOffer(ctx, t, runtimePool, owner, scope, device, 2, "10.40.0.0/16", "172.16.0.0/24")
	many := []string{"10.40.0.0/16"}
	for third := range 19 {
		many = append(many, fmt.Sprintf("172.16.%d.0/24", third))
	}
	// A host route and IPv6 come back as Go wrote them, after the 16 a list shows.
	many = append(many, "192.168.1.1/32", "2001:db8::/48")
	step("offer many", false, many...)
	assertConsoleDeviceOffer(ctx, t, runtimePool, owner, scope, device, 22, many...)
	step("offer nothing", true)
	assertConsoleDeviceOffer(ctx, t, runtimePool, owner, scope, device, 0)
	if stored() != "{}" {
		t.Fatalf("an empty offer stored %q, want an empty row", stored())
	}

	assertRouteOfferDroppedWithDevice(ctx, t, admin, device, report)

	if _, err := sites.Delete(ctx, owner, scope, created.Site.ID, 2, newCorrelationID(t)); err != nil {
		t.Fatalf("delete the Site: %v", err)
	}
}

// assertRouteOfferDroppedWithDevice qualifies schema 200: suspending a
// Device keeps its offer, revoking it deletes the offer in the same change.
// It runs in a transaction it rolls back, so the Device stays active.
func assertRouteOfferDroppedWithDevice(ctx context.Context, t *testing.T, admin *pgx.Conn, device node.ID,
	report func(...string) (bool, error)) {
	t.Helper()
	if _, err := report("10.40.0.0/16"); err != nil {
		t.Fatal(err)
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	offers := func() int {
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM mesh.device_route_advertisement
WHERE device_id = (SELECT id FROM mesh.device WHERE public_id = $1::UUID)`, device.String()).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('mesh.change_public_id', $1, TRUE)`,
		newCorrelationID(t).String()); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE mesh.device SET state = 'suspended', suspended_reason = 'admin', version = version + 1
WHERE public_id = $1::UUID`, device.String()); err != nil {
		t.Fatalf("suspend the router: %v", err)
	}
	if offers() != 1 {
		t.Fatal("suspending a Device dropped its offer")
	}
	if _, err := tx.Exec(ctx, `UPDATE mesh.device SET state = 'revoked', suspended_reason = NULL, version = version + 1
WHERE public_id = $1::UUID`, device.String()); err != nil {
		t.Fatalf("revoke the router: %v", err)
	}
	if offers() != 0 {
		t.Fatal("revoking a Device kept its offer")
	}
}

// assertConsoleDeviceOffer reads device through the Console inventory store
// (schema 192): the Device's own read lists every offered prefix, a list page
// the first 16, and both count them all.
func assertConsoleDeviceOffer(ctx context.Context, t *testing.T, runtimePool *postgresadapter.Pool,
	owner accountsession.Session, scope network.Scope, device node.ID, count int, want ...string) {
	t.Helper()
	store, err := postgresadapter.NewConsoleDeviceInventoryStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service, err := inventory.NewService(store, integrationShiftedClock{})
	if err != nil {
		t.Fatal(err)
	}
	texts := func(prefixes []netip.Prefix) []string {
		out := make([]string, len(prefixes))
		for index, prefix := range prefixes {
			out[index] = prefix.String()
		}
		return out
	}
	record, err := service.Get(ctx, owner, scope, device)
	if err != nil {
		t.Fatal(err)
	}
	if listed, total := record.Device.Offer(); total != count || !slices.Equal(texts(listed), want) {
		t.Fatalf("Device read offers %v of %d, want %v of %d", texts(listed), total, want, count)
	}
	page, err := service.List(ctx, owner, scope, inventory.Query{Limit: inventory.MaximumPageSize})
	if err != nil {
		t.Fatal(err)
	}
	index := slices.IndexFunc(page.Devices(), func(item inventory.Device) bool { return item.ID() == device })
	if index < 0 {
		t.Fatalf("the list does not hold Device %s", device)
	}
	listed, total := page.Devices()[index].Offer()
	if total != count || !slices.Equal(texts(listed), want[:min(16, len(want))]) {
		t.Fatalf("the list offers %v of %d, want the first 16 of %v", texts(listed), total, want)
	}
}
