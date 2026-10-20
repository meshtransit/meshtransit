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
	"meshtransit.net/core/internal/domain/exitpool"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/shared/internet"
)

func newIntegrationExitPoolService(t *testing.T, runtimePool *postgresadapter.Pool) *exitpool.Service {
	t.Helper()
	store, err := postgresadapter.NewExitPoolStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service, err := exitpool.NewService(store, accountsession.SystemClock{}, exitpool.SystemIDs{},
		exitpool.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func countExitPoolAudit(ctx context.Context, t *testing.T, admin *pgx.Conn, action string) int64 {
	t.Helper()
	var count int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh_audit.audit_event
WHERE target_kind = 'network_exit_pool' AND action = $1`, action).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func exitPoolEventWakesMaps(ctx context.Context, t *testing.T, admin *pgx.Conn, id exitpool.ID) bool {
	t.Helper()
	var wakes bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM mesh_ops.outbox_event AS outbox
WHERE outbox.event_class = 'network.revision.advanced' AND outbox.payload->>'exit_pool_id' = $1::TEXT)`,
		id.String()).Scan(&wakes); err != nil {
		t.Fatal(err)
	}
	return wakes
}

// workspaceOwnedDevice transfers device to the Workspace unless it already
// is the Workspace's.
func workspaceOwnedDevice(ctx context.Context, t *testing.T, admin *pgx.Conn,
	lifecycle *devicelifecycle.Service, owner accountsession.Session, scope network.Scope, device node.ID) {
	t.Helper()
	row := readIntegrationDevice(ctx, t, admin, device)
	if row.ownership == "workspace" {
		return
	}
	if _, err := lifecycle.Change(ctx, owner, devicelifecycle.Request{Scope: scope, DeviceID: device,
		Action: devicelifecycle.ActionTransferWorkspace, Reason: "Exit node",
		ExpectedVersion: row.version, CorrelationID: newCorrelationID(t)}); err != nil {
		t.Fatalf("transfer the Device to the Workspace: %v", err)
	}
}

// assertPostgreSQLExitPools qualifies schema 201 through the production
// store: route.read gates the list, route.approve creating and changing,
// route.withdraw deleting and removing exit nodes; names are unique per
// Network ignoring case; resolvers off the Internet are refused by the
// database too; stale versions are refused; an exit node must be an active
// Workspace Device of the Network and an exit node of one pool only; it can
// serve only once it offers to; every change advances the Network and route
// revisions with one audit event that wakes map sessions; deleting a pool
// removes its exit nodes, and a Device that leaves drops its offer.
func assertPostgreSQLExitPools(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool) {
	t.Helper()
	service := newIntegrationExitPoolService(t, runtimePool)
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

	listing, err := service.List(ctx, owner, scope, exitpool.ID{}, exitpool.DefaultPage)
	if err != nil || len(listing.Pools) != 0 || !listing.CanManage || !listing.CanDelete {
		t.Fatalf("owner Exit Pools = %+v, error = %v", listing, err)
	}
	if _, err := service.List(ctx, member, scope, exitpool.ID{}, exitpool.DefaultPage); !errors.Is(err,
		exitpool.ErrForbidden) {
		t.Fatalf("plain member listed Exit Pools: %v", err)
	}
	singapore := exitpool.Definition{Name: "Singapore", ConntrackPerConsumer: exitpool.DefaultConntrackPerConsumer,
		DNSUpstreams: []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2606:4700:4700::1111")},
		Probes:       []exitpool.Probe{{Address: netip.MustParseAddr("8.8.8.8"), Port: 443}}}
	if _, err := service.Create(ctx, member, scope, singapore, newCorrelationID(t)); !errors.Is(err,
		exitpool.ErrForbidden) {
		t.Fatalf("plain member created an Exit Pool: %v", err)
	}
	networkBefore, _ := fixtureNetworkRevisions(ctx, t, admin)
	routeBefore := fixtureRouteRevision(ctx, t, admin)
	created, err := service.Create(ctx, owner, scope, singapore, newCorrelationID(t))
	if err != nil || created.Pool.Version != 1 || len(created.Pool.Nodes) != 0 ||
		created.Pool.ConntrackPerConsumer != exitpool.DefaultConntrackPerConsumer ||
		len(created.Pool.DNSUpstreams) != 2 || created.Pool.Probes[0].Port != 443 {
		t.Fatalf("create Exit Pool = %+v, error = %v", created, err)
	}
	if networkAfter, _ := fixtureNetworkRevisions(ctx, t, admin); networkAfter != networkBefore+1 ||
		fixtureRouteRevision(ctx, t, admin) != routeBefore+1 ||
		countExitPoolAudit(ctx, t, admin, "network_exit_pool.created") != 1 ||
		!exitPoolEventWakesMaps(ctx, t, admin, created.Pool.ID) {
		t.Fatal("creating an Exit Pool did not advance the revisions with one waking audit event")
	}
	id := created.Pool.ID
	duplicate := singapore
	duplicate.Name = "SINGAPORE"
	if _, err := service.Create(ctx, owner, scope, duplicate, newCorrelationID(t)); !errors.Is(err,
		exitpool.ErrNameTaken) {
		t.Fatalf("duplicate name differing in case: %v", err)
	}
	// The database refuses a resolver off the Internet even past Go.
	var refused bool
	if err := admin.QueryRow(ctx, `SELECT NOT mesh_ops.exit_pool_upstreams_valid_internal_v1(
ARRAY['169.254.169.254']::INET[]) AND NOT mesh_ops.exit_pool_upstreams_valid_internal_v1(ARRAY['fd00:ec2::254']::INET[])
AND mesh_ops.exit_pool_upstreams_valid_internal_v1(ARRAY['8.8.8.8','2001:4860::8888']::INET[])`).Scan(&refused); err != nil ||
		!refused {
		t.Fatalf("the database Internet guard = %v, error = %v", refused, err)
	}

	assertExitPoolGuardsMatchGo(ctx, t, admin)

	// An update that changes nothing writes nothing.
	if same, err := service.Update(ctx, owner, scope, id, 1, singapore, newCorrelationID(t)); err != nil ||
		same.Changed || same.Pool.Version != 1 {
		t.Fatalf("no-op update = %+v, error = %v", same, err)
	}
	if countExitPoolAudit(ctx, t, admin, "network_exit_pool.updated") != 0 {
		t.Fatal("a no-op update wrote evidence")
	}
	changed := singapore
	changed.SMTPAllowed, changed.DNSUpstreams = true, nil
	updated, err := service.Update(ctx, owner, scope, id, 1, changed, newCorrelationID(t))
	if err != nil || !updated.Changed || updated.Pool.Version != 2 || !updated.Pool.SMTPAllowed ||
		len(updated.Pool.DNSUpstreams) != 0 || updated.Previous == nil {
		t.Fatalf("update Exit Pool = %+v, error = %v", updated, err)
	}
	if _, err := service.Update(ctx, owner, scope, id, 1, changed, newCorrelationID(t)); !errors.Is(err,
		exitpool.ErrVersionConflict) {
		t.Fatalf("stale update: %v", err)
	}
	if _, err := service.Read(ctx, owner, scope, exitpool.ID(newCorrelationID(t))); !errors.Is(err,
		exitpool.ErrNotFound) {
		t.Fatalf("read an unknown Exit Pool: %v", err)
	}

	devices := activeFixtureDevices(ctx, t, admin, 2)
	exitDevice, other := devices[0], devices[1]
	workspaceOwnedDevice(ctx, t, admin, lifecycle, owner, scope, exitDevice)
	assignment := exitpool.NodeAssignment{DeviceID: exitDevice, Priority: 10, State: exitpool.NodeActive}
	// A Device may be assigned before it offers; it cannot serve until it
	// does.
	withNode, err := service.PutNode(ctx, owner, scope, id, 2, assignment, newCorrelationID(t))
	if err != nil || withNode.Pool.Version != 3 || len(withNode.Pool.Nodes) != 1 ||
		withNode.Pool.Nodes[0].Eligible || withNode.Pool.Nodes[0].Offered {
		t.Fatalf("put exit node = %+v, error = %v", withNode, err)
	}
	var auditedDevice string
	if err := admin.QueryRow(ctx, `SELECT payload->'exit_node'->>'device_id' FROM mesh_audit.audit_event
WHERE target_kind = 'network_exit_pool' AND action = 'network_exit_pool.node_set'
ORDER BY event_identity_id DESC LIMIT 1`).Scan(&auditedDevice); err != nil || auditedDevice != exitDevice.String() {
		t.Fatalf("exit node audit names %q, error = %v", auditedDevice, err)
	}
	// Offers come from nodes; the fixture writes one directly.
	if err := fixtureRouteOffer(ctx, admin, `INSERT INTO mesh.device_exit_offer
    (device_id, workspace_id, network_id, offered, reported_at)
SELECT id, workspace_id, network_id, TRUE, now() FROM mesh.device WHERE public_id = $1::UUID`,
		exitDevice.String()); err != nil {
		t.Fatal(err)
	}
	if reading, err := service.Read(ctx, owner, scope, id); err != nil || !reading.Pool.Nodes[0].Eligible ||
		!reading.Pool.Nodes[0].Offered {
		t.Fatalf("an offering exit node = %+v, error = %v", reading, err)
	}
	if same, err := service.PutNode(ctx, owner, scope, id, 3, assignment, newCorrelationID(t)); err != nil ||
		same.Changed {
		t.Fatalf("no-op exit node put = %+v, error = %v", same, err)
	}
	assignment.Priority, assignment.State = 5, exitpool.NodeDraining
	if drained, err := service.PutNode(ctx, owner, scope, id, 3, assignment, newCorrelationID(t)); err != nil ||
		drained.Pool.Nodes[0].Priority != 5 || drained.Pool.Nodes[0].State != exitpool.NodeDraining {
		t.Fatalf("change exit node = %+v, error = %v", drained, err)
	}

	// A Device is an exit node of one pool only.
	second, err := service.Create(ctx, owner, scope, exitpool.Definition{Name: "Frankfurt",
		ConntrackPerConsumer: exitpool.MinimumConntrackPerConsumer}, newCorrelationID(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.PutNode(ctx, owner, scope, second.Pool.ID, 1, exitpool.NodeAssignment{DeviceID: exitDevice,
		Priority: 1, State: exitpool.NodeActive}, newCorrelationID(t)); !errors.Is(err, exitpool.ErrNodeInOtherPool) {
		t.Fatalf("an exit node of two pools: %v", err)
	}
	if row := readIntegrationDevice(ctx, t, admin, other); row.ownership != "workspace" {
		if _, err := service.PutNode(ctx, owner, scope, second.Pool.ID, 1, exitpool.NodeAssignment{DeviceID: other,
			Priority: 1, State: exitpool.NodeActive}, newCorrelationID(t)); !errors.Is(err,
			exitpool.ErrNodeNotEligible) {
			t.Fatalf("a member's Device as exit node: %v", err)
		}
	}
	workspaceOwnedDevice(ctx, t, admin, lifecycle, owner, scope, other)
	if paired, err := service.PutNode(ctx, owner, scope, second.Pool.ID, 1, exitpool.NodeAssignment{DeviceID: other,
		Priority: 1, State: exitpool.NodeActive}, newCorrelationID(t)); err != nil || len(paired.Pool.Nodes) != 1 {
		t.Fatalf("an exit node of the second pool = %+v, error = %v", paired, err)
	}

	// Paging in name order: Frankfurt, then Singapore.
	first, err := service.List(ctx, owner, scope, exitpool.ID{}, 1)
	if err != nil || len(first.Pools) != 1 || !first.HasMore || first.Pools[0].Name != "Frankfurt" {
		t.Fatalf("first page = %+v, error = %v", first, err)
	}
	if next, err := service.List(ctx, owner, scope, first.Pools[0].ID, 1); err != nil || len(next.Pools) != 1 ||
		next.HasMore || next.Pools[0].ID != id {
		t.Fatalf("second page = %+v, error = %v", next, err)
	}

	removed, err := service.RemoveNode(ctx, owner, scope, id, 4, exitDevice, newCorrelationID(t))
	if err != nil || len(removed.Pool.Nodes) != 0 {
		t.Fatalf("remove exit node = %+v, error = %v", removed, err)
	}
	if _, err := service.RemoveNode(ctx, owner, scope, id, 5, exitDevice, newCorrelationID(t)); !errors.Is(err,
		exitpool.ErrNotFound) {
		t.Fatalf("remove an absent exit node: %v", err)
	}
	if countExitPoolAudit(ctx, t, admin, "network_exit_pool.node_set") != 3 ||
		countExitPoolAudit(ctx, t, admin, "network_exit_pool.node_removed") != 1 {
		t.Fatal("exit node changes were not audited once each")
	}
	// Deleting a pool removes its exit nodes in the same change.
	for _, target := range []struct {
		id      exitpool.ID
		version int64
	}{{id, 5}, {second.Pool.ID, 2}} {
		if deleted, err := service.Delete(ctx, owner, scope, target.id, target.version, newCorrelationID(t)); err != nil ||
			!deleted.Deleted {
			t.Fatalf("delete Exit Pool = %+v, error = %v", deleted, err)
		}
	}
	var removedNode string
	if err := admin.QueryRow(ctx, `SELECT payload->'removed_exit_nodes'->>0 FROM mesh_audit.audit_event
WHERE target_kind = 'network_exit_pool' AND action = 'network_exit_pool.deleted'
ORDER BY event_identity_id DESC LIMIT 1`).Scan(&removedNode); err != nil || removedNode != other.String() {
		t.Fatalf("deleting a pool audited removed exit node %q, error = %v", removedNode, err)
	}
	var leftover int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh.network_exit_node`).Scan(&leftover); err != nil ||
		leftover != 0 {
		t.Fatalf("exit nodes left after deleting their pools: %d, %v", leftover, err)
	}
	assertExitOfferDroppedWithDevice(ctx, t, admin, exitDevice)
	if err := fixtureRouteOffer(ctx, admin, `DELETE FROM mesh.device_exit_offer`); err != nil {
		t.Fatal(err)
	}
}

// assertExitOfferDroppedWithDevice: a Device that leaves the Network drops
// its exit offer in the same transaction; a suspended one keeps it. The
// changes roll back.
func assertExitOfferDroppedWithDevice(ctx context.Context, t *testing.T, admin *pgx.Conn, device node.ID) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	offers := func() int64 {
		var count int64
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM mesh.device_exit_offer
WHERE device_id = (SELECT id FROM mesh.device WHERE public_id = $1::UUID)`, device.String()).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	if offers() != 1 {
		t.Fatal("the fixture exit offer is missing")
	}
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('mesh.change_public_id', $1, TRUE)`,
		newCorrelationID(t).String()); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE mesh.device SET state = 'suspended', suspended_reason = 'admin',
version = version + 1 WHERE public_id = $1::UUID`, device.String()); err != nil {
		t.Fatalf("suspend the Device: %v", err)
	}
	if offers() != 1 {
		t.Fatal("a suspended Device lost its exit offer")
	}
	if _, err := tx.Exec(ctx, `UPDATE mesh.device SET state = 'revoked', suspended_reason = NULL,
version = version + 1 WHERE public_id = $1::UUID`, device.String()); err != nil {
		t.Fatalf("revoke the Device: %v", err)
	}
	if offers() != 0 {
		t.Fatal("a revoked Device kept its exit offer")
	}
}

// assertExitPoolGuardsMatchGo: the database's Internet guard holds the same
// set as Go's shared/internet, at both ends of every excluded range and
// just outside them, and the probe guard refuses malformed probes.
func assertExitPoolGuardsMatchGo(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	addresses := []netip.Addr{
		netip.MustParseAddr("::ffff:1.2.3.4"), netip.MustParseAddr("::1"), netip.MustParseAddr("fc00::1"),
		netip.MustParseAddr("2001:db8::1"), netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("4000::1"),
		netip.MustParseAddr("1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), netip.MustParseAddr("2000::"),
	}
	for _, prefix := range internet.Excluded() {
		first := prefix.Addr()
		last := lastAddress(prefix)
		addresses = append(addresses, first, last)
		if before := first.Prev(); before.IsValid() {
			addresses = append(addresses, before)
		}
		if after := last.Next(); after.IsValid() {
			addresses = append(addresses, after)
		}
	}
	for _, address := range addresses {
		var inSQL bool
		if err := admin.QueryRow(ctx, `SELECT mesh_ops.internet_address_internal_v1($1::INET)`,
			address.String()).Scan(&inSQL); err != nil {
			t.Fatalf("SQL guard for %s: %v", address, err)
		}
		if inSQL != internet.Contains(address) {
			t.Errorf("%s: SQL says %v, Go says %v", address, inSQL, internet.Contains(address))
		}
	}
	for text, valid := range map[string]bool{
		`[]`:                                                                  true,
		`[{"address":"8.8.8.8","port":443}]`:                                  true,
		`[{"address":"2606:4700::1","port":1}]`:                               true,
		`[{"address":"10.0.0.1","port":443}]`:                                 false,
		`[{"address":"169.254.169.254","port":80}]`:                           false,
		`[{"address":"8.8.8.8","port":0}]`:                                    false,
		`[{"address":"8.8.8.8","port":65536}]`:                                false,
		`[{"address":"8.8.8.8","port":"443"}]`:                                false,
		`[{"address":"8.8.8.8/24","port":443}]`:                               false,
		`[{"address":"8.8.8.8","port":443,"kind":"tcp"}]`:                     false,
		`[{"address":"8.8.8.8","port":443},{"address":"8.8.8.8","port":443}]`: false,
		`[1]`: false,
		`{}`:  false,
	} {
		var got bool
		if err := admin.QueryRow(ctx, `SELECT mesh_ops.exit_pool_probes_valid_internal_v1($1::JSONB)`,
			text).Scan(&got); err != nil {
			t.Fatalf("SQL probe guard for %s: %v", text, err)
		}
		if got != valid {
			t.Errorf("probes %s: valid = %v, want %v", text, got, valid)
		}
	}
	var nullRefused bool
	if err := admin.QueryRow(ctx, `SELECT mesh_ops.exit_pool_upstreams_valid_internal_v1(
ARRAY[NULL]::INET[]) IS NOT TRUE AND NOT mesh_ops.exit_pool_upstreams_valid_internal_v1(ARRAY['1.1.1.1/24']::INET[])`).
		Scan(&nullRefused); err != nil || !nullRefused {
		t.Fatalf("a NULL or masked resolver passed the guard: %v, %v", nullRefused, err)
	}
}

// lastAddress is the highest address of prefix.
func lastAddress(prefix netip.Prefix) netip.Addr {
	bytes := prefix.Masked().Addr().AsSlice()
	for bit := prefix.Bits(); bit < len(bytes)*8; bit++ {
		bytes[bit/8] |= 0x80 >> (bit % 8)
	}
	address, _ := netip.AddrFromSlice(bytes)
	return address
}
