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
	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/dnszone"
	"meshtransit.net/core/internal/domain/exitpool"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

func newIntegrationDNSZoneService(t *testing.T, runtimePool *postgresadapter.Pool,
	limits dnszone.Limits) *dnszone.Service {
	t.Helper()
	store, err := postgresadapter.NewDNSZoneStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service, err := dnszone.NewService(store, accountsession.SystemClock{}, dnszone.SystemIDs{}, limits,
		dnszone.Options{Enabled: true, Names: dnszone.Names{Suffix: dnsname.Default()}})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func countDNSZoneAudit(ctx context.Context, t *testing.T, admin *pgx.Conn, action string) int64 {
	t.Helper()
	var count int64
	if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh_audit.audit_event
WHERE target_kind = 'network_dns_zone' AND action = $1`, action).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func fixtureDNSRevision(ctx context.Context, t *testing.T, admin *pgx.Conn) int64 {
	t.Helper()
	var revision int64
	if err := admin.QueryRow(ctx, `SELECT dns_revision FROM mesh_ops.network_revision
WHERE workspace_id = 103 AND network_id = 203`).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	return revision
}

// assertPostgreSQLDNSZones qualifies schema 213 through the production
// store: network.read lists zones, dns.manage changes them; a domain has one
// active zone per Network; a resolver Device is an active, Workspace-owned
// Device of the Network and no exit node, and never becomes one; Device
// Groups a zone is sent to cannot be deleted; the search domain and resolver
// limits hold in the database; every change advances the Network and DNS
// revisions with one audit event that wakes map sessions; a no-op writes
// nothing; maps carry the zone (assertDNSZoneMaps). It leaves no zone or
// group behind.
func assertPostgreSQLDNSZones(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool) {
	t.Helper()
	service := newIntegrationDNSZoneService(t, runtimePool, dnszone.DefaultLimits())
	groups := newIntegrationDeviceGroupService(t, runtimePool)
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

	listing, err := service.List(ctx, owner, scope, dnszone.ID{}, dnszone.DefaultPage)
	if err != nil || len(listing.Zones) != 0 || !listing.CanManage {
		t.Fatalf("owner DNS zones = %+v, error = %v", listing, err)
	}
	internetResolver := []dnszone.Resolver{{Address: netip.MustParseAddr("1.1.1.1"), Port: dnszone.DNSPort}}
	corp := dnszone.Definition{Domain: "corp.internal", FailureMode: dnszone.FailClosed, Resolvers: internetResolver}
	if _, err := service.Create(ctx, member, scope, corp, false, newCorrelationID(t)); !errors.Is(err, dnszone.ErrForbidden) {
		t.Fatalf("plain member created a DNS zone: %v", err)
	}
	networkBefore, _ := fixtureNetworkRevisions(ctx, t, admin)
	dnsBefore := fixtureDNSRevision(ctx, t, admin)
	created, err := service.Create(ctx, owner, scope, corp, false, newCorrelationID(t))
	if err != nil || created.Zone.Version != 1 || created.Zone.Domain != "corp.internal" ||
		created.Zone.Class != dnszone.ClassPrivate || created.Zone.FailureMode != dnszone.FailClosed ||
		len(created.Zone.Resolvers) != 1 || created.Zone.Resolvers[0].Device != nil {
		t.Fatalf("create DNS zone = %+v, error = %v", created, err)
	}
	zone := created.Zone.ID
	if networkAfter, _ := fixtureNetworkRevisions(ctx, t, admin); networkAfter != networkBefore+1 ||
		fixtureDNSRevision(ctx, t, admin) != dnsBefore+1 || countDNSZoneAudit(ctx, t, admin, "dns_zone.created") != 1 {
		t.Fatal("creating a DNS zone did not advance the revisions with one audit event")
	}
	var wakes bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM mesh_ops.outbox_event
WHERE event_class = 'network.revision.advanced' AND payload->>'dns_zone_id' = $1::TEXT)`,
		zone.String()).Scan(&wakes); err != nil || !wakes {
		t.Fatalf("the DNS zone change does not wake map sessions: %v", err)
	}
	if _, err := service.Create(ctx, owner, scope, corp, false, newCorrelationID(t)); !errors.Is(err,
		dnszone.ErrDomainTaken) {
		t.Fatalf("a second zone for the domain: %v", err)
	}
	if same, err := service.Update(ctx, owner, scope, zone, 1, corp, newCorrelationID(t)); err != nil ||
		same.Changed || same.Zone.Version != 1 || countDNSZoneAudit(ctx, t, admin, "dns_zone.updated") != 0 {
		t.Fatalf("no-op update = %+v, error = %v", same, err)
	}

	// A Device of the Workspace serves; the zone goes to a Device Group.
	devices := activeFixtureDevices(ctx, t, admin, 2)
	resolver, consumer := devices[0], devices[1]
	workspaceOwnedDevice(ctx, t, admin, lifecycle, owner, scope, resolver)
	group, err := groups.Create(ctx, owner, scope, devicegroup.Definition{Name: "DNS consumers"},
		newCorrelationID(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := groups.ChangeMembers(ctx, owner, scope, group.Group.ID, 1, []node.ID{consumer}, nil,
		newCorrelationID(t)); err != nil {
		t.Fatal(err)
	}
	position := 1
	withDevice := corp
	withDevice.Resolvers = []dnszone.Resolver{{DeviceID: resolver, Port: 5335}, internetResolver[0]}
	withDevice.Groups, withDevice.SearchPosition = []devicegroup.ID{group.Group.ID}, &position
	updated, err := service.Update(ctx, owner, scope, zone, 1, withDevice, newCorrelationID(t))
	if err != nil || !updated.Changed || updated.Zone.Version != 2 || len(updated.Zone.Groups) != 1 ||
		updated.Zone.Resolvers[0].Device == nil || !updated.Zone.Resolvers[0].Device.Eligible() ||
		updated.Zone.Resolvers[0].Port != 5335 || updated.Zone.SearchPosition == nil || updated.Previous == nil {
		t.Fatalf("update DNS zone = %+v, error = %v", updated, err)
	}
	var auditedResolver string
	if err := admin.QueryRow(ctx, `SELECT payload->'resolvers'->0->>'device_id' FROM mesh_audit.audit_event
WHERE target_kind = 'network_dns_zone' AND action = 'dns_zone.updated'
ORDER BY event_identity_id DESC LIMIT 1`).Scan(&auditedResolver); err != nil || auditedResolver != resolver.String() {
		t.Fatalf("the audit names resolver %q, error = %v", auditedResolver, err)
	}
	assertDNSZoneMaps(ctx, t, admin, runtimePool, owner, scope, group.Group.ID, resolver, consumer)
	if _, err := service.Update(ctx, owner, scope, zone, 1, withDevice, newCorrelationID(t)); !errors.Is(err,
		dnszone.ErrVersionConflict) {
		t.Fatalf("stale update: %v", err)
	}
	if row := readIntegrationDevice(ctx, t, admin, consumer); row.ownership != "workspace" {
		foreign := withDevice
		foreign.Resolvers = []dnszone.Resolver{{DeviceID: consumer, Port: dnszone.DNSPort}}
		if _, err := service.Update(ctx, owner, scope, zone, 2, foreign, newCorrelationID(t)); !errors.Is(err,
			dnszone.ErrResolverNotEligible) {
			t.Fatalf("a member's Device as resolver: %v", err)
		}
	}

	// A resolver Device never becomes an exit node, and a group a zone is
	// sent to cannot be deleted.
	exits := newIntegrationExitPoolService(t, runtimePool)
	pool, err := exits.Create(ctx, owner, scope, exitpool.Definition{Name: "DNS check",
		ConntrackPerConsumer: exitpool.MinimumConntrackPerConsumer}, newCorrelationID(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exits.PutNode(ctx, owner, scope, pool.Pool.ID, 1, exitpool.NodeAssignment{DeviceID: resolver,
		Priority: 1, State: exitpool.NodeActive}, newCorrelationID(t)); !errors.Is(err, exitpool.ErrNodeIsDNSResolver) {
		t.Fatalf("a DNS resolver became an exit node: %v", err)
	}
	if _, err := exits.Delete(ctx, owner, scope, pool.Pool.ID, 1, newCorrelationID(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := groups.Delete(ctx, owner, scope, group.Group.ID, 2, newCorrelationID(t)); !errors.Is(err,
		devicegroup.ErrInUseByDNS) {
		t.Fatalf("deleted a Device Group a DNS zone is sent to: %v", err)
	}

	// The database holds the search domain and resolver limits.
	strictLimits := dnszone.DefaultLimits()
	strictLimits.ZonesPerNetwork, strictLimits.SearchZonesPerNetwork, strictLimits.ConsumersPerResolver = 2, 1, 1
	strict := newIntegrationDNSZoneService(t, runtimePool, strictLimits)
	lab := dnszone.Definition{Domain: "lab.internal", FailureMode: dnszone.FailOpen, Resolvers: internetResolver,
		SearchPosition: &position}
	if _, err := strict.Create(ctx, owner, scope, lab, false, newCorrelationID(t)); !errors.Is(err, dnszone.ErrSearchLimit) {
		t.Fatalf("a search domain over the limit: %v", err)
	}
	lab.SearchPosition = nil
	lab.Resolvers = []dnszone.Resolver{{DeviceID: resolver, Port: dnszone.DNSPort}}
	if _, err := strict.Create(ctx, owner, scope, lab, false, newCorrelationID(t)); !errors.Is(err,
		dnszone.ErrResolverPeerLimit) {
		t.Fatalf("a resolver Device serving more Devices than allowed: %v", err)
	}

	// A public domain needs confirming; zones page in domain order.
	public := dnszone.Definition{Domain: "corp.com", FailureMode: dnszone.FailOpen, Resolvers: internetResolver}
	if _, err := service.Create(ctx, owner, scope, public, false, newCorrelationID(t)); !errors.Is(err,
		dnszone.ErrPublicUnconfirmed) {
		t.Fatalf("an unconfirmed public zone: %v", err)
	}
	public.PublicConfirmed = true
	second, err := service.Create(ctx, owner, scope, public, false, newCorrelationID(t))
	if err != nil || second.Zone.Class != dnszone.ClassPublic || !second.Zone.PublicConfirmed {
		t.Fatalf("create public zone = %+v, error = %v", second, err)
	}
	first, err := service.List(ctx, owner, scope, dnszone.ID{}, 1)
	if err != nil || len(first.Zones) != 1 || !first.HasMore || first.Zones[0].Domain != "corp.com" {
		t.Fatalf("first page = %+v, error = %v", first, err)
	}
	if next, err := service.List(ctx, owner, scope, first.Zones[0].ID, 1); err != nil || len(next.Zones) != 1 ||
		next.HasMore || next.Zones[0].ID != zone {
		t.Fatalf("second page = %+v, error = %v", next, err)
	}

	// The database refuses resolvers off the Internet or of another shape.
	var refused bool
	if err := admin.QueryRow(ctx, `SELECT NOT mesh_ops.dns_zone_resolvers_valid_internal_v1('[{"address":"10.0.0.2","port":53}]')
AND NOT mesh_ops.dns_zone_resolvers_valid_internal_v1('[{"address":"1.1.1.1","port":5353}]')
AND NOT mesh_ops.dns_zone_resolvers_valid_internal_v1('[{"address":"1.1.1.1","port":53,"x":1}]')
AND NOT mesh_ops.dns_zone_resolvers_valid_internal_v1('[{"address":"not an address","port":53}]')
AND NOT mesh_ops.dns_zone_resolvers_valid_internal_v1('[]')
AND mesh_ops.dns_zone_resolvers_valid_internal_v1('[{"address":"2606:4700:4700::1111","port":53}]')`).Scan(&refused); err != nil ||
		!refused {
		t.Fatalf("the database resolver guard = %v, error = %v", refused, err)
	}

	for _, target := range []struct {
		id      dnszone.ID
		version int64
	}{{zone, 2}, {second.Zone.ID, 1}} {
		if _, err := service.Delete(ctx, owner, scope, target.id, target.version, false, newCorrelationID(t)); err != nil {
			t.Fatalf("delete DNS zone: %v", err)
		}
	}
	if countDNSZoneAudit(ctx, t, admin, "dns_zone.deleted") != 2 {
		t.Fatal("deleting zones was not audited once each")
	}
	if _, err := service.Read(ctx, owner, scope, zone); !errors.Is(err, dnszone.ErrNotFound) {
		t.Fatalf("read a deleted zone: %v", err)
	}
	if _, err := groups.Delete(ctx, owner, scope, group.Group.ID, 2, newCorrelationID(t)); err != nil {
		t.Fatalf("delete the Device Group once no zone uses it: %v", err)
	}
}
