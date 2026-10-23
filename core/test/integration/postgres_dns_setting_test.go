//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/dnszone"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

// assertPostgreSQLDNSSettings qualifies schema 221 through the production
// store: network.read reads the settings (version 0 before the first
// change), dns.manage replaces the unmanaged Device Groups at the expected
// version; a change advances the Network and DNS revisions with one audit
// event that wakes map sessions, a no-op writes nothing, a stale version and
// an unknown group are refused; maps leave a member Device without DNS; a
// group the settings name cannot be deleted. It leaves the settings empty
// and no group behind.
func assertPostgreSQLDNSSettings(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool,
) {
	t.Helper()
	service := newIntegrationDNSZoneService(t, runtimePool, dnszone.DefaultLimits())
	groups := newIntegrationDeviceGroupService(t, runtimePool)
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
	auditCount := func() int64 {
		t.Helper()
		var count int64
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM mesh_audit.audit_event
WHERE target_kind = 'network_dns_setting' AND action = 'network_dns.updated'`).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}

	initial, err := service.ReadSettings(ctx, owner, scope)
	if err != nil || initial.Version != 0 || len(initial.UnmanagedGroups) != 0 {
		t.Fatalf("initial DNS settings = %+v, error = %v", initial, err)
	}
	consumer := activeFixtureDevices(ctx, t, admin, 1)[0]
	group, err := groups.Create(ctx, owner, scope, devicegroup.Definition{Name: "Unmanaged DNS"}, newCorrelationID(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := groups.ChangeMembers(ctx, owner, scope, group.Group.ID, 1, []node.ID{consumer}, nil,
		newCorrelationID(t)); err != nil {
		t.Fatal(err)
	}
	unmanaged := []devicegroup.ID{group.Group.ID}
	if _, err := service.ChangeSettings(ctx, member, scope, 0, unmanaged, newCorrelationID(t)); !errors.Is(err,
		dnszone.ErrForbidden) {
		t.Fatalf("a plain member changed the DNS settings: %v", err)
	}
	networkBefore, _ := fixtureNetworkRevisions(ctx, t, admin)
	dnsBefore, auditBefore := fixtureDNSRevision(ctx, t, admin), auditCount()
	changed, err := service.ChangeSettings(ctx, owner, scope, 0, unmanaged, newCorrelationID(t))
	if err != nil || !changed.Changed || changed.Settings.Version != 1 || len(changed.Settings.UnmanagedGroups) != 1 ||
		changed.Settings.UnmanagedGroups[0].ID != group.Group.ID {
		t.Fatalf("change DNS settings = %+v, error = %v", changed, err)
	}
	if networkAfter, _ := fixtureNetworkRevisions(ctx, t, admin); networkAfter != networkBefore+1 ||
		fixtureDNSRevision(ctx, t, admin) != dnsBefore+1 || auditCount() != auditBefore+1 {
		t.Fatal("changing the DNS settings did not advance the revisions with one audit event")
	}
	var wakes bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM mesh_ops.outbox_event
WHERE event_class = 'network.revision.advanced' AND aggregate_kind = 'network_dns_setting')`).Scan(&wakes); err != nil ||
		!wakes {
		t.Fatalf("the DNS settings change does not wake map sessions: %v", err)
	}
	if same, err := service.ChangeSettings(ctx, owner, scope, 1, unmanaged, newCorrelationID(t)); err != nil ||
		same.Changed || same.Settings.Version != 1 || auditCount() != auditBefore+1 {
		t.Fatalf("no-op DNS settings change = %+v, error = %v", same, err)
	}
	if _, err := service.ChangeSettings(ctx, owner, scope, 0, nil, newCorrelationID(t)); !errors.Is(err,
		dnszone.ErrVersionConflict) {
		t.Fatalf("a stale DNS settings change: %v", err)
	}
	unknown, _ := devicegroup.ParseID("01890f00-0000-7000-8000-00000000ffff")
	if _, err := service.ChangeSettings(ctx, owner, scope, 1, []devicegroup.ID{unknown},
		newCorrelationID(t)); !errors.Is(err, dnszone.ErrGroupNotFound) {
		t.Fatalf("an unknown Device Group: %v", err)
	}
	if read, err := service.ReadSettings(ctx, owner, scope); err != nil || read.Version != 1 ||
		len(read.UnmanagedGroups) != 1 || read.UnmanagedGroups[0].Name != "Unmanaged DNS" {
		t.Fatalf("DNS settings read = %+v, error = %v", read, err)
	}

	// Maps leave the member Device without DNS.
	store, err := postgresadapter.NewMapSessionStore(runtimePool, postgresadapter.MapSessionOptions{
		StatementTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second,
		PeerCandidateLimit: mapsession.MaximumPeerCandidates, PolicyRuleLimit: mapsession.MaximumPacketPolicyRules,
		RelayDirectory: integrationRelayDirectory(t), SharedInventory: true,
		InventoryStatementTimeout: 30 * time.Second, InventoryMaxAge: 30 * time.Second,
		DNSZones: true, RoutePeerLimit: mapsession.DefaultPeerLimit,
	})
	if err != nil {
		t.Fatal(err)
	}
	// An exit node's stream reads the revision the change advanced to.
	if revision, err := store.NetworkRevision(ctx, scope); err != nil || revision != networkBefore+1 {
		t.Fatalf("NetworkRevision() = %d, error = %v, want %d", revision, err, networkBefore+1)
	}
	snapshot, err := store.Load(ctx, fixtureDeviceIdentity(ctx, t, admin, consumer))
	if err != nil || !snapshot.Routes().DNSUnmanaged() {
		t.Fatalf("a Device of an unmanaged group: unmanaged %v, error = %v", snapshot.Routes().DNSUnmanaged(), err)
	}

	if _, err := groups.Delete(ctx, owner, scope, group.Group.ID, 2, newCorrelationID(t)); !errors.Is(err,
		devicegroup.ErrInUseByDNS) {
		t.Fatalf("deleting an unmanaged Device Group: %v", err)
	}
	if cleared, err := service.ChangeSettings(ctx, owner, scope, 1, nil, newCorrelationID(t)); err != nil ||
		!cleared.Changed || cleared.Settings.Version != 2 || len(cleared.Settings.UnmanagedGroups) != 0 {
		t.Fatalf("clear DNS settings = %+v, error = %v", cleared, err)
	}
	if _, err := groups.Delete(ctx, owner, scope, group.Group.ID, 2, newCorrelationID(t)); err != nil {
		t.Fatal(err)
	}
}
