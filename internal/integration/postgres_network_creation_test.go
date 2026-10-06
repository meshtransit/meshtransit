//go:build integration

package integration

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/network/provisioning"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

// assertPostgreSQLNetworkCreation drives schemas 100 and 102 through the
// production store in the fixture Workspace: create with owner membership,
// enrollment profile and Network stream; replay; ID reuse; duplicate name;
// overlap with an existing and a new Network in either family; prefixes
// outside the pools; assigned IPv6 /64s; and missing network.create.
func assertPostgreSQLNetworkCreation(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimePool *postgresadapter.Pool) {
	t.Helper()
	store, err := postgresadapter.NewNetworkCreationStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	service, err := provisioning.NewService(store, accountsession.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	owner := managementRBACAccountSessionFixture(t)
	member := authorityConfirmerAccountSessionFixture(t)
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)
	workspaceID, _ := owner.LoginWorkspaceID()
	addFixtureIPv6OverlayPool(ctx, t, admin, workspaceID.String())
	// Legacy fixtures insert explicit identities; production rows always use
	// the sequences, so align them before the first sequenced insert.
	if _, err := admin.Exec(ctx, `SELECT
 pg_catalog.setval(pg_catalog.pg_get_serial_sequence('mesh_audit.audit_stream', 'id'), (SELECT max(id) FROM mesh_audit.audit_stream)),
 pg_catalog.setval(pg_catalog.pg_get_serial_sequence('mesh.network', 'id'), (SELECT max(id) FROM mesh.network))`); err != nil {
		t.Fatal(err)
	}
	var existing string
	if err := admin.QueryRow(ctx, `SELECT p.prefix::TEXT FROM mesh.network_prefix p
JOIN mesh.workspace w ON w.id = p.workspace_id
WHERE w.public_id = $1::UUID AND p.family = 4 AND p.state = 'active' ORDER BY p.id LIMIT 1`,
		workspaceID.String()).Scan(&existing); err != nil {
		t.Fatal(err)
	}
	auditBefore := countAuditTarget(ctx, t, admin, "network")

	first := newNetworkCommand(t, owner, "Office", "100.64.200.0/24", "fd42:42:42:200::/64")
	created, err := service.Create(ctx, first)
	if err != nil || created.Replayed || created.Version != 1 || !created.DisplayCode.IsValid() ||
		created.IPv6Prefix != first.IPv6Prefix || created.IPv4Prefix != first.IPv4Prefix {
		t.Fatalf("create = %+v, %v", created, err)
	}
	if replay, err := service.Create(ctx, first); err != nil || !replay.Replayed || replay.DisplayCode != created.DisplayCode {
		t.Fatalf("replay = %+v, %v", replay, err)
	}
	reused := first
	reused.DisplayName = "Another"
	if _, err := service.Create(ctx, reused); !errors.Is(err, provisioning.ErrConflict) {
		t.Fatalf("reused ID: %v", err)
	}
	if _, err := service.Create(ctx, newNetworkCommand(t, owner, "office", "100.64.201.0/24", "fd42:42:42:201::/64")); !errors.Is(err, provisioning.ErrConflict) {
		t.Fatalf("duplicate name: %v", err)
	}
	for name, command := range map[string]provisioning.Command{
		"inside the new IPv4":     newNetworkCommand(t, owner, "Overlap A", "100.64.200.128/25", "fd42:42:42:300::/64"),
		"covering the new IPv4":   newNetworkCommand(t, owner, "Overlap B", "100.64.192.0/18", "fd42:42:42:301::/64"),
		"existing fixture prefix": newNetworkCommand(t, owner, "Overlap C", existing, "fd42:42:42:302::/64"),
		"same IPv6":               newNetworkCommand(t, owner, "Overlap D", "100.64.210.0/24", "fd42:42:42:200::/64"),
	} {
		if _, err := service.Create(ctx, command); !errors.Is(err, provisioning.ErrPrefixOverlap) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := service.Create(ctx, newNetworkCommand(t, owner, "Outside Pool", "100.65.0.0/24", "fd42:42:42:400::/64")); !errors.Is(err, provisioning.ErrPrefixOutsidePool) {
		t.Fatalf("outside the Workspace pool: %v", err)
	}
	if _, err := service.Create(ctx, newNetworkCommand(t, owner, "Outside IPv6 Pool", "100.64.230.0/24", "fd99:1:2:3::/64")); !errors.Is(err, provisioning.ErrPrefixOutsidePool) {
		t.Fatalf("outside the Workspace IPv6 pool: %v", err)
	}
	assertAssignedNetworkIPv6(ctx, t, service, owner)
	if _, err := service.Create(ctx, newNetworkCommand(t, owner, "Not CGNAT", "10.10.0.0/24", "fd42:42:42:401::/64")); !errors.Is(err, provisioning.ErrInvalid) {
		t.Fatalf("outside 100.64.0.0/10: %v", err)
	}
	if _, err := service.Create(ctx, newNetworkCommand(t, member, "Member Network", "100.64.220.0/24", "fd42:42:42:220::/64")); !errors.Is(err, provisioning.ErrForbidden) {
		t.Fatalf("member without network.create: %v", err)
	}
	if countAuditTarget(ctx, t, admin, "network") != auditBefore+3 {
		t.Fatal("each created Network needs exactly one audit event")
	}
	var memberships, profiles, streams, prefixes int64
	if err := admin.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM mesh.network_membership m WHERE m.network_id = n.id AND m.state = 'active'),
 (SELECT count(*) FROM mesh.enrollment_profile e WHERE e.network_id = n.id AND e.interactive_authorization_enabled),
 (SELECT count(*) FROM mesh_audit.audit_stream s WHERE s.network_id = n.id AND s.scope_kind = 'network'),
 (SELECT count(*) FROM mesh.network_prefix p WHERE p.network_id = n.id AND p.state = 'active')
FROM mesh.network n WHERE n.public_id = $1::UUID`, first.NetworkID.String()).Scan(&memberships, &profiles, &streams, &prefixes); err != nil {
		t.Fatal(err)
	}
	if memberships != 1 || profiles != 1 || streams != 1 || prefixes != 2 {
		t.Fatalf("memberships=%d profiles=%d streams=%d prefixes=%d", memberships, profiles, streams, prefixes)
	}
}

// assertAssignedNetworkIPv6 omits the IPv6 prefix twice: Core assigns two
// distinct free /64s of the Workspace /48, a replay returns the same one, and
// an explicit request for an assigned range overlaps.
func assertAssignedNetworkIPv6(ctx context.Context, t *testing.T, service *provisioning.Service, owner accountsession.Session) {
	t.Helper()
	pool := netip.MustParsePrefix("fd42:42:42::/48")
	first := newNetworkCommand(t, owner, "Assigned A", "100.64.240.0/24", "")
	created, err := service.Create(ctx, first)
	if err != nil || created.IPv6Prefix.Bits() != 64 || !pool.Contains(created.IPv6Prefix.Addr()) {
		t.Fatalf("assigned IPv6 = %+v, %v", created, err)
	}
	if replay, err := service.Create(ctx, first); err != nil || !replay.Replayed || replay.IPv6Prefix != created.IPv6Prefix {
		t.Fatalf("assigned replay = %+v, %v", replay, err)
	}
	second, err := service.Create(ctx, newNetworkCommand(t, owner, "Assigned B", "100.64.241.0/24", ""))
	if err != nil || second.IPv6Prefix == created.IPv6Prefix || !pool.Contains(second.IPv6Prefix.Addr()) ||
		second.IPv6Prefix.Bits() != 64 {
		t.Fatalf("second assigned IPv6 = %+v, %v (first %s)", second, err, created.IPv6Prefix)
	}
	taken := newNetworkCommand(t, owner, "Assigned Taken", "100.64.242.0/24", created.IPv6Prefix.String())
	if _, err := service.Create(ctx, taken); !errors.Is(err, provisioning.ErrPrefixOverlap) {
		t.Fatalf("explicit assigned range: %v", err)
	}
}

// newNetworkCommand builds a request; an empty ipv6 asks Core to assign one.
func newNetworkCommand(t *testing.T, session accountsession.Session, name, ipv4, ipv6 string) provisioning.Command {
	t.Helper()
	id, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	correlation, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	workspaceID, _ := session.LoginWorkspaceID()
	var ipv6Prefix netip.Prefix
	if ipv6 != "" {
		ipv6Prefix = netip.MustParsePrefix(ipv6)
	}
	return provisioning.Command{Session: session, WorkspaceID: workspaceID, NetworkID: network.ID(id), DisplayName: name,
		IPv4Prefix: netip.MustParsePrefix(ipv4), IPv6Prefix: ipv6Prefix, CorrelationID: correlation}
}

// addFixtureIPv6OverlayPool gives the legacy fixture Workspace the IPv6 node
// pool every provisioned Workspace has.
func addFixtureIPv6OverlayPool(ctx context.Context, t *testing.T, admin *pgx.Conn, workspacePublicID string) {
	t.Helper()
	commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
		changePublicID: "01890f01-0000-7000-8000-00000000a601", eventPublicID: "01890f02-0000-7000-8000-00000000a601",
		outboxPublicID: "01890f03-0000-7000-8000-00000000a601", streamID: 1, aggregateKind: "address_pool",
		aggregatePublicID: "01890f00-0000-7000-8000-00000000a601", aggregateVersion: 1,
		action: "address_pool.created", permission: "system.bootstrap", outboxEventClass: "address_pool.created",
	}, func(transaction pgx.Tx) {
		if _, err := transaction.Exec(ctx, `INSERT INTO mesh.address_pool (
 public_id, deployment_id, workspace_id, address_realm_id, purpose, prefix, family, state)
SELECT '01890f00-0000-7000-8000-00000000a601', w.deployment_id, w.id, r.id, 'node_overlay', 'fd42:42:42::/48', 6, 'active'
FROM mesh.workspace w JOIN mesh.address_realm r ON r.workspace_id = w.id AND r.kind = 'workspace_overlay' AND r.state = 'active'
WHERE w.public_id = $1::UUID`, workspacePublicID); err != nil {
			t.Fatalf("add fixture IPv6 pool: %v", err)
		}
	})
}
