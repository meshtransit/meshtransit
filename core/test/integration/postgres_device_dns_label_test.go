//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/sharing"
	"meshtransit.net/core/migrations"
)

// The Network the DNS label fixture owns in Workspace 103 (schema 169).
const (
	dnsLabelNetwork       = int64(9205)
	dnsLabelNetworkPublic = "01890f00-0000-7000-8000-000000009205"
)

// assertPostgreSQLDeviceDNSLabels qualifies schema 169: every live Device of
// a Network holds a label derived from its hostname, unique in the Network
// (numbered variants in Device order), a revoked Device releases its label,
// and the migration's backfill is deterministic and idempotent. It adds a
// Network to Workspace 103.
func assertPostgreSQLDeviceDNSLabels(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	assertDeviceDNSLabelDerivation(ctx, t, admin)
	seedDNSLabelNetwork(ctx, t, admin)
	now := time.Now().UTC()
	// Key bytes no other fixture uses (0x45-0x4f, 0x56-0x58).
	nodes := []peerProjectionNodeFixture{
		{id: 92051, hostname: "laptop.home", address: "100.64.250.1", machineMaterial: 0x45, nodeMaterial: 0x46},
		{id: 92052, hostname: "laptop.office", address: "100.64.250.2", machineMaterial: 0x47, nodeMaterial: 0x48},
		{id: 92053, hostname: "laptop-1", address: "100.64.250.3", machineMaterial: 0x49, nodeMaterial: 0x4a},
		{id: 92054, hostname: "1234", address: "100.64.250.4", machineMaterial: 0x4b, nodeMaterial: 0x4c},
		{id: 92055, hostname: "My_Box.example", address: "100.64.250.5", machineMaterial: 0x4d, nodeMaterial: 0x4e},
		{id: 92056, hostname: strings.Repeat("x", 70) + ".example", address: "100.64.250.6",
			machineMaterial: 0x4f, nodeMaterial: 0x56},
		{id: 92057, hostname: "gone", address: "100.64.250.7", machineMaterial: 0x57, nodeMaterial: 0x58,
			deviceState: "revoked"},
	}
	for index := range nodes {
		nodes[index].ownerID, nodes[index].nodeKeyState = 11, "active"
		if nodes[index].deviceState == "" {
			nodes[index].deviceState = "active"
		}
		nodes[index].createdAt, nodes[index].expiresAt = now.Add(-time.Hour), now.Add(2*time.Hour)
	}
	seedPeerProjectionScope(ctx, t, admin, 103, dnsLabelNetwork, 303, 403, dnsLabelNetwork, dnsLabelNetwork, nodes)
	want := map[int64]string{
		92051: "laptop", 92052: "laptop-1", 92053: "laptop-1-1", 92054: "device-1234", 92055: "my-box",
		92056: strings.Repeat("x", 63),
	}
	assertDNSLabels(ctx, t, admin, want, "registration")

	// Revoking releases the label at once; the hostname stays.
	revokeDNSLabelFixtureDevice(ctx, t, admin, 92051)
	delete(want, 92051)
	assertDNSLabels(ctx, t, admin, want, "after revoke")

	// The backfill gives the same labels in Device order and leaves labeled
	// Devices as they are.
	if _, err := admin.Exec(ctx, `DELETE FROM mesh.device_dns_label WHERE workspace_id = 103 AND network_id = $1`,
		dnsLabelNetwork); err != nil {
		t.Fatal(err)
	}
	backfill := migrations.Catalog()[168].SQL
	start := strings.Index(backfill, "DO $backfill$")
	end := strings.Index(backfill, "$backfill$;") + len("$backfill$;")
	if start < 0 || end <= start {
		t.Fatal("schema 169 backfill not found")
	}
	before := readAllDNSLabels(ctx, t, admin)
	for range 2 {
		if _, err := admin.Exec(ctx, backfill[start:end]); err != nil {
			t.Fatalf("rerun the schema 169 backfill: %v", err)
		}
	}
	want[92052], want[92053] = "laptop", "laptop-1" // in Device order without the revoked one
	assertDNSLabels(ctx, t, admin, want, "backfill")
	after := readAllDNSLabels(ctx, t, admin)
	for device, label := range before {
		if after[device] != label {
			t.Fatalf("backfill relabeled Device %d from %q to %q", device, label, after[device])
		}
	}
}

// assertDeviceDNSLabelDerivation checks the SQL derivation against the
// share access label derivation it mirrors.
func assertDeviceDNSLabelDerivation(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	for _, hostname := range []string{
		"laptop", "Laptop.Example", "my_box.local", "1234", "1234.example", "a--b", "-edge-.x", "...",
		"", strings.Repeat("y", 63) + "-z", strings.Repeat("9", 70), "café-bar",
	} {
		var derived string
		if err := admin.QueryRow(ctx, `SELECT mesh_ops.derive_device_dns_label_v1($1)`, hostname).
			Scan(&derived); err != nil {
			t.Fatal(err)
		}
		if want := sharing.DefaultAccessLabel(hostname).String(); derived != want {
			t.Errorf("derive_device_dns_label_v1(%q) = %q, want %q", hostname, derived, want)
		}
	}
}

func seedDNSLabelNetwork(ctx context.Context, t *testing.T, connection *pgx.Conn) {
	t.Helper()
	commitAuditedAuthorityFixture(ctx, t, connection, authorityEvidenceFixture{
		changePublicID:         integrationPublicID("01890f45-0000-7000-8000-", dnsLabelNetwork),
		eventPublicID:          integrationPublicID("01890f46-0000-7000-8000-", dnsLabelNetwork),
		outboxPublicID:         integrationPublicID("01890f47-0000-7000-8000-", dnsLabelNetwork),
		streamID:               dnsLabelNetwork,
		aggregateKind:          "network",
		aggregatePublicID:      dnsLabelNetworkPublic,
		aggregateVersion:       1,
		networkRevision:        int64(1),
		actorPrincipalPublicID: integrationPublicID("01890f00-0000-7000-8000-", 11),
		action:                 "network.created",
		permission:             "system.bootstrap",
		outboxEventClass:       "network.created",
	}, func(transaction pgx.Tx) {
		setIntegrationScope(ctx, t, transaction, 103, dnsLabelNetwork)
		for _, statement := range []string{
			`INSERT INTO mesh.network (id, public_id, workspace_id, display_name, name_key, node_limit, state)
OVERRIDING SYSTEM VALUE VALUES (9205, '` + dnsLabelNetworkPublic + `', 103, 'DNS labels', 'dns-labels', 1000, 'active')`,
			`INSERT INTO mesh.network_prefix (id, public_id, workspace_id, network_id, address_realm_id,
    address_pool_id, prefix, family, state)
OVERRIDING SYSTEM VALUE VALUES (9205, '01890f00-0000-7000-8000-000000092050', 103, 9205, 303, 403,
    '100.64.250.0/24', 4, 'active')`,
			`INSERT INTO mesh_ops.network_revision (workspace_id, network_id) VALUES (103, 9205)`,
			`INSERT INTO mesh_audit.audit_stream (id, deployment_id, workspace_id, network_id, scope_kind)
OVERRIDING SYSTEM VALUE VALUES (9205, 1, 103, 9205, 'network')`,
		} {
			if _, err := transaction.Exec(ctx, statement); err != nil {
				t.Fatalf("seed the DNS label Network: %v", err)
			}
		}
	})
}

// revokeDNSLabelFixtureDevice revokes one fixture Device as a revocation
// does: state, session generation and version in one audited change.
func revokeDNSLabelFixtureDevice(ctx context.Context, t *testing.T, admin *pgx.Conn, device int64) {
	t.Helper()
	var version, revision int64
	if err := admin.QueryRow(ctx, `SELECT device.version, revision.network_revision
FROM mesh.device AS device
JOIN mesh_ops.network_revision AS revision
  ON revision.workspace_id = device.workspace_id AND revision.network_id = device.network_id
WHERE device.id = $1`, device).Scan(&version, &revision); err != nil {
		t.Fatal(err)
	}
	commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
		changePublicID:         integrationPublicID("01890f45-0000-7000-8000-", device),
		eventPublicID:          integrationPublicID("01890f46-0000-7000-8000-", device),
		outboxPublicID:         integrationPublicID("01890f47-0000-7000-8000-", device),
		streamID:               dnsLabelNetwork,
		aggregateKind:          "device",
		aggregatePublicID:      integrationPublicID("01890f31-0000-7000-8000-", device),
		aggregateVersion:       version + 1,
		networkRevision:        revision + 1,
		actorPrincipalPublicID: integrationPublicID("01890f00-0000-7000-8000-", 11),
		action:                 "device.revoked",
		permission:             "device.revoke",
		outboxEventClass:       "network.revision.advanced",
	}, func(transaction pgx.Tx) {
		setIntegrationScope(ctx, t, transaction, 103, dnsLabelNetwork)
		for _, statement := range []string{
			`UPDATE mesh.device SET state = 'revoked', session_generation = session_generation + 1,
    version = version + 1, updated_at = clock_timestamp() WHERE id = $1`,
			`UPDATE mesh_ops.network_revision SET network_revision = network_revision + 1,
    inventory_revision = inventory_revision + 1, updated_at = clock_timestamp()
WHERE workspace_id = 103 AND network_id = 9205 AND $1::BIGINT > 0`,
		} {
			if _, err := transaction.Exec(ctx, statement, device); err != nil {
				t.Fatalf("revoke DNS label fixture Device %d: %v", device, err)
			}
		}
	})
}

func assertDNSLabels(ctx context.Context, t *testing.T, admin *pgx.Conn, want map[int64]string, stage string) {
	t.Helper()
	rows, err := admin.Query(ctx, `SELECT device_id, dns_label FROM mesh.device_dns_label
WHERE workspace_id = 103 AND network_id = $1`, dnsLabelNetwork)
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[int64]string)
	for rows.Next() {
		var device int64
		var label string
		if err := rows.Scan(&device, &label); err != nil {
			t.Fatal(err)
		}
		got[device] = label
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("%s: labels = %v, want %v", stage, got, want)
	}
	for device, label := range want {
		if got[device] != label {
			t.Fatalf("%s: labels = %v, want %v", stage, got, want)
		}
	}
}

func readAllDNSLabels(ctx context.Context, t *testing.T, admin *pgx.Conn) map[int64]string {
	t.Helper()
	rows, err := admin.Query(ctx, `SELECT device_id, dns_label FROM mesh.device_dns_label`)
	if err != nil {
		t.Fatal(err)
	}
	labels, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (struct {
		device int64
		label  string
	}, error) {
		var value struct {
			device int64
			label  string
		}
		return value, row.Scan(&value.device, &value.label)
	})
	if err != nil {
		t.Fatal(err)
	}
	result := make(map[int64]string, len(labels))
	for _, value := range labels {
		result[value.device] = value.label
	}
	return result
}

// assertPostgreSQLMapDeviceNames reads the peer projection Device's map: it
// names itself and its two authorized peers in its Network's zone, with an
// address record each, and no Device of another Network (980, 990).
func assertPostgreSQLMapDeviceNames(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool, identity control.AuthenticatedNode) {
	t.Helper()
	snapshot, err := newPeerCandidateStore(t, runtimePool, 8).Load(ctx, identity)
	if err != nil {
		t.Fatalf("load the named map: %v", err)
	}
	var workspaceCode, networkCode string
	if err := admin.QueryRow(ctx, `SELECT workspace_identity.display_code, network_identity.display_code
FROM mesh_ops.tenant_display_identity AS workspace_identity, mesh_ops.tenant_display_identity AS network_identity
WHERE workspace_identity.workspace_public_id = '01890f00-0000-7000-8000-000000000103'
  AND network_identity.network_public_id = '01890f00-0000-7000-8000-000000000203'`).
		Scan(&workspaceCode, &networkCode); err != nil {
		t.Fatal(err)
	}
	view, err := snapshot.DNSView(dnsname.Default())
	if err != nil {
		t.Fatal(err)
	}
	zone := workspaceCode + "." + networkCode + ".mesh.internal"
	if view.SelfName() != "peer-910."+zone || view.SearchDomain() != zone {
		t.Fatalf("self %q, search domain %q; want peer-910.%s", view.SelfName(), view.SearchDomain(), zone)
	}
	want := []string{"peer-910." + zone}
	for _, peer := range snapshot.AuthorizedPeers() {
		label, labeled := peer.DNSLabel()
		if !labeled || peer.Scope() != snapshot.Scope() {
			t.Fatalf("authorized peer %s has label %q (%v) in scope %v", peer.NodeID(), label, labeled, peer.Scope())
		}
		want = append(want, label.String()+"."+zone)
	}
	names := make([]string, 0, len(want))
	for _, record := range view.Records() {
		names = append(names, record.Name)
		if strings.Contains(record.Name, "peer-980") || strings.Contains(record.Name, "peer-990") {
			t.Fatalf("the map names a Device of another Network: %s", record.Name)
		}
	}
	if len(want) < 2 || strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("records = %v, want self and every authorized peer %v", names, want)
	}
}
