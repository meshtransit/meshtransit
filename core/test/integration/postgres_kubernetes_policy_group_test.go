//go:build integration

package integration

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

// ensureKubernetesPolicyGroup qualifies schema 230's lazy group on Network
// 203: the first use makes the cluster's group with evidence, the next ones
// find it, and the ordinary group functions neither list nor change it.
func ensureKubernetesPolicyGroup(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool, owner accountsession.Session, scope network.Scope,
	clusterID kubecluster.ID) devicegroup.ID {
	t.Helper()
	store, err := postgresadapter.NewKubernetesClusterPolicyGroupStore(runtimePool,
		postgresadapter.AccountSessionOptions{StatementTimeout: 3 * time.Second, IdleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.ResolvePolicyKubernetesClusters(ctx, owner, scope, []kubecluster.ID{clusterID})
	index := slices.IndexFunc(first, func(group kubecluster.PolicyGroup) bool { return group.ClusterID == clusterID })
	if err != nil || index < 0 || first[index].Name != "prod" {
		t.Fatalf("ResolvePolicyKubernetesClusters() = %+v, %v", first, err)
	}
	group := first[index].GroupID
	again, err := store.ResolvePolicyKubernetesClusters(ctx, owner, scope, []kubecluster.ID{clusterID})
	if err != nil || !slices.Contains(again, first[index]) {
		t.Fatalf("the second ensure = %+v, %v", again, err)
	}
	if _, err := store.ResolvePolicyKubernetesClusters(ctx, owner, scope,
		[]kubecluster.ID{kubecluster.ID(mustPublicID(t))}); !errors.Is(err, kubecluster.ErrNotFound) {
		t.Fatalf("an unknown cluster: %v", err)
	}
	var groups, events int
	var name, kind string
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*), pg_catalog.min(device_group.name),
    pg_catalog.min(device_group.kind)
FROM mesh.device_group AS device_group
JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = device_group.kubernetes_cluster_id
WHERE cluster.public_id = $1::UUID`, clusterID.String()).Scan(&groups, &name, &kind); err != nil ||
		groups != 1 || name != "kubernetes-cluster:"+clusterID.String() || kind != "kubernetes_cluster" {
		t.Fatalf("the cluster's groups = %d %q %q, %v", groups, name, kind, err)
	}
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_audit.audit_event
WHERE target_kind = 'device_group' AND target_public_id = $1::UUID
  AND action = 'kubernetes_cluster.policy_group_created'`, group.String()).Scan(&events); err != nil || events != 1 {
		t.Fatalf("policy group events = %d, %v", events, err)
	}

	// The ordinary group functions answer as if it did not exist.
	groupsService := newIntegrationDeviceGroupService(t, runtimePool)
	listing, err := groupsService.List(ctx, owner, scope)
	if err != nil || slices.ContainsFunc(listing.Groups, func(listed devicegroup.Group) bool { return listed.ID == group }) {
		t.Fatalf("the user group list = %+v, %v", listing.Groups, err)
	}
	if _, err := groupsService.Members(ctx, owner, scope, group, node.ID{}, 10); !errors.Is(err, devicegroup.ErrNotFound) {
		t.Fatalf("reading the cluster group's members: %v", err)
	}
	devices := activeFixtureDevices(ctx, t, admin, 1)
	if _, err := groupsService.ChangeMembers(ctx, owner, scope, group, 1, devices, nil,
		newCorrelationID(t)); !errors.Is(err, devicegroup.ErrNotFound) {
		t.Fatalf("adding a Device to the cluster group: %v", err)
	}
	if _, err := groupsService.Delete(ctx, owner, scope, group, 1, newCorrelationID(t)); !errors.Is(err,
		devicegroup.ErrNotFound) {
		t.Fatalf("deleting the cluster group: %v", err)
	}
	assertKubernetesGroupMembers(ctx, t, admin, group)
	return group
}

// assertKubernetesGroupMembers: the group holds exactly the given Devices
// and counts them.
func assertKubernetesGroupMembers(ctx context.Context, t *testing.T, admin *pgx.Conn, group devicegroup.ID,
	devices ...string) {
	t.Helper()
	var members []string
	var count int
	if err := admin.QueryRow(ctx, `SELECT COALESCE(pg_catalog.array_agg(device.public_id::TEXT ORDER BY device.public_id::TEXT)
    FILTER (WHERE device.id IS NOT NULL), '{}'), pg_catalog.min(device_group.member_count)
FROM mesh.device_group AS device_group
LEFT JOIN mesh.device_group_member AS member ON member.device_group_id = device_group.id
LEFT JOIN mesh.device AS device ON device.id = member.device_id
WHERE device_group.public_id = $1::UUID`, group.String()).Scan(&members, &count); err != nil {
		t.Fatal(err)
	}
	slices.Sort(devices)
	if !slices.Equal(members, devices) || count != len(devices) {
		t.Fatalf("cluster group members = %v (count %d), want %v", members, count, devices)
	}
}

// assertGatewayJoinedItsGroup: completing the replica made it a member in
// the completion's transaction and recorded the group in its evidence.
func assertGatewayJoinedItsGroup(ctx context.Context, t *testing.T, admin *pgx.Conn, group devicegroup.ID,
	gatewayDevice string) {
	t.Helper()
	assertKubernetesGroupMembers(ctx, t, admin, group, gatewayDevice)
	var recorded string
	if err := admin.QueryRow(ctx, `SELECT event.payload::TEXT FROM mesh_audit.audit_event AS event
WHERE event.target_public_id = $1::UUID AND event.action = 'kubernetes_replica.enrolled'`, gatewayDevice).Scan(
		&recorded); err != nil {
		t.Fatalf("read the enrollment evidence: %v", err)
	}
	if !strings.Contains(recorded, group.String()) || !strings.Contains(recorded, "member_set_sha256_before") {
		t.Fatalf("the enrollment evidence does not name the group: %s", recorded)
	}
}

// assertKubernetesPolicyGroupGuards checks, in a transaction rolled back,
// that a gateway or the cluster's group enter no rule, DNS setting or group
// except as schema 230 allows, that the edge budget holds on approval, that
// a user group never selects a gateway, that a cluster a rule names is not
// deleted, and that a gateway leaving active leaves its group.
func assertKubernetesPolicyGroupGuards(ctx context.Context, t *testing.T, admin *pgx.Conn,
	group devicegroup.ID, gatewayDevice string) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	exec := func(statement string, arguments ...any) error {
		if _, err := tx.Exec(ctx, `SAVEPOINT guard`); err != nil {
			t.Fatal(err)
		}
		_, err := tx.Exec(ctx, statement, arguments...)
		if err != nil {
			if _, rollbackErr := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT guard`); rollbackErr != nil {
				t.Fatal(rollbackErr)
			}
			return err
		}
		if _, err := tx.Exec(ctx, `RELEASE SAVEPOINT guard`); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	refused := func(name, code string, statement string, arguments ...any) {
		t.Helper()
		if err := exec(statement, arguments...); err == nil || !strings.Contains(err.Error(), code) {
			t.Errorf("%s: %v, want %s", name, err, code)
		}
	}
	if err := exec(`SELECT pg_catalog.set_config('mesh.change_public_id', pg_catalog.uuidv7()::TEXT, TRUE)`); err != nil {
		t.Fatal(err)
	}
	var gateway, groupID, clusterInternal, release, revision, ordinary, userGroup int64
	if err := tx.QueryRow(ctx, `SELECT device.id, device_group.id, cluster.id
FROM mesh.device AS device
JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = device.kubernetes_cluster_id
JOIN mesh.device_group AS device_group ON device_group.kubernetes_cluster_id = cluster.id
WHERE device.public_id = $1::UUID AND device_group.public_id = $2::UUID`, gatewayDevice, group.String()).Scan(
		&gateway, &groupID, &clusterInternal); err != nil {
		t.Fatalf("read the gateway and group: %v", err)
	}
	if err := tx.QueryRow(ctx, `SELECT release.id, release.policy_revision FROM mesh.policy_release AS release
WHERE release.workspace_id = 103 AND release.network_id = 203 AND release.state = 'active'`).Scan(
		&release, &revision); err != nil {
		t.Fatalf("read the active release: %v", err)
	}
	if err := tx.QueryRow(ctx, `SELECT device.id FROM mesh.device AS device
WHERE device.workspace_id = 103 AND device.network_id = 203 AND device.kind = 'standard'
  AND device.state = 'active' AND device.deleted_at IS NULL ORDER BY device.id LIMIT 1`).Scan(&ordinary); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `INSERT INTO mesh.device_group (public_id, deployment_id, workspace_id, network_id,
    name, name_key, created_at, updated_at)
SELECT pg_catalog.uuidv7(), workspace.deployment_id, 103, 203, 'k1a2a-users', 'k1a2a-users', pg_catalog.now(),
    pg_catalog.now()
FROM mesh.workspace AS workspace WHERE workspace.id = 103 RETURNING id`).Scan(&userGroup); err != nil {
		t.Fatalf("make a user group: %v", err)
	}

	// Membership: only the cluster's active gateways, and no gateway elsewhere.
	member := `INSERT INTO mesh.device_group_member (public_id, workspace_id, network_id, device_group_id, device_id,
    created_at) VALUES (pg_catalog.uuidv7(), 103, 203, $1, $2, pg_catalog.now())`
	refused("an ordinary Device in the cluster's group", "MTL01", member, groupID, ordinary)
	refused("the gateway in a user group", "MTL01", member, userGroup, gateway)
	if err := exec(member, userGroup, ordinary); err != nil {
		t.Fatalf("an ordinary Device in a user group: %v", err)
	}

	// Compiled rules.
	rule := `INSERT INTO mesh.compiled_policy_group_rule (public_id, access_rule_public_id, workspace_id, network_id,
    policy_release_id, policy_revision, source_device_id, source_device_group_id, destination_device_id,
    destination_device_group_id, protocol, destination_ports, created_at)
VALUES (pg_catalog.uuidv7(), pg_catalog.uuidv7(), 103, 203, $1, $2, $3, $4, $5, $6, $7, $8::INT4MULTIRANGE,
    pg_catalog.now())`
	refused("UDP to the cluster's group", "MTP06", rule, release, revision, nil, userGroup, nil, groupID, "udp",
		"{[443,444)}")
	refused("TCP 6443 to the cluster's group", "MTP06", rule, release, revision, nil, userGroup, nil, groupID, "tcp",
		"{[6443,6444)}")
	refused("the cluster's group as a source", "MTP06", rule, release, revision, nil, groupID, nil, userGroup, "tcp",
		"{[443,444)}")
	refused("a group to the gateway itself", "MTP06", rule, release, revision, nil, userGroup, gateway, nil, "tcp",
		"{[443,444)}")
	refused("the gateway as a source", "MTP06", rule, release, revision, gateway, nil, nil, userGroup, "tcp",
		"{[22,23)}")
	refused("the gateway in a Device rule", "MTP06", `INSERT INTO mesh.compiled_policy_rule (public_id,
    access_rule_public_id, workspace_id, network_id, policy_release_id, policy_revision, source_device_id,
    destination_device_id, protocol, destination_ports, created_at)
VALUES (pg_catalog.uuidv7(), pg_catalog.uuidv7(), 103, 203, $1, $2, $3, $4, 'tcp', '{[443,444)}', pg_catalog.now())`,
		release, revision, ordinary, gateway)
	if err := exec(rule, release, revision, nil, userGroup, nil, groupID, "tcp", "{[443,444)}"); err != nil {
		t.Fatalf("TCP 443 from a user group to the cluster: %v", err)
	}
	assertCarriedGatewayRule(ctx, t, tx, exec, gateway, ordinary)

	// With that rule, approval checks the edge budget (here a limit of 0).
	refused("approval over the edge budget", "MTD06",
		`SELECT mesh_ops.check_kubernetes_cluster_edge_budget_internal_v1($1, 0)`, clusterInternal)
	if err := exec(`SELECT mesh_ops.check_kubernetes_cluster_edge_budget_internal_v1($1, 10000)`,
		clusterInternal); err != nil {
		t.Fatalf("approval within the edge budget: %v", err)
	}
	// The membership triggers and cluster deletion work only in the Network
	// scope every lifecycle change binds: without it they refuse rather than
	// leave maps behind.
	refused("revoking the gateway outside its Network scope", "42501",
		`UPDATE mesh.device SET state = 'revoked', version = version + 1 WHERE id = $1`, gateway)
	if err := exec(`SELECT * FROM mesh_ops.set_network_scope(
    (SELECT workspace.public_id FROM mesh.workspace AS workspace WHERE workspace.id = 103),
    (SELECT network.public_id FROM mesh.network AS network WHERE network.id = 203))`); err != nil {
		t.Fatal(err)
	}
	// A cluster a rule names is not deleted.
	refused("deleting a cluster a rule names", "MTK05", `UPDATE mesh.kubernetes_cluster
SET state = 'deleted', deleted_at = pg_catalog.now(), version = version + 1 WHERE id = $1`, clusterInternal)

	// DNS: no gateway resolver, no cluster group.
	if err := exec(`CREATE TEMP TABLE kubernetes_dns_probe (resolvers JSONB, distribution_group_ids BIGINT[])
ON COMMIT DROP`); err != nil {
		t.Fatal(err)
	}
	if err := exec(`CREATE TRIGGER kubernetes_dns_probe BEFORE INSERT ON kubernetes_dns_probe
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_kubernetes_dns_reference_v1()`); err != nil {
		t.Fatal(err)
	}
	refused("a gateway resolver", "MTL01", `INSERT INTO kubernetes_dns_probe VALUES
(pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object('device_id', $1::TEXT, 'port', 53)), NULL)`,
		gatewayDevice)
	refused("the cluster's group in a zone", "MTL01", `INSERT INTO kubernetes_dns_probe VALUES (NULL, ARRAY[$1::BIGINT])`,
		groupID)
	if err := exec(`INSERT INTO kubernetes_dns_probe VALUES (NULL, ARRAY[$1::BIGINT])`, userGroup); err != nil {
		t.Fatalf("a user group in a zone: %v", err)
	}

	// No user group selects a gateway, whose owner may be one of its members.
	var selected int
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_ops.selector_devices_internal_v1(103, 203)
WHERE selector_kind = 'identity_group' AND device_id = $1`, gateway).Scan(&selected); err != nil || selected != 0 {
		t.Fatalf("a user group selects the gateway: %d, %v", selected, err)
	}

	// Leaving active leaves the group and advances the group revision.
	var before, after int64
	if err := tx.QueryRow(ctx, `SELECT group_revision FROM mesh_ops.network_revision
WHERE workspace_id = 103 AND network_id = 203`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := exec(`UPDATE mesh.device SET state = 'revoked', version = version + 1 WHERE id = $1`, gateway); err != nil {
		t.Fatalf("revoke the gateway: %v", err)
	}
	var members int
	if err := tx.QueryRow(ctx, `SELECT (SELECT pg_catalog.count(*) FROM mesh.device_group_member WHERE device_group_id = $1),
    (SELECT group_revision FROM mesh_ops.network_revision WHERE workspace_id = 103 AND network_id = 203)`,
		groupID).Scan(&members, &after); err != nil || members != 0 || after != before+1 {
		t.Fatalf("after revoking: %d members, group revision %d -> %d, %v", members, before, after, err)
	}
}

// assertCarriedGatewayRule: a Device rule to a gateway that the replaced
// release held unchanged is carried; changed, it is refused.
func assertCarriedGatewayRule(ctx context.Context, t *testing.T, tx pgx.Tx, exec func(string, ...any) error,
	gateway, ordinary int64) {
	t.Helper()
	var current, previous, revision int64
	if err := tx.QueryRow(ctx, `SELECT active.id, previous.id, active.policy_revision
FROM mesh.policy_release AS active
JOIN mesh.policy_release AS previous ON previous.workspace_id = active.workspace_id
 AND previous.network_id = active.network_id AND previous.policy_revision = active.policy_revision - 1
WHERE active.workspace_id = 103 AND active.network_id = 203 AND active.state = 'active'`).Scan(
		&current, &previous, &revision); err != nil {
		t.Fatalf("read two releases: %v", err)
	}
	if err := exec(`SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if err := exec(`INSERT INTO mesh.compiled_policy_rule (public_id, access_rule_public_id, workspace_id,
    network_id, policy_release_id, policy_revision, source_device_id, destination_device_id, protocol,
    destination_ports, created_at)
VALUES (pg_catalog.uuidv7(), '01890f00-0000-7000-8000-00000000ca44', 103, 203, $1, $2, $3, $4, 'tcp',
    '{[443,444)}', pg_catalog.now())`, previous, revision-1, ordinary, gateway); err != nil {
		t.Fatalf("the replaced release's rule to a gateway: %v", err)
	}
	if err := exec(`SET LOCAL session_replication_role = origin`); err != nil {
		t.Fatal(err)
	}
	carried := `INSERT INTO mesh.compiled_policy_rule (public_id, access_rule_public_id, workspace_id,
    network_id, policy_release_id, policy_revision, source_device_id, destination_device_id, protocol,
    destination_ports, created_at)
VALUES (pg_catalog.uuidv7(), '01890f00-0000-7000-8000-00000000ca44', 103, 203, $1, $2, $3, $4, 'tcp',
    $5::INT4MULTIRANGE, pg_catalog.now())`
	if err := exec(carried, current, revision, ordinary, gateway, "{[443,444)}"); err != nil {
		t.Fatalf("carrying an unchanged rule to a gateway: %v", err)
	}
	if err := exec(carried, current, revision, ordinary, gateway, "{[22,23)}"); err == nil ||
		!strings.Contains(err.Error(), "MTP06") {
		t.Fatalf("a changed rule to a gateway: %v", err)
	}
}

// assertKubernetesGroupReferenceCoverage: every foreign key to
// mesh.device_group and every array of group IDs in mesh is guarded against
// a cluster's group, or listed with its reason.
func assertKubernetesGroupReferenceCoverage(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	guards := []string{"mesh_ops.refuse_kubernetes_policy_rule_v1", "mesh_ops.enforce_kubernetes_group_member_v1",
		"mesh_ops.refuse_kubernetes_dns_reference_v1"}
	rows, err := admin.Query(ctx, `SELECT DISTINCT constraint_row.conrelid::REGCLASS::TEXT
FROM pg_catalog.pg_constraint AS constraint_row
WHERE constraint_row.confrelid = 'mesh.device_group'::REGCLASS AND constraint_row.contype = 'f'
UNION
SELECT table_schema || '.' || table_name FROM information_schema.columns
WHERE table_schema IN ('mesh', 'mesh_ops') AND column_name LIKE '%group_ids'`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, table)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(tables) < 6 {
		t.Fatalf("tables referring to Device Groups: %v, %v", tables, err)
	}
	for _, table := range tables {
		var guarded bool
		if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_trigger
WHERE tgrelid = $1::REGCLASS AND NOT tgisinternal AND tgfoid::REGPROC::TEXT = ANY ($2))`, table, guards).Scan(
			&guarded); err != nil {
			t.Fatal(err)
		}
		if !guarded {
			t.Errorf("%s refers to Device Groups without the Kubernetes cluster guard", table)
		}
	}
}

// assertMapListsKubernetesGateways: schema 231 tells mesh_runtime, in its
// installed scope only, which live Devices are gateway replicas and of
// which cluster; standard Devices are not listed (K1a2b).
func assertMapListsKubernetesGateways(ctx context.Context, t *testing.T, admin *pgx.Conn, scope network.Scope,
	gatewayDevice string, cluster string) {
	t.Helper()
	read := func(scoped bool) ([][2]any, error) {
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
			t.Fatal(err)
		}
		if scoped {
			if _, err := tx.Exec(ctx, `SELECT * FROM mesh_ops.set_network_scope($1::UUID, $2::UUID)`,
				scope.WorkspaceID().String(), scope.NetworkID().String()); err != nil {
				t.Fatal(err)
			}
		}
		rows, err := tx.Query(ctx, `SELECT numeric_node_id, cluster_name
FROM mesh_ops.load_map_network_kubernetes_gateways_v1()`)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var listed [][2]any
		for rows.Next() {
			var numeric int64
			var name string
			if err := rows.Scan(&numeric, &name); err != nil {
				return nil, err
			}
			listed = append(listed, [2]any{numeric, name})
		}
		return listed, rows.Err()
	}
	var numeric int64
	if err := admin.QueryRow(ctx, `SELECT id FROM mesh.device WHERE public_id = $1::UUID`,
		gatewayDevice).Scan(&numeric); err != nil {
		t.Fatal(err)
	}
	var standard int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh.device AS device
JOIN mesh.network AS network ON network.id = device.network_id
WHERE network.public_id = $1::UUID AND device.kind = 'standard' AND device.state = 'active'`,
		scope.NetworkID().String()).Scan(&standard); err != nil || standard == 0 {
		t.Fatalf("the Network has %d standard Devices to leave out, %v", standard, err)
	}
	listed, err := read(true)
	if err != nil || len(listed) != 1 || listed[0] != [2]any{numeric, cluster} {
		t.Fatalf("gateways = %v, %v", listed, err)
	}
	var pgError *pgconn.PgError
	if _, err := read(false); !errors.As(err, &pgError) || pgError.Code != "42501" {
		t.Fatalf("an unscoped read: %v", err)
	}
}

// assertMapMarksKubernetesReplicas: a standard Device's map, read through
// Core's store as mesh_runtime per Device and from the shared Network
// inventory, marks the gateway replica with its cluster and nothing else.
func assertMapMarksKubernetesReplicas(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool, scope network.Scope, gatewayDevice string, cluster string) {
	t.Helper()
	var ordinary string
	if err := admin.QueryRow(ctx, `SELECT device.public_id::TEXT FROM mesh.device AS device
JOIN mesh.network AS network ON network.id = device.network_id
WHERE network.public_id = $1::UUID AND device.kind = 'standard' AND device.state = 'active'
  AND device.deleted_at IS NULL AND device.expires_at > pg_catalog.now()
ORDER BY device.id LIMIT 1`, scope.NetworkID().String()).Scan(&ordinary); err != nil {
		t.Fatal(err)
	}
	ordinaryID, err := node.ParseID(ordinary)
	if err != nil {
		t.Fatal(err)
	}
	identity := fixtureDeviceIdentity(ctx, t, admin, ordinaryID)
	for _, shared := range []bool{false, true} {
		store, err := postgresadapter.NewMapSessionStore(runtimePool, postgresadapter.MapSessionOptions{
			StatementTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second,
			PeerCandidateLimit: mapsession.MaximumPeerCandidates, PolicyRuleLimit: mapsession.MaximumPacketPolicyRules,
			RelayDirectory: integrationRelayDirectory(t), SharedInventory: shared,
			InventoryStatementTimeout: 30 * time.Second, InventoryMaxAge: 30 * time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := store.Load(ctx, identity)
		if err != nil {
			t.Fatalf("shared %t: Load() error = %v", shared, err)
		}
		marked := 0
		for _, candidate := range snapshot.PeerCandidates() {
			name, replica := candidate.KubernetesCluster()
			isGateway := candidate.NodeID().String() == gatewayDevice
			if replica != isGateway || (replica && name.String() != cluster) {
				t.Fatalf("shared %t: candidate %s marked %q (%t)", shared, candidate.NodeID(), name, replica)
			}
			if replica {
				marked++
			}
		}
		if marked != 1 {
			t.Fatalf("shared %t: %d replicas marked among %d candidates", shared, marked,
				len(snapshot.PeerCandidates()))
		}
		if stats := store.InventoryStats(); shared && stats.Shared != 1 {
			t.Fatalf("the shared read did not use the Network inventory: %+v", stats)
		}
	}
}
