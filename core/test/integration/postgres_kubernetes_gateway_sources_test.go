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

	"meshtransit.net/core/internal/domain/network"
)

// kubernetesSourceRow is one row of load_map_network_kubernetes_sources_v1.
type kubernetesSourceRow struct {
	kind, ref                     string
	memberOwned, active, forwards bool
	validUntil, changed           *time.Time
}

// readKubernetesSources runs the schema 237 readers as the runtime in tx,
// scoped to the Network when scoped: the sources by Device and how many
// rules of the active release name groups. The role is reset on success.
func readKubernetesSources(ctx context.Context, t *testing.T, tx pgx.Tx, scope network.Scope, scoped bool) (
	map[int64]kubernetesSourceRow, int, error) {
	t.Helper()
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
		t.Fatal(err)
	}
	if scoped {
		if _, err := tx.Exec(ctx, `SELECT * FROM mesh_ops.set_network_scope($1::UUID, $2::UUID)`,
			scope.WorkspaceID().String(), scope.NetworkID().String()); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := tx.Query(ctx, `SELECT device_id, owner_kind, owner_ref, member_owned, owner_active,
    owner_valid_until, owner_changed_at, forwards
FROM mesh_ops.load_map_network_kubernetes_sources_v1(1000)`)
	if err != nil {
		return nil, 0, err
	}
	sources := map[int64]kubernetesSourceRow{}
	for rows.Next() {
		var device int64
		var value kubernetesSourceRow
		if err := rows.Scan(&device, &value.kind, &value.ref, &value.memberOwned, &value.active, &value.validUntil,
			&value.changed, &value.forwards); err != nil {
			rows.Close()
			return nil, 0, err
		}
		sources[device] = value
	}
	rows.Close()
	if rows.Err() != nil {
		return nil, 0, rows.Err()
	}
	var groups int
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_ops.load_map_network_kubernetes_rule_groups_v1(
    (SELECT policy_revision FROM mesh_ops.network_revision LIMIT 1))`).Scan(&groups); err != nil {
		return nil, 0, err
	}
	if _, err := tx.Exec(ctx, `RESET ROLE`); err != nil {
		t.Fatal(err)
	}
	return sources, groups, nil
}

// assertKubernetesGatewaySources qualifies schema 237: the runtime reads, in
// the Network's scope only, each standard Device's owner and whether it
// forwards, and the groups of the active release's rules; a member's Device
// rests on that member's memberships whether tagged or not; changing a
// Device's owner records when, and nothing else writes that.
func assertKubernetesGatewaySources(ctx context.Context, t *testing.T, admin *pgx.Conn, scope network.Scope) {
	t.Helper()
	read := func(scoped bool) (map[int64]kubernetesSourceRow, error) {
		tx, err := admin.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		sources, _, err := readKubernetesSources(ctx, t, tx, scope, scoped)
		return sources, err
	}
	sources, err := read(true)
	if err != nil || len(sources) == 0 {
		t.Fatalf("sources = %v, %v", sources, err)
	}
	var pgError *pgconn.PgError
	if _, err := read(false); !errors.As(err, &pgError) || pgError.Code != "42501" {
		t.Fatalf("an unscoped read: %v", err)
	}
	// Only standard Devices of this Network, each with a known owner kind,
	// and forwards exactly for routers and exit nodes.
	var strangers, misforwarded int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh.device AS device
JOIN mesh.network AS network ON network.id = device.network_id
WHERE device.id = ANY($1::BIGINT[]) AND (device.kind <> 'standard' OR network.public_id <> $2::UUID)`,
		keysOf(sources), scope.NetworkID().String()).Scan(&strangers); err != nil || strangers != 0 {
		t.Fatalf("Devices of another kind or Network among sources: %d, %v", strangers, err)
	}
	for device, value := range sources {
		var forwards bool
		if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM mesh.network_site_router WHERE device_id = $1)
    OR EXISTS (SELECT 1 FROM mesh.network_exit_node WHERE device_id = $1)`, device).Scan(&forwards); err != nil {
			t.Fatal(err)
		}
		if forwards != value.forwards {
			misforwarded++
		}
		switch value.kind {
		case "member":
			if value.ref == "" || !value.memberOwned {
				t.Errorf("Device %d: member owner %+v", device, value)
			}
		case "workspace":
			if value.ref != "" || value.memberOwned || value.active || value.validUntil != nil {
				t.Errorf("Device %d: workspace owner %+v", device, value)
			}
		case "tags":
			if len(value.ref) < 6 || !value.memberOwned && (value.active || value.validUntil != nil) {
				t.Errorf("Device %d: tags owner %+v", device, value)
			}
		default:
			t.Errorf("Device %d: owner kind %q", device, value.kind)
		}
	}
	if misforwarded != 0 {
		t.Fatalf("%d sources disagree on forwarding", misforwarded)
	}
	assertKubernetesTaggedMemberSource(ctx, t, admin, scope)
	// Changing a Device's owner records when; the runtime cannot write it.
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var device int64
	if err := tx.QueryRow(ctx, `SELECT device.id FROM mesh.device AS device
JOIN mesh.network AS network ON network.id = device.network_id
WHERE network.public_id = $1::UUID AND device.kind = 'standard' AND device.ownership = 'member'
ORDER BY device.id LIMIT 1`, scope.NetworkID().String()).Scan(&device); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('mesh.change_public_id', pg_catalog.uuidv7()::TEXT, TRUE)`); err != nil {
		t.Fatal(err)
	}
	var before *time.Time
	_ = tx.QueryRow(ctx, `SELECT changed_at FROM mesh.device_owner_change WHERE device_id = $1`, device).Scan(&before)
	// Only the owner-change trigger runs, in this rolled-back transaction:
	// the Device's other guards are not what is tested here.
	if _, err := tx.Exec(ctx, `ALTER TABLE mesh.device DISABLE TRIGGER USER`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `ALTER TABLE mesh.device ENABLE TRIGGER device_owner_change`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE mesh.device SET ownership = 'workspace' WHERE id = $1`, device); err != nil {
		t.Fatalf("change the owner: %v", err)
	}
	var after time.Time
	if err := tx.QueryRow(ctx, `SELECT changed_at FROM mesh.device_owner_change WHERE device_id = $1`,
		device).Scan(&after); err != nil || after.IsZero() || before != nil && !after.After(*before) {
		t.Fatalf("owner change = %v (before %v), %v", after, before, err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL ROLE mesh_runtime`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SAVEPOINT direct`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM mesh.device_owner_change WHERE device_id = $1`, device); err == nil {
		t.Fatal("the runtime cleared an owner change")
	}
}

func keysOf[V any](values map[int64]V) []int64 {
	keys := make([]int64, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

// assertKubernetesTaggedMemberSource: in a rolled-back transaction, a
// member's Device with two tags speaks through them, sorted, while its
// owner's memberships last, until the earlier of their ends; once the
// Network membership ends it no longer does; the release's group rules
// come back with their groups (b1 review H1).
func assertKubernetesTaggedMemberSource(ctx context.Context, t *testing.T, admin *pgx.Conn, scope network.Scope) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	exec := func(statement string, arguments ...any) int64 {
		t.Helper()
		tag, err := tx.Exec(ctx, statement, arguments...)
		if err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
		return tag.RowsAffected()
	}
	// Only the rows matter here, not the guards that keep them consistent.
	exec(`SET LOCAL session_replication_role = replica`)
	var device, owner, workspace, networkID, deployment int64
	if err := tx.QueryRow(ctx, `SELECT device.id, device.owner_principal_id, device.workspace_id, device.network_id,
    workspace.deployment_id
FROM mesh.device AS device
JOIN mesh.network AS network ON network.id = device.network_id
JOIN mesh.workspace AS workspace ON workspace.id = device.workspace_id
WHERE network.public_id = $1::UUID AND device.kind = 'standard' AND device.ownership = 'member'
  AND device.deleted_at IS NULL
ORDER BY device.id LIMIT 1`, scope.NetworkID().String()).Scan(&device, &owner, &workspace, &networkID,
		&deployment); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE mesh.principal SET state = 'active', deleted_at = NULL WHERE id = $1`, owner)
	if exec(`UPDATE mesh.workspace_membership SET state = 'active', expires_at = NULL
WHERE workspace_id = $1 AND principal_id = $2`, workspace, owner) != 1 ||
		exec(`UPDATE mesh.network_membership SET state = 'active', expires_at = pg_catalog.now() + interval '1 hour'
WHERE network_id = $1 AND principal_id = $2`, networkID, owner) != 1 {
		t.Fatal("the Device's owner holds no memberships to adjust")
	}
	tags := make([]string, 0, 2)
	for _, name := range []string{"k1a3-b1-two", "k1a3-b1-one"} {
		var id int64
		var publicID string
		if err := tx.QueryRow(ctx, `INSERT INTO mesh.device_tag (public_id, deployment_id, workspace_id, name,
    created_at, updated_at)
VALUES (pg_catalog.uuidv7(), $1, $2, $3, pg_catalog.now(), pg_catalog.now()) RETURNING id, public_id::TEXT`,
			deployment, workspace, name).Scan(&id, &publicID); err != nil {
			t.Fatal(err)
		}
		exec(`INSERT INTO mesh.device_tag_assignment (public_id, workspace_id, network_id, device_id, device_tag_id,
    created_at)
VALUES (pg_catalog.uuidv7(), $1, $2, $3, $4, pg_catalog.now())`, workspace, networkID, device, id)
		tags = append(tags, publicID)
	}
	slices.Sort(tags)
	// A group rule of the active release names a group.
	var release, revision, users int64
	if err := tx.QueryRow(ctx, `SELECT id, policy_revision FROM mesh.policy_release
WHERE workspace_id = $1 AND network_id = $2 AND state = 'active'`, workspace, networkID).Scan(&release,
		&revision); err != nil {
		t.Fatalf("the active release: %v", err)
	}
	if err := tx.QueryRow(ctx, `INSERT INTO mesh.device_group (public_id, deployment_id, workspace_id, network_id,
    name, name_key, created_at, updated_at)
VALUES (pg_catalog.uuidv7(), $1, $2, $3, 'k1a3-b1-users', 'k1a3-b1-users', pg_catalog.now(), pg_catalog.now())
RETURNING id`, deployment, workspace, networkID).Scan(&users); err != nil {
		t.Fatal(err)
	}
	named := exec(`INSERT INTO mesh.compiled_policy_group_rule (public_id, access_rule_public_id, workspace_id,
    network_id, policy_release_id, policy_revision, source_device_group_id, destination_device_group_id, protocol,
    destination_ports, kubernetes_groups, created_at)
VALUES (pg_catalog.uuidv7(), pg_catalog.uuidv7(), $1, $2, $3, $4, $5, $5, 'tcp', '{[443,444)}', ARRAY['view'],
    pg_catalog.now())`, workspace, networkID, release, revision, users)
	var expected int
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh.compiled_policy_group_rule AS rule
JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id
WHERE release.workspace_id = $1 AND release.network_id = $2 AND release.state = 'active'
  AND rule.kubernetes_groups IS NOT NULL`, workspace, networkID).Scan(&expected); err != nil {
		t.Fatal(err)
	}
	var hourLater time.Time
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.now() + interval '1 hour'`).Scan(&hourLater); err != nil {
		t.Fatal(err)
	}
	sources, groups, err := readKubernetesSources(ctx, t, tx, scope, true)
	if err != nil {
		t.Fatal(err)
	}
	if named != 1 || groups != expected {
		t.Fatalf("rules naming groups: read %d, want %d (named %d)", groups, expected, named)
	}
	tagged := sources[device]
	if tagged.kind != "tags" || tagged.ref != "tags:"+strings.Join(tags, ",") || !tagged.memberOwned ||
		!tagged.active || tagged.validUntil == nil || !tagged.validUntil.Equal(hourLater) {
		t.Fatalf("a tagged member's Device = %+v (tags %v)", tagged, tags)
	}
	exec(`UPDATE mesh.network_membership SET expires_at = pg_catalog.now()
WHERE network_id = $1 AND principal_id = $2`, networkID, owner)
	if sources, _, err = readKubernetesSources(ctx, t, tx, scope, true); err != nil {
		t.Fatal(err)
	}
	if lapsed := sources[device]; !lapsed.memberOwned || lapsed.active || lapsed.validUntil != nil {
		t.Fatalf("a lapsed member's tagged Device = %+v", lapsed)
	}
}
