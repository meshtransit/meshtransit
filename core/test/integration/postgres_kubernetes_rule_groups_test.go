//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"meshtransit.net/core/internal/domain/devicegroup"
)

// assertKubernetesRuleGroups qualifies schema 236 on compiled rows: a rule to
// a cluster that the replaced release held with groups keeps them when a
// Core before K1a3 writes it unchanged, and is refused when that Core
// changed it or when a Core that hashes groups drops them; only rules to a
// cluster name groups, only sorted labels, and only rows attached knowingly
// are marked hashed.
func assertKubernetesRuleGroups(ctx context.Context, t *testing.T, admin *pgx.Conn, group devicegroup.ID) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	exec := func(statement string, arguments ...any) error {
		if _, err := tx.Exec(ctx, `SAVEPOINT rule_groups`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, statement, arguments...); err != nil {
			if _, rollbackErr := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT rule_groups`); rollbackErr != nil {
				t.Fatal(rollbackErr)
			}
			return err
		}
		if _, err := tx.Exec(ctx, `RELEASE SAVEPOINT rule_groups`); err != nil {
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
	var clusterGroup, current, previous, revision, users, others int64
	if err := tx.QueryRow(ctx, `SELECT device_group.id FROM mesh.device_group AS device_group
WHERE device_group.public_id = $1::UUID`, group.String()).Scan(&clusterGroup); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `SELECT active.id, previous.id, active.policy_revision
FROM mesh.policy_release AS active
JOIN mesh.policy_release AS previous ON previous.workspace_id = active.workspace_id
 AND previous.network_id = active.network_id AND previous.policy_revision = active.policy_revision - 1
WHERE active.workspace_id = 103 AND active.network_id = 203 AND active.state = 'active'`).Scan(
		&current, &previous, &revision); err != nil {
		t.Fatalf("read two releases: %v", err)
	}
	for name, target := range map[string]*int64{"k1a3-users": &users, "k1a3-others": &others} {
		if err := tx.QueryRow(ctx, `INSERT INTO mesh.device_group (public_id, deployment_id, workspace_id,
    network_id, name, name_key, created_at, updated_at)
SELECT pg_catalog.uuidv7(), workspace.deployment_id, 103, 203, $1, $1, pg_catalog.now(), pg_catalog.now()
FROM mesh.workspace AS workspace WHERE workspace.id = 103 RETURNING id`, name).Scan(target); err != nil {
			t.Fatalf("make %s: %v", name, err)
		}
	}
	const insert = `INSERT INTO mesh.compiled_policy_group_rule (public_id, access_rule_public_id, workspace_id,
    network_id, policy_release_id, policy_revision, source_device_group_id, destination_device_group_id, protocol,
    destination_ports, kubernetes_groups, created_at)
VALUES (pg_catalog.uuidv7(), $1::UUID, 103, 203, $2, $3, $4, $5, 'tcp', '{[443,444)}', $6::TEXT[], pg_catalog.now())`
	const held, fresh = "01890f00-0000-7000-8000-00000000cb01", "01890f00-0000-7000-8000-00000000cb02"
	// The replaced release held the rule with groups.
	if err := exec(`SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if err := exec(insert, held, previous, revision-1, users, clusterGroup, []string{"view"}); err != nil {
		t.Fatalf("the replaced release's rule: %v", err)
	}
	if err := exec(`SET LOCAL session_replication_role = origin`); err != nil {
		t.Fatal(err)
	}
	aware := func(on bool) {
		t.Helper()
		value := "off"
		if on {
			value = "on"
		}
		if err := exec(`SELECT pg_catalog.set_config('mesh.kubernetes_groups_aware', $1, TRUE)`, value); err != nil {
			t.Fatal(err)
		}
	}
	var noGroups []string
	aware(false)
	refused("an old Core changing the rule", "MTP07", insert, held, current, revision, others, clusterGroup, noGroups)
	refused("an old Core naming groups", "MTP07", insert, fresh, current, revision, users, clusterGroup,
		[]string{"view"})
	aware(true)
	refused("dropping the groups knowingly", "MTP07", insert, held, current, revision, users, clusterGroup, noGroups)
	refused("groups to a user group", "MTP07", insert, fresh, current, revision, users, others, []string{"view"})
	refused("unsorted groups", "23514", insert, fresh, current, revision, users, clusterGroup,
		[]string{"view", "edit"})
	refused("an upper-case group", "23514", insert, fresh, current, revision, users, clusterGroup, []string{"View"})
	if err := exec(insert, fresh, current, revision, users, clusterGroup, []string{"edit", "view"}); err != nil {
		t.Fatalf("a new rule with groups: %v", err)
	}
	aware(false)
	if err := exec(insert, held, current, revision, users, clusterGroup, noGroups); err != nil {
		t.Fatalf("an old Core republishing the rule unchanged: %v", err)
	}
	rows, err := tx.Query(ctx, `SELECT access_rule_public_id::TEXT, kubernetes_groups, kubernetes_groups_hashed
FROM mesh.compiled_policy_group_rule WHERE policy_release_id = $1 AND access_rule_public_id = ANY($2::UUID[])
ORDER BY access_rule_public_id`, current, []string{held, fresh})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for rows.Next() {
		var id string
		var groups []string
		var hashed bool
		if err := rows.Scan(&id, &groups, &hashed); err != nil {
			t.Fatal(err)
		}
		got[id] = strings.Join(groups, ",") + map[bool]string{true: " hashed", false: ""}[hashed]
	}
	if rows.Err() != nil || got[held] != "view" || got[fresh] != "edit,view hashed" {
		t.Fatalf("rows = %v, %v", got, rows.Err())
	}
	// The runtime no longer writes group rules through _v1.
	var granted bool
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.has_function_privilege('mesh_runtime',
    'mesh_ops.attach_policy_group_rules_v1(uuid,timestamp with time zone,jsonb)', 'EXECUTE')`).Scan(&granted); err != nil ||
		granted {
		t.Fatalf("mesh_runtime may run attach_policy_group_rules_v1: %v, %v", granted, err)
	}
}
