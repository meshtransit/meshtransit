//go:build integration

package integration

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"meshtransit.net/core/internal/domain/devicegroup"
)

// assertKubernetesRuleProfiles qualifies schema 258 (K2 §24): a Core that
// does not hash profiles keeps a rule's profile only by republishing it
// unchanged, groups included, with every profile of the replaced release;
// it is refused for a changed rule and can never name a profile itself; a
// profile's shape and pin are checked; and a Core before K2 reads no groups
// from a rule that names a profile.
func assertKubernetesRuleProfiles(ctx context.Context, t *testing.T, admin *pgx.Conn, group devicegroup.ID) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	exec := func(statement string, arguments ...any) error {
		if _, err := tx.Exec(ctx, `SAVEPOINT rule_profiles`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, statement, arguments...); err != nil {
			if _, rollbackErr := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT rule_profiles`); rollbackErr != nil {
				t.Fatal(rollbackErr)
			}
			return err
		}
		if _, err := tx.Exec(ctx, `RELEASE SAVEPOINT rule_profiles`); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	must := func(name, statement string, arguments ...any) {
		t.Helper()
		if err := exec(statement, arguments...); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	refused := func(name, code, statement string, arguments ...any) {
		t.Helper()
		if err := exec(statement, arguments...); err == nil || !strings.Contains(err.Error(), code) {
			t.Errorf("%s: %v, want %s", name, err, code)
		}
	}
	must("change id", `SELECT pg_catalog.set_config('mesh.change_public_id', pg_catalog.uuidv7()::TEXT, TRUE)`)
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
	for name, target := range map[string]*int64{"k2-users": &users, "k2-others": &others} {
		if err := tx.QueryRow(ctx, `INSERT INTO mesh.device_group (public_id, deployment_id, workspace_id,
    network_id, name, name_key, created_at, updated_at)
SELECT pg_catalog.uuidv7(), workspace.deployment_id, 103, 203, $1, $1, pg_catalog.now(), pg_catalog.now()
FROM mesh.workspace AS workspace WHERE workspace.id = 103 RETURNING id`, name).Scan(target); err != nil {
			t.Fatalf("make %s: %v", name, err)
		}
	}
	const (
		usedProfile   = "01890f00-0000-7000-8000-00000000cc01"
		unusedProfile = "01890f00-0000-7000-8000-00000000cc02"
		heldV3        = "01890f00-0000-7000-8000-00000000cc11"
		heldV2        = "01890f00-0000-7000-8000-00000000cc12"
		plain         = "01890f00-0000-7000-8000-00000000cc13"
		fresh         = "01890f00-0000-7000-8000-00000000cc14"
	)
	usedHash, unusedHash := bytes.Repeat([]byte{0xa1}, 32), bytes.Repeat([]byte{0xa2}, 32)
	// The replaced release, as a Core that hashes profiles left it.
	must("replica role", `SET LOCAL session_replication_role = replica`)
	for _, profile := range []struct {
		id   string
		hash []byte
		name string
	}{{usedProfile, usedHash, "developer"}, {unusedProfile, unusedHash, "read-only"}} {
		must("content "+profile.name, `INSERT INTO mesh.kubernetes_access_profile_content (deployment_id,
    workspace_id, network_id, content_hash, name, rules, created_at)
SELECT workspace.deployment_id, 103, 203, $1, $2, '{"format":1}'::JSONB, pg_catalog.now()
FROM mesh.workspace AS workspace WHERE workspace.id = 103`, profile.hash, profile.name)
		must("held "+profile.name, `INSERT INTO mesh.policy_release_kubernetes_profile (workspace_id, network_id,
    policy_release_id, policy_revision, profile_public_id, content_hash, description, created_at)
VALUES (103, 203, $1, $2, $3::UUID, $4, '', pg_catalog.now())`, previous, revision-1, profile.id, profile.hash)
	}
	const insertProfiled = `INSERT INTO mesh.compiled_policy_group_rule (public_id, access_rule_public_id,
    workspace_id, network_id, policy_release_id, policy_revision, source_device_group_id,
    destination_device_group_id, protocol, destination_ports, kubernetes_groups, kubernetes_profile_public_id,
    kubernetes_profile_hash, kubernetes_namespaces, kubernetes_cluster_part, kubernetes_mode,
    kubernetes_report_until, created_at)
VALUES (pg_catalog.uuidv7(), $1::UUID, 103, 203, $2, $3, $4, $5, 'tcp', '{[443,444)}', $6::TEXT[], $7::UUID, $8,
    $9::TEXT[], $10, $11, $12::TIMESTAMPTZ, pg_catalog.now())`
	const insert = `INSERT INTO mesh.compiled_policy_group_rule (public_id, access_rule_public_id, workspace_id,
    network_id, policy_release_id, policy_revision, source_device_group_id, destination_device_group_id, protocol,
    destination_ports, kubernetes_groups, created_at)
VALUES (pg_catalog.uuidv7(), $1::UUID, 103, 203, $2, $3, $4, $5, 'tcp', '{[443,444)}', $6::TEXT[], pg_catalog.now())`
	view, edit, none := []string{"view"}, []string{"edit"}, []string(nil)
	teamA := []string{"team-a"}
	for _, held := range []string{heldV3, heldV2} {
		must("held rule", insertProfiled, held, previous, revision-1, users, clusterGroup, view, usedProfile, usedHash,
			teamA, false, "enforce", nil)
	}
	must("plain rule", insert, plain, previous, revision-1, users, clusterGroup, view)
	must("origin role", `SET LOCAL session_replication_role = origin`)
	aware := func(groups, profiles bool) {
		t.Helper()
		value := map[bool]string{true: "on", false: "off"}
		must("aware", `SELECT pg_catalog.set_config('mesh.kubernetes_groups_aware', $1, TRUE),
    pg_catalog.set_config('mesh.kubernetes_profiles_aware', $2, TRUE)`, value[groups], value[profiles])
	}

	// A Core that hashes groups but not profiles (K1).
	aware(true, false)
	refused("changing the groups of a profiled rule", "lose its access profile", insert, heldV3, current, revision,
		users, clusterGroup, edit)
	refused("changing the source of a profiled rule", "lose its access profile", insert, heldV3, current,
		revision, others, clusterGroup, view)
	refused("naming a profile", "names an access profile", insertProfiled, fresh, current, revision, users,
		clusterGroup, view, usedProfile, usedHash, teamA, false, "enforce", nil)
	must("republishing a profiled rule unchanged", insert, heldV3, current, revision, users, clusterGroup, view)
	// A Core before K1a3: neither hashed.
	aware(false, false)
	// Changed, the groups are refused first: they would be lost too.
	refused("an older Core changing a profiled rule", "lose its Kubernetes groups", insert, heldV2, current,
		revision, others, clusterGroup, none)
	must("an older Core republishing it unchanged", insert, heldV2, current, revision, users, clusterGroup, none)
	// A Core that hashes profiles: its shapes are checked, its pins too.
	aware(true, true)
	refused("unsorted namespaces", "23514", insertProfiled, fresh, current, revision, users, clusterGroup, view,
		usedProfile, usedHash, []string{"team-b", "team-a"}, false, "enforce", nil)
	refused("every namespace and another", "23514", insertProfiled, fresh, current, revision, users, clusterGroup,
		view, usedProfile, usedHash, []string{"*", "team-a"}, false, "enforce", nil)
	refused("report without a deadline", "23514", insertProfiled, fresh, current, revision, users, clusterGroup,
		view, usedProfile, usedHash, teamA, false, "report", nil)
	refused("enforce with a deadline", "23514", insertProfiled, fresh, current, revision, users, clusterGroup,
		view, usedProfile, usedHash, teamA, false, "enforce", "2026-11-01T00:00:00Z")
	refused("report past fourteen days", "23514", insertProfiled, fresh, current, revision, users, clusterGroup,
		view, usedProfile, usedHash, teamA, false, "report", "2099-01-01T00:00:00Z")
	refused("a profile without groups", "23514", insertProfiled, fresh, current, revision, users, clusterGroup,
		none, usedProfile, usedHash, teamA, false, "enforce", nil)
	refused("a profile the release does not hold", "23503", insertProfiled, fresh, current, revision, users,
		clusterGroup, view, "01890f00-0000-7000-8000-00000000cc09", usedHash, teamA, false, "enforce", nil)
	refused("a profile without a hash", "23514", insertProfiled, fresh, current, revision, users, clusterGroup,
		view, usedProfile, nil, teamA, false, "enforce", nil)
	refused("a profile without a mode", "23514", insertProfiled, fresh, current, revision, users, clusterGroup,
		view, usedProfile, usedHash, teamA, false, nil, nil)
	refused("a profile to a user group", "names an access profile", insertProfiled, fresh, current, revision,
		users, others, none, usedProfile, usedHash, teamA, false, "enforce", nil)
	tomorrow := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	must("a new rule with a profile", insertProfiled, fresh, current, revision, users, clusterGroup, edit,
		usedProfile, usedHash, []string{"*"}, true, "report", tomorrow)

	// Both carried rules keep their profile, unhashed; the release holds
	// both profiles of the replaced one; the new rule is hashed.
	rows, err := tx.Query(ctx, `SELECT access_rule_public_id::TEXT, kubernetes_groups,
    kubernetes_profile_public_id::TEXT, kubernetes_namespaces, kubernetes_profile_hashed, kubernetes_groups_hashed
FROM mesh.compiled_policy_group_rule WHERE policy_release_id = $1 AND access_rule_public_id = ANY($2::UUID[])
ORDER BY access_rule_public_id`, current, []string{heldV3, heldV2, fresh})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for rows.Next() {
		var id string
		var groups, namespaces []string
		var profile *string
		var hashed, groupsHashed bool
		if err := rows.Scan(&id, &groups, &profile, &namespaces, &hashed, &groupsHashed); err != nil {
			t.Fatal(err)
		}
		pinned := "none"
		if profile != nil {
			pinned = *profile
		}
		got[id] = strings.Join(groups, ",") + " " + pinned + " " + strings.Join(namespaces, ",") +
			map[bool]string{true: " hashed", false: ""}[hashed] +
			map[bool]string{true: " groups-hashed", false: ""}[groupsHashed]
	}
	if rows.Err() != nil || got[heldV3] != "view "+usedProfile+" team-a groups-hashed" ||
		got[heldV2] != "view "+usedProfile+" team-a" || got[fresh] != "edit "+usedProfile+" * hashed groups-hashed" {
		t.Fatalf("rows = %v, %v", got, rows.Err())
	}
	var held []string
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.array_agg(profile_public_id::TEXT ORDER BY profile_public_id)
FROM mesh.policy_release_kubernetes_profile WHERE policy_release_id = $1`, current).Scan(&held); err != nil ||
		!slices.Equal(held, []string{usedProfile, unusedProfile}) {
		t.Fatalf("profiles of the release = %v, %v", held, err)
	}

	// A Core before K2 reads groups only from rules without a profile.
	must("scope", `SELECT pg_catalog.set_config('mesh.workspace_id', '103', TRUE),
    pg_catalog.set_config('mesh.network_id', '203', TRUE)`)
	must("plain republished", insert, plain, current, revision, users, clusterGroup, view)
	var loaded []string
	if err := tx.QueryRow(ctx, `SELECT COALESCE(pg_catalog.array_agg(access_rule_public_id::TEXT
    ORDER BY access_rule_public_id), '{}')
FROM mesh_ops.load_map_network_kubernetes_rule_groups_v1($1)
WHERE access_rule_public_id = ANY($2::UUID[])`, revision, []string{heldV3, heldV2, plain, fresh}).Scan(&loaded); err != nil ||
		!slices.Equal(loaded, []string{plain}) {
		t.Fatalf("an old Core's map reader = %v, %v", loaded, err)
	}

	// Content and pins never change.
	refused("changing a content", "immutable security evidence", `UPDATE mesh.kubernetes_access_profile_content
SET name = 'other' WHERE workspace_id = 103 AND network_id = 203 AND content_hash = $1`, usedHash)
	refused("dropping a pin", "immutable security evidence", `DELETE FROM mesh.policy_release_kubernetes_profile
WHERE policy_release_id = $1`, previous)
}

// assertKubernetesRuleProfileWriters republishes through the writers a Core
// before K2 calls (review d1 M4): attach_policy_group_rules_v3 keeps a
// profiled rule's profile and the release's unused profile even with the
// profiles flag left on before it, and attach_policy_group_rules_v2, one
// release later, keeps them again.
func assertKubernetesRuleProfileWriters(ctx context.Context, t *testing.T, admin *pgx.Conn, group devicegroup.ID) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	exec := func(name, statement string, arguments ...any) {
		t.Helper()
		if _, err := tx.Exec(ctx, statement, arguments...); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	const (
		usedProfile   = "01890f00-0000-7000-8000-00000000cd01"
		unusedProfile = "01890f00-0000-7000-8000-00000000cd02"
		profiled      = "01890f00-0000-7000-8000-00000000cd11"
	)
	usedHash, unusedHash := bytes.Repeat([]byte{0xb1}, 32), bytes.Repeat([]byte{0xb2}, 32)
	exec("change id", `SELECT pg_catalog.set_config('mesh.change_public_id', pg_catalog.uuidv7()::TEXT, TRUE)`)
	var current, revision, users int64
	var usersPublic string
	if err := tx.QueryRow(ctx, `SELECT release.id, release.policy_revision FROM mesh.policy_release AS release
WHERE release.workspace_id = 103 AND release.network_id = 203 AND release.state = 'active'`).Scan(
		&current, &revision); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `INSERT INTO mesh.device_group (public_id, deployment_id, workspace_id, network_id,
    name, name_key, created_at, updated_at)
SELECT pg_catalog.uuidv7(), workspace.deployment_id, 103, 203, 'k2-writers', 'k2-writers', pg_catalog.now(),
    pg_catalog.now()
FROM mesh.workspace AS workspace WHERE workspace.id = 103 RETURNING id, public_id::TEXT`).Scan(
		&users, &usersPublic); err != nil {
		t.Fatal(err)
	}
	// The active release, as a Core that hashes profiles left it.
	exec("replica role", `SET LOCAL session_replication_role = replica`)
	for _, profile := range []struct {
		id   string
		hash []byte
	}{{usedProfile, usedHash}, {unusedProfile, unusedHash}} {
		exec("content", `INSERT INTO mesh.kubernetes_access_profile_content (deployment_id, workspace_id, network_id,
    content_hash, name, rules, created_at)
SELECT workspace.deployment_id, 103, 203, $1, 'p' || pg_catalog.left(pg_catalog.encode($1, 'hex'), 8),
    '{"format":1}'::JSONB, pg_catalog.now()
FROM mesh.workspace AS workspace WHERE workspace.id = 103`, profile.hash)
		exec("held", `INSERT INTO mesh.policy_release_kubernetes_profile (workspace_id, network_id, policy_release_id,
    policy_revision, profile_public_id, content_hash, description, created_at)
VALUES (103, 203, $1, $2, $3::UUID, $4, '', pg_catalog.now())`, current, revision, profile.id, profile.hash)
	}
	var clusterGroup int64
	if err := tx.QueryRow(ctx, `SELECT id FROM mesh.device_group WHERE public_id = $1::UUID`,
		group.String()).Scan(&clusterGroup); err != nil {
		t.Fatal(err)
	}
	exec("profiled rule", `INSERT INTO mesh.compiled_policy_group_rule (public_id, access_rule_public_id,
    workspace_id, network_id, policy_release_id, policy_revision, source_device_group_id,
    destination_device_group_id, protocol, destination_ports, kubernetes_groups, kubernetes_profile_public_id,
    kubernetes_profile_hash, kubernetes_namespaces, kubernetes_cluster_part, kubernetes_mode, created_at)
VALUES (pg_catalog.uuidv7(), $1::UUID, 103, 203, $2, $3, $4, $5, 'tcp', '{[443,444)}', '{view}', $6::UUID, $7,
    '{team-a}', FALSE, 'enforce', pg_catalog.now())`, profiled, current, revision, users, clusterGroup, usedProfile,
		usedHash)
	exec("origin role", `SET LOCAL session_replication_role = origin`)
	exec("scope", `SELECT pg_catalog.set_config('mesh.workspace_id', '103', TRUE),
    pg_catalog.set_config('mesh.network_id', '203', TRUE)`)
	// release supersedes the active release with a new one, published now.
	release := func() string {
		t.Helper()
		exec("change id", `SELECT pg_catalog.set_config('mesh.change_public_id', pg_catalog.uuidv7()::TEXT, TRUE)`)
		exec("supersede", `UPDATE mesh.policy_release SET state = 'superseded', superseded_at = pg_catalog.now(),
    version = version + 1
WHERE workspace_id = 103 AND network_id = 203 AND state = 'active'`)
		var public string
		if err := tx.QueryRow(ctx, `INSERT INTO mesh.policy_release (public_id, workspace_id, network_id,
    policy_revision, semantic_hash, compiler_format_version, state)
SELECT pg_catalog.uuidv7(), 103, 203, pg_catalog.max(policy_revision) + 1, pg_catalog.sha256('k2'::BYTEA), 1,
    'active'
FROM mesh.policy_release WHERE workspace_id = 103 AND network_id = 203
RETURNING public_id::TEXT`).Scan(&public); err != nil {
			t.Fatal(err)
		}
		return public
	}
	rules := func(groups bool) string {
		rule := `{"projection_public_id":"` + "%s" + `","access_rule_public_id":"` + profiled +
			`","source_device_group_public_id":"` + usersPublic + `","destination_device_group_public_id":"` +
			group.String() + `","protocol":"tcp","port_range_first":[443],"port_range_last":[443]`
		if groups {
			rule += `,"kubernetes_groups":["view"]`
		}
		return rule + "}"
	}
	attach := func(function string, groups bool) {
		t.Helper()
		public := release()
		var projection string
		if err := tx.QueryRow(ctx, `SELECT pg_catalog.uuidv7()::TEXT`).Scan(&projection); err != nil {
			t.Fatal(err)
		}
		payload := "[" + strings.Replace(rules(groups), "%s", projection, 1) + "]"
		exec(function, `SELECT mesh_ops.`+function+`($1::UUID, pg_catalog.now(), $2::JSONB)`, public, payload)
		var profile string
		var hashed bool
		var held []string
		if err := tx.QueryRow(ctx, `SELECT rule.kubernetes_profile_public_id::TEXT, rule.kubernetes_profile_hashed,
    (SELECT pg_catalog.array_agg(set.profile_public_id::TEXT ORDER BY set.profile_public_id)
     FROM mesh.policy_release_kubernetes_profile AS set WHERE set.policy_release_id = rule.policy_release_id)
FROM mesh.compiled_policy_group_rule AS rule JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id
WHERE release.public_id = $1::UUID AND rule.access_rule_public_id = $2::UUID`, public, profiled).Scan(
			&profile, &hashed, &held); err != nil {
			t.Fatalf("%s: read back: %v", function, err)
		}
		if profile != usedProfile || hashed || !slices.Equal(held, []string{usedProfile, unusedProfile}) {
			t.Fatalf("%s: profile %s, hashed %v, release holds %v", function, profile, hashed, held)
		}
	}
	// A flag left on earlier in the transaction changes nothing.
	exec("stray flag", `SELECT pg_catalog.set_config('mesh.kubernetes_profiles_aware', 'on', TRUE)`)
	attach("attach_policy_group_rules_v3", true)
	attach("attach_policy_group_rules_v2", false)
}
