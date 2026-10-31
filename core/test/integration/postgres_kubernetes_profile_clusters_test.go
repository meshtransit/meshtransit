//go:build integration

package integration

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/shared/kubeprofile"
)

// assertKubernetesProfileClusters qualifies schema 264 (K2h §32): a Core
// that knows clusters binds each set to its cluster for good, and a set of
// one name may be in two clusters; a rule applies only a set of its cluster
// (MTP09) and a set never changes cluster (MTP10), nor binds first to a
// deleted cluster; an older Core's set rows take the bound cluster; maps
// leave out a rule of another cluster's set and read one content once.
func assertKubernetesProfileClusters(ctx context.Context, t *testing.T, admin *pgx.Conn, group devicegroup.ID,
	owner accountsession.Session) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	exec := func(statement string, arguments ...any) error {
		if _, err := tx.Exec(ctx, `SAVEPOINT profile_clusters`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, statement, arguments...); err != nil {
			if _, rollbackErr := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT profile_clusters`); rollbackErr != nil {
				t.Fatal(rollbackErr)
			}
			return err
		}
		if _, err := tx.Exec(ctx, `RELEASE SAVEPOINT profile_clusters`); err != nil {
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
	scalar := func(name, statement string, target any, arguments ...any) {
		t.Helper()
		if err := tx.QueryRow(ctx, statement, arguments...).Scan(target); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	must("scope", `SELECT pg_catalog.set_config('mesh.workspace_id', '103', TRUE),
    pg_catalog.set_config('mesh.network_id', '203', TRUE)`)

	// The fixture's cluster C and its group; a second cluster D with its
	// group, and a deleted cluster, cloned without triggers.
	var clusterC int64
	var publicC string
	if err := tx.QueryRow(ctx, `SELECT device_group.kubernetes_cluster_id, cluster.public_id::TEXT
FROM mesh.device_group AS device_group
JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = device_group.kubernetes_cluster_id
WHERE device_group.public_id = $1::UUID`, group.String()).Scan(&clusterC, &publicC); err != nil {
		t.Fatal(err)
	}
	must("replica role", `SET LOCAL session_replication_role = replica`)
	clone := func(name, state string) (int64, string) {
		t.Helper()
		var id int64
		var public string
		if err := tx.QueryRow(ctx, `INSERT INTO mesh.kubernetes_cluster OVERRIDING SYSTEM VALUE
SELECT (pg_catalog.jsonb_populate_record(NULL::mesh.kubernetes_cluster, pg_catalog.to_jsonb(cluster)
    || pg_catalog.jsonb_build_object('id', (SELECT pg_catalog.max(id) + 1000 FROM mesh.kubernetes_cluster),
       'public_id', pg_catalog.uuidv7(), 'name', $2::TEXT, 'state', $3::TEXT,
       'deleted_at', CASE WHEN $3::TEXT = 'deleted' THEN pg_catalog.now() END))).*
FROM mesh.kubernetes_cluster AS cluster WHERE cluster.id = $1
RETURNING id, public_id::TEXT`, clusterC, name, state).Scan(&id, &public); err != nil {
			t.Fatalf("clone %s: %v", name, err)
		}
		return id, public
	}
	clusterD, publicD := clone("k2h-other", "active")
	_, publicGone := clone("k2h-gone", "deleted")
	var groupD string
	if err := tx.QueryRow(ctx, `INSERT INTO mesh.device_group OVERRIDING SYSTEM VALUE
SELECT (pg_catalog.jsonb_populate_record(NULL::mesh.device_group, pg_catalog.to_jsonb(device_group)
    || pg_catalog.jsonb_build_object('id', (SELECT pg_catalog.max(id) + 1000 FROM mesh.device_group),
       'public_id', pg_catalog.uuidv7(), 'name', 'k2h-other', 'name_key', 'k2h-other',
       'kubernetes_cluster_id', $2::BIGINT))).*
FROM mesh.device_group AS device_group WHERE device_group.public_id = $1::UUID
RETURNING public_id::TEXT`, group.String(), clusterD).Scan(&groupD); err != nil {
		t.Fatal(err)
	}
	must("origin role", `SET LOCAL session_replication_role = origin`)

	var usersPublic string
	must("change id", `SELECT pg_catalog.set_config('mesh.change_public_id', pg_catalog.uuidv7()::TEXT, TRUE)`)
	scalar("users", `INSERT INTO mesh.device_group (public_id, deployment_id, workspace_id, network_id,
    name, name_key, created_at, updated_at)
SELECT pg_catalog.uuidv7(), workspace.deployment_id, 103, 203, 'k2h-users', 'k2h-users', pg_catalog.now(),
    pg_catalog.now()
FROM mesh.workspace AS workspace WHERE workspace.id = 103 RETURNING public_id::TEXT`, &usersPublic)
	release := func() (string, int64) {
		t.Helper()
		must("change id", `SELECT pg_catalog.set_config('mesh.change_public_id', pg_catalog.uuidv7()::TEXT, TRUE)`)
		must("supersede", `UPDATE mesh.policy_release SET state = 'superseded', superseded_at = pg_catalog.now(),
    version = version + 1
WHERE workspace_id = 103 AND network_id = 203 AND state = 'active'`)
		var public string
		var revision int64
		if err := tx.QueryRow(ctx, `INSERT INTO mesh.policy_release (public_id, workspace_id, network_id,
    policy_revision, semantic_hash, compiler_format_version, state)
SELECT pg_catalog.uuidv7(), 103, 203, pg_catalog.max(policy_revision) + 1, pg_catalog.sha256('k2h'::BYTEA), 1,
    'active'
FROM mesh.policy_release WHERE workspace_id = 103 AND network_id = 203
RETURNING public_id::TEXT, policy_revision`).Scan(&public, &revision); err != nil {
			t.Fatal(err)
		}
		return public, revision
	}
	type setPayload struct {
		ID          string         `json:"profile_public_id"`
		Hash        string         `json:"content_hash"`
		Name        string         `json:"name"`
		Rules       map[string]any `json:"rules"`
		Description string         `json:"description"`
		Cluster     *string        `json:"cluster_id"`
		CopiedFrom  *string        `json:"copied_from,omitempty"`
	}
	set := func(id, name string, cluster *string) setPayload {
		t.Helper()
		rules := []kubeprofile.Rule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}}
		hash, err := kubeprofile.ContentHash(kubeprofile.Profile{Name: name, Namespaced: rules})
		if err != nil {
			t.Fatal(err)
		}
		return setPayload{ID: id, Hash: hex.EncodeToString(hash[:]), Name: name,
			Rules: map[string]any{"namespaced": rules}, Cluster: cluster}
	}
	encode := func(value any) string {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	}
	rule := func(id, destination string, pinned setPayload) map[string]any {
		var projection string
		scalar("projection", `SELECT pg_catalog.uuidv7()::TEXT`, &projection)
		return map[string]any{"projection_public_id": projection, "access_rule_public_id": id,
			"source_device_group_public_id": usersPublic, "destination_device_group_public_id": destination,
			"protocol": "tcp", "port_range_first": []int{443}, "port_range_last": []int{443},
			"kubernetes_groups": []string{"view"}, "kubernetes_profile_public_id": pinned.ID,
			"kubernetes_profile_hash": pinned.Hash, "kubernetes_namespaces": []string{"team-a"},
			"kubernetes_cluster_part": false, "kubernetes_mode": "enforce"}
	}
	const (
		attachV2 = `SELECT mesh_ops.attach_policy_kubernetes_profiles_v2($1::UUID, pg_catalog.now(), $2::JSONB)`
		attachV1 = `SELECT mesh_ops.attach_policy_kubernetes_profiles_v1($1::UUID, pg_catalog.now(), $2::JSONB)`
		rulesV4  = `SELECT mesh_ops.attach_policy_group_rules_v4($1::UUID, pg_catalog.now(), $2::JSONB)`
		rulesV3  = `SELECT mesh_ops.attach_policy_group_rules_v3($1::UUID, pg_catalog.now(), $2::JSONB)`
		devID    = "01890f00-0000-7000-8000-00000000cf01"
		twinID   = "01890f00-0000-7000-8000-00000000cf02"
		ruleC    = "01890f00-0000-7000-8000-00000000cf11"
		ruleD    = "01890f00-0000-7000-8000-00000000cf12"
	)
	developer, twin := set(devID, "developer", &publicC), set(twinID, "developer", &publicD)
	origin := devID
	twin.CopiedFrom = &origin

	// One name in two clusters, one content: bound for good, hashed.
	first, revision := release()
	must("attach sets of two clusters", attachV2, first, encode([]setPayload{developer, twin}))
	must("rules of each cluster", rulesV4, first,
		encode([]map[string]any{rule(ruleC, group.String(), developer), rule(ruleD, groupD, twin)}))
	var bound int
	scalar("bindings", `SELECT pg_catalog.count(*) FROM mesh.kubernetes_profile_binding
WHERE profile_public_id = ANY($1::UUID[])
  AND kubernetes_cluster_id = CASE profile_public_id WHEN $2::UUID THEN $3::BIGINT ELSE $4::BIGINT END`,
		&bound, []string{devID, twinID}, devID, clusterC, clusterD)
	var flag string
	scalar("flag off after", `SELECT pg_catalog.current_setting('mesh.kubernetes_profiles_clustered_aware', TRUE)`,
		&flag)
	if bound != 2 || flag != "off" {
		t.Fatalf("bindings = %d, flag %q", bound, flag)
	}
	refused("a binding changes", "immutable", `UPDATE mesh.kubernetes_profile_binding
SET kubernetes_cluster_id = $1 WHERE profile_public_id = $2::UUID`, clusterD, devID)
	refused("a binding goes", "immutable", `DELETE FROM mesh.kubernetes_profile_binding
WHERE profile_public_id = $1::UUID`, devID)

	var workspacePublic, networkPublic string
	if err := tx.QueryRow(ctx, `SELECT workspace.public_id::TEXT, network.public_id::TEXT FROM mesh.network AS network
JOIN mesh.workspace AS workspace ON workspace.id = network.workspace_id WHERE network.id = 203`).Scan(
		&workspacePublic, &networkPublic); err != nil {
		t.Fatal(err)
	}
	read := func(revision int64) string {
		t.Helper()
		var encoded *string
		if err := tx.QueryRow(ctx, `SELECT mesh_ops.read_policy_kubernetes_access_v2(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID, $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::UUID, $12::BIGINT, $13::TIMESTAMPTZ)::TEXT`,
			owner.ID().String(), owner.DeploymentID().String(), owner.PrincipalID().String(),
			owner.IdentitySubjectID().String(), owner.Version(), owner.PrincipalAuthorityGeneration(),
			owner.AccountSessionGeneration(), owner.ProviderGeneration(), owner.DeploymentRecoveryEpoch(),
			workspacePublic, networkPublic, revision, time.Now().UTC()).Scan(&encoded); err != nil || encoded == nil {
			t.Fatalf("access read = %v, %v", encoded, err)
		}
		return *encoded
	}
	if encoded := read(revision); !strings.Contains(encoded, `"clusters_hashed": true`) ||
		!strings.Contains(encoded, `"cluster_id": "`+publicC+`"`) ||
		!strings.Contains(encoded, `"cluster_id": "`+publicD+`"`) {
		t.Fatalf("access read = %s", encoded)
	}
	// Maps: one content once, by its smallest ID; both rules.
	var mapSets []string
	scalar("map sets", `SELECT pg_catalog.array_agg(profile_public_id::TEXT)
FROM mesh_ops.load_map_network_kubernetes_profiles_v1($1)`, &mapSets, revision)
	var mapRules []string
	scalar("map rules", `SELECT pg_catalog.array_agg(access_rule_public_id::TEXT ORDER BY access_rule_public_id)
FROM mesh_ops.load_map_network_kubernetes_rule_access_v1($1)
WHERE access_rule_public_id = ANY($2::UUID[])`, &mapRules, revision, []string{ruleC, ruleD})
	if !slices.Equal(mapSets, []string{devID}) || !slices.Equal(mapRules, []string{ruleC, ruleD}) {
		t.Fatalf("map sets %v, rules %v", mapSets, mapRules)
	}

	// An older Core republishing carries the sets with their clusters, not
	// hashed; one re-adding a bound ID gets its cluster.
	carried, carriedRevision := release()
	plain := func(id, destination string) map[string]any {
		item := rule(id, destination, developer)
		for _, key := range []string{"kubernetes_profile_public_id", "kubernetes_profile_hash",
			"kubernetes_namespaces", "kubernetes_cluster_part", "kubernetes_mode"} {
			delete(item, key)
		}
		return item
	}
	must("an older Core republishing", rulesV3, carried,
		encode([]map[string]any{plain(ruleC, group.String()), plain(ruleD, groupD)}))
	var carriedClusters int
	scalar("carried clusters", `SELECT pg_catalog.count(*) FROM mesh.policy_release_kubernetes_profile AS held
JOIN mesh.policy_release AS release ON release.id = held.policy_release_id
WHERE release.public_id = $1::UUID AND NOT held.cluster_hashed
  AND held.kubernetes_cluster_id = CASE held.profile_public_id WHEN $2::UUID THEN $3::BIGINT ELSE $4::BIGINT END
  AND held.copied_from IS NOT DISTINCT FROM CASE held.profile_public_id WHEN $5::UUID THEN $2::UUID END`,
		&carriedClusters, carried, devID, clusterC, clusterD, twinID)
	if encoded := read(carriedRevision); carriedClusters != 2 || !strings.Contains(encoded, `"clusters_hashed": false`) {
		t.Fatalf("carried = %d, %s", carriedClusters, encoded)
	}
	older, _ := release()
	must("an older Core's writer", attachV1, older, encode([]setPayload{set(devID, "developer", nil)}))
	var olderCluster int64
	scalar("older writer cluster", `SELECT held.kubernetes_cluster_id FROM mesh.policy_release_kubernetes_profile AS held
JOIN mesh.policy_release AS release ON release.id = held.policy_release_id
WHERE release.public_id = $1::UUID AND held.profile_public_id = $2::UUID`, &olderCluster, older, devID)
	if olderCluster != clusterC {
		t.Fatalf("older writer bound %d, want %d", olderCluster, clusterC)
	}

	// A set keeps its cluster; a first binding needs an active cluster; a
	// rule applies only a set of its cluster.
	moved, _ := release()
	refused("a set moved to another cluster", "MTP10", attachV2, moved,
		encode([]setPayload{set(devID, "developer", &publicD)}))
	refused("a bound set made every cluster's", "MTP10", attachV2, moved,
		encode([]setPayload{set(devID, "developer", nil)}))
	gone := "01890f00-0000-7000-8000-00000000cf03"
	refused("a first binding to a deleted cluster", "MTP10", attachV2, moved,
		encode([]setPayload{set(gone, "gone", &publicGone)}))
	refused("a cluster of no Network", "MTP10", attachV2, moved,
		encode([]setPayload{set(gone, "gone", &usersPublic)}))
	refused("one name twice in a cluster", "23514", attachV2, moved,
		encode([]setPayload{developer, set(gone, "developer", &publicC)}))
	refused("a set of every cluster named like another", "23514", attachV2, moved,
		encode([]setPayload{developer, set(gone, "developer", nil)}))
	must("sets of two clusters again", attachV2, moved, encode([]setPayload{developer, twin}))
	refused("a rule applying another cluster's set", "MTP09", rulesV4, moved,
		encode([]map[string]any{rule(ruleC, group.String(), twin)}))
	// A Core of K2d (sets through _v1, which takes the bound cluster) is
	// refused the same.
	older2, _ := release()
	must("an older Core's sets", attachV1, older2, encode([]setPayload{set(twinID, "developer", nil)}))
	refused("an older Core's rule applying another cluster's set", "MTP09", rulesV4, older2,
		encode([]map[string]any{rule(ruleC, group.String(), twin)}))

	// A rule that applies another cluster's set (written past the checks)
	// grants nothing: the map leaves its whole row out.
	bypass, bypassRevision := release()
	must("sets", attachV2, bypass, encode([]setPayload{developer, twin}))
	must("replica role", `SET LOCAL session_replication_role = replica`)
	must("a rule past the checks", rulesV4, bypass, encode([]map[string]any{rule(ruleC, group.String(), twin)}))
	must("origin role", `SET LOCAL session_replication_role = origin`)
	var leftOut int
	scalar("map rule left out", `SELECT pg_catalog.count(*)
FROM mesh_ops.load_map_network_kubernetes_rule_access_v1($1) WHERE access_rule_public_id = $2::UUID`,
		&leftOut, bypassRevision, ruleC)
	if leftOut != 0 {
		t.Fatalf("a rule of another cluster's set reached the map")
	}
}
