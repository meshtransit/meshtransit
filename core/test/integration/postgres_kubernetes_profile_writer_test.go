//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/shared/kubeprofile"
)

// assertKubernetesProfileWriter qualifies schema 259 (K2 §24 d2): a Core
// that hashes profiles attaches a release's profiles, content by hash, then
// its rules with their profiles through attach_policy_group_rules_v4, both
// marked hashed and both flags off again after; the access read returns
// them; a hash that names other content, an ID of another Network, or
// profiles attached twice are refused.
func assertKubernetesProfileWriter(ctx context.Context, t *testing.T, admin *pgx.Conn, group devicegroup.ID,
	owner accountsession.Session) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	exec := func(statement string, arguments ...any) error {
		if _, err := tx.Exec(ctx, `SAVEPOINT profile_writer`); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, statement, arguments...); err != nil {
			if _, rollbackErr := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT profile_writer`); rollbackErr != nil {
				t.Fatal(rollbackErr)
			}
			return err
		}
		if _, err := tx.Exec(ctx, `RELEASE SAVEPOINT profile_writer`); err != nil {
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
	must("scope", `SELECT pg_catalog.set_config('mesh.workspace_id', '103', TRUE),
    pg_catalog.set_config('mesh.network_id', '203', TRUE)`)
	var usersPublic string
	must("change id", `SELECT pg_catalog.set_config('mesh.change_public_id', pg_catalog.uuidv7()::TEXT, TRUE)`)
	if err := tx.QueryRow(ctx, `INSERT INTO mesh.device_group (public_id, deployment_id, workspace_id, network_id,
    name, name_key, created_at, updated_at)
SELECT pg_catalog.uuidv7(), workspace.deployment_id, 103, 203, 'k2-v4', 'k2-v4', pg_catalog.now(), pg_catalog.now()
FROM mesh.workspace AS workspace WHERE workspace.id = 103 RETURNING public_id::TEXT`).Scan(&usersPublic); err != nil {
		t.Fatal(err)
	}
	release := func() string {
		t.Helper()
		must("change id", `SELECT pg_catalog.set_config('mesh.change_public_id', pg_catalog.uuidv7()::TEXT, TRUE)`)
		must("supersede", `UPDATE mesh.policy_release SET state = 'superseded', superseded_at = pg_catalog.now(),
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
	type profilePayload struct {
		ID          string         `json:"profile_public_id"`
		Hash        string         `json:"content_hash"`
		Name        string         `json:"name"`
		Rules       map[string]any `json:"rules"`
		Description string         `json:"description"`
	}
	profile := func(id, name string, verbs ...string) profilePayload {
		t.Helper()
		rules := []kubeprofile.Rule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: verbs}}
		hash, err := kubeprofile.ContentHash(kubeprofile.Profile{Name: name, Namespaced: rules})
		if err != nil {
			t.Fatal(err)
		}
		return profilePayload{ID: id, Hash: hex.EncodeToString(hash[:]), Name: name,
			Rules: map[string]any{"namespaced": rules}, Description: "pods of " + name}
	}
	encode := func(value any) string {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	}
	const (
		developerID = "01890f00-0000-7000-8000-00000000ce01"
		auditorID   = "01890f00-0000-7000-8000-00000000ce02"
		profiledID  = "01890f00-0000-7000-8000-00000000ce11"
		fullID      = "01890f00-0000-7000-8000-00000000ce12"
	)
	developer, auditor := profile(developerID, "developer", "get"), profile(auditorID, "auditor", "list")
	public := release()
	const attachProfiles = `SELECT mesh_ops.attach_policy_kubernetes_profiles_v1($1::UUID, pg_catalog.now(), $2::JSONB)`
	var attached int
	if err := tx.QueryRow(ctx, attachProfiles, public, encode([]profilePayload{developer, auditor})).Scan(
		&attached); err != nil || attached != 2 {
		t.Fatalf("attach profiles = %d, %v", attached, err)
	}
	refused("profiles attached twice", "23514", attachProfiles, public, encode([]profilePayload{developer}))
	until := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Millisecond)
	rule := func(id string, groups []string, access map[string]any) map[string]any {
		var projection string
		if err := tx.QueryRow(ctx, `SELECT pg_catalog.uuidv7()::TEXT`).Scan(&projection); err != nil {
			t.Fatal(err)
		}
		item := map[string]any{"projection_public_id": projection, "access_rule_public_id": id,
			"source_device_group_public_id": usersPublic, "destination_device_group_public_id": group.String(),
			"protocol": "tcp", "port_range_first": []int{443}, "port_range_last": []int{443},
			"kubernetes_groups": groups}
		for key, value := range access {
			item[key] = value
		}
		return item
	}
	rules := encode([]map[string]any{
		rule(profiledID, []string{"view"}, map[string]any{"kubernetes_profile_public_id": developerID,
			"kubernetes_profile_hash": developer.Hash, "kubernetes_namespaces": []string{"team-a"},
			"kubernetes_cluster_part": false, "kubernetes_mode": "report", "kubernetes_report_until": until}),
		rule(fullID, []string{"edit"}, nil),
	})
	if err := tx.QueryRow(ctx, `SELECT mesh_ops.attach_policy_group_rules_v4($1::UUID, pg_catalog.now(), $2::JSONB)`,
		public, rules).Scan(&attached); err != nil || attached != 2 {
		t.Fatalf("attach rules = %d, %v", attached, err)
	}
	var groupsFlag, profilesFlag string
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.current_setting('mesh.kubernetes_groups_aware', TRUE),
    pg_catalog.current_setting('mesh.kubernetes_profiles_aware', TRUE)`).Scan(&groupsFlag, &profilesFlag); err != nil ||
		groupsFlag != "off" || profilesFlag != "off" {
		t.Fatalf("flags after attach = %q %q, %v", groupsFlag, profilesFlag, err)
	}
	var mode string
	var hashed, groupsHashed bool
	var reportUntil time.Time
	if err := tx.QueryRow(ctx, `SELECT rule.kubernetes_mode, rule.kubernetes_profile_hashed,
    rule.kubernetes_groups_hashed, rule.kubernetes_report_until
FROM mesh.compiled_policy_group_rule AS rule JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id
WHERE release.public_id = $1::UUID AND rule.access_rule_public_id = $2::UUID`, public, profiledID).Scan(
		&mode, &hashed, &groupsHashed, &reportUntil); err != nil || mode != "report" || !hashed || !groupsHashed ||
		!reportUntil.Equal(until) {
		t.Fatalf("profiled rule = %s %v %v %v, %v", mode, hashed, groupsHashed, reportUntil, err)
	}

	// The access read, as the compiler, catalog and simulation see it.
	var revision int64
	if err := tx.QueryRow(ctx, `SELECT policy_revision FROM mesh.policy_release WHERE public_id = $1::UUID`,
		public).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	var encoded *string
	var workspacePublic, networkPublic string
	if err := tx.QueryRow(ctx, `SELECT workspace.public_id::TEXT, network.public_id::TEXT FROM mesh.network AS network
JOIN mesh.workspace AS workspace ON workspace.id = network.workspace_id WHERE network.id = 203`).Scan(
		&workspacePublic, &networkPublic); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `SELECT mesh_ops.read_policy_kubernetes_access_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID, $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::UUID, $12::BIGINT, $13::TIMESTAMPTZ)::TEXT`,
		owner.ID().String(), owner.DeploymentID().String(), owner.PrincipalID().String(),
		owner.IdentitySubjectID().String(), owner.Version(), owner.PrincipalAuthorityGeneration(),
		owner.AccountSessionGeneration(), owner.ProviderGeneration(), owner.DeploymentRecoveryEpoch(),
		workspacePublic, networkPublic, revision, time.Now().UTC()).Scan(&encoded); err != nil || encoded == nil {
		t.Fatalf("access read = %v, %v", encoded, err)
	}
	var read struct {
		GroupsHashed   bool `json:"groups_hashed"`
		ProfilesHashed bool `json:"profiles_hashed"`
		Rules          []struct {
			ID      string `json:"id"`
			Profile *struct {
				ID            string   `json:"id"`
				Hash          string   `json:"hash"`
				Namespaces    []string `json:"namespaces"`
				Mode          string   `json:"mode"`
				ReportUntilMS *int64   `json:"report_until_ms"`
			} `json:"profile"`
		} `json:"rules"`
		Profiles []profilePayload `json:"profiles"`
	}
	if err := json.Unmarshal([]byte(*encoded), &read); err != nil {
		t.Fatal(err)
	}
	profiled := map[string]string{}
	for _, item := range read.Rules {
		if item.Profile != nil && item.Profile.ReportUntilMS != nil {
			profiled[item.ID] = item.Profile.ID + " " + item.Profile.Hash + " " + item.Profile.Mode
			if *item.Profile.ReportUntilMS != until.UnixMilli() {
				t.Errorf("report deadline = %d, want %d", *item.Profile.ReportUntilMS, until.UnixMilli())
			}
		}
	}
	if !read.GroupsHashed || !read.ProfilesHashed || len(read.Profiles) != 2 ||
		profiled[profiledID] != developerID+" "+developer.Hash+" report" || len(profiled) != 1 {
		t.Fatalf("access read = %s", *encoded)
	}

	// The map readers of schema 260: every rule to the cluster with its
	// profile, and only the profiles a rule pins (auditor is unused).
	var mapRules, mapProfiled int
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.count(*), pg_catalog.count(profile_public_id)
FROM mesh_ops.load_map_network_kubernetes_rule_access_v1($1)
WHERE access_rule_public_id = ANY($2::UUID[])`, revision, []string{profiledID, fullID}).Scan(
		&mapRules, &mapProfiled); err != nil || mapRules != 2 || mapProfiled != 1 {
		t.Fatalf("map rules = %d with %d profiles, %v", mapRules, mapProfiled, err)
	}
	var mapProfiles []string
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.array_agg(profile_public_id::TEXT || ':' || name)
FROM mesh_ops.load_map_network_kubernetes_profiles_v1($1)`, revision).Scan(&mapProfiles); err != nil ||
		len(mapProfiles) != 1 || mapProfiles[0] != developerID+":developer" {
		t.Fatalf("map profiles = %v, %v", mapProfiles, err)
	}

	// A Core before d2 republishes through _v3 (review d2 M3): the profile
	// and the release's profiles are carried, no longer hashed.
	older := release()
	plainRules := encode([]map[string]any{rule(profiledID, []string{"view"}, nil), rule(fullID, []string{"edit"}, nil)})
	if err := tx.QueryRow(ctx, `SELECT mesh_ops.attach_policy_group_rules_v3($1::UUID, pg_catalog.now(), $2::JSONB)`,
		older, plainRules).Scan(&attached); err != nil || attached != 2 {
		t.Fatalf("an older Core republishing = %d, %v", attached, err)
	}
	var carried string
	var carriedHashed bool
	var heldProfiles int
	if err := tx.QueryRow(ctx, `SELECT rule.kubernetes_profile_public_id::TEXT, rule.kubernetes_profile_hashed,
    (SELECT pg_catalog.count(*) FROM mesh.policy_release_kubernetes_profile AS held
     WHERE held.policy_release_id = rule.policy_release_id)
FROM mesh.compiled_policy_group_rule AS rule JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id
WHERE release.public_id = $1::UUID AND rule.access_rule_public_id = $2::UUID`, older, profiledID).Scan(
		&carried, &carriedHashed, &heldProfiles); err != nil || carried != developerID || carriedHashed ||
		heldProfiles != 2 {
		t.Fatalf("carried = %s %v %d, %v", carried, carriedHashed, heldProfiles, err)
	}
	if err := tx.QueryRow(ctx, `SELECT policy_revision FROM mesh.policy_release WHERE public_id = $1::UUID`,
		older).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `SELECT mesh_ops.read_policy_kubernetes_access_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID, $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::UUID, $12::BIGINT, $13::TIMESTAMPTZ)::TEXT`,
		owner.ID().String(), owner.DeploymentID().String(), owner.PrincipalID().String(),
		owner.IdentitySubjectID().String(), owner.Version(), owner.PrincipalAuthorityGeneration(),
		owner.AccountSessionGeneration(), owner.ProviderGeneration(), owner.DeploymentRecoveryEpoch(),
		workspacePublic, networkPublic, revision, time.Now().UTC()).Scan(&encoded); err != nil || encoded == nil ||
		!strings.Contains(*encoded, `"groups_hashed": true`) || !strings.Contains(*encoded, `"profiles_hashed": false`) {
		t.Fatalf("carried read = %v, %v", encoded, err)
	}

	// _v4 pins only profiles of the release, within 14 days.
	pinned := release()
	if err := tx.QueryRow(ctx, attachProfiles, pinned, encode([]profilePayload{developer})).Scan(&attached); err != nil {
		t.Fatal(err)
	}
	const attachV4 = `SELECT mesh_ops.attach_policy_group_rules_v4($1::UUID, pg_catalog.now(), $2::JSONB)`
	pin := func(id, hash, mode string, until any) string {
		access := map[string]any{"kubernetes_profile_public_id": id, "kubernetes_profile_hash": hash,
			"kubernetes_namespaces": []string{"team-a"}, "kubernetes_cluster_part": false, "kubernetes_mode": mode}
		if until != nil {
			access["kubernetes_report_until"] = until
		}
		return encode([]map[string]any{rule(profiledID, []string{"view"}, access)})
	}
	refused("a profile the release lacks", "23503", attachV4, pinned, pin(auditorID, auditor.Hash, "enforce", nil))
	refused("a deadline past 14 days", "23514", attachV4, pinned,
		pin(developerID, developer.Hash, "report", time.Now().Add(20*24*time.Hour).UTC()))
	refused("a hash that is not hex", "23514", attachV4, pinned, pin(developerID, "xyz", "enforce", nil))

	// A hash names one content; an ID names a profile within its Network.
	other := release()
	twisted := profile(developerID, "developer", "get", "delete")
	twisted.Hash = developer.Hash
	refused("a hash naming other content", "MTP08", attachProfiles, other, encode([]profilePayload{twisted}))
	refused("a name twice", "23514", attachProfiles, other,
		encode([]profilePayload{profile(auditorID, "developer", "get"), developer}))
	must("replica role", `SET LOCAL session_replication_role = replica`)
	foreignID := "01890f00-0000-7000-8000-00000000ce09"
	must("a profile of Network 204", `INSERT INTO mesh.policy_release_kubernetes_profile (workspace_id, network_id,
    policy_release_id, policy_revision, profile_public_id, content_hash, description, created_at)
VALUES (103, 204, -1, 1, $1::UUID, $2, '', pg_catalog.now())`, foreignID, bytes.Repeat([]byte{0xc1}, 32))
	must("origin role", `SET LOCAL session_replication_role = origin`)
	must("the same ID in another Network", attachProfiles, other,
		encode([]profilePayload{profile(foreignID, "foreign", "get")}))
}
