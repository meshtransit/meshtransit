//go:build integration

package integration

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/migrations"
)

// groupTagUpgradeSnapshot is every schema 121 catalog row, with the audit and
// outbox counts, as the upgrade must leave them.
const groupTagUpgradeSnapshot = `SELECT jsonb_build_object(
 'groups',(SELECT jsonb_agg(jsonb_build_array(id, public_id, workspace_id, name, state, version, member_count)
   ORDER BY id) FROM mesh.identity_group),
 'members',(SELECT jsonb_agg(jsonb_build_array(identity_group_id, principal_id) ORDER BY id)
   FROM mesh.identity_group_member),
 'tags',(SELECT jsonb_agg(jsonb_build_array(id, public_id, workspace_id, name, state, version) ORDER BY id)
   FROM mesh.device_tag),
 'owners',(SELECT jsonb_agg(jsonb_build_array(device_tag_id, identity_group_id, role_key) ORDER BY id)
   FROM mesh.device_tag_owner),
 'audit',(SELECT count(*) FROM mesh_audit.audit_event),
 'outbox',(SELECT count(*) FROM mesh_ops.outbox_event))::TEXT`

// assertGroupTagUpgrade qualifies schema 228 on a database that already
// holds Workspace user groups and tags. The upgrade refuses while a Device
// carries such a tag; once nothing depends on them it rewrites no catalog
// row and owes no evidence, and the rows stay without a Network, inert.
func assertGroupTagUpgrade(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	var database string
	if err := admin.QueryRow(ctx, `SELECT 'mesh_group_upgrade_'||replace(gen_random_uuid()::TEXT,'-','')`).
		Scan(&database); err != nil {
		t.Fatal(err)
	}
	quoted := pgx.Identifier{database}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+quoted+" OWNER mesh_migrator TEMPLATE template0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanupCtx, "DROP DATABASE "+quoted+" WITH (FORCE)"); err != nil {
			t.Errorf("remove group upgrade fixture: %v", err)
		}
	})
	connectionConfig := admin.Config().Copy()
	connectionConfig.Database = database
	connection, err := pgx.ConnectConfig(ctx, connectionConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close(ctx) }()
	if _, err := connection.Exec(ctx, "CREATE EXTENSION btree_gist"); err != nil {
		t.Fatal(err)
	}
	exec := func(label, sql string) error {
		t.Helper()
		if _, err := connection.Exec(ctx, "SET ROLE mesh_migrator"); err != nil {
			t.Fatal(err)
		}
		_, err := connection.Exec(ctx, sql)
		if _, resetErr := connection.Exec(ctx, "RESET ROLE"); resetErr != nil {
			t.Fatalf("%s: reset role: %v", label, resetErr)
		}
		return err
	}
	catalog := migrations.Catalog()
	for _, migration := range catalog {
		if migration.Version >= 228 {
			break
		}
		if err := exec("upgrade fixture", migration.SQL); err != nil {
			t.Fatalf("upgrade fixture migration %d: %v", migration.Version, err)
		}
	}
	seedAuthorityFixture(ctx, t, connection)
	// Schema 121 rows: an active group with a member, an active tag it owns,
	// and a deleted tag.
	seed := func(statements ...string) {
		t.Helper()
		tx, err := connection.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
			t.Fatal(err)
		}
		for _, statement := range statements {
			if _, err := tx.Exec(ctx, statement); err != nil {
				t.Fatalf("group upgrade seed: %v", err)
			}
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	seed(`INSERT INTO mesh.identity_group (id, public_id, deployment_id, workspace_id, name, name_key, member_count,
    created_at, updated_at) OVERRIDING SYSTEM VALUE
VALUES (9301, '01890f00-0000-7000-8000-000000009301', 1, 101, 'Legacy', 'legacy', 1, now(), now())`,
		`INSERT INTO mesh.identity_group_member (id, public_id, workspace_id, identity_group_id, principal_id,
    created_at) OVERRIDING SYSTEM VALUE
VALUES (9302, '01890f00-0000-7000-8000-000000009302', 101, 9301, 11, now())`,
		`INSERT INTO mesh.device_tag (id, public_id, deployment_id, workspace_id, name, created_at, updated_at)
OVERRIDING SYSTEM VALUE VALUES (9303, '01890f00-0000-7000-8000-000000009303', 1, 101, 'legacy', now(), now())`,
		`INSERT INTO mesh.device_tag_owner (id, public_id, workspace_id, device_tag_id, identity_group_id,
    created_at) OVERRIDING SYSTEM VALUE
VALUES (9304, '01890f00-0000-7000-8000-000000009304', 101, 9303, 9301, now())`,
		`INSERT INTO mesh.device_tag (id, public_id, deployment_id, workspace_id, name, state, version, created_at,
    updated_at, deleted_at) OVERRIDING SYSTEM VALUE
VALUES (9305, '01890f00-0000-7000-8000-000000009305', 1, 101, 'gone', 'deleted', 2, now(), now(), now())`,
		// A Device still carries the legacy tag.
		`INSERT INTO mesh.device_tag_assignment (id, public_id, workspace_id, network_id, device_id, device_tag_id,
    created_at) OVERRIDING SYSTEM VALUE
VALUES (9306, '01890f00-0000-7000-8000-000000009306', 101, 201, 9399, 9303, now())`)
	if err := exec("refused upgrade", catalog[227].SQL); err == nil ||
		!strings.Contains(err.Error(), "Devices carry Workspace tags") {
		t.Fatalf("schema 228 over a tagged Device: %v", err)
	}
	seed(`DELETE FROM mesh.device_tag_assignment WHERE id = 9306`)

	var before string
	if err := connection.QueryRow(ctx, groupTagUpgradeSnapshot).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err := exec("upgrade", catalog[227].SQL); err != nil {
		t.Fatalf("schema 228 over Workspace groups and tags: %v", err)
	}
	var after string
	if err := connection.QueryRow(ctx, groupTagUpgradeSnapshot).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("schema 228 rewrote catalog rows or evidence:\n before %s\n after  %s", before, after)
	}
	var withNetwork int
	if err := connection.QueryRow(ctx, `SELECT (SELECT count(*) FROM mesh.identity_group WHERE network_id IS NOT NULL)
 + (SELECT count(*) FROM mesh.device_tag WHERE network_id IS NOT NULL)`).Scan(&withNetwork); err != nil ||
		withNetwork != 0 {
		t.Fatalf("legacy rows with a Network = %d, %v", withNetwork, err)
	}
	// New rows must name a Network.
	if err := exec("network-less group", `SELECT pg_catalog.set_config('mesh.change_public_id',
 '01890f01-0000-7000-8000-000000009307', TRUE);
INSERT INTO mesh.identity_group (public_id, deployment_id, workspace_id, name, name_key, created_at, updated_at)
VALUES ('01890f00-0000-7000-8000-000000009307', 1, 101, 'New', 'new', now(), now())`); err == nil ||
		!strings.Contains(err.Error(), "in a Network") {
		t.Fatalf("a group without a Network was created: %v", err)
	}
}
