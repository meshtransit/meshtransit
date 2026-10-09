//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"meshtransit.net/core/migrations"
)

func assertTenantDisplayIdentities(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	assertDisplayIdentityCoverage(ctx, t, admin)
	var canRead, canAllocate, canProject bool
	if err := admin.QueryRow(ctx, `SELECT
    has_table_privilege('mesh_runtime','mesh_ops.tenant_display_identity','SELECT'),
    has_function_privilege('mesh_runtime','mesh_ops.assign_tenant_display_code_v1(text,uuid)','EXECUTE'),
    has_function_privilege('mesh_runtime','mesh_ops.read_console_management_scopes_v2(uuid,uuid,uuid,uuid,bigint,bigint,bigint,bigint,bigint,uuid,timestamptz,uuid,integer)','EXECUTE')`).Scan(&canRead, &canAllocate, &canProject); err != nil {
		t.Fatal(err)
	}
	if canRead || canAllocate || !canProject {
		t.Fatal("display identity runtime privileges widened")
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setIntegrationChange(ctx, t, tx, "01890f00-0000-7000-8000-000000012100")
	setIntegrationScope(ctx, t, tx, 103, 203)
	var workspaceCode, networkCode string
	if err := tx.QueryRow(ctx, `SELECT
    (SELECT display_code FROM mesh_ops.tenant_display_identity WHERE workspace_public_id='01890f00-0000-7000-8000-000000000103'),
    (SELECT display_code FROM mesh_ops.tenant_display_identity WHERE network_public_id='01890f00-0000-7000-8000-000000000203')`).Scan(&workspaceCode, &networkCode); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `UPDATE mesh.workspace SET display_name='Renamed Workspace',
    version=version+1,authority_generation=authority_generation+1,
    updated_at=pg_catalog.transaction_timestamp() WHERE id=103;
UPDATE mesh.network SET display_name='Renamed Network',version=version+1,
    authority_generation=authority_generation+1,updated_at=pg_catalog.transaction_timestamp() WHERE id=203`); err != nil {
		t.Fatal(err)
	}
	session := managementRBACAccountSessionFixture(t)
	workspaceID, _ := session.LoginWorkspaceID()
	args := ownerSessionArguments(session, workspaceID.String())
	var matched bool
	if err := tx.QueryRow(ctx, `WITH projections AS (
 SELECT mesh_ops.read_console_management_scopes_v1($1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,$7::BIGINT,$8::BIGINT,$9::BIGINT,$10::UUID,$11::TIMESTAMPTZ,NULL::UUID,100) AS old,
 mesh_ops.read_console_management_scopes_v2($1::UUID,$2::UUID,$3::UUID,$4::UUID,$5::BIGINT,$6::BIGINT,$7::BIGINT,$8::BIGINT,$9::BIGINT,$10::UUID,$11::TIMESTAMPTZ,NULL::UUID,100) AS new
 ) SELECT old IS NOT NULL AND
 new->>'workspace_display_code'=$12 AND
 (new-'workspace_display_code'-'scopes')=(old-'scopes') AND
 (SELECT jsonb_agg(item-'network_display_code' ORDER BY position)
  FROM jsonb_array_elements(new->'scopes') WITH ORDINALITY AS items(item,position))=old->'scopes' AND
 EXISTS(SELECT 1 FROM jsonb_array_elements(new->'scopes') AS item
        WHERE item->>'network_id'='01890f00-0000-7000-8000-000000000203'
          AND item->>'network_display_code'=$13)
 FROM projections`, append(args, workspaceCode, networkCode)...).Scan(&matched); err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("display projection changed UUID/permission authority or rename changed display code")
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		`UPDATE mesh_ops.tenant_display_identity SET display_code='000000000001' WHERE workspace_public_id='01890f00-0000-7000-8000-000000000103'`,
		`DELETE FROM mesh_ops.tenant_display_identity WHERE workspace_public_id='01890f00-0000-7000-8000-000000000103'`,
	} {
		immutableTx, beginErr := admin.Begin(ctx)
		if beginErr != nil {
			t.Fatal(beginErr)
		}
		_, mutationErr := immutableTx.Exec(ctx, query)
		_ = immutableTx.Rollback(ctx)
		var pgErr *pgconn.PgError
		if !errors.As(mutationErr, &pgErr) || pgErr.Code != "23514" {
			t.Fatalf("display code mutation was not rejected: %v", mutationErr)
		}
	}
}

func assertDisplayIdentityCoverage(ctx context.Context, t *testing.T, connection *pgx.Conn) {
	t.Helper()
	var complete bool
	if err := connection.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM mesh_ops.tenant_display_identity)=
 ((SELECT count(*) FROM mesh.workspace)+(SELECT count(*) FROM mesh.network)) AND
 NOT EXISTS(SELECT 1 FROM mesh_ops.tenant_display_identity WHERE display_code !~ '^[0-9]{12}$') AND
 NOT EXISTS(SELECT 1 FROM mesh.workspace AS w LEFT JOIN mesh_ops.tenant_display_identity AS i ON i.workspace_public_id=w.public_id WHERE i.display_code IS NULL) AND
 NOT EXISTS(SELECT 1 FROM mesh.network AS n LEFT JOIN mesh_ops.tenant_display_identity AS i ON i.network_public_id=n.public_id WHERE i.display_code IS NULL)`).Scan(&complete); err != nil {
		t.Fatal(err)
	}
	if !complete {
		t.Fatal("tenant display identity coverage is incomplete")
	}
}

// A separate owned database exercises the released schema with populated tenant
// rows before the new migration runs. It is never a deployment connection.
func assertTenantDisplayUpgrade(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	var database string
	if err := admin.QueryRow(ctx, `SELECT 'mesh_display_upgrade_'||replace(gen_random_uuid()::TEXT,'-','')`).Scan(&database); err != nil {
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
			t.Errorf("remove owned upgrade fixture: %v", err)
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
	if _, err := connection.Exec(ctx, "SET ROLE mesh_migrator"); err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations.Catalog() {
		if migration.Version >= 77 {
			break
		}
		if _, err := connection.Exec(ctx, migration.SQL); err != nil {
			t.Fatalf("upgrade fixture migration %d: %v", migration.Version, err)
		}
	}
	if _, err := connection.Exec(ctx, "RESET ROLE"); err != nil {
		t.Fatal(err)
	}
	seedAuthorityFixture(ctx, t, connection)
	var before string
	const authoritySnapshot = `SELECT jsonb_build_object(
 'workspace',(SELECT jsonb_agg(to_jsonb(w) ORDER BY id) FROM mesh.workspace AS w),
 'network',(SELECT jsonb_agg(to_jsonb(n) ORDER BY id) FROM mesh.network AS n),
 'audit',(SELECT count(*) FROM mesh_audit.audit_event),
 'outbox',(SELECT count(*) FROM mesh_ops.outbox_event))::TEXT`
	if err := connection.QueryRow(ctx, authoritySnapshot).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, "SET ROLE mesh_migrator"); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, migrations.Catalog()[76].SQL); err != nil {
		t.Fatal("display upgrade", err)
	}
	if _, err := connection.Exec(ctx, "RESET ROLE"); err != nil {
		t.Fatal(err)
	}
	assertDisplayIdentityCoverage(ctx, t, connection)
	var after string
	if err := connection.QueryRow(ctx, authoritySnapshot).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("display backfill rewrote tenant authority or audit/outbox")
	}
}
