//go:build integration

package integration

import (
	"context"
	"errors"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func assertDatabasePrivilegeContract(t *testing.T, ctx context.Context, connection *pgx.Conn) {
	t.Helper()

	var runtimeConnect, workerConnect, observerConnect bool
	var runtimeCreate, runtimeTemporary, runtimePublicCreate bool
	if err := connection.QueryRow(ctx, `SELECT
    pg_catalog.has_database_privilege('mesh_runtime', pg_catalog.current_database(), 'CONNECT'),
    pg_catalog.has_database_privilege('mesh_worker', pg_catalog.current_database(), 'CONNECT'),
    pg_catalog.has_database_privilege('mesh_observer', pg_catalog.current_database(), 'CONNECT'),
    pg_catalog.has_database_privilege('mesh_runtime', pg_catalog.current_database(), 'CREATE'),
    pg_catalog.has_database_privilege('mesh_runtime', pg_catalog.current_database(), 'TEMPORARY'),
    pg_catalog.has_schema_privilege('mesh_runtime', 'public', 'CREATE')`).Scan(
		&runtimeConnect,
		&workerConnect,
		&observerConnect,
		&runtimeCreate,
		&runtimeTemporary,
		&runtimePublicCreate,
	); err != nil {
		t.Fatalf("query database privilege contract: %v", err)
	}
	if !runtimeConnect || !workerConnect || observerConnect || runtimeCreate ||
		runtimeTemporary || runtimePublicCreate {
		t.Fatalf(
			"database privilege contract: runtime connect=%t worker connect=%t observer connect=%t "+
				"runtime create=%t runtime temporary=%t runtime public create=%t",
			runtimeConnect,
			workerConnect,
			observerConnect,
			runtimeCreate,
			runtimeTemporary,
			runtimePublicCreate,
		)
	}
}

func assertAuthorityConstraints(t *testing.T, ctx context.Context, connection *pgx.Conn) {
	t.Helper()

	tests := []struct {
		name      string
		networkID int64
		prefixID  int64
		prefix    string
		wantCode  string
	}{
		{
			name:      "overlapping prefix in one realm",
			networkID: 201,
			prefixID:  503,
			prefix:    "100.64.1.128/25",
			wantCode:  "23P01",
		},
		{
			name:      "cross workspace network substitution",
			networkID: 202,
			prefixID:  504,
			prefix:    "100.64.2.0/24",
			wantCode:  "23503",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transaction, err := connection.Begin(ctx)
			if err != nil {
				t.Fatalf("begin constraint transaction: %v", err)
			}
			defer rollbackIntegrationTransaction(t, ctx, transaction)
			setIntegrationScope(t, ctx, transaction, 101, test.networkID)
			_, err = transaction.Exec(ctx, `INSERT INTO mesh.network_prefix (
    id, public_id, workspace_id, network_id, address_realm_id, address_pool_id, prefix, family, state
) OVERRIDING SYSTEM VALUE VALUES (
    $1, '01890f00-0000-7000-8000-000000000999', 101, $2, 301, 401, $3, 4, 'active'
)`, test.prefixID, test.networkID, test.prefix)
			assertPostgreSQLCode(t, err, test.wantCode)
		})
	}
}

func assertRuntimeAuthorityIsolation(t *testing.T, ctx context.Context, connection *pgx.Conn) {
	t.Helper()

	assertScopeCounts(t, ctx, connection, "", "", 0, 0, 0, 0)
	assertScopeCounts(t, ctx, connection, "invalid", "invalid", 0, 0, 0, 0)
	assertScopeCounts(t, ctx, connection, "101", "201", 1, 1, 1, 1)
	assertScopeCounts(t, ctx, connection, "101", "202", 1, 0, 0, 0)
	assertScopeCounts(t, ctx, connection, "102", "202", 1, 1, 1, 1)

	var canInsertWorkspace, canReadPrincipal, canCreateSchema bool
	var canReadOutbox, canInsertOutbox, canReadAudit, canExecuteAuditAppend bool
	if err := connection.QueryRow(ctx, `SELECT
    pg_catalog.has_table_privilege(CURRENT_USER, 'mesh.workspace', 'INSERT'),
    pg_catalog.has_table_privilege(CURRENT_USER, 'mesh.principal', 'SELECT'),
    pg_catalog.has_schema_privilege(CURRENT_USER, 'mesh', 'CREATE'),
    pg_catalog.has_table_privilege(CURRENT_USER, 'mesh_ops.outbox_event', 'SELECT'),
    pg_catalog.has_table_privilege(CURRENT_USER, 'mesh_ops.outbox_event', 'INSERT'),
    COALESCE((
        SELECT pg_catalog.bool_or(
            pg_catalog.has_table_privilege(CURRENT_USER, relation.oid, 'SELECT')
        )
        FROM pg_catalog.pg_class AS relation
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = relation.relnamespace
        WHERE namespace.nspname = 'mesh_audit'
          AND relation.relname = 'audit_event'
    ), FALSE),
    COALESCE((
        SELECT pg_catalog.bool_or(
            pg_catalog.has_function_privilege(CURRENT_USER, procedure.oid, 'EXECUTE')
        )
        FROM pg_catalog.pg_proc AS procedure
        JOIN pg_catalog.pg_namespace AS namespace
          ON namespace.oid = procedure.pronamespace
        WHERE namespace.nspname = 'mesh_audit'
          AND procedure.proname = 'append_authority_evidence'
    ), FALSE)`).Scan(
		&canInsertWorkspace,
		&canReadPrincipal,
		&canCreateSchema,
		&canReadOutbox,
		&canInsertOutbox,
		&canReadAudit,
		&canExecuteAuditAppend,
	); err != nil {
		t.Fatalf("query runtime negative privileges: %v", err)
	}
	if canInsertWorkspace || canReadPrincipal || canCreateSchema || canReadOutbox ||
		canInsertOutbox || canReadAudit || canExecuteAuditAppend {
		t.Fatalf(
			"runtime excessive privileges: workspace insert=%t principal read=%t schema create=%t "+
				"outbox read=%t outbox insert=%t audit read=%t audit append=%t",
			canInsertWorkspace,
			canReadPrincipal,
			canCreateSchema,
			canReadOutbox,
			canInsertOutbox,
			canReadAudit,
			canExecuteAuditAppend,
		)
	}
	_, err := connection.Exec(ctx, `INSERT INTO mesh.workspace (
    public_id, deployment_id, owner_principal_id, display_name, name_key, state
) VALUES ('01890f00-0000-7000-8000-000000000998', 1, 11, 'Denied', 'denied', 'active')`)
	assertPostgreSQLCode(t, err, "42501")
}

func assertWorkerOutboxPrivilegeContract(t *testing.T, ctx context.Context, connection *pgx.Conn) {
	t.Helper()

	var selectEventID, selectPayload, updateState, updatePublicID bool
	var insertAttemptEventID, insertAttemptID, deleteEvent, truncateEvent bool
	if err := connection.QueryRow(ctx, `SELECT
    pg_catalog.has_column_privilege(CURRENT_USER, 'mesh_ops.outbox_event', 'id', 'SELECT'),
    pg_catalog.has_column_privilege(CURRENT_USER, 'mesh_ops.outbox_event', 'payload', 'SELECT'),
    pg_catalog.has_column_privilege(CURRENT_USER, 'mesh_ops.outbox_event', 'state', 'UPDATE'),
    pg_catalog.has_column_privilege(CURRENT_USER, 'mesh_ops.outbox_event', 'public_id', 'UPDATE'),
    pg_catalog.has_column_privilege(CURRENT_USER, 'mesh_ops.outbox_attempt', 'outbox_event_id', 'INSERT'),
    pg_catalog.has_column_privilege(CURRENT_USER, 'mesh_ops.outbox_attempt', 'id', 'INSERT'),
    pg_catalog.has_table_privilege(CURRENT_USER, 'mesh_ops.outbox_event', 'DELETE'),
    pg_catalog.has_table_privilege(CURRENT_USER, 'mesh_ops.outbox_event', 'TRUNCATE')`).Scan(
		&selectEventID,
		&selectPayload,
		&updateState,
		&updatePublicID,
		&insertAttemptEventID,
		&insertAttemptID,
		&deleteEvent,
		&truncateEvent,
	); err != nil {
		t.Fatalf("query worker outbox privilege contract: %v", err)
	}
	if !selectEventID || selectPayload || !updateState || updatePublicID ||
		!insertAttemptEventID || insertAttemptID || deleteEvent || truncateEvent {
		t.Fatalf(
			"worker outbox privileges: select id=%t payload=%t update state=%t public id=%t "+
				"insert attempt event=%t attempt id=%t delete=%t truncate=%t",
			selectEventID,
			selectPayload,
			updateState,
			updatePublicID,
			insertAttemptEventID,
			insertAttemptID,
			deleteEvent,
			truncateEvent,
		)
	}

	var visibleEvents int64
	if err := connection.QueryRow(
		ctx,
		"SELECT pg_catalog.count(*) FROM mesh_ops.outbox_event",
	).Scan(&visibleEvents); err != nil {
		t.Fatalf("query worker-visible outbox events: %v", err)
	}
	if visibleEvents == 0 {
		t.Fatal("worker RLS policy hid all claimable outbox events")
	}

	var canReadAttempts bool
	if err := connection.QueryRow(ctx, `SELECT pg_catalog.has_table_privilege(
    CURRENT_USER,
    'mesh_ops.outbox_attempt',
    'SELECT'
)`).Scan(&canReadAttempts); err != nil {
		t.Fatalf("query worker outbox attempt read privilege: %v", err)
	}
	if canReadAttempts {
		t.Fatal("worker can read immutable outbox attempt history")
	}
}

func assertScopeCounts(
	t *testing.T,
	ctx context.Context,
	connection *pgx.Conn,
	workspaceScope string,
	networkScope string,
	wantWorkspaces int64,
	wantNetworks int64,
	wantPrefixes int64,
	wantRevisions int64,
) {
	t.Helper()

	transaction, err := connection.Begin(ctx)
	if err != nil {
		t.Fatalf("begin runtime scope transaction: %v", err)
	}
	defer rollbackIntegrationTransaction(t, ctx, transaction)
	if workspaceScope != "" || networkScope != "" {
		if _, err := transaction.Exec(ctx, `SELECT
    pg_catalog.set_config('mesh.workspace_id', $1, TRUE),
    pg_catalog.set_config('mesh.network_id', $2, TRUE)`, workspaceScope, networkScope); err != nil {
			t.Fatalf("set runtime scope: %v", err)
		}
	}

	queries := []struct {
		name  string
		query string
		want  int64
	}{
		{name: "workspace", query: "SELECT pg_catalog.count(*) FROM mesh.workspace", want: wantWorkspaces},
		{name: "network", query: "SELECT pg_catalog.count(*) FROM mesh.network", want: wantNetworks},
		{name: "network prefix", query: "SELECT pg_catalog.count(*) FROM mesh.network_prefix", want: wantPrefixes},
		{name: "network revision", query: "SELECT pg_catalog.count(*) FROM mesh_ops.network_revision", want: wantRevisions},
	}
	for _, query := range queries {
		var count int64
		if err := transaction.QueryRow(ctx, query.query).Scan(&count); err != nil {
			t.Fatalf("query scoped %s: %v", query.name, err)
		}
		if count != query.want {
			t.Fatalf("scoped %s count = %d, want %d", query.name, count, query.want)
		}
	}
}

func setIntegrationScope(
	t *testing.T,
	ctx context.Context,
	transaction pgx.Tx,
	workspaceID int64,
	networkID int64,
) {
	t.Helper()

	if _, err := transaction.Exec(ctx, `SELECT
    pg_catalog.set_config('mesh.workspace_id', $1, TRUE),
    pg_catalog.set_config('mesh.network_id', $2, TRUE)`,
		strconv.FormatInt(workspaceID, 10),
		strconv.FormatInt(networkID, 10),
	); err != nil {
		t.Fatalf("set integration authority scope: %v", err)
	}
}

func assertPostgreSQLCode(t *testing.T, err error, wantCode string) {
	t.Helper()

	postgresError, ok := errors.AsType[*pgconn.PgError](err)
	if !ok || postgresError.Code != wantCode {
		t.Fatalf("PostgreSQL error = %v, want SQLSTATE %s", err, wantCode)
	}
}
