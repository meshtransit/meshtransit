//go:build integration

package integration

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"meshtransit.net/core/migrations"
)

// integrationSchemaRuntimeUser is the login the schema assertions' raw SQL
// runs as: MESHTRANSIT_TEST_POSTGRES_SCHEMA_RUNTIME_USER (the harness sets
// mesh_runtime, with the same password, when the stores run as mesh_all), or
// the stores' own login.
func integrationSchemaRuntimeUser(runtimeUser string) string {
	if user := os.Getenv("MESHTRANSIT_TEST_POSTGRES_SCHEMA_RUNTIME_USER"); user != "" {
		return user
	}
	return runtimeUser
}

// grantIntegrationRuntimeGroups does what the operator command keeps for a
// serving login (role isolation S2.2): membership of its role's group roles,
// INHERIT without SET.
func grantIntegrationRuntimeGroups(ctx context.Context, t *testing.T, admin *pgx.Conn, login string) {
	t.Helper()
	for _, group := range migrations.OperatorRequiredGroups(login) {
		statement := "GRANT " + pgx.Identifier{group}.Sanitize() + " TO " + pgx.Identifier{login}.Sanitize() +
			" WITH INHERIT TRUE, SET FALSE"
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatalf("grant %s to %s: %v", group, login, err)
		}
	}
}

var groupFunctionGrant = regexp.MustCompile(`(?m)^GRANT EXECUTE ON FUNCTION (\S+\)) TO ([a-z_,]+);$`)

// applyGroupFunctionGrantsSoFar runs the grants of operator step 298 whose
// function mesh_runtime already holds directly: the tests apply earlier
// operator steps by hand, in their own order, and a group must never get a
// function before mesh_runtime does.
func applyGroupFunctionGrantsSoFar(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	matches := groupFunctionGrant.FindAllStringSubmatch(migrations.GroupFunctionGrantsSQL(), -1)
	if len(matches) == 0 {
		t.Fatal("operator step 298 holds no grant")
	}
	for _, match := range matches {
		var held bool
		if err := admin.QueryRow(ctx, `SELECT EXISTS (
    SELECT 1 FROM pg_catalog.pg_proc AS routine CROSS JOIN LATERAL pg_catalog.aclexplode(routine.proacl) AS acl
    WHERE routine.oid = pg_catalog.to_regprocedure($1) AND acl.privilege_type = 'EXECUTE'
      AND acl.grantee = (SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = 'mesh_runtime'))`,
			match[1]).Scan(&held); err != nil {
			t.Fatalf("read mesh_runtime's grant on %s: %v", match[1], err)
		}
		if held {
			if _, err := admin.Exec(ctx, match[0]); err != nil {
				t.Fatalf("%s: %v", match[0], err)
			}
		}
	}
}

// groupRoleExcessSQL lists every privilege a group role holds that
// mesh_runtime does not hold itself on the same object (schemas 298–299,
// operator step 298): the groups are a projection of mesh_runtime, never more.
const groupRoleExcessSQL = `WITH entries AS (
    SELECT 'function' AS kind, routine.oid::REGPROCEDURE::TEXT AS object, '' AS part,
        acl.grantee, acl.privilege_type
    FROM pg_catalog.pg_proc AS routine CROSS JOIN LATERAL pg_catalog.aclexplode(routine.proacl) AS acl
    UNION ALL
    SELECT 'relation', relation.oid::REGCLASS::TEXT, '', acl.grantee, acl.privilege_type
    FROM pg_catalog.pg_class AS relation CROSS JOIN LATERAL pg_catalog.aclexplode(relation.relacl) AS acl
    UNION ALL
    SELECT 'column', attribute.attrelid::REGCLASS::TEXT, attribute.attname::TEXT, acl.grantee, acl.privilege_type
    FROM pg_catalog.pg_attribute AS attribute CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS acl
    UNION ALL
    SELECT 'schema', namespace.nspname::TEXT, '', acl.grantee, acl.privilege_type
    FROM pg_catalog.pg_namespace AS namespace CROSS JOIN LATERAL pg_catalog.aclexplode(namespace.nspacl) AS acl
    UNION ALL
    SELECT 'database', database.datname::TEXT, '', acl.grantee, acl.privilege_type
    FROM pg_catalog.pg_database AS database CROSS JOIN LATERAL pg_catalog.aclexplode(database.datacl) AS acl
    WHERE database.datname = pg_catalog.current_database()
)
SELECT COALESCE(pg_catalog.array_agg(group_role.rolname || ': ' || held.kind || ' ' || held.object ||
    CASE WHEN held.part = '' THEN '' ELSE '.' || held.part END || ' ' || held.privilege_type
    ORDER BY 1), ARRAY[]::TEXT[])
FROM entries AS held
JOIN pg_catalog.pg_roles AS group_role ON group_role.oid = held.grantee
WHERE group_role.rolname IN ('mesh_api_rights', 'mesh_control_rights')
  -- Functions created from schema 297 on are granted to the groups only ($1).
  AND NOT (held.kind = 'function' AND pg_catalog.split_part(held.object, '(', 1) = ANY($1::TEXT[]))
  AND NOT EXISTS (
      SELECT 1 FROM entries AS runtime_held
      WHERE runtime_held.grantee = (SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = 'mesh_runtime')
        AND runtime_held.kind = held.kind AND runtime_held.object = held.object
        AND runtime_held.part = held.part AND runtime_held.privilege_type = held.privilege_type)`

var createdFunction = regexp.MustCompile(`(?i)CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+([a-z_]+\.[a-z0-9_]+)\s*\(`)

// groupOnlyFunctions are the functions the migrations from schema 297 create:
// from S2.2 they are granted to the group roles, never to mesh_runtime.
func groupOnlyFunctions(t *testing.T) []string {
	t.Helper()
	names := []string{}
	for _, migration := range migrations.Catalog() {
		if migration.Version < 297 {
			continue
		}
		for _, match := range createdFunction.FindAllStringSubmatch(migration.SQL, -1) {
			names = append(names, strings.ToLower(match[1]))
		}
	}
	if len(names) == 0 {
		t.Fatal("no function created from schema 297")
	}
	return names
}

// groupRoleUsageSQL reports, for one group role ($1), the manifest entries
// it cannot use: a function no overload of which it may run ($2), a table it
// may not touch with the statement's privilege ($3 table, $4 privilege).
const groupRoleUsageSQL = `SELECT
    ARRAY(
        SELECT wanted.name FROM pg_catalog.unnest($2::TEXT[]) AS wanted(name)
        WHERE NOT EXISTS (
            SELECT 1 FROM pg_catalog.pg_proc AS routine
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = routine.pronamespace
            WHERE namespace.nspname || '.' || routine.proname = wanted.name
              AND pg_catalog.has_function_privilege($1::TEXT, routine.oid, 'EXECUTE'))
          -- Only what mesh_runtime can use today: the manifest names a few
          -- objects the code reaches through a definer, never directly.
          AND EXISTS (
            SELECT 1 FROM pg_catalog.pg_proc AS routine
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = routine.pronamespace
            WHERE namespace.nspname || '.' || routine.proname = wanted.name
              AND pg_catalog.has_function_privilege('mesh_runtime', routine.oid, 'EXECUTE'))
        ORDER BY 1),
    ARRAY(
        SELECT wanted.relation || ' ' || wanted.privilege
        FROM ROWS FROM (pg_catalog.unnest($3::TEXT[]), pg_catalog.unnest($4::TEXT[])) AS wanted(relation, privilege)
        WHERE pg_catalog.to_regclass(wanted.relation) IS NOT NULL
          AND NOT (pg_catalog.has_table_privilege($1::TEXT, wanted.relation, wanted.privilege)
               OR (wanted.privilege <> 'DELETE'
                   AND pg_catalog.has_any_column_privilege($1::TEXT, wanted.relation, wanted.privilege)))
          AND (pg_catalog.has_table_privilege('mesh_runtime', wanted.relation, wanted.privilege)
               OR (wanted.privilege <> 'DELETE'
                   AND pg_catalog.has_any_column_privilege('mesh_runtime', wanted.relation, wanted.privilege)))
        ORDER BY 1)`

// groupRolePolicyGapSQL lists, for each group role, every table and command
// mesh_runtime reaches through a permissive policy where the group, which
// holds the privilege, has none: without one RLS returns no row, not an
// error.
const groupRolePolicyGapSQL = `WITH commands(privilege, command) AS (
    VALUES ('SELECT', 'r'), ('INSERT', 'a'), ('UPDATE', 'w'), ('DELETE', 'd')
)
SELECT COALESCE(pg_catalog.array_agg(group_role.rolname || ': ' || relation.oid::REGCLASS::TEXT || ' ' ||
    commands.privilege ORDER BY 1), ARRAY[]::TEXT[])
FROM pg_catalog.pg_class AS relation
CROSS JOIN commands
CROSS JOIN pg_catalog.pg_roles AS group_role
WHERE relation.relrowsecurity AND relation.relkind IN ('r', 'p')
  AND group_role.rolname IN ('mesh_api_rights', 'mesh_control_rights')
  AND (pg_catalog.has_table_privilege(group_role.oid, relation.oid, commands.privilege)
      OR (commands.privilege <> 'DELETE'
          AND pg_catalog.has_any_column_privilege(group_role.oid, relation.oid, commands.privilege)))
  AND EXISTS (
      SELECT 1 FROM pg_catalog.pg_policy AS policy
      WHERE policy.polrelid = relation.oid AND policy.polpermissive
        AND policy.polcmd IN (commands.command, '*')
        AND (SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname = 'mesh_runtime') = ANY(policy.polroles))
  AND NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_policy AS policy
      WHERE policy.polrelid = relation.oid AND policy.polpermissive
        AND policy.polcmd IN (commands.command, '*')
        AND group_role.oid = ANY(policy.polroles))`

// assertGroupRolesWithinRuntime checks role isolation S2.2 on a database
// every migration and operator step reached: each group holds only what
// mesh_runtime holds, can use everything its role's code uses, and every
// RLS policy that lets mesh_runtime reach rows lets the group reach them.
func assertGroupRolesWithinRuntime(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	var excess []string
	if err := admin.QueryRow(ctx, groupRoleExcessSQL, groupOnlyFunctions(t)).Scan(&excess); err != nil {
		t.Fatalf("read group role privileges: %v", err)
	}
	for _, entry := range excess {
		t.Errorf("group role holds what mesh_runtime does not: %s", entry)
	}

	manifest, err := migrations.RoleGrants()
	if err != nil {
		t.Fatal(err)
	}
	for role, group := range map[string]string{"api": "mesh_api_rights", "control": "mesh_control_rights"} {
		usage := manifest[role]
		var relations, privileges []string
		for _, entry := range []struct {
			tables    []string
			privilege string
		}{
			{usage.Reads, "SELECT"}, {usage.Inserts, "INSERT"}, {usage.Updates, "UPDATE"},
			{usage.Locks, "UPDATE"}, {usage.Deletes, "DELETE"},
		} {
			for _, table := range entry.tables {
				relations = append(relations, table)
				privileges = append(privileges, entry.privilege)
			}
		}
		var missingFunctions, missingTables []string
		if err := admin.QueryRow(ctx, groupRoleUsageSQL, group, usage.Functions, relations, privileges).Scan(
			&missingFunctions, &missingTables); err != nil {
			t.Fatalf("read %s usage: %v", group, err)
		}
		for _, name := range missingFunctions {
			t.Errorf("%s cannot run %s, which the %s role calls", group, name, role)
		}
		for _, entry := range missingTables {
			t.Errorf("%s lacks %s, which the %s role uses", group, entry, role)
		}
	}

	var gaps []string
	if err := admin.QueryRow(ctx, groupRolePolicyGapSQL).Scan(&gaps); err != nil {
		t.Fatalf("read group role policies: %v", err)
	}
	for _, gap := range gaps {
		t.Errorf("no row-level security policy lets the group reach rows mesh_runtime reaches: %s", gap)
	}
}
