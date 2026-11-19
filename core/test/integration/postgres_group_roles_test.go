//go:build integration

package integration

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/platform/config"

	"meshtransit.net/core/migrations"
)

// integrationSchemaRuntimeUser is the login the schema assertions' raw SQL
// runs as: MESHTRANSIT_TEST_POSTGRES_SCHEMA_RUNTIME_USER, or mesh_it_schema,
// a member of mesh_it_legacy, which holds what mesh_runtime held before
// S2.3 (the harness creates it with the runtime login's password).
func integrationSchemaRuntimeUser(string) string {
	if user := os.Getenv("MESHTRANSIT_TEST_POSTGRES_SCHEMA_RUNTIME_USER"); user != "" && user != "mesh_runtime" {
		return user
	}
	return "mesh_it_schema"
}

//go:embed testdata/role_split_narrowing.sql
var roleSplitNarrowingSQL string

//go:embed testdata/role_legacy_copy.sql
var roleLegacyCopySQL string

// integrationLegacyCopyVersion is the last schema before S2.3 narrows
// mesh_runtime (migration 300): the tests copy its privileges there.
const integrationLegacyCopyVersion = 299

// grantLegacyCatalogRuntimeFunctions gives mesh_it_legacy every function the
// operator steps before S2.3 granted mesh_runtime: on a database whose
// operator command ran every step (step 300 included) after the legacy copy,
// that is what mesh_runtime held before S2.3 took it away.
func grantLegacyCatalogRuntimeFunctions(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	steps, err := migrations.OperatorSteps()
	if err != nil {
		t.Fatal(err)
	}
	before := slices.DeleteFunc(steps, func(step migrations.OperatorStep) bool {
		return step.Version > integrationLegacyCopyVersion
	})
	for _, requirement := range migrations.OperatorRequirements(before) {
		if requirement.Effect.Kind != migrations.OperatorEffectExecute || requirement.Effect.Role != "mesh_runtime" {
			continue
		}
		if _, err := admin.Exec(ctx, "GRANT EXECUTE ON FUNCTION "+requirement.Effect.Function+" TO mesh_it_legacy"); err != nil {
			t.Fatalf("grant %s to mesh_it_legacy: %v", requirement.Effect.Function, err)
		}
	}
}

// execOperatorStep runs an operator step the test applies by hand and, once
// the legacy role took its copy (S2.3), copies again whatever the step gave
// mesh_runtime: steps written before S2.3 still grant to it.
func execOperatorStep(ctx context.Context, admin *pgx.Conn, step string) (pgconn.CommandTag, error) {
	tag, err := admin.Exec(ctx, step)
	if err != nil || legacyRuntimeRole == "" {
		return tag, err
	}
	if _, err := admin.Exec(ctx, roleLegacyCopySQL); err != nil {
		return tag, fmt.Errorf("copy the step's grants to mesh_it_legacy: %w", err)
	}
	return tag, nil
}

// copyIntegrationLegacyRuntime gives mesh_it_legacy, on the database
// (default: the integration database), every privilege mesh_runtime holds
// directly and a place in its policies, then points the legacy contracts at
// it (legacyRuntimeSQL) for the rest of the test.
func copyIntegrationLegacyRuntime(ctx context.Context, t *testing.T, database ...string) {
	t.Helper()
	adminConfig := loadIntegrationAdminConfig(t)
	if len(database) == 1 {
		adminConfig.PostgreSQL.Database = database[0]
	}
	admin := openIntegrationPostgreSQLConnection(ctx, t, adminConfig.PostgreSQL.Address,
		adminConfig.PostgreSQL.Database, adminConfig.PostgreSQL.User, adminConfig.PostgreSQL.PasswordFile,
		adminConfig.PostgreSQL.CAFile, adminConfig.ConnectTimeout)
	if _, err := admin.Exec(ctx, `DO $legacy$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'mesh_it_legacy') THEN
        CREATE ROLE mesh_it_legacy NOLOGIN;
    END IF;
END $legacy$`); err != nil {
		t.Fatalf("create mesh_it_legacy: %v", err)
	}
	if _, err := admin.Exec(ctx, roleLegacyCopySQL); err != nil {
		t.Fatalf("copy mesh_runtime's privileges to mesh_it_legacy: %v", err)
	}
	legacyRuntimeRole = "mesh_it_legacy"
	t.Cleanup(func() { legacyRuntimeRole = "" })
}

// openIntegrationRoleSplit returns the pool control's flows run on: a pool
// as control's login (MESHTRANSIT_TEST_POSTGRES_CONTROL_USER, default
// mesh_control), which holds only control's group, after moving away
// whatever hand-applied operator steps gave mesh_runtime again
// (testdata/role_split_narrowing.sql); the api's stores keep mesh_runtime,
// which holds only the api's group (S2.3). A flow on the wrong pool fails
// when it uses an object only the other role's group holds. With the stores
// as mesh_all (self-host, both groups) it returns runtimePool.
func openIntegrationRoleSplit(ctx context.Context, t *testing.T, admin *pgx.Conn, runtimeUser string,
	runtimePool *postgresadapter.Pool,
	address, database string, passwordFile config.SecretFile, caFile config.TrustFile,
	timeout time.Duration) *postgresadapter.Pool {
	t.Helper()
	// From S2.3 control's flows always run as control's login, unless the
	// stores run as mesh_all (self-host), which holds both groups.
	if runtimeUser == "mesh_all" {
		return runtimePool
	}
	user := os.Getenv("MESHTRANSIT_TEST_POSTGRES_CONTROL_USER")
	if user == "" {
		user = "mesh_control"
	}
	if _, err := admin.Exec(ctx, roleSplitNarrowingSQL); err != nil {
		t.Fatalf("narrow the database as S2.3 will: %v", err)
	}
	assertRoleSplitNarrowed(ctx, t, admin)
	grantIntegrationRuntimeGroups(ctx, t, admin, user)
	pool, err := postgresadapter.Open(ctx, postgresadapter.Options{
		Role: postgresadapter.PoolRoleRuntime, Address: address, Database: database, User: user,
		PasswordFile: passwordFile, CAFile: caFile, MaxConnections: 2, ConnectTimeout: timeout,
	})
	if err != nil {
		t.Fatalf("open the control pool as %s: %v", user, err)
	}
	t.Cleanup(func() {
		if err := pool.Close(); err != nil {
			t.Errorf("control pool Close() error = %v", err)
		}
	})
	if err := pool.Check(ctx); err != nil {
		t.Fatalf("control pool Check() error = %v", err)
	}
	integrationControlPool, integrationRuntimePool = pool, runtimePool
	t.Cleanup(func() { integrationControlPool, integrationRuntimePool = nil, nil })
	return pool
}

// legacyRuntimeSQL points a privilege contract's 'mesh_runtime' (and a
// schema test's SET ROLE mesh_runtime) at the role holding what mesh_runtime
// held directly before S2.3: mesh_runtime itself, or mesh_it_legacy once the
// split run narrowed the database (S2.1). It is for contracts on retired
// versions no serving role calls and for schema tests of them; a contract on
// an object the api calls keeps mesh_runtime, one on control's object uses
// controlRuntimeName. Some wrapped contracts run before the narrowing, where
// it changes nothing. S2.3 rewrites the retired ones as "no serving role".
func legacyRuntimeSQL(query string) string {
	if legacyRuntimeRole == "" {
		return query
	}
	return strings.NewReplacer("'mesh_runtime'", "'"+legacyRuntimeRole+"'",
		"ROLE mesh_runtime", "ROLE "+legacyRuntimeRole).Replace(query)
}

// integrationControlPool is control's pool once the split run narrowed the
// database (S2.1); controlPoolFor hands it to the stores control builds in
// cmd/meshcore, and the pool given otherwise.
var integrationControlPool *postgresadapter.Pool

func controlPoolFor(pool *postgresadapter.Pool) *postgresadapter.Pool {
	if integrationControlPool != nil && pool == integrationRuntimePool {
		return integrationControlPool
	}
	return pool
}

// integrationRuntimePool is the api's pool the control pool stands in for.
var integrationRuntimePool *postgresadapter.Pool

// controlRuntimeName is the role a privilege contract on an object control
// calls checks: mesh_control once the split run narrowed the database,
// mesh_runtime (which control logged in as through S2.2) otherwise.
func controlRuntimeName() string {
	if legacyRuntimeRole == "" {
		return "mesh_runtime"
	}
	return "mesh_control"
}

// legacyRuntimeName is the role name a privilege contract written for
// mesh_runtime checks (see legacyRuntimeSQL).
func legacyRuntimeName() string {
	if legacyRuntimeRole == "" {
		return "mesh_runtime"
	}
	return legacyRuntimeRole
}

// legacyRuntimeRole is set once the split run narrowed the database.
var legacyRuntimeRole string

// assertRoleSplitNarrowed checks the state the split run (S2.1) works in:
// mesh_runtime holds nothing directly, no policy names it, and mesh_control
// is not its member.
func assertRoleSplitNarrowed(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	var directGrants, policies int
	var controlInRuntime bool
	if err := admin.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*)::INT FROM pg_catalog.pg_proc AS routine
        CROSS JOIN LATERAL pg_catalog.aclexplode(routine.proacl) AS acl WHERE acl.grantee = 'mesh_runtime'::REGROLE)
    + (SELECT pg_catalog.count(*)::INT FROM pg_catalog.pg_class AS relation
        CROSS JOIN LATERAL pg_catalog.aclexplode(relation.relacl) AS acl WHERE acl.grantee = 'mesh_runtime'::REGROLE)
    + (SELECT pg_catalog.count(*)::INT FROM pg_catalog.pg_attribute AS attribute
        CROSS JOIN LATERAL pg_catalog.aclexplode(attribute.attacl) AS acl WHERE acl.grantee = 'mesh_runtime'::REGROLE)
    + (SELECT pg_catalog.count(*)::INT FROM pg_catalog.pg_namespace AS namespace
        CROSS JOIN LATERAL pg_catalog.aclexplode(namespace.nspacl) AS acl WHERE acl.grantee = 'mesh_runtime'::REGROLE)
    + (SELECT pg_catalog.count(*)::INT FROM pg_catalog.pg_database AS database
        CROSS JOIN LATERAL pg_catalog.aclexplode(database.datacl) AS acl
        WHERE database.datname = pg_catalog.current_database() AND acl.grantee = 'mesh_runtime'::REGROLE),
    (SELECT pg_catalog.count(*)::INT FROM pg_catalog.pg_policy AS policy
        WHERE 'mesh_runtime'::REGROLE = ANY(policy.polroles)),
    pg_catalog.pg_has_role('mesh_control', 'mesh_runtime', 'MEMBER')`).Scan(
		&directGrants, &policies, &controlInRuntime); err != nil {
		t.Fatal(err)
	}
	if directGrants != 0 || policies != 0 || controlInRuntime {
		t.Fatalf("narrowed state: mesh_runtime direct grants %d, policies %d, mesh_control in mesh_runtime %v",
			directGrants, policies, controlInRuntime)
	}
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
      AND acl.grantee IN (SELECT role.oid FROM pg_catalog.pg_roles AS role WHERE role.rolname IN ('mesh_runtime', $2)))`,
			match[1], legacyRuntimeName()).Scan(&held); err != nil {
			t.Fatalf("read mesh_runtime's grant on %s: %v", match[1], err)
		}
		if held {
			if _, err := admin.Exec(ctx, match[0]); err != nil {
				t.Fatalf("%s: %v", match[0], err)
			}
		}
	}
	// A step applied after the split run narrowed the database granted to
	// mesh_runtime again: narrow once more (S2.1).
	if legacyRuntimeRole != "" {
		if _, err := admin.Exec(ctx, roleSplitNarrowingSQL); err != nil {
			t.Fatalf("narrow again after an operator step: %v", err)
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
          -- Only what mesh_runtime can use today (or a function created for
          -- the groups only, $5): the manifest names a few objects the code
          -- reaches through a definer, never directly.
          AND (wanted.name = ANY($5::TEXT[]) OR EXISTS (
            SELECT 1 FROM pg_catalog.pg_proc AS routine
            JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = routine.pronamespace
            WHERE namespace.nspname || '.' || routine.proname = wanted.name
              AND pg_catalog.has_function_privilege('mesh_runtime', routine.oid, 'EXECUTE')))
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
	// Split run: no operator step applied since gave mesh_runtime anything
	// back (each must be followed by applyGroupFunctionGrantsSoFar).
	if legacyRuntimeRole != "" {
		assertRoleSplitNarrowed(ctx, t, admin)
	}
	var excess []string
	if err := admin.QueryRow(ctx, legacyRuntimeSQL(groupRoleExcessSQL), groupOnlyFunctions(t)).Scan(&excess); err != nil {
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
		if err := admin.QueryRow(ctx, legacyRuntimeSQL(groupRoleUsageSQL), group, usage.Functions, relations, privileges,
			groupOnlyFunctions(t)).Scan(
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
	if err := admin.QueryRow(ctx, legacyRuntimeSQL(groupRolePolicyGapSQL)).Scan(&gaps); err != nil {
		t.Fatalf("read group role policies: %v", err)
	}
	for _, gap := range gaps {
		t.Errorf("no row-level security policy lets the group reach rows mesh_runtime reaches: %s", gap)
	}
}
