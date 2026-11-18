//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/prometheus/client_golang/prometheus"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/sharing/devicealias"
	"meshtransit.net/core/internal/platform/config"
)

// TestPostgreSQLOperatorSteps runs after TestPostgreSQLMigrations on the same
// fixture: the operator steps that test applied by hand verify as applied,
// and a separate empty database goes through the operator command from its
// first role step to a clean verification.
func TestPostgreSQLOperatorSteps(t *testing.T) {
	if os.Getenv("MESHTRANSIT_MIGRATION_INTEGRATION") != "1" {
		t.Skip("set MESHTRANSIT_MIGRATION_INTEGRATION=1 after TestPostgreSQLMigrations on a disposable database")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	migrationConfig, err := config.LoadMigration(os.LookupEnv)
	if err != nil {
		t.Fatal(err)
	}
	adminConfig := loadIntegrationAdminConfig(t)

	// Steps applied by hand, as existing deployments did, verify as applied.
	verification, err := openIntegrationMigrationRunner(ctx, t, migrationConfig).Verify(ctx)
	if err != nil {
		t.Fatalf("Verify() on the hand-hardened database: %v", err)
	}
	if pending := verification.Operator.Pending(); len(pending) != 0 ||
		verification.Status.State != postgresadapter.MigrationStateClean {
		t.Fatalf("hand-hardened database: state %s, pending %+v", verification.Status.State, pending)
	}

	admin := openIntegrationPostgreSQLConnection(ctx, t, adminConfig.PostgreSQL.Address, adminConfig.PostgreSQL.Database,
		adminConfig.PostgreSQL.User, adminConfig.PostgreSQL.PasswordFile, adminConfig.PostgreSQL.CAFile,
		adminConfig.ConnectTimeout)
	database := createOperatorStepDatabase(ctx, t, admin)
	freshMigration := migrationConfig
	freshMigration.PostgreSQL.Database = database
	freshAdmin := adminConfig
	freshAdmin.PostgreSQL.Database = database
	operator := openIntegrationOperatorRunner(ctx, t, freshAdmin)

	// Before migrating: role steps run, an ownership step is refused.
	report, err := operator.Status(ctx)
	if err != nil || report.CurrentSchemaVersion != 0 {
		t.Fatalf("Status() on an empty database = %+v, %v", report.CurrentSchemaVersion, err)
	}
	for _, step := range report.Steps {
		if step.Kind == "ownership" && step.State != postgresadapter.OperatorStepAwaitingMigration {
			t.Fatalf("%s on an empty database: %s", step.Name, step.State)
		}
	}
	var refused *postgresadapter.OperatorStepRefusedError
	if _, err := operator.Apply(ctx, postgresadapter.OperatorApplyOptions{Through: 80}); !errors.As(err, &refused) ||
		refused.Step != "000051_resource_sharing_function_ownership" {
		t.Fatalf("Apply(through 80) before migration 51 = %v", err)
	}
	if _, err := openIntegrationMigrationRunner(ctx, t, freshMigration).Up(ctx); err != nil {
		t.Fatalf("migrate the operator step database: %v", err)
	}

	// Migrated, no step run: verify names the steps, readiness stays open,
	// the worker falls back to the previous alias functions.
	verification, err = openIntegrationMigrationRunner(ctx, t, freshMigration).Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pending := verification.Operator.Pending()
	if len(pending) == 0 || pending[0].Name != "000051_resource_sharing_function_ownership" {
		t.Fatalf("pending before any step = %+v", pending)
	}
	readmission := operatorStepStatus(t, verification.Operator, "000170_device_alias_consumer_readmission_ownership")
	if readmission.State != postgresadapter.OperatorStepPending || !slices.Contains(readmission.Missing,
		"owner of mesh_ops.load_device_alias_work_v3(UUID,UUID,UUID,INTEGER) is not mesh_device_alias_writer") {
		t.Fatalf("schema 170 step before running it = %+v", readmission)
	}
	worker := openOperatorStepWorkerPool(ctx, t, adminConfig, database)
	waitOperatorStepGauge(ctx, t, worker, float64(len(pending)))
	if version := aliasWorkerVersion(ctx, t, worker); version >= 5 {
		t.Fatalf("alias worker version before the operator steps = %v", version)
	}

	// Without the rollout flag the steps before 53 run and the rest wait.
	result, err := operator.Apply(ctx, postgresadapter.OperatorApplyOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(result.Applied, ",") != "000051_resource_sharing_function_ownership,"+
		"000052_policy_imported_resource_function_ownership" || len(result.Waiting) == 0 ||
		result.Waiting[0].Step != "000053_resource_sharing_access_name_function_ownership" ||
		result.Waiting[0].Reason != postgresadapter.OperatorWaitRollout {
		t.Fatalf("Apply() during a rollout = applied %v, waiting %+v", result.Applied, result.Waiting)
	}

	// After the rollout every step runs, in order, and then nothing is left.
	result, err = operator.Apply(ctx, postgresadapter.OperatorApplyOptions{AfterRollout: true})
	if err != nil || len(result.Applied) != len(pending)-2 || len(result.Waiting) != 0 {
		t.Fatalf("Apply(after rollout) = applied %v, waiting %+v, %v", result.Applied, result.Waiting, err)
	}
	assertNoPendingOperatorSteps(ctx, t, freshMigration)
	// A new installation: migrations ran before any operator step, and the
	// group roles still end as a projection of mesh_runtime (S2.2).
	assertGroupRolesWithinRuntime(ctx, t, openFreshAdmin(ctx, t, admin, database))
	waitOperatorStepGauge(ctx, t, worker, 0)
	if version := aliasWorkerVersion(ctx, t, worker); version != 6 {
		t.Fatalf("alias worker version after the operator steps = %v", version)
	}
	result, err = operator.Apply(ctx, postgresadapter.OperatorApplyOptions{AfterRollout: true})
	if err != nil || len(result.Applied) != 0 || len(result.Replayed) != 0 {
		t.Fatalf("second Apply() = applied %v replayed %v, %v", result.Applied, result.Replayed, err)
	}

	// A step undone later is found; a dry run changes nothing; apply
	// repairs it and replays the later steps in order.
	if _, err := openFreshAdmin(ctx, t, admin, database).Exec(ctx,
		"ALTER FUNCTION mesh_ops.load_device_alias_work_v3(UUID,UUID,UUID,INTEGER) OWNER TO mesh_migrator"); err != nil {
		t.Fatal(err)
	}
	verification, err = openIntegrationMigrationRunner(ctx, t, freshMigration).Verify(ctx)
	if err != nil || len(verification.Operator.Pending()) != 1 ||
		verification.Operator.Pending()[0].Name != "000170_device_alias_consumer_readmission_ownership" {
		t.Fatalf("Verify() after undoing the schema 170 owner = %+v, %v", verification.Operator.Pending(), err)
	}
	result, err = operator.Apply(ctx, postgresadapter.OperatorApplyOptions{AfterRollout: true, DryRun: true})
	if err != nil || !result.DryRun || strings.Join(result.Applied, ",") != "000170_device_alias_consumer_readmission_ownership" ||
		!slices.Contains(result.Replayed, "000171_device_alias_provider_readmission_ownership") {
		t.Fatalf("dry run = %+v, %v", result, err)
	}
	if report, err := operator.Status(ctx); err != nil || len(report.Pending()) != 1 {
		t.Fatalf("dry run committed: %+v, %v", report.Pending(), err)
	}
	if _, err := operator.Apply(ctx, postgresadapter.OperatorApplyOptions{AfterRollout: true}); err != nil {
		t.Fatal(err)
	}
	assertNoPendingOperatorSteps(ctx, t, freshMigration)

	// A membership of a MeshTransit role makes verification incomplete.
	if _, err := admin.Exec(ctx, "CREATE ROLE mesh_operator_test_member NOLOGIN"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.WithoutCancel(ctx), "DROP ROLE IF EXISTS mesh_operator_test_member") })
	if _, err := admin.Exec(ctx, "GRANT mesh_direct_map_reader TO mesh_operator_test_member"); err != nil {
		t.Fatal(err)
	}
	verification, err = openIntegrationMigrationRunner(ctx, t, freshMigration).Verify(ctx)
	if err != nil || !slices.Contains(verification.Operator.Memberships,
		"mesh_operator_test_member is a member of mesh_direct_map_reader") || verification.Operator.Complete() {
		t.Fatalf("Verify() with a membership = %+v, %v", verification.Operator.Memberships, err)
	}
	if report, err := operator.Status(ctx); err != nil || len(report.Memberships) != 1 {
		t.Fatalf("operator Status() with a membership = %+v, %v", report.Memberships, err)
	}
	if _, err := admin.Exec(ctx, "DROP ROLE mesh_operator_test_member"); err != nil {
		t.Fatal(err)
	}

	assertOperatorLogins(ctx, t, admin, operator, freshAdmin, freshMigration)
	assertOperatorGroups(ctx, t, admin, operator, freshMigration)
	assertCreateRoleOperator(ctx, t, admin, freshAdmin, freshMigration)

	// The runtime role is never an operator.
	runtimeOperator := freshAdmin
	runtimeConfig, err := config.Load(os.LookupEnv)
	if err != nil || runtimeConfig.Storage == nil || runtimeConfig.Storage.PostgreSQL.Runtime == nil {
		t.Fatalf("runtime settings: %v", err)
	}
	runtimeOperator.PostgreSQL.User = runtimeConfig.Storage.PostgreSQL.Runtime.User
	runtimeOperator.PostgreSQL.PasswordFile = runtimeConfig.Storage.PostgreSQL.Runtime.PasswordFile
	if _, err := openIntegrationOperatorRunner(ctx, t, runtimeOperator).Apply(ctx,
		postgresadapter.OperatorApplyOptions{AfterRollout: true}); !errors.Is(err, postgresadapter.ErrOperatorPreflight) {
		t.Fatalf("Apply() as the runtime role = %v, want preflight refusal", err)
	}
}

func createOperatorStepDatabase(ctx context.Context, t *testing.T, admin *pgx.Conn) string {
	t.Helper()
	var database string
	if err := admin.QueryRow(ctx, `SELECT 'mesh_operator_steps_'||replace(gen_random_uuid()::TEXT,'-','')`).Scan(&database); err != nil {
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
			t.Errorf("remove operator step database: %v", err)
		}
	})
	if _, err := openFreshAdmin(ctx, t, admin, database).Exec(ctx, "CREATE EXTENSION btree_gist"); err != nil {
		t.Fatal(err)
	}
	return database
}

func openFreshAdmin(ctx context.Context, t *testing.T, admin *pgx.Conn, database string) *pgx.Conn {
	t.Helper()
	freshConfig := admin.Config().Copy()
	freshConfig.Database = database
	connection, err := pgx.ConnectConfig(ctx, freshConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close(context.WithoutCancel(ctx)) })
	return connection
}

func openIntegrationOperatorRunner(ctx context.Context, t *testing.T, operatorConfig config.MigrationConfig) *postgresadapter.OperatorRunner {
	t.Helper()
	runner, err := postgresadapter.OpenOperatorRunner(ctx, postgresadapter.OperatorOptions{
		Address:          operatorConfig.PostgreSQL.Address,
		Database:         operatorConfig.PostgreSQL.Database,
		User:             operatorConfig.PostgreSQL.User,
		PasswordFile:     operatorConfig.PostgreSQL.PasswordFile,
		CAFile:           operatorConfig.PostgreSQL.CAFile,
		ConnectTimeout:   operatorConfig.ConnectTimeout,
		LockTimeout:      operatorConfig.LockTimeout,
		StatementTimeout: operatorConfig.StatementTimeout,
	})
	if err != nil {
		t.Fatalf("OpenOperatorRunner() error = %v", err)
	}
	t.Cleanup(func() {
		closeContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), operatorConfig.ConnectTimeout)
		defer cancel()
		if err := runner.Close(closeContext); err != nil {
			t.Errorf("OperatorRunner.Close() error = %v", err)
		}
	})
	return runner
}

func openOperatorStepWorkerPool(ctx context.Context, t *testing.T, adminConfig config.MigrationConfig, database string) *postgresadapter.Pool {
	t.Helper()
	workerConfig := loadIntegrationWorkerConfig(t, adminConfig)
	postgresConfig := workerConfig.Storage.PostgreSQL
	pool, err := postgresadapter.Open(ctx, postgresadapter.Options{
		Role: postgresadapter.PoolRoleWorker, Address: postgresConfig.Address, Database: database,
		User: postgresConfig.Worker.User, PasswordFile: postgresConfig.Worker.PasswordFile, CAFile: postgresConfig.CAFile,
		MaxConnections: 2, ConnectTimeout: workerConfig.Dependencies.CheckTimeout,
		OperatorStepCheckInterval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pool.Close(); err != nil {
			t.Errorf("operator step worker pool Close() error = %v", err)
		}
	})
	return pool
}

// waitOperatorStepGauge runs readiness checks, which must pass whatever is
// pending and only wake the background step read, until the pending-step
// gauge shows want.
func waitOperatorStepGauge(ctx context.Context, t *testing.T, pool *postgresadapter.Pool, want float64) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if err := pool.Check(ctx); err != nil {
			t.Fatalf("Check() = %v", err)
		}
		got, ok := poolGauge(t, pool, "meshtransit_postgres_operator_steps_pending", "")
		if ok && got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pending operator steps gauge = %v (exported %t), want %v", got, ok, want)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func aliasWorkerVersion(ctx context.Context, t *testing.T, pool *postgresadapter.Pool) float64 {
	t.Helper()
	store, err := postgresadapter.NewDeviceAliasWorkerStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	installation, err := deployment.ParseID(integrationDeploymentPublicID)
	if err != nil {
		t.Fatal(err)
	}
	// Discovery selects the version first; the fallback functions may not
	// be granted on a database no step ran on, so only the version counts.
	_, _ = store.List(ctx, installation, devicealias.Cursor{}, 1)
	version, ok := poolGauge(t, pool, "meshtransit_postgres_function_version", "device_alias_worker")
	if !ok {
		t.Fatal("alias worker version not exported")
	}
	return version
}

func poolGauge(t *testing.T, pool *postgresadapter.Pool, name, path string) (float64, bool) {
	t.Helper()
	collector, err := postgresadapter.NewMetricsCollector(pool)
	if err != nil {
		t.Fatal(err)
	}
	registry := prometheus.NewRegistry()
	if err := registry.Register(collector); err != nil {
		t.Fatal(err)
	}
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			matches := path == ""
			for _, label := range metric.GetLabel() {
				if label.GetName() == "path" && label.GetValue() == path {
					matches = true
				}
			}
			if matches {
				return metric.GetGauge().GetValue(), true
			}
		}
	}
	return 0, false
}

func operatorStepStatus(t *testing.T, report postgresadapter.OperatorReport, name string) postgresadapter.OperatorStepStatus {
	t.Helper()
	for _, step := range report.Steps {
		if step.Name == name {
			return step
		}
	}
	t.Fatalf("step %s not reported", name)
	return postgresadapter.OperatorStepStatus{}
}

func assertNoPendingOperatorSteps(ctx context.Context, t *testing.T, migrationConfig config.MigrationConfig) {
	t.Helper()
	verification, err := openIntegrationMigrationRunner(ctx, t, migrationConfig).Verify(ctx)
	if err != nil || len(verification.Operator.Pending()) != 0 {
		t.Fatalf("Verify() = pending %+v, %v", verification.Operator.Pending(), err)
	}
}

// assertCreateRoleOperator: on PostgreSQL 16 and later a CREATEROLE role that
// creates a role holds it WITH ADMIN, without INHERIT or SET. That grant is
// neither counted as a membership nor refused by the operator preflight;
// one that lets the operator act as the role is.
func assertCreateRoleOperator(ctx context.Context, t *testing.T, admin *pgx.Conn, operatorConfig,
	migrationConfig config.MigrationConfig) {
	t.Helper()
	secret := make([]byte, 24)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(secret)
	passwordFile := filepath.Join(t.TempDir(), "operator-password")
	if err := os.WriteFile(passwordFile, []byte(password), 0o600); err != nil {
		t.Fatal(err)
	}
	const operatorRole = "meshtransit_test_createrole_operator"
	if _, err := admin.Exec(ctx, "CREATE ROLE "+operatorRole+" LOGIN CREATEROLE PASSWORD '"+password+"'"); err != nil {
		t.Fatal(err)
	}
	database := pgx.Identifier{operatorConfig.PostgreSQL.Database}.Sanitize()
	inDatabase := openFreshAdmin(ctx, t, admin, operatorConfig.PostgreSQL.Database)
	dropOperator := func(ctx context.Context) error {
		if _, err := inDatabase.Exec(ctx, "DROP OWNED BY "+operatorRole); err != nil {
			return err
		}
		if _, err := admin.Exec(ctx, "REVOKE CONNECT ON DATABASE "+database+" FROM "+operatorRole); err != nil {
			return err
		}
		_, err := admin.Exec(ctx, "DROP ROLE "+operatorRole)
		return err
	}
	t.Cleanup(func() { _ = dropOperator(context.WithoutCancel(ctx)) })
	// What a non-superuser operator needs besides CREATEROLE: to connect
	// and to read the schema state.
	if _, err := admin.Exec(ctx, "GRANT CONNECT ON DATABASE "+database+" TO "+operatorRole); err != nil {
		t.Fatal(err)
	}
	if _, err := inDatabase.Exec(ctx, "GRANT USAGE ON SCHEMA mesh_ops TO "+operatorRole+
		"; GRANT SELECT ON mesh_ops.schema_compatibility TO "+operatorRole); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "GRANT mesh_direct_map_reader TO "+operatorRole+
		" WITH ADMIN OPTION, INHERIT FALSE, SET FALSE"); err != nil {
		t.Fatal(err)
	}
	loaded, err := config.LoadOperatorMigration(func(key string) (string, bool) {
		values := map[string]string{
			"MESHTRANSIT_OPERATOR_POSTGRES_ADDRESS":       operatorConfig.PostgreSQL.Address,
			"MESHTRANSIT_OPERATOR_POSTGRES_DATABASE":      operatorConfig.PostgreSQL.Database,
			"MESHTRANSIT_OPERATOR_POSTGRES_USER":          operatorRole,
			"MESHTRANSIT_OPERATOR_POSTGRES_PASSWORD_FILE": passwordFile,
			"MESHTRANSIT_OPERATOR_POSTGRES_CA_FILE":       os.Getenv("MESHTRANSIT_MIGRATION_POSTGRES_CA_FILE"),
		}
		value, ok := values[key]
		return value, ok
	})
	if err != nil {
		t.Fatal(err)
	}
	asOperator := operatorConfig
	asOperator.PostgreSQL = loaded.PostgreSQL
	createRoleOperator := openIntegrationOperatorRunner(ctx, t, asOperator)
	report, err := createRoleOperator.Status(ctx)
	if err != nil || !report.Complete() {
		t.Fatalf("CREATEROLE operator Status() = memberships %v pending %v, %v", report.Memberships, report.Pending(), err)
	}
	// With every step applied, its apply runs nothing and succeeds.
	if result, err := createRoleOperator.Apply(ctx, postgresadapter.OperatorApplyOptions{AfterRollout: true}); err != nil ||
		len(result.Applied) != 0 {
		t.Fatalf("CREATEROLE operator Apply() = %+v, %v", result.Applied, err)
	}
	verification, err := openIntegrationMigrationRunner(ctx, t, migrationConfig).Verify(ctx)
	if err != nil || !verification.Operator.Complete() {
		t.Fatalf("Verify() with an admin-only grant = %+v, %v", verification.Operator.Memberships, err)
	}
	if _, err := admin.Exec(ctx, "GRANT mesh_direct_map_reader TO "+operatorRole+" WITH INHERIT TRUE"); err != nil {
		t.Fatal(err)
	}
	if _, err := openIntegrationOperatorRunner(ctx, t, asOperator).Status(ctx); !errors.Is(err, postgresadapter.ErrOperatorPreflight) {
		t.Fatalf("Status() as a member of an owner role = %v", err)
	}
	verification, err = openIntegrationMigrationRunner(ctx, t, migrationConfig).Verify(ctx)
	if err != nil || !slices.Contains(verification.Operator.Memberships,
		operatorRole+" is a member of mesh_direct_map_reader") {
		t.Fatalf("Verify() with an inheriting grant = %+v, %v", verification.Operator.Memberships, err)
	}
	if err := dropOperator(ctx); err != nil {
		t.Fatal(err)
	}
}

// assertOperatorLogins qualifies TD-SEC-90 S1: the operator keeps the
// mesh_control login, created with its password and a member of
// mesh_runtime only (inherit, no set role); a repeat with the same password
// changes nothing; another password replaces it; the membership is not
// reported; the login connects and holds what the runtime role holds.
func assertOperatorLogins(ctx context.Context, t *testing.T, admin *pgx.Conn,
	operator *postgresadapter.OperatorRunner, operatorConfig, migrationConfig config.MigrationConfig) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = admin.Exec(context.WithoutCancel(ctx), "DROP ROLE IF EXISTS mesh_control")
	})
	keepOrRotate := func(password string, rotate bool) ([]postgresadapter.OperatorLoginResult, error) {
		t.Helper()
		result, err := operator.Apply(ctx, postgresadapter.OperatorApplyOptions{AfterRollout: true,
			LoginPasswords: map[string][]byte{"mesh_control": []byte(password)}, RotateLoginPasswords: rotate})
		return result.Logins, err
	}
	keep := func(password string) []postgresadapter.OperatorLoginResult {
		t.Helper()
		logins, err := keepOrRotate(password, false)
		if err != nil {
			t.Fatalf("Apply(login) = %v", err)
		}
		return logins
	}
	first := strings.Repeat("Kq7x", 10)
	if logins := keep(first); len(logins) != 1 || logins[0].Name != "mesh_control" || !logins[0].PasswordChanged {
		t.Fatalf("first login apply = %+v", logins)
	}
	if logins := keep(first); len(logins) != 1 || logins[0].Created || logins[0].PasswordChanged {
		t.Fatalf("repeat login apply = %+v, want no change", logins)
	}
	var superuser, inherits, setsRole, member bool
	if err := admin.QueryRow(ctx, `SELECT role.rolsuper OR role.rolcreaterole OR role.rolbypassrls OR NOT role.rolcanlogin,
    membership.inherit_option, membership.set_option,
    pg_catalog.pg_has_role('mesh_control', 'mesh_runtime', 'USAGE')
FROM pg_catalog.pg_roles AS role
JOIN pg_catalog.pg_auth_members AS membership ON membership.member = role.oid
JOIN pg_catalog.pg_roles AS granted ON granted.oid = membership.roleid AND granted.rolname = 'mesh_runtime'
WHERE role.rolname = 'mesh_control'`).Scan(&superuser, &inherits, &setsRole, &member); err != nil {
		t.Fatal(err)
	}
	if superuser || !inherits || setsRole || !member {
		t.Fatalf("mesh_control attributes: privileged %v inherit %v set %v member %v", superuser, inherits, setsRole, member)
	}
	verification, err := openIntegrationMigrationRunner(ctx, t, migrationConfig).Verify(ctx)
	if err != nil || len(verification.Operator.Memberships) != 0 {
		t.Fatalf("Verify() with the mesh_control login = %+v, %v", verification.Operator.Memberships, err)
	}
	// S2.2 (review blocker): mesh_runtime is a creation-only membership.
	// Once removed (S2.3), an apply of this release keeps it removed, while
	// the group membership comes back.
	if _, err := admin.Exec(ctx, "REVOKE mesh_runtime FROM mesh_control; REVOKE mesh_control_rights FROM mesh_control"); err != nil {
		t.Fatal(err)
	}
	keep(first)
	var inRuntime, inGroup bool
	if err := admin.QueryRow(ctx, `SELECT
    EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members AS m WHERE m.member = 'mesh_control'::REGROLE AND m.roleid = 'mesh_runtime'::REGROLE),
    EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members AS m WHERE m.member = 'mesh_control'::REGROLE AND m.roleid = 'mesh_control_rights'::REGROLE)`).Scan(
		&inRuntime, &inGroup); err != nil {
		t.Fatal(err)
	}
	if inRuntime || !inGroup {
		t.Fatalf("apply after S2.3 removed mesh_runtime: in mesh_runtime %v, in mesh_control_rights %v", inRuntime, inGroup)
	}
	if _, err := admin.Exec(ctx, "GRANT mesh_runtime TO mesh_control WITH INHERIT TRUE, SET FALSE"); err != nil {
		t.Fatal(err)
	}
	// A different password is refused: the running pods use the stored one.
	second := strings.Repeat("Zr4m", 10)
	if _, err := keepOrRotate(second, false); !errors.Is(err, postgresadapter.ErrOperatorLoginPasswordDiffers) {
		t.Fatalf("Apply(another password) = %v, want ErrOperatorLoginPasswordDiffers", err)
	}
	if logins, err := keepOrRotate(second, true); err != nil || len(logins) != 1 || !logins[0].PasswordChanged {
		t.Fatalf("rotate password apply = %+v, %v", logins, err)
	}
	// A role granted mesh_control would inherit the runtime role: the
	// migrator refuses to run.
	if _, err := admin.Exec(ctx, "CREATE ROLE mesh_operator_test_heir NOLOGIN; GRANT mesh_control TO mesh_operator_test_heir"); err != nil {
		t.Fatal(err)
	}
	if _, err := openIntegrationMigrationRunner(ctx, t, migrationConfig).Verify(ctx); !errors.Is(err,
		postgresadapter.ErrMigrationPreflight) {
		t.Fatalf("Verify() with mesh_control granted onward = %v, want preflight refusal", err)
	}
	if _, err := admin.Exec(ctx, "DROP ROLE mesh_operator_test_heir"); err != nil {
		t.Fatal(err)
	}
	passwordPath := filepath.Join(t.TempDir(), "control-password")
	if err := os.WriteFile(passwordPath, []byte(second), 0o600); err != nil {
		t.Fatal(err)
	}
	passwordFile, err := config.NewSecretFile(passwordPath)
	if err != nil {
		t.Fatal(err)
	}
	control := openIntegrationPostgreSQLConnection(ctx, t, operatorConfig.PostgreSQL.Address,
		operatorConfig.PostgreSQL.Database, "mesh_control", passwordFile, operatorConfig.PostgreSQL.CAFile,
		operatorConfig.ConnectTimeout)
	var executes bool
	if err := control.QueryRow(ctx, `SELECT pg_catalog.has_function_privilege(
    'mesh_ops.current_workspace_id()', 'EXECUTE')`).Scan(&executes); err != nil || !executes {
		t.Fatalf("mesh_control runs a runtime function: %v, %v", executes, err)
	}
	// Core accepts the login as its runtime role (schema check, TD-SEC-90 S1).
	pool, err := postgresadapter.Open(ctx, postgresadapter.Options{
		Role: postgresadapter.PoolRoleRuntime, Address: operatorConfig.PostgreSQL.Address,
		Database: operatorConfig.PostgreSQL.Database, User: "mesh_control", PasswordFile: passwordFile,
		CAFile: operatorConfig.PostgreSQL.CAFile, MaxConnections: 2, ConnectTimeout: operatorConfig.ConnectTimeout,
	})
	if err != nil {
		t.Fatalf("open a runtime pool as mesh_control: %v", err)
	}
	if err := pool.Close(); err != nil {
		t.Fatal(err)
	}
	// Any other membership of the login is still reported.
	if _, err := admin.Exec(ctx, "GRANT mesh_observer TO mesh_control"); err != nil {
		t.Fatal(err)
	}
	if report, err := operator.Status(ctx); err != nil ||
		!slices.Equal(report.Memberships, []string{"mesh_control is a member of mesh_observer"}) {
		t.Fatalf("Status() with an extra login membership = %v, %v", report.Memberships, err)
	}
	if _, err := admin.Exec(ctx, "REVOKE mesh_observer FROM mesh_control"); err != nil {
		t.Fatal(err)
	}
	if _, err := operator.Apply(ctx, postgresadapter.OperatorApplyOptions{AfterRollout: true,
		LoginPasswords: map[string][]byte{"mesh_control": []byte("short")}}); !errors.Is(err,
		postgresadapter.ErrInvalidLoginPassword) {
		t.Fatalf("Apply(short password) = %v, want ErrInvalidLoginPassword", err)
	}
	if _, err := operator.Apply(ctx, postgresadapter.OperatorApplyOptions{AfterRollout: true,
		LoginPasswords: map[string][]byte{"mesh_runtime": []byte(first)}}); !errors.Is(err,
		postgresadapter.ErrInvalidOperatorOptions) {
		t.Fatalf("Apply(password for a non-login role) = %v, want ErrInvalidOperatorOptions", err)
	}
}

// Role isolation S2 (design §3.5): apply keeps the two group roles NOLOGIN
// with no special right (N0) and, from S2.2, mesh_runtime a member of the
// api's group, inherit only, restoring it when removed or changed; the
// migrator's checks accept that membership, while a crossed pair, SET or
// ADMIN, or a group that is itself a member of something is refused.
func assertOperatorGroups(ctx context.Context, t *testing.T, admin *pgx.Conn,
	operator *postgresadapter.OperatorRunner, migrationConfig config.MigrationConfig) {
	t.Helper()
	applyResult := func(dryRun bool) postgresadapter.OperatorApplyResult {
		t.Helper()
		result, err := operator.Apply(ctx, postgresadapter.OperatorApplyOptions{AfterRollout: true, DryRun: dryRun})
		if err != nil {
			t.Fatalf("Apply(groups, dry run %v) = %v", dryRun, err)
		}
		return result
	}
	apply := func(dryRun bool) []postgresadapter.OperatorGroupResult {
		t.Helper()
		return applyResult(dryRun).Groups
	}
	exec := func(statement string) {
		t.Helper()
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	count := func(query string) int {
		t.Helper()
		var value int
		if err := admin.QueryRow(ctx, query).Scan(&value); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		return value
	}
	const groupNames = `('mesh_api_rights', 'mesh_control_rights')`
	// The groups exist (migrations grant to them since S2.2): apply keeps
	// them and creates nothing.
	if groups := apply(false); len(groups) != 2 || groups[0].Name != "mesh_api_rights" ||
		groups[1].Name != "mesh_control_rights" || groups[0].Created || groups[1].Created {
		t.Fatalf("groups = %+v", groups)
	}
	plain := func() bool {
		t.Helper()
		return count(`SELECT pg_catalog.count(*)::INT FROM pg_catalog.pg_roles AS role
WHERE role.rolname IN `+groupNames+` AND NOT role.rolcanlogin AND NOT role.rolsuper AND NOT role.rolcreatedb
  AND NOT role.rolcreaterole AND NOT role.rolreplication AND NOT role.rolbypassrls AND role.rolconnlimit = -1
  AND role.rolconfig IS NULL
  AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_db_role_setting AS setting WHERE setting.setrole = role.oid)`) == 2
	}
	if !plain() {
		t.Fatal("group roles are not plain NOLOGIN roles")
	}
	// A group is a member of nothing.
	if n := count(`SELECT pg_catalog.count(*)::INT FROM pg_catalog.pg_auth_members AS membership
JOIN pg_catalog.pg_roles AS role ON role.oid = membership.member
WHERE role.rolname IN ` + groupNames); n != 0 {
		t.Fatalf("group roles are members of %d roles", n)
	}
	// S2.2: mesh_runtime joins the api's group, inherit only; a removed or
	// changed membership is restored, a dry run commits nothing.
	membership := func() (present, inherit, set, adminOption bool) {
		t.Helper()
		err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) = 1, COALESCE(pg_catalog.bool_and(membership.inherit_option), FALSE),
    COALESCE(pg_catalog.bool_or(membership.set_option), FALSE), COALESCE(pg_catalog.bool_or(membership.admin_option), FALSE)
FROM pg_catalog.pg_auth_members AS membership
JOIN pg_catalog.pg_roles AS member_role ON member_role.oid = membership.member
JOIN pg_catalog.pg_roles AS granted_role ON granted_role.oid = membership.roleid
WHERE member_role.rolname = 'mesh_runtime' AND granted_role.rolname = 'mesh_api_rights'`).Scan(
			&present, &inherit, &set, &adminOption)
		if err != nil {
			t.Fatal(err)
		}
		return present, inherit, set, adminOption
	}
	held := func() bool {
		t.Helper()
		present, inherit, set, adminOption := membership()
		return present && inherit && !set && !adminOption
	}
	if !held() {
		t.Fatal("apply did not make mesh_runtime an inheriting member of mesh_api_rights")
	}
	if result := applyResult(false); len(result.Memberships) != 1 || result.Memberships[0].Granted {
		t.Fatalf("repeat membership apply = %+v, want no change", result.Memberships)
	}
	exec("REVOKE mesh_api_rights FROM mesh_runtime")
	if result := applyResult(true); len(result.Memberships) != 1 || !result.Memberships[0].Granted {
		t.Fatalf("dry-run membership apply = %+v", result.Memberships)
	}
	if present, _, _, _ := membership(); present {
		t.Fatal("a dry run left the membership behind")
	}
	if result := applyResult(false); len(result.Memberships) != 1 || !result.Memberships[0].Granted || !held() {
		t.Fatalf("membership apply after a removal = %+v", result.Memberships)
	}
	for _, statement := range []string{"GRANT mesh_api_rights TO mesh_runtime WITH SET TRUE",
		"GRANT mesh_api_rights TO mesh_runtime WITH ADMIN OPTION",
		"GRANT mesh_api_rights TO mesh_runtime WITH INHERIT FALSE"} {
		exec(statement)
		if held() {
			t.Fatalf("%q did not change the membership", statement)
		}
		if result := applyResult(false); !result.Memberships[0].Granted || !held() {
			t.Fatalf("apply after %q = %+v", statement, result.Memberships)
		}
	}
	// Drift is reset: attributes and settings.
	exec("ALTER ROLE mesh_api_rights LOGIN CREATEDB CONNECTION LIMIT 3")
	exec("ALTER ROLE mesh_control_rights SET work_mem = '8MB'")
	var database string
	if err := admin.QueryRow(ctx, "SELECT pg_catalog.current_database()").Scan(&database); err != nil {
		t.Fatal(err)
	}
	exec("ALTER ROLE mesh_api_rights IN DATABASE " + pgx.Identifier{database}.Sanitize() + " SET work_mem = '8MB'")
	apply(false)
	if !plain() {
		t.Fatal("apply did not reset a changed group role")
	}
	verify := func() error {
		t.Helper()
		_, err := openIntegrationMigrationRunner(ctx, t, migrationConfig).Verify(ctx)
		return err
	}
	t.Cleanup(func() {
		for _, statement := range []string{"REVOKE mesh_control_rights FROM mesh_runtime",
			"REVOKE pg_read_all_data FROM mesh_api_rights"} {
			_, _ = admin.Exec(context.WithoutCancel(ctx), statement)
		}
	})
	// The membership S2.2 keeps passes the migrator's checks…
	exec("GRANT mesh_api_rights TO mesh_runtime WITH INHERIT TRUE, SET FALSE")
	if err := verify(); err != nil {
		t.Fatalf("Verify() with mesh_runtime in mesh_api_rights = %v", err)
	}
	if report, err := operator.Status(ctx); err != nil || len(report.Memberships) != 0 {
		t.Fatalf("operator status with mesh_runtime in mesh_api_rights = %v, %v", report.Memberships, err)
	}
	// …but not with SET or ADMIN,…
	for _, statement := range []string{"GRANT mesh_api_rights TO mesh_runtime WITH SET TRUE",
		"GRANT mesh_api_rights TO mesh_runtime WITH ADMIN OPTION"} {
		exec(statement)
		if err := verify(); !errors.Is(err, postgresadapter.ErrMigrationPreflight) {
			t.Fatalf("Verify() after %q = %v, want preflight refusal", statement, err)
		}
		exec("REVOKE mesh_api_rights FROM mesh_runtime")
		exec("GRANT mesh_api_rights TO mesh_runtime WITH INHERIT TRUE, SET FALSE")
	}
	// …nor with the group itself a member of something,…
	exec("GRANT pg_read_all_data TO mesh_api_rights")
	if err := verify(); !errors.Is(err, postgresadapter.ErrMigrationPreflight) {
		t.Fatalf("Verify() with mesh_api_rights in pg_read_all_data = %v, want preflight refusal", err)
	}
	exec("REVOKE pg_read_all_data FROM mesh_api_rights")
	// …and the crossed pair is refused and reported.
	exec("GRANT mesh_control_rights TO mesh_runtime WITH INHERIT TRUE, SET FALSE")
	if err := verify(); !errors.Is(err, postgresadapter.ErrMigrationPreflight) {
		t.Fatalf("Verify() with mesh_runtime in mesh_control_rights = %v, want preflight refusal", err)
	}
	if report, err := operator.Status(ctx); err != nil ||
		!slices.Contains(report.Memberships, "mesh_runtime is a member of mesh_control_rights") {
		t.Fatalf("operator status with the crossed pair = %v, %v", report.Memberships, err)
	}
	exec("REVOKE mesh_control_rights FROM mesh_runtime")
	// The kept membership stays for what follows (a CREATEROLE operator
	// without ADMIN on the group cannot grant it again).
	if !held() {
		t.Fatal("the membership S2.2 keeps is gone")
	}
}
