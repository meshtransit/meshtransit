//go:build integration

package integration

import (
	"context"
	"errors"
	"os"
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
	waitOperatorStepGauge(ctx, t, worker, 0)
	if version := aliasWorkerVersion(ctx, t, worker); version != 5 {
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
