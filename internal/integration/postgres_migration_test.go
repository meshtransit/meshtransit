//go:build integration

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/config"
)

func TestPostgreSQLMigrations(t *testing.T) {
	if os.Getenv("MESHTRANSIT_MIGRATION_INTEGRATION") != "1" {
		t.Skip("set MESHTRANSIT_MIGRATION_INTEGRATION=1 with a disposable empty PostgreSQL database")
	}
	migrationConfig, err := config.LoadMigration(os.LookupEnv)
	if err != nil {
		t.Fatalf("config.LoadMigration() error = %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()

	runners := make([]*postgresadapter.MigrationRunner, 2)
	for index := range runners {
		runners[index] = openIntegrationMigrationRunner(t, ctx, migrationConfig)
	}
	initialStatus, err := runners[0].Status(ctx)
	if err != nil {
		t.Fatalf("initial MigrationRunner.Status() error = %v", err)
	}
	if initialStatus.State != postgresadapter.MigrationStateUninitialized {
		t.Fatalf("initial MigrationRunner.Status() = %+v, want uninitialized", initialStatus)
	}

	type outcome struct {
		result postgresadapter.MigrationResult
		err    error
	}
	outcomes := make(chan outcome, len(runners))
	for _, runner := range runners {
		go func() {
			result, runErr := runner.Up(ctx)
			outcomes <- outcome{result: result, err: runErr}
		}()
	}

	results := make([]outcome, 0, len(runners))
	for range runners {
		select {
		case result := <-outcomes:
			results = append(results, result)
		case <-ctx.Done():
			t.Fatalf("wait for concurrent migration result: %v", ctx.Err())
		}
	}

	applied := 0
	for _, outcome := range results {
		if outcome.err != nil {
			t.Fatalf("MigrationRunner.Up() error = %v", outcome.err)
		}
		if outcome.result.Status.State != postgresadapter.MigrationStateClean ||
			outcome.result.Status.CurrentVersion != outcome.result.Status.LatestVersion {
			t.Fatalf("MigrationRunner.Up() status = %+v, want current clean schema", outcome.result.Status)
		}
		applied += outcome.result.Applied
	}
	if applied != int(initialStatus.LatestVersion) {
		t.Fatalf(
			"concurrent applied migration count = %d, want exactly %d",
			applied,
			initialStatus.LatestVersion,
		)
	}

	status, err := runners[0].Status(ctx)
	if err != nil {
		t.Fatalf("MigrationRunner.Status() error = %v", err)
	}
	if status.State != postgresadapter.MigrationStateClean || status.CurrentVersion != status.LatestVersion {
		t.Fatalf("MigrationRunner.Status() = %+v, want current clean schema", status)
	}
	result, err := runners[0].Up(ctx)
	if err != nil {
		t.Fatalf("idempotent MigrationRunner.Up() error = %v", err)
	}
	if result.Applied != 0 {
		t.Fatalf("idempotent MigrationRunner.Up() applied = %d, want 0", result.Applied)
	}

	processConfig, err := config.Load(os.LookupEnv)
	if err != nil {
		t.Fatalf("config.Load() runtime settings error = %v", err)
	}
	if processConfig.Storage == nil {
		t.Fatal("runtime integration configuration did not load storage")
	}
	postgresConfig := processConfig.Storage.PostgreSQL
	if postgresConfig.Runtime == nil {
		t.Fatal("runtime integration configuration did not load runtime PostgreSQL credentials")
	}
	runtimePostgreSQL := *postgresConfig.Runtime
	runtimePool, err := postgresadapter.Open(ctx, postgresadapter.Options{
		Role:           postgresadapter.PoolRoleRuntime,
		Address:        postgresConfig.Address,
		Database:       postgresConfig.Database,
		User:           runtimePostgreSQL.User,
		PasswordFile:   runtimePostgreSQL.PasswordFile,
		CAFile:         postgresConfig.CAFile,
		MaxConnections: runtimePostgreSQL.MaxConnections,
		ConnectTimeout: processConfig.Dependencies.CheckTimeout,
	})
	if err != nil {
		t.Fatalf("postgres.Open() runtime compatibility pool error = %v", err)
	}
	t.Cleanup(func() {
		if err := runtimePool.Close(); err != nil {
			t.Errorf("runtime compatibility pool Close() error = %v", err)
		}
	})
	if err := runtimePool.Check(ctx); err != nil {
		t.Fatalf("runtime compatibility pool Check() error = %v", err)
	}

	adminConfig := loadIntegrationAdminConfig(t)
	adminConnection := openIntegrationPostgreSQLConnection(
		t,
		ctx,
		adminConfig.PostgreSQL.Address,
		adminConfig.PostgreSQL.Database,
		adminConfig.PostgreSQL.User,
		adminConfig.PostgreSQL.PasswordFile,
		adminConfig.PostgreSQL.CAFile,
		adminConfig.ConnectTimeout,
	)
	seedAuthorityFixture(t, ctx, adminConnection)
	assertAuthorityEvidenceFoundation(t, ctx, adminConnection)
	assertAuthorityMutationAtomicity(t, ctx, adminConnection)
	assertAuthorityConstraints(t, ctx, adminConnection)
	assertDatabasePrivilegeContract(t, ctx, adminConnection)

	runtimeConnection := openIntegrationPostgreSQLConnection(
		t,
		ctx,
		postgresConfig.Address,
		postgresConfig.Database,
		runtimePostgreSQL.User,
		runtimePostgreSQL.PasswordFile,
		postgresConfig.CAFile,
		processConfig.Dependencies.CheckTimeout,
	)
	assertRuntimeAuthorityIsolation(t, ctx, runtimeConnection)

	workerConnection := openIntegrationWorkerConnection(t, ctx, adminConfig)
	assertWorkerOutboxPrivilegeContract(t, ctx, workerConnection)
	workerPool := openIntegrationWorkerPool(t, ctx, adminConfig)
	assertWorkerOutboxDelivery(t, ctx, adminConnection, workerPool)
	assertRevisionDispatcherDelivery(t, ctx, adminConnection, workerPool)
	assertRevisionDispatcherRecovery(t, ctx, adminConnection, workerPool)
}
