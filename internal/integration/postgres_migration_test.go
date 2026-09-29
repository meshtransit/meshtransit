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
		runners[index] = openIntegrationMigrationRunner(ctx, t, migrationConfig)
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
		ctx,
		t,
		adminConfig.PostgreSQL.Address,
		adminConfig.PostgreSQL.Database,
		adminConfig.PostgreSQL.User,
		adminConfig.PostgreSQL.PasswordFile,
		adminConfig.PostgreSQL.CAFile,
		adminConfig.ConnectTimeout,
	)
	seedAuthorityFixture(ctx, t, adminConnection)
	assertAuthorityEvidenceFoundation(ctx, t, adminConnection)
	assertAuthorityMutationAtomicity(ctx, t, adminConnection)
	assertAuthorityConstraints(ctx, t, adminConnection)
	assertDatabasePrivilegeContract(ctx, t, adminConnection)
	assertCompiledPacketPolicyPrivilegeContract(ctx, t, adminConnection)
	assertPolicyApprovalPersistencePrivilegeContract(ctx, t, adminConnection)
	registrationReplayCommand := seedRegistrationAuthority(ctx, t, adminConnection)
	assertRegistrationSchemaConstraints(ctx, t, adminConnection)
	registrationReplayStore, err := postgresadapter.NewRegistrationReplayStore(runtimePool)
	if err != nil {
		t.Fatalf("postgres.NewRegistrationReplayStore() error = %v", err)
	}
	assertPostgreSQLRegistrationReplay(ctx, t, registrationReplayStore, registrationReplayCommand)
	assertPostgreSQLMapSessionSnapshot(ctx, t, runtimePool, registrationReplayCommand)

	runtimeConnection := openIntegrationPostgreSQLConnection(
		ctx,
		t,
		postgresConfig.Address,
		postgresConfig.Database,
		runtimePostgreSQL.User,
		runtimePostgreSQL.PasswordFile,
		postgresConfig.CAFile,
		processConfig.Dependencies.CheckTimeout,
	)
	runtimeContenderConnection := openIntegrationPostgreSQLConnection(
		ctx,
		t,
		postgresConfig.Address,
		postgresConfig.Database,
		runtimePostgreSQL.User,
		runtimePostgreSQL.PasswordFile,
		postgresConfig.CAFile,
		processConfig.Dependencies.CheckTimeout,
	)
	assertRuntimePublicNetworkScope(ctx, t, runtimeConnection)
	assertRuntimeRejectsInvalidPublicNetworkScope(ctx, t, runtimeConnection)
	assertRuntimeNetworkRevisionLock(ctx, t, runtimeConnection, runtimeContenderConnection)
	assertRuntimeNetworkAuditStreamHead(ctx, t, runtimeConnection, runtimeContenderConnection)
	assertRuntimeNetworkInventoryRevision(ctx, t, runtimeConnection)
	assertRuntimeAuthorityIsolation(ctx, t, runtimeConnection)
	assertRegistrationRuntimeIsolation(ctx, t, runtimeConnection)

	workerConnection := openIntegrationWorkerConnection(ctx, t, adminConfig)
	assertWorkerCannotSetPublicNetworkScope(ctx, t, workerConnection)
	assertWorkerCannotLockNetworkRevision(ctx, t, workerConnection)
	assertWorkerCannotLockNetworkAuditStream(ctx, t, workerConnection)
	assertWorkerCannotAdvanceNetworkInventoryRevision(ctx, t, workerConnection)
	assertWorkerCannotLockRegistrationResources(ctx, t, workerConnection)
	assertWorkerCannotResolveRegistrationIntakeScope(ctx, t, workerConnection)
	assertWorkerCannotResolveMapSessionScope(ctx, t, workerConnection)
	assertWorkerCannotResolveNodeKeyRotationScope(ctx, t, workerConnection)
	assertWorkerCannotLoadMapPeerCandidates(ctx, t, workerConnection)
	assertWorkerOutboxPrivilegeContract(ctx, t, workerConnection)
	workerPool := openIntegrationWorkerPool(ctx, t, adminConfig)
	assertWorkerOutboxDelivery(ctx, t, adminConnection, workerPool)
	assertRevisionDispatcherDelivery(ctx, t, adminConnection, workerPool)
	assertRevisionDispatcherRecovery(ctx, t, adminConnection, workerPool)

	openRegistrationCommand := seedOpenRegistrationAuthority(ctx, t, adminConnection)
	assertRegistrationTransactionLockHelpers(
		ctx,
		t,
		runtimeConnection,
		openRegistrationCommand,
	)
	assertPostgreSQLRegistrationTransaction(
		ctx,
		t,
		adminConnection,
		runtimePool,
		openRegistrationCommand,
	)
	assertPostgreSQLRegistrationServiceResume(
		ctx,
		t,
		adminConnection,
		runtimePool,
	)
	assertPostgreSQLRegistrationServiceConcurrency(
		ctx,
		t,
		adminConnection,
		runtimePool,
	)
	assertPostgreSQLRegistrationIntake(ctx, t, adminConnection, runtimePool)
	adminContenderConnection := openIntegrationPostgreSQLConnection(
		ctx,
		t,
		adminConfig.PostgreSQL.Address,
		adminConfig.PostgreSQL.Database,
		adminConfig.PostgreSQL.User,
		adminConfig.PostgreSQL.PasswordFile,
		adminConfig.PostgreSQL.CAFile,
		adminConfig.ConnectTimeout,
	)
	peerIdentity := assertPostgreSQLPeerCandidateProjection(
		ctx,
		t,
		adminConnection,
		adminContenderConnection,
		runtimePool,
	)
	assertCompiledPacketPolicyRuleImmutability(ctx, t, adminConnection)
	assertPostgreSQLPolicyPublication(ctx, t, adminConnection, runtimePool, peerIdentity)
	assertIdentityProviderSchemaFoundation(ctx, t, adminConnection, runtimeConnection)
	assertPostgreSQLAuthTransactionAdmission(ctx, t, adminConnection, runtimeConnection, runtimePool)
	assertPostgreSQLPendingBrowserEvidence(ctx, t, adminConnection, runtimeConnection, runtimePool)
	assertPostgreSQLBrowserClaim(ctx, t, adminConnection, runtimeConnection, runtimePool)
	assertPostgreSQLBrowserFailure(ctx, t, adminConnection, runtimeConnection, runtimePool)
	assertPostgreSQLAuthTransaction(ctx, t, adminConnection, adminContenderConnection, runtimePool)
	assertAccountIdentityPermissionFoundation(ctx, t, adminConnection, runtimeConnection)
	assertHumanAuthenticationSessionAuthority(
		ctx,
		t,
		adminConnection,
		adminContenderConnection,
		runtimeConnection,
		runtimePool,
	)
	assertNetworkManagementRBACAuthority(ctx, t, adminConnection, runtimeConnection)
	assertPostgreSQLConsoleManagementScopes(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLResourceAuthority(
		ctx,
		t,
		adminConnection,
		runtimeConnection,
		runtimePool,
		workerConnection,
	)
	assertPostgreSQLLoginSubjectResolution(ctx, t, adminConnection, runtimeConnection, runtimePool)
	assertPostgreSQLSessionIssuance(ctx, t, adminConnection, runtimeConnection, runtimePool)
	assertPostgreSQLBrowserCallback(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLAbandonedExpiry(ctx, t, adminConnection,
		openIntegrationWorkerConnection(ctx, t, adminConfig), openIntegrationWorkerPool(ctx, t, adminConfig), runtimePool)
	assertPostgreSQLManagementPolicyPublication(
		ctx,
		t,
		adminConnection,
		runtimePool,
		peerIdentity,
	)
	assertPostgreSQLNodeKeyRotation(
		ctx,
		t,
		adminConnection,
		runtimePool,
		registrationReplayCommand,
	)
	assertPostgreSQLDeviceRevocation(
		ctx,
		t,
		adminConnection,
		runtimePool,
		peerIdentity,
	)
	assertPostgreSQLAccountSessionLogout(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLRevokedConsoleManagementScopes(ctx, t, runtimePool)
}
