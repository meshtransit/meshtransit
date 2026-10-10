//go:build integration

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/core/migrations"
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
	for range 2 {
		if _, err := adminConnection.Exec(ctx, migrations.ImportedPolicySimulationReaderOwnershipSQL()); err != nil {
			t.Fatalf("apply idempotent Imported policy baseline reader ownership: %v", err)
		}
		if _, err := adminConnection.Exec(ctx, migrations.ResourceSharingFunctionOwnershipSQL()); err != nil {
			t.Fatalf("apply idempotent Resource Sharing function ownership hardening: %v", err)
		}
		if _, err := adminConnection.Exec(
			ctx,
			migrations.PolicyImportedResourceFunctionOwnershipSQL(),
		); err != nil {
			t.Fatalf("apply idempotent Imported Resource resolver ownership hardening: %v", err)
		}
		if _, err := adminConnection.Exec(
			ctx,
			migrations.ResourceSharingAccessNameFunctionOwnershipSQL(),
		); err != nil {
			t.Fatalf("apply idempotent Resource Sharing access-name ownership hardening: %v", err)
		}
		if _, err := adminConnection.Exec(
			ctx,
			migrations.ResourceSharingPrivateEndpointFunctionOwnershipSQL(),
		); err != nil {
			t.Fatalf("apply idempotent Resource Sharing Private Endpoint ownership hardening: %v", err)
		}
		if _, err := adminConnection.Exec(
			ctx,
			migrations.ResourceSharingEndpointPublicationOwnershipSQL(),
		); err != nil {
			t.Fatalf("apply idempotent Resource Sharing endpoint publication ownership hardening: %v", err)
		}
		if _, err := adminConnection.Exec(ctx, migrations.DirectDeviceEndpointFunctionOwnershipSQL()); err != nil {
			t.Fatalf("apply idempotent direct Device endpoint ownership hardening: %v", err)
		}
		if _, err := adminConnection.Exec(ctx, migrations.ExpiredUnprovisionedShareCleanupOwnershipSQL()); err != nil {
			t.Fatalf("apply idempotent expired Trust Contract cleanup ownership hardening: %v", err)
		}
		if _, err := adminConnection.Exec(ctx, migrations.ResourceSharingNeverExpiryOwnershipSQL()); err != nil {
			t.Fatalf("apply idempotent never-expiring share ownership hardening: %v", err)
		}
		if _, err := adminConnection.Exec(ctx, migrations.DirectDeviceMapFunctionOwnershipSQL()); err != nil {
			t.Fatalf("apply direct map reader ownership: %v", err)
		}
	}
	if _, err := adminConnection.Exec(ctx, migrations.DeviceAliasClientOwnershipSQL()); err != nil {
		t.Fatalf("harden alias compatibility observer: %v", err)
	}
	if _, err := adminConnection.Exec(ctx, migrations.DeviceAliasMapOwnershipSQL()); err != nil {
		t.Fatalf("harden alias map reader: %v", err)
	}
	if _, err := adminConnection.Exec(ctx, migrations.DeviceAliasWorkerOwnershipSQL()); err != nil {
		t.Fatal(err)
	}
	if _, err := adminConnection.Exec(ctx, migrations.DeviceAliasWithdrawalOwnershipSQL()); err != nil {
		t.Fatal(err)
	}
	if _, err := adminConnection.Exec(ctx, migrations.DeviceAliasWorkOwnershipSQL()); err != nil {
		t.Fatal(err)
	}
	if _, err := adminConnection.Exec(ctx, migrations.DeviceSharingDependenciesOwnershipSQL()); err != nil {
		t.Fatalf("harden sharing dependencies: %v", err)
	}
	if _, err := adminConnection.Exec(ctx, migrations.UnifiedDeviceAliasOwnershipSQL()); err != nil {
		t.Fatalf("harden unified Device alias entry points: %v", err)
	}
	if _, err := adminConnection.Exec(ctx, migrations.AliasMapReaderOwnershipSQL()); err != nil {
		t.Fatalf("harden bounded alias map reader: %v", err)
	}
	if _, err := adminConnection.Exec(ctx, migrations.ShareOfferAccessLabelOwnershipSQL()); err != nil {
		t.Fatalf("harden labeled share offer entry points: %v", err)
	}
	if _, err := adminConnection.Exec(ctx, migrations.TrustContractExpiryOwnershipSQL()); err != nil {
		t.Fatalf("harden Trust Contract expiry entry points: %v", err)
	}
	if _, err := adminConnection.Exec(ctx, migrations.AliasMapReachableSharesOwnershipSQL()); err != nil {
		t.Fatalf("harden reachable-share alias map reader: %v", err)
	}
	assertResourceSharingPrivilegeContract(ctx, t, adminConnection)
	assertDeviceSharingDeploymentPreflight(ctx, t, adminConnection)
	seedAuthorityFixture(ctx, t, adminConnection)
	assertAuthorityEvidenceFoundation(ctx, t, adminConnection)
	assertAuthorityMutationAtomicity(ctx, t, adminConnection)
	assertAuthorityConstraints(ctx, t, adminConnection)
	assertDatabasePrivilegeContract(ctx, t, adminConnection)
	assertBrowserRegistrationSchemaIsolation(ctx, t, adminConnection)
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
	assertPostgreSQLDeviceAliasClientVersion(ctx, t, adminConnection, runtimeConnection, runtimePool, registrationReplayCommand)
	assertPostgreSQLMTCPTimestamp(ctx, t, runtimePool, registrationReplayCommand)
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
	assertPostgreSQLConsoleDeviceInventory(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLDeviceDistribution(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLAccessEdgeLedger(ctx, t, adminConnection, workerPool, runtimePool)
	assertPostgreSQLDeviceEnforcementLedger(ctx, t, adminConnection, workerPool, runtimePool)
	assertPostgreSQLRelayRevocations(ctx, t, adminConnection, runtimePool)
	assertWorkspaceOwnerAuthority(ctx, t, adminConnection)
	assertBuiltinWorkspaceRoles(ctx, t, adminConnection)
	assertTenantDisplayIdentities(ctx, t, adminConnection)
	assertTenantDisplayUpgrade(ctx, t, adminConnection)
	assertBrowserEnrollmentNetworkChoices(ctx, t, adminConnection)
	assertBrowserRegistrationIntentIssue(ctx, t, adminConnection)
	assertPostgreSQLBrowserRegistrationApproval(ctx, t, adminConnection, runtimeConnection, runtimePool)
	assertPostgreSQLBrowserWorkspaceSelection(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLResourceAuthority(
		ctx,
		t,
		adminConnection,
		runtimeConnection,
		runtimePool,
		workerConnection,
	)
	assertPostgreSQLResourceSharing(
		ctx, t, adminConnection, workerConnection, workerPool, runtimePool,
	)
	assertPostgreSQLWorkspaceRename(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLWorkspaceRoles(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLGuardrails(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLDeviceGroups(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLIdentityCatalog(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLDeploymentEntitlement(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLBootstrap(ctx, t, adminConnection, migrationConfig)
	assertSessionAuthorityPlanning(ctx, t, adminConnection)
	assertPostgreSQLWorkspaceCreation(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLNetworkCreation(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLSessionWorkspace(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLShareTarget(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLLoginSubjectResolution(ctx, t, adminConnection, runtimeConnection, runtimePool)
	assertPostgreSQLInvitationAcceptance(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLAccountSignup(ctx, t, adminConnection, runtimePool)
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
	assertPostgreSQLGroupPolicy(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLIdentityTagPolicy(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLDeviceLifecycle(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLMemberSuspension(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLMemberRemoval(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLInvitations(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLAccountSessionActivity(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLAccountSessionLogout(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLRevokedConsoleManagementScopes(ctx, t, runtimePool)
	assertPostgreSQLDeviceLogout(ctx, t, adminConnection, runtimePool)
	// Last, so every evidence writer exercised above is covered.
	assertAuditSealV2(ctx, t, adminConnection)
}
