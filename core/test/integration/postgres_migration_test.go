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
	// About 40 s on a fixture database; under -race in a container runner
	// past one minute (TD-TEST-58).
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
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
	// Role isolation S2.3: before schema 300 narrows mesh_runtime, the
	// schema assertions' legacy role takes a copy of what it held.
	preNarrowed, err := runners[0].UpThrough(ctx, integrationLegacyCopyVersion)
	if err != nil || preNarrowed.Applied != int(integrationLegacyCopyVersion) {
		t.Fatalf("MigrationRunner.UpThrough(%d) = %+v, %v", integrationLegacyCopyVersion, preNarrowed, err)
	}
	copyIntegrationLegacyRuntime(ctx, t)

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
	if applied != int(initialStatus.LatestVersion-integrationLegacyCopyVersion) {
		t.Fatalf(
			"concurrent applied migration count = %d, want exactly %d",
			applied,
			initialStatus.LatestVersion-integrationLegacyCopyVersion,
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
	// What the operator command keeps (role isolation S2.2): the api's login
	// in its group. A serving login outside its groups stays closed.
	grantIntegrationRuntimeGroups(ctx, t, adminConnection, runtimePostgreSQL.User)
	// The operator keeps mesh_runtime, the api login, in its group whatever
	// login the stores use here (mesh_all).
	grantIntegrationRuntimeGroups(ctx, t, adminConnection, "mesh_runtime")
	if err := runtimePool.Check(ctx); err != nil {
		t.Fatalf("runtime compatibility pool Check() error = %v", err)
	}
	for range 2 {
		if _, err := execOperatorStep(ctx, adminConnection, migrations.ImportedPolicySimulationReaderOwnershipSQL()); err != nil {
			t.Fatalf("apply idempotent Imported policy baseline reader ownership: %v", err)
		}
		if _, err := execOperatorStep(ctx, adminConnection, migrations.ResourceSharingFunctionOwnershipSQL()); err != nil {
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
		if _, err := execOperatorStep(ctx, adminConnection, migrations.DirectDeviceEndpointFunctionOwnershipSQL()); err != nil {
			t.Fatalf("apply idempotent direct Device endpoint ownership hardening: %v", err)
		}
		if _, err := execOperatorStep(ctx, adminConnection, migrations.ExpiredUnprovisionedShareCleanupOwnershipSQL()); err != nil {
			t.Fatalf("apply idempotent expired Trust Contract cleanup ownership hardening: %v", err)
		}
		if _, err := execOperatorStep(ctx, adminConnection, migrations.ResourceSharingNeverExpiryOwnershipSQL()); err != nil {
			t.Fatalf("apply idempotent never-expiring share ownership hardening: %v", err)
		}
		if _, err := execOperatorStep(ctx, adminConnection, migrations.DirectDeviceMapFunctionOwnershipSQL()); err != nil {
			t.Fatalf("apply direct map reader ownership: %v", err)
		}
	}
	if _, err := execOperatorStep(ctx, adminConnection, migrations.DeviceAliasClientOwnershipSQL()); err != nil {
		t.Fatalf("harden alias compatibility observer: %v", err)
	}
	if _, err := execOperatorStep(ctx, adminConnection, migrations.DeviceAliasMapOwnershipSQL()); err != nil {
		t.Fatalf("harden alias map reader: %v", err)
	}
	if _, err := execOperatorStep(ctx, adminConnection, migrations.DeviceAliasWorkerOwnershipSQL()); err != nil {
		t.Fatal(err)
	}
	if _, err := execOperatorStep(ctx, adminConnection, migrations.DeviceAliasWithdrawalOwnershipSQL()); err != nil {
		t.Fatal(err)
	}
	if _, err := execOperatorStep(ctx, adminConnection, migrations.DeviceAliasWorkOwnershipSQL()); err != nil {
		t.Fatal(err)
	}
	if _, err := execOperatorStep(ctx, adminConnection, migrations.DeviceSharingDependenciesOwnershipSQL()); err != nil {
		t.Fatalf("harden sharing dependencies: %v", err)
	}
	if _, err := execOperatorStep(ctx, adminConnection, migrations.UnifiedDeviceAliasOwnershipSQL()); err != nil {
		t.Fatalf("harden unified Device alias entry points: %v", err)
	}
	if _, err := execOperatorStep(ctx, adminConnection, migrations.AliasMapReaderOwnershipSQL()); err != nil {
		t.Fatalf("harden bounded alias map reader: %v", err)
	}
	if _, err := execOperatorStep(ctx, adminConnection, migrations.ShareOfferAccessLabelOwnershipSQL()); err != nil {
		t.Fatalf("harden labeled share offer entry points: %v", err)
	}
	if _, err := execOperatorStep(ctx, adminConnection, migrations.TrustContractExpiryOwnershipSQL()); err != nil {
		t.Fatalf("harden Trust Contract expiry entry points: %v", err)
	}
	if _, err := execOperatorStep(ctx, adminConnection, migrations.AliasMapReachableSharesOwnershipSQL()); err != nil {
		t.Fatalf("harden reachable-share alias map reader: %v", err)
	}
	if _, err := execOperatorStep(ctx, adminConnection, migrations.DeviceSharingDependenciesV2OwnershipSQL()); err != nil {
		t.Fatalf("harden narrowed sharing dependency reader: %v", err)
	}
	if _, err := execOperatorStep(ctx, adminConnection, migrations.ShareMapReaderScaleOwnershipSQL()); err != nil {
		t.Fatalf("harden scaled share map readers: %v", err)
	}
	if _, err := execOperatorStep(ctx, adminConnection, migrations.ShareMapReaderSelectionOwnershipSQL()); err != nil {
		t.Fatalf("harden selective share map readers: %v", err)
	}
	if _, err := execOperatorStep(ctx, adminConnection, migrations.ShareReaderKeyLookupOwnershipSQL()); err != nil {
		t.Fatalf("harden key-lookup share map readers: %v", err)
	}
	if _, err := execOperatorStep(ctx, adminConnection, migrations.DependencyReaderNetworkOnceOwnershipSQL()); err != nil {
		t.Fatalf("harden network-once dependency reader: %v", err)
	}
	if _, err := execOperatorStep(ctx, adminConnection, migrations.DeviceAliasConsumerReadmissionOwnershipSQL()); err != nil {
		t.Fatalf("harden readmitting alias worker: %v", err)
	}
	if _, err := execOperatorStep(ctx, adminConnection, migrations.DeviceAliasProviderReadmissionOwnershipSQL()); err != nil {
		t.Fatalf("harden provider readmitting alias worker: %v", err)
	}
	if _, err := execOperatorStep(ctx, adminConnection, migrations.FlowlogReaderOwnershipSQL()); err != nil {
		t.Fatalf("hand the connection log receiver reads to their reader: %v", err)
	}
	if _, err := execOperatorStep(ctx, adminConnection, migrations.FlowlogDirectoryOwnershipSQL()); err != nil {
		t.Fatalf("hand the connection log directory reads to their reader: %v", err)
	}
	if _, err := execOperatorStep(ctx, adminConnection, migrations.FlowlogStatusOwnershipSQL()); err != nil {
		t.Fatalf("hand the connection log receiver reports to their writer: %v", err)
	}
	if _, err := execOperatorStep(ctx, adminConnection, migrations.ConnectionLogConsoleStatusOwnershipSQL()); err != nil {
		t.Fatalf("hand the connection log status read to the status writer: %v", err)
	}
	if _, err := execOperatorStep(ctx, adminConnection, migrations.ConnectionLogPushOwnershipSQL()); err != nil {
		t.Fatalf("hand the push destination reads and reports to their owners: %v", err)
	}
	if _, err := execOperatorStep(ctx, adminConnection, migrations.RetentionOwnershipSQL()); err != nil {
		t.Fatalf("hand the row retention functions to mesh_retention: %v", err)
	}
	if _, err := execOperatorStep(ctx, adminConnection, migrations.AuditRetentionFloorOwnershipSQL()); err != nil {
		t.Fatalf("hand prune_audit_rows_v2 to mesh_retention: %v", err)
	}
	if _, err := execOperatorStep(ctx, adminConnection, migrations.DeviceAliasPendingWorkOwnershipSQL()); err != nil {
		t.Fatalf("harden pending-only alias worker loader: %v", err)
	}
	// Role isolation S2.2: the group roles' owner-held functions, as far as
	// the steps applied so far gave them to mesh_runtime (an operator apply
	// runs step 298 after every earlier step).
	applyGroupFunctionGrantsSoFar(ctx, t, adminConnection)
	if _, err := execOperatorStep(ctx, adminConnection, migrations.TrustContractDeviceRemovalOwnershipSQL()); err != nil {
		t.Fatalf("harden Trust Contract device removal entry points: %v", err)
	}
	assertShareLimitGuardPrivileges(ctx, t, adminConnection)
	if _, err := execOperatorStep(ctx, adminConnection, migrations.PolicyImportedResourceScaleOwnershipSQL()); err != nil {
		t.Fatalf("harden scaled Imported Resource publication: %v", err)
	}
	assertPolicyImportedResourceScalePrivileges(ctx, t, adminConnection)
	assertResourceSharingPrivilegeContract(ctx, t, adminConnection)
	seedAuthorityFixture(ctx, t, adminConnection)
	assertAuthorityEvidenceFoundation(ctx, t, adminConnection)
	assertAuthorityMutationAtomicity(ctx, t, adminConnection)
	assertAuthorityConstraints(ctx, t, adminConnection)
	assertDatabasePrivilegeContract(ctx, t, adminConnection)
	assertBrowserRegistrationSchemaIsolation(ctx, t, adminConnection)
	assertCompiledPacketPolicyPrivilegeContract(ctx, t, adminConnection)
	assertPolicyApprovalPersistencePrivilegeContract(ctx, t, adminConnection)
	// S2.1: with MESHTRANSIT_TEST_ROLE_SPLIT=1 the database reaches the
	// state S2.3 aims for, and control's flows run on their own pool.
	controlPool := openIntegrationRoleSplit(ctx, t, adminConnection, runtimePostgreSQL.User, runtimePool, postgresConfig.Address,
		postgresConfig.Database, runtimePostgreSQL.PasswordFile, postgresConfig.CAFile,
		processConfig.Dependencies.CheckTimeout)
	registrationReplayCommand := seedRegistrationAuthority(ctx, t, adminConnection)
	assertRegistrationSchemaConstraints(ctx, t, adminConnection)
	registrationReplayStore, err := postgresadapter.NewRegistrationReplayStore(controlPool)
	if err != nil {
		t.Fatalf("postgres.NewRegistrationReplayStore() error = %v", err)
	}
	assertPostgreSQLRegistrationReplay(ctx, t, registrationReplayStore, registrationReplayCommand)
	assertPostgreSQLMapSessionSnapshot(ctx, t, controlPool, registrationReplayCommand)

	// The schema assertions' raw SQL runs as mesh_runtime, which holds every
	// object the schema grants (mesh_it_schema, holding the same, with
	// RUNTIME_LOGIN=split); the stores (runtimePool) run as the configured
	// login, mesh_all with RUNTIME_LOGIN=mesh_all, so the code's own SQL
	// proves the group roles suffice (role isolation S2.2).
	schemaUser := integrationSchemaRuntimeUser(runtimePostgreSQL.User)
	runtimeConnection := openIntegrationPostgreSQLConnection(
		ctx,
		t,
		postgresConfig.Address,
		postgresConfig.Database,
		schemaUser,
		runtimePostgreSQL.PasswordFile,
		postgresConfig.CAFile,
		processConfig.Dependencies.CheckTimeout,
	)
	runtimeContenderConnection := openIntegrationPostgreSQLConnection(
		ctx,
		t,
		postgresConfig.Address,
		postgresConfig.Database,
		schemaUser,
		runtimePostgreSQL.PasswordFile,
		postgresConfig.CAFile,
		processConfig.Dependencies.CheckTimeout,
	)
	assertPostgreSQLDeviceAliasClientVersion(ctx, t, adminConnection, runtimeConnection, runtimePool, registrationReplayCommand)
	assertPostgreSQLMTCPTimestamp(ctx, t, controlPool, registrationReplayCommand)
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
	assertDeploymentAuditVolume(ctx, t, adminConnection, workerConnection)
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
	// The limiter script is not covered by the dependency test in CI.
	assertRateLimitRefund(ctx, t)
	assertRevisionDispatcherRecovery(ctx, t, adminConnection, workerPool)
	assertKubernetesOperationPartitions(ctx, t, workerPool)

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
		controlPool,
		openRegistrationCommand,
	)
	assertPostgreSQLRegistrationServiceResume(
		ctx,
		t,
		adminConnection,
		controlPool,
	)
	assertPostgreSQLRegistrationServiceRefusesForeignKey(ctx, t, adminConnection, controlPool)
	assertPostgreSQLRegistrationServiceConcurrency(
		ctx,
		t,
		adminConnection,
		controlPool,
	)
	assertPostgreSQLRegistrationIntake(ctx, t, adminConnection, controlPool)
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
		controlPool,
	)
	assertPostgreSQLMapDeviceNames(ctx, t, adminConnection, controlPool, peerIdentity)
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
	assertPostgreSQLNetworkSummary(ctx, t, adminConnection, workerPool)
	assertPostgreSQLConsoleNetworkSummaries(ctx, t, adminConnection, workerPool, runtimePool)
	assertPostgreSQLDeviceEnforcementLedger(ctx, t, adminConnection, workerPool, runtimePool)
	assertPostgreSQLRelayRevocations(ctx, t, adminConnection, controlPool)
	assertWorkspaceOwnerAuthority(ctx, t, adminConnection)
	assertBuiltinWorkspaceRoles(ctx, t, adminConnection)
	assertTenantDisplayIdentities(ctx, t, adminConnection)
	assertTenantDisplayUpgrade(ctx, t, adminConnection)
	assertGroupTagUpgrade(ctx, t, adminConnection)
	assertBrowserEnrollmentNetworkChoices(ctx, t, adminConnection)
	assertBrowserRegistrationIntentIssue(ctx, t, adminConnection)
	assertPostgreSQLBrowserRegistrationApproval(ctx, t, adminConnection, runtimeConnection, runtimePool, controlPool)
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
	assertPostgreSQLPrivateInterchange(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLDeviceGroups(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLIdentityCatalog(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLDeploymentEntitlement(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLBootstrap(ctx, t, adminConnection, migrationConfig)
	assertSessionAuthorityPlanning(ctx, t, adminConnection)
	assertPostgreSQLWorkspaceCreation(ctx, t, adminConnection, runtimePool)
	// After Workspace creation, which records its own generations 4 to 6.
	assertPostgreSQLDeploymentEntitlementRenewal(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLNetworkCreation(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLNetworkDeletion(ctx, t, adminConnection, runtimePool, workerPool)
	assertPostgreSQLSessionWorkspace(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLShareTarget(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLLoginSubjectResolution(ctx, t, adminConnection, runtimeConnection, runtimePool)
	assertPostgreSQLInvitationAcceptance(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLAccountSignup(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLAccountEmail(ctx, t, adminConnection, runtimeConnection, runtimePool)
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
	assertPostgreSQLSites(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLSitePolicy(ctx, t, adminConnection, runtimePool, workerPool)
	assertPostgreSQLRouteOffers(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLSiteMaps(ctx, t, adminConnection, runtimePool, workerPool)
	assertPostgreSQLExitPools(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLExitPolicy(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLExitOffers(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLExitPoolElection(ctx, t, adminConnection, runtimePool, workerPool)
	assertPostgreSQLExitPoolSpread(ctx, t, adminConnection, runtimePool, workerPool)
	assertPostgreSQLExitMaps(ctx, t, adminConnection, runtimePool, workerPool)
	assertPostgreSQLCaptiveWindows(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLDNSZones(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLDNSNames(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLDNSShareNames(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLDNSSettings(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLConsoleDeviceSearch(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLMemberSuspension(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLMemberRemoval(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLNetworkMembers(ctx, t, adminConnection, runtimePool)
	// Beside the other member tests, while the fixture owner may still
	// assign roles.
	assertPostgreSQLConnectionLogs(ctx, t, adminConnection, runtimePool, migrationConfig)
	assertPostgreSQLEnrollmentKeys(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLSingleUseEnrollmentKey(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLKubernetesClusters(ctx, t, adminConnection, runtimeConnection, runtimePool, workerPool,
		workerConnection)
	assertPostgreSQLAccountSessionRevocation(ctx, t, adminConnection, runtimePool, migrationConfig)
	assertPostgreSQLInvitations(ctx, t, adminConnection, runtimePool)
	// After the tests that need four active Devices: it revokes one.
	assertPostgreSQLPolicyInactiveDevice(ctx, t, adminConnection, runtimePool, workerPool)
	assertPostgreSQLAccountSessionActivity(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLAccountSessionLogout(ctx, t, adminConnection, runtimePool)
	assertPostgreSQLRevokedConsoleManagementScopes(ctx, t, runtimePool)
	assertPostgreSQLDeviceLogout(ctx, t, adminConnection, runtimePool, workerPool)
	// After every revocation path, so their quarantines are all checked.
	assertPostgreSQLNodeAddressQuarantine(ctx, t, adminConnection, runtimeConnection, runtimePool)
	assertRegistrationAddressFloor(ctx, t, adminConnection, runtimePool)
	// Add Devices in transactions they roll back.
	assertMapReaderPlansScale(ctx, t)
	assertRegistrationAllocationPlansScale(ctx, t)
	assertMapInventoryChanges(ctx, t)
	assertMapNetworkDirectEndpoints(ctx, t, adminConnection)
	// The policy publication, group and tag fixtures above compared maps
	// whose packet policy was expanded from the Network policy.
	if sharedPoliciesExpanded.Load() == 0 {
		t.Fatal("no shared map load expanded the Network policy")
	}
	assertPostgreSQLDeviceDNSLabels(ctx, t, adminConnection)
	assertDeletedNetworkMapSessionRevoked(ctx, t, adminConnection)
	assertNetworkDeletionWorkerRevokesDevices(ctx, t, adminConnection, workerPool)
	// After every hand-applied operator step, step 298 as the operator runs
	// it: the groups are a projection of mesh_runtime (role isolation S2.2).
	if _, err := execOperatorStep(ctx, adminConnection, migrations.GroupFunctionGrantsSQL()); err != nil {
		t.Fatalf("grant the group roles the owner-held functions: %v", err)
	}
	// S2.3: step 300 takes the owner-held functions away from mesh_runtime
	// (the hand-applied steps above granted some again).
	if _, err := execOperatorStep(ctx, adminConnection, migrations.RuntimeFunctionGrantsSQL()); err != nil {
		t.Fatalf("take the owner-held functions away from mesh_runtime: %v", err)
	}
	// The deployment gate runs after every operator step, as in production.
	assertDeviceSharingDeploymentPreflight(ctx, t, adminConnection)
	assertGroupRolesWithinRuntime(ctx, t, adminConnection)
	assertPostgreSQLAPIKeyFoundation(ctx, t, adminConnection, managementRBACAccountSessionFixture(t))
	assertPostgreSQLAPIKeysEndWithSessions(ctx, t, adminConnection, managementRBACAccountSessionFixture(t))
	assertPostgreSQLAPIKeyLifecycle(ctx, t, adminConnection, managementRBACAccountSessionFixture(t))
	// Last, so every evidence writer exercised above is covered.
	assertAuditSealV2(ctx, t, adminConnection)
	assertAuditStreamLoad(ctx, t, adminConnection, adminConfig)
}
