//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	registrationapp "meshtransit.net/core/internal/domain/enrollment/registration"
)

const concurrentRegistrationCalls = 2

type registrationServiceOutcome struct {
	result registrationapp.Result
	err    error
}

func assertPostgreSQLRegistrationServiceConcurrency(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimePool *postgresadapter.Pool,
) {
	t.Helper()
	command := seedConcurrentRegistrationAuthority(ctx, t, adminConnection)
	beforeNetworkRevision, beforeInventoryRevision := readRegistrationRevisions(
		ctx,
		t,
		adminConnection,
	)
	service := newIntegrationRegistrationService(t, runtimePool)

	start := make(chan struct{})
	outcomes := make(chan registrationServiceOutcome, concurrentRegistrationCalls)
	for range concurrentRegistrationCalls {
		go func() {
			<-start
			result, registerErr := service.Register(ctx, command)
			outcomes <- registrationServiceOutcome{result: result, err: registerErr}
		}()
	}
	close(start)

	results := make([]registrationapp.Result, 0, concurrentRegistrationCalls)
	for range concurrentRegistrationCalls {
		select {
		case outcome := <-outcomes:
			if outcome.err != nil {
				t.Fatalf("concurrent registration Service error = %v", outcome.err)
			}
			results = append(results, outcome.result)
		case <-ctx.Done():
			t.Fatalf("wait for concurrent registration Service: %v", ctx.Err())
		}
	}
	if !sameRegistrationResult(results[0], results[1]) {
		t.Fatalf("concurrent registration results differ: first=%+v second=%+v", results[0], results[1])
	}
	if results[0].Disposition() != registrationapp.DispositionCreated ||
		results[0].NetworkRevision() != beforeNetworkRevision+1 {
		t.Fatalf(
			"concurrent registration result = %+v, want one created mutation at revision %d",
			results[0],
			beforeNetworkRevision+1,
		)
	}
	assertStampedByDatabaseClock(ctx, t, adminConnection, "device", results[0].NodeID().String())
	assertConcurrentRegistrationEvidence(
		ctx,
		t,
		adminConnection,
		command,
		results[0],
		beforeNetworkRevision+1,
		beforeInventoryRevision+1,
	)
}

func assertPostgreSQLRegistrationServiceResume(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimePool *postgresadapter.Pool,
) {
	t.Helper()
	command := seedResumeRegistrationAuthority(ctx, t, adminConnection)
	fingerprint := command.Identity.MachineKey().Fingerprint()
	before := readRegisteredNodeEvidence(ctx, t, adminConnection, fingerprint[:])
	beforeNetworkRevision, beforeInventoryRevision := readRegistrationRevisions(
		ctx,
		t,
		adminConnection,
	)

	result, err := newIntegrationRegistrationService(t, runtimePool).Register(ctx, command)
	if err != nil {
		t.Fatalf("resume registration Service error = %v", err)
	}
	if result.NodeID().String() != before.nodePublicID ||
		result.Hostname() != command.Hostname ||
		result.Disposition() != registrationapp.DispositionResumed ||
		result.NetworkRevision() != beforeNetworkRevision+1 {
		t.Fatalf(
			"resume registration result = %+v, want existing Node %q at revision %d",
			result,
			before.nodePublicID,
			beforeNetworkRevision+1,
		)
	}
	after := readRegisteredNodeEvidence(ctx, t, adminConnection, fingerprint[:])
	if after.nodePublicID != before.nodePublicID || after.deviceVersion != before.deviceVersion+1 ||
		after.hostname != command.Hostname.String() || after.deviceCount != before.deviceCount ||
		after.machineKeyEpochs != before.machineKeyEpochs ||
		after.nodeKeyEpochs != before.nodeKeyEpochs ||
		after.primaryLeases != before.primaryLeases || after.primaryAddress != before.primaryAddress ||
		after.auditEvents != before.auditEvents+1 || after.outboxEvents != before.outboxEvents+1 {
		t.Fatalf("resume changed stable Node evidence: before=%+v after=%+v", before, after)
	}
	assertResumeRegistrationEvidence(
		ctx,
		t,
		adminConnection,
		command,
		beforeNetworkRevision+1,
		beforeInventoryRevision+1,
	)
}

func newIntegrationRegistrationService(
	t *testing.T,
	runtimePool *postgresadapter.Pool,
) *registrationapp.Service {
	t.Helper()
	transactions, err := postgresadapter.NewRegistrationTransactions(
		runtimePool,
		postgresadapter.RegistrationTransactionOptions{
			StatementTimeout:      5 * time.Second,
			LockTimeout:           2 * time.Second,
			IdleTimeout:           10 * time.Second,
			AddressCandidateLimit: 256,
		},
	)
	if err != nil {
		t.Fatalf("postgres.NewRegistrationTransactions() for Service error = %v", err)
	}
	replayStore, err := postgresadapter.NewRegistrationReplayStore(runtimePool)
	if err != nil {
		t.Fatalf("postgres.NewRegistrationReplayStore() for Service error = %v", err)
	}
	retry, err := registrationapp.NewExponentialBackoff(time.Millisecond, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("registration.NewExponentialBackoff() error = %v", err)
	}
	service, err := registrationapp.NewService(
		registrationapp.Options{
			MaxAttempts:     3,
			RollbackTimeout: 2 * time.Second,
		},
		registrationapp.Dependencies{
			Transactions:     transactions,
			CommittedResults: replayStore,
			NodeIDs:          registrationapp.PublicNodeIDGenerator{},
			MutationIDs:      registrationapp.PublicMutationIDGenerator{},
			Retry:            retry,
		},
	)
	if err != nil {
		t.Fatalf("registration.NewService() error = %v", err)
	}
	return service
}

func readRegistrationRevisions(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
) (networkRevision int64, inventoryRevision int64) {
	t.Helper()
	if err := connection.QueryRow(ctx, `SELECT network_revision, inventory_revision
FROM mesh_ops.network_revision
WHERE workspace_id = 101 AND network_id = 201`).Scan(
		&networkRevision,
		&inventoryRevision,
	); err != nil {
		t.Fatalf("read revisions before registration Service concurrency: %v", err)
	}
	return networkRevision, inventoryRevision
}

func sameRegistrationResult(first, second registrationapp.Result) bool {
	return first.IsValid() && second.IsValid() &&
		first.RegistrationID() == second.RegistrationID() &&
		first.Scope() == second.Scope() &&
		first.NodeID() == second.NodeID() &&
		first.Hostname() == second.Hostname() &&
		first.Disposition() == second.Disposition() &&
		first.NetworkRevision() == second.NetworkRevision()
}

func assertConcurrentRegistrationEvidence(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	command registrationapp.Command,
	result registrationapp.Result,
	wantNetworkRevision int64,
	wantInventoryRevision int64,
) {
	t.Helper()
	var (
		usedCount                          int64
		networkRevision, inventoryRevision int64
		credentialUses, machineKeyEpochs   int64
		nodeKeyEpochs, primaryLeases       int64
		auditEvents, outboxEvents          int64
		registrationState, nodePublicID    string
	)
	if err := connection.QueryRow(ctx, `SELECT
    credential.used_count,
    registration.state,
    device.public_id::TEXT,
    revision.network_revision,
    revision.inventory_revision,
    (SELECT pg_catalog.count(*) FROM mesh.enrollment_credential_use AS credential_use
     WHERE credential_use.pending_registration_id = registration.id),
    (SELECT pg_catalog.count(*) FROM mesh.device_machine_key_epoch AS machine_epoch
     WHERE machine_epoch.device_id = device.id),
    (SELECT pg_catalog.count(*) FROM mesh.device_node_key_epoch AS node_epoch
     WHERE node_epoch.device_id = device.id),
    (SELECT pg_catalog.count(*) FROM mesh.node_address_lease AS lease
     WHERE lease.device_id = device.id AND lease.lease_role = 'primary' AND lease.state = 'active'),
    (SELECT pg_catalog.count(*) FROM mesh_audit.audit_event AS audit_event
     WHERE audit_event.target_kind = 'device' AND audit_event.target_public_id = device.public_id),
    (SELECT pg_catalog.count(*) FROM mesh_ops.outbox_event AS outbox
     WHERE outbox.aggregate_kind = 'device' AND outbox.aggregate_public_id = device.public_id)
FROM mesh.pending_registration AS registration
JOIN mesh.enrollment_credential AS credential
  ON credential.id = registration.enrollment_credential_id
JOIN mesh.device AS device ON device.id = registration.device_id
JOIN mesh_ops.network_revision AS revision
  ON revision.workspace_id = registration.workspace_id
 AND revision.network_id = registration.network_id
WHERE registration.public_id = $1::UUID`, command.RegistrationID.String()).Scan(
		&usedCount,
		&registrationState,
		&nodePublicID,
		&networkRevision,
		&inventoryRevision,
		&credentialUses,
		&machineKeyEpochs,
		&nodeKeyEpochs,
		&primaryLeases,
		&auditEvents,
		&outboxEvents,
	); err != nil {
		t.Fatalf("query concurrent registration evidence: %v", err)
	}
	if usedCount != 1 || registrationState != "completed" || nodePublicID != result.NodeID().String() ||
		networkRevision != wantNetworkRevision || inventoryRevision != wantInventoryRevision ||
		credentialUses != 1 || machineKeyEpochs != 1 || nodeKeyEpochs != 1 || primaryLeases != 1 ||
		auditEvents != 1 || outboxEvents != 1 {
		t.Fatalf(
			"concurrent registration evidence = uses %d state %q Node %q revisions %d/%d "+
				"credential uses %d key epochs %d/%d leases %d audit/outbox %d/%d",
			usedCount,
			registrationState,
			nodePublicID,
			networkRevision,
			inventoryRevision,
			credentialUses,
			machineKeyEpochs,
			nodeKeyEpochs,
			primaryLeases,
			auditEvents,
			outboxEvents,
		)
	}
}

type registeredNodeEvidence struct {
	nodePublicID     string
	hostname         string
	primaryAddress   string
	deviceVersion    int64
	deviceCount      int64
	machineKeyEpochs int64
	nodeKeyEpochs    int64
	primaryLeases    int64
	auditEvents      int64
	outboxEvents     int64
}

func readRegisteredNodeEvidence(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	machineFingerprint []byte,
) registeredNodeEvidence {
	t.Helper()
	var evidence registeredNodeEvidence
	if err := connection.QueryRow(ctx, `SELECT
    device.public_id::TEXT,
    device.hostname,
    device.version,
    (SELECT pg_catalog.count(*) FROM mesh.device AS scoped_device
     WHERE scoped_device.workspace_id = device.workspace_id
       AND scoped_device.network_id = device.network_id),
    (SELECT pg_catalog.count(*) FROM mesh.device_machine_key_epoch AS machine_epoch
     WHERE machine_epoch.device_id = device.id),
    (SELECT pg_catalog.count(*) FROM mesh.device_node_key_epoch AS node_epoch
     WHERE node_epoch.device_id = device.id),
    (SELECT pg_catalog.count(*) FROM mesh.node_address_lease AS lease
     WHERE lease.device_id = device.id AND lease.lease_role = 'primary' AND lease.state = 'active'),
    (SELECT pg_catalog.host(lease.address) FROM mesh.node_address_lease AS lease
     WHERE lease.device_id = device.id AND lease.lease_role = 'primary' AND lease.state = 'active'),
    (SELECT pg_catalog.count(*) FROM mesh_audit.audit_event AS audit_event
     WHERE audit_event.target_kind = 'device' AND audit_event.target_public_id = device.public_id),
    (SELECT pg_catalog.count(*) FROM mesh_ops.outbox_event AS outbox
     WHERE outbox.aggregate_kind = 'device' AND outbox.aggregate_public_id = device.public_id)
FROM mesh.device_machine_key_epoch AS machine_epoch
JOIN mesh.device AS device ON device.id = machine_epoch.device_id
WHERE machine_epoch.fingerprint = $1::BYTEA
  AND machine_epoch.state = 'active'`, machineFingerprint).Scan(
		&evidence.nodePublicID,
		&evidence.hostname,
		&evidence.deviceVersion,
		&evidence.deviceCount,
		&evidence.machineKeyEpochs,
		&evidence.nodeKeyEpochs,
		&evidence.primaryLeases,
		&evidence.primaryAddress,
		&evidence.auditEvents,
		&evidence.outboxEvents,
	); err != nil {
		t.Fatalf("query registered Node evidence: %v", err)
	}
	return evidence
}

func assertResumeRegistrationEvidence(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	command registrationapp.Command,
	wantNetworkRevision int64,
	wantInventoryRevision int64,
) {
	t.Helper()
	var (
		usedCount, credentialUses          int64
		networkRevision, inventoryRevision int64
		state, disposition                 string
	)
	if err := connection.QueryRow(ctx, `SELECT
    credential.used_count,
    registration.state,
    registration.completed_disposition,
    revision.network_revision,
    revision.inventory_revision,
    (SELECT pg_catalog.count(*) FROM mesh.enrollment_credential_use AS credential_use
     WHERE credential_use.pending_registration_id = registration.id)
FROM mesh.pending_registration AS registration
JOIN mesh.enrollment_credential AS credential
  ON credential.id = registration.enrollment_credential_id
JOIN mesh_ops.network_revision AS revision
  ON revision.workspace_id = registration.workspace_id
 AND revision.network_id = registration.network_id
WHERE registration.public_id = $1::UUID`, command.RegistrationID.String()).Scan(
		&usedCount,
		&state,
		&disposition,
		&networkRevision,
		&inventoryRevision,
		&credentialUses,
	); err != nil {
		t.Fatalf("query resume registration evidence: %v", err)
	}
	if usedCount != 1 || credentialUses != 1 || state != "completed" || disposition != "resumed" ||
		networkRevision != wantNetworkRevision || inventoryRevision != wantInventoryRevision {
		t.Fatalf(
			"resume evidence = uses %d/%d state %q disposition %q revisions %d/%d",
			usedCount,
			credentialUses,
			state,
			disposition,
			networkRevision,
			inventoryRevision,
		)
	}
}
