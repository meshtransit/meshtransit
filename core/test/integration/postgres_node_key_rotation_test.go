//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/enrollment"
	registrationapp "meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/keyrotation"
)

type nodeKeyRotationEvidence struct {
	nodePublicID      string
	hostname          string
	deviceVersion     int64
	sessionGeneration int64
	currentEpoch      int64
	nodeKeyEpochs     int64
	activeNodeKeys    int64
	primaryLeases     int64
	primaryAddress    string
	auditEvents       int64
	outboxEvents      int64
}

func assertPostgreSQLNodeKeyRotation(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimePool *postgresadapter.Pool,
	registered registrationapp.Command,
) {
	t.Helper()
	command := integrationNodeKeyRotationCommand(t, registered, 0x23, "000000000701")
	machineKey := command.MachineKey().Bytes()
	machineFingerprint := command.MachineKey().Fingerprint()
	oldNodeKey := command.OldNodeKey().Bytes()
	newNodeKey := command.NewNodeKey().Bytes()
	var resolvedScopes int64
	if err := adminConnection.QueryRow(ctx, `SELECT pg_catalog.count(*)
FROM mesh_ops.resolve_node_key_rotation_scope($1::BYTEA, $2::BYTEA, $3::BYTEA, $4::BYTEA)`,
		machineFingerprint[:],
		machineKey[:],
		oldNodeKey[:],
		newNodeKey[:],
	).Scan(&resolvedScopes); err != nil {
		t.Fatalf("resolve Node-key rotation integration scope: %v", err)
	}
	if resolvedScopes != 1 {
		t.Fatalf("resolved Node-key rotation integration scopes = %d, want 1", resolvedScopes)
	}
	before := readNodeKeyRotationEvidence(ctx, t, adminConnection, machineKey[:])
	beforeNetworkRevision, beforeInventoryRevision := readRegistrationRevisions(
		ctx,
		t,
		adminConnection,
	)
	service := newIntegrationNodeKeyRotationService(t, runtimePool)

	result, err := service.Rotate(ctx, command)
	if err != nil {
		t.Fatalf("Node-key rotation Service error = %v", err)
	}
	if result.NodeID().String() != before.nodePublicID ||
		result.DeviceVersion() != before.deviceVersion+1 ||
		result.SessionGeneration() != before.sessionGeneration+1 ||
		result.NodeKeyEpoch() != before.currentEpoch+1 ||
		result.NetworkRevision() != beforeNetworkRevision+1 ||
		result.InventoryRevision() != beforeInventoryRevision+1 {
		t.Fatalf("Node-key rotation result = %+v, want exact +1 authority", result)
	}
	after := readNodeKeyRotationEvidence(ctx, t, adminConnection, machineKey[:])
	if after.nodePublicID != before.nodePublicID || after.hostname != before.hostname ||
		after.deviceVersion != before.deviceVersion+1 ||
		after.sessionGeneration != before.sessionGeneration+1 ||
		after.currentEpoch != before.currentEpoch+1 ||
		after.nodeKeyEpochs != before.nodeKeyEpochs+1 ||
		after.activeNodeKeys != 1 ||
		after.primaryLeases != before.primaryLeases ||
		after.primaryAddress != before.primaryAddress ||
		after.auditEvents != before.auditEvents+1 || after.outboxEvents != before.outboxEvents+1 {
		t.Fatalf("Node-key rotation stable evidence changed: before=%+v after=%+v", before, after)
	}

	replayed, err := service.Rotate(ctx, command)
	if err != nil || replayed.NodeID() != result.NodeID() ||
		replayed.NodeKeyEpoch() != result.NodeKeyEpoch() ||
		replayed.NetworkRevision() != result.NetworkRevision() {
		t.Fatalf("exact Node-key rotation replay = (%+v, %v), want committed result", replayed, err)
	}
	afterReplay := readNodeKeyRotationEvidence(ctx, t, adminConnection, machineKey[:])
	if afterReplay != after {
		t.Fatalf("exact replay changed authority: before=%+v after=%+v", after, afterReplay)
	}

	reuse := integrationNodeKeyRotationCommand(t, registered, 0x24, "000000000702")
	reuse, err = keyrotation.NewCommand(keyrotation.CommandParams{
		OperationID: reuse.OperationID(),
		MachineKey:  reuse.MachineKey(),
		OldNodeKey:  command.NewNodeKey(),
		NewNodeKey:  registered.Identity.NodeKey(),
	})
	if err != nil {
		t.Fatalf("construct historical-key reuse command: %v", err)
	}
	if _, err := service.Rotate(ctx, reuse); !errors.Is(err, keyrotation.ErrConflict) {
		t.Fatalf("historical-key reuse error = %v, want conflict", err)
	}
	if got := readNodeKeyRotationEvidence(ctx, t, adminConnection, machineKey[:]); got != after {
		t.Fatalf("rejected historical-key reuse changed authority: before=%+v after=%+v", after, got)
	}
}

func newIntegrationNodeKeyRotationService(
	t *testing.T,
	runtimePool *postgresadapter.Pool,
) *keyrotation.Service {
	t.Helper()
	store, err := postgresadapter.NewNodeKeyRotationStore(
		runtimePool,
		postgresadapter.NodeKeyRotationOptions{
			StatementTimeout: 5 * time.Second,
			LockTimeout:      2 * time.Second,
			IdleTimeout:      10 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("postgres.NewNodeKeyRotationStore() error = %v", err)
	}
	retry, err := registrationapp.NewExponentialBackoff(time.Millisecond, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("registration.NewExponentialBackoff() error = %v", err)
	}
	service, err := keyrotation.NewService(
		keyrotation.Options{MaxAttempts: 3, RollbackTimeout: 2 * time.Second},
		keyrotation.Dependencies{
			Transactions: store,
			MutationIDs:  keyrotation.PublicMutationIDGenerator{},
			Clock:        registrationapp.SystemClock{},
			Retry:        retry,
		},
	)
	if err != nil {
		t.Fatalf("keyrotation.NewService() error = %v", err)
	}
	return service
}

func integrationNodeKeyRotationCommand(
	t *testing.T,
	registered registrationapp.Command,
	newKeyMaterial byte,
	operationSuffix string,
) keyrotation.Command {
	t.Helper()
	operationID, err := enrollment.ParseRegistrationID(
		"01890f30-0000-7000-8000-" + operationSuffix,
	)
	if err != nil {
		t.Fatalf("parse Node-key rotation operation ID: %v", err)
	}
	newNodeKey, err := node.NewKey(filledIntegrationKey(newKeyMaterial))
	if err != nil {
		t.Fatalf("construct rotated Node key: %v", err)
	}
	command, err := keyrotation.NewCommand(keyrotation.CommandParams{
		OperationID: operationID,
		MachineKey:  registered.Identity.MachineKey(),
		OldNodeKey:  registered.Identity.NodeKey(),
		NewNodeKey:  newNodeKey,
	})
	if err != nil {
		t.Fatalf("keyrotation.NewCommand() error = %v", err)
	}
	return command
}

func readNodeKeyRotationEvidence(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	machineKey []byte,
) nodeKeyRotationEvidence {
	t.Helper()
	var evidence nodeKeyRotationEvidence
	if err := connection.QueryRow(ctx, `SELECT
    device.public_id::TEXT,
    device.hostname,
    device.version,
    device.session_generation,
    device.current_node_key_epoch,
    (SELECT pg_catalog.count(*) FROM mesh.device_node_key_epoch AS key_epoch
     WHERE key_epoch.workspace_id = device.workspace_id
       AND key_epoch.network_id = device.network_id
       AND key_epoch.device_id = device.id),
    (SELECT pg_catalog.count(*) FROM mesh.device_node_key_epoch AS key_epoch
     WHERE key_epoch.workspace_id = device.workspace_id
       AND key_epoch.network_id = device.network_id
       AND key_epoch.device_id = device.id
       AND key_epoch.state = 'active'),
    (SELECT pg_catalog.count(*) FROM mesh.node_address_lease AS lease
     WHERE lease.workspace_id = device.workspace_id
       AND lease.network_id = device.network_id
       AND lease.device_id = device.id
       AND lease.lease_role = 'primary'
       AND lease.state = 'active'),
    (SELECT lease.address::TEXT FROM mesh.node_address_lease AS lease
     WHERE lease.workspace_id = device.workspace_id
       AND lease.network_id = device.network_id
       AND lease.device_id = device.id
       AND lease.lease_role = 'primary'
       AND lease.state = 'active'
     ORDER BY lease.id LIMIT 1),
    (SELECT pg_catalog.count(*) FROM mesh_audit.audit_event AS event
     WHERE event.target_kind = 'device'
       AND event.target_public_id = device.public_id
       AND event.action = 'device.node_key_rotated'),
    (SELECT pg_catalog.count(*) FROM mesh_ops.outbox_event AS event
     WHERE event.aggregate_kind = 'device'
       AND event.aggregate_public_id = device.public_id
       AND event.event_class = 'network.revision.advanced')
FROM mesh.device AS device
JOIN mesh.device_machine_key_epoch AS machine_key
  ON machine_key.workspace_id = device.workspace_id
 AND machine_key.network_id = device.network_id
 AND machine_key.device_id = device.id
 AND machine_key.epoch = device.current_machine_key_epoch
WHERE machine_key.public_key = $1::BYTEA`, machineKey).Scan(
		&evidence.nodePublicID,
		&evidence.hostname,
		&evidence.deviceVersion,
		&evidence.sessionGeneration,
		&evidence.currentEpoch,
		&evidence.nodeKeyEpochs,
		&evidence.activeNodeKeys,
		&evidence.primaryLeases,
		&evidence.primaryAddress,
		&evidence.auditEvents,
		&evidence.outboxEvents,
	); err != nil {
		t.Fatalf("read Node-key rotation evidence: %v", err)
	}
	return evidence
}

func assertWorkerCannotResolveNodeKeyRotationScope(
	ctx context.Context,
	t *testing.T,
	workerConnection *pgx.Conn,
) {
	t.Helper()
	var canResolve bool
	if err := workerConnection.QueryRow(ctx, `SELECT pg_catalog.has_function_privilege(
    CURRENT_USER,
    'mesh_ops.resolve_node_key_rotation_scope(bytea,bytea,bytea,bytea)',
    'EXECUTE'
)`).Scan(&canResolve); err != nil {
		t.Fatalf("query worker Node-key rotation scope privilege: %v", err)
	}
	if canResolve {
		t.Fatal("worker can resolve Node-key rotation scope, want false")
	}
}
