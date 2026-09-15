//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/control"
	"github.com/meshtransit/meshtransit/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/internal/idempotency"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/node/revocation"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

func assertPostgreSQLDeviceRevocation(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimePool *postgresadapter.Pool,
	selfIdentity control.AuthenticatedNode,
) {
	t.Helper()
	assertDeviceRevocationPrivilegeContract(ctx, t, adminConnection)
	beforeNetworkRevision, beforeInventoryRevision := loadDeviceRevocationRevisions(
		ctx,
		t,
		adminConnection,
		203,
	)
	command := deviceRevocationIntegrationCommand(t, 203, 930, 1, 1, "compromised peer")
	service := newIntegrationDeviceRevocationService(t, runtimePool)

	result, err := service.Revoke(ctx, command)
	if err != nil {
		t.Fatalf("revoke Device: %v", err)
	}
	if !result.IsValid() || result.Scope() != command.Scope() ||
		result.NodeID() != command.NodeID() || result.DeviceVersion() != 2 ||
		result.SessionGeneration() != 2 ||
		result.NetworkRevision() != beforeNetworkRevision+1 ||
		result.InventoryRevision() != beforeInventoryRevision+1 {
		t.Fatalf("revocation result = %+v, want one exact Device/inventory revision advance", result)
	}
	assertCommittedDeviceRevocation(ctx, t, adminConnection, command, result, 203)

	replayed, err := service.Revoke(ctx, command)
	if err != nil {
		t.Fatalf("replay committed Device revocation: %v", err)
	}
	if replayed != result {
		t.Fatalf("replayed result = %+v, want exact %+v", replayed, result)
	}
	assertCommittedDeviceRevocation(ctx, t, adminConnection, command, result, 203)

	conflicting := deviceRevocationIntegrationCommand(t, 203, 930, 1, 1, "different intent")
	if _, err := service.Revoke(ctx, conflicting); !errors.Is(err, revocation.ErrIntentConflict) {
		t.Fatalf("conflicting idempotency replay error = %v, want ErrIntentConflict", err)
	}
	stale := deviceRevocationIntegrationCommand(t, 203, 930, 1, 2, "stale version")
	if _, err := service.Revoke(ctx, stale); !errors.Is(err, revocation.ErrConflict) {
		t.Fatalf("stale Device revocation error = %v, want ErrConflict", err)
	}
	alreadyRevoked := deviceRevocationIntegrationCommand(t, 203, 930, 2, 3, "repeat revocation")
	if _, err := service.Revoke(ctx, alreadyRevoked); !errors.Is(err, revocation.ErrAlreadyRevoked) {
		t.Fatalf("terminal Device revocation error = %v, want ErrAlreadyRevoked", err)
	}
	crossNetwork := deviceRevocationIntegrationCommand(t, 204, 930, 1, 4, "wrong Network")
	if _, err := service.Revoke(ctx, crossNetwork); !errors.Is(err, revocation.ErrNotFound) {
		t.Fatalf("cross-Network Device revocation error = %v, want ErrNotFound", err)
	}

	assertRevokedDeviceExcludedFromMap(ctx, t, runtimePool, selfIdentity, result.NetworkRevision())
	assertRevokedDeviceCannotResumeMap(ctx, t, runtimePool)
	assertConcurrentDeviceRevocationReplay(ctx, t, adminConnection, runtimePool)
}

func assertConcurrentDeviceRevocationReplay(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimePool *postgresadapter.Pool,
) {
	t.Helper()
	beforeNetworkRevision, beforeInventoryRevision := loadDeviceRevocationRevisions(
		ctx,
		t,
		adminConnection,
		204,
	)
	command := deviceRevocationIntegrationCommand(t, 204, 980, 1, 5, "concurrent revoke")
	service := newIntegrationDeviceRevocationService(t, runtimePool)
	type outcome struct {
		result revocation.Result
		err    error
	}
	outcomes := make(chan outcome, 2)
	var ready sync.WaitGroup
	ready.Add(2)
	start := make(chan struct{})
	for range 2 {
		go func() {
			ready.Done()
			<-start
			result, err := service.Revoke(ctx, command)
			outcomes <- outcome{result: result, err: err}
		}()
	}
	ready.Wait()
	close(start)
	first := <-outcomes
	second := <-outcomes
	if first.err != nil || second.err != nil {
		t.Fatalf("concurrent revocation errors = %v / %v", first.err, second.err)
	}
	if first.result != second.result ||
		first.result.NetworkRevision() != beforeNetworkRevision+1 ||
		first.result.InventoryRevision() != beforeInventoryRevision+1 {
		t.Fatalf(
			"concurrent results = %+v / %+v, want one shared revision advance",
			first.result,
			second.result,
		)
	}
	assertCommittedDeviceRevocation(ctx, t, adminConnection, command, first.result, 204)
}

func newIntegrationDeviceRevocationService(
	t *testing.T,
	runtimePool *postgresadapter.Pool,
) *revocation.Service {
	t.Helper()
	store, err := postgresadapter.NewDeviceRevocationStore(
		runtimePool,
		postgresadapter.DeviceRevocationOptions{
			StatementTimeout: 5 * time.Second,
			LockTimeout:      2 * time.Second,
			IdleTimeout:      10 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("postgres.NewDeviceRevocationStore() error = %v", err)
	}
	retry, err := revocation.NewExponentialBackoff(time.Millisecond, 5*time.Millisecond)
	if err != nil {
		t.Fatalf("revocation.NewExponentialBackoff() error = %v", err)
	}
	service, err := revocation.NewService(
		revocation.Options{
			MaxAttempts:     3,
			RollbackTimeout: 2 * time.Second,
			IdempotencyTTL:  time.Hour,
		},
		revocation.Dependencies{
			Transactions:     store,
			CommittedResults: store,
			MutationIDs:      revocation.PublicMutationIDGenerator{},
			Clock:            revocation.SystemClock{},
			Retry:            retry,
		},
	)
	if err != nil {
		t.Fatalf("revocation.NewService() error = %v", err)
	}
	return service
}

func deviceRevocationIntegrationCommand(
	t *testing.T,
	networkNumericID int,
	nodeNumericID int,
	expectedVersion int64,
	digestDiscriminator byte,
	reasonValue string,
) revocation.Command {
	t.Helper()
	workspaceID, err := workspace.ParseID(integrationPublicID("01890f00-0000-7000-8000-", 103))
	if err != nil {
		t.Fatalf("parse Device revocation Workspace: %v", err)
	}
	networkID, err := network.ParseID(
		integrationPublicID("01890f00-0000-7000-8000-", int64(networkNumericID)),
	)
	if err != nil {
		t.Fatalf("parse Device revocation Network: %v", err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatalf("construct Device revocation scope: %v", err)
	}
	nodeID, err := node.ParseID(
		integrationPublicID("01890f31-0000-7000-8000-", int64(nodeNumericID)),
	)
	if err != nil {
		t.Fatalf("parse revoked Node ID: %v", err)
	}
	actorID, err := identity.ParsePrincipalID(
		integrationPublicID("01890f00-0000-7000-8000-", 11),
	)
	if err != nil {
		t.Fatalf("parse Device revocation actor: %v", err)
	}
	reason, err := revocation.NewReason(reasonValue)
	if err != nil {
		t.Fatalf("construct Device revocation reason: %v", err)
	}
	digest := sha256.Sum256([]byte{0x6d, 0x74, digestDiscriminator})
	proof, err := idempotency.NewProof("integration-v1", digest)
	if err != nil {
		t.Fatalf("construct Device revocation idempotency proof: %v", err)
	}
	command, err := revocation.NewCommand(revocation.CommandParams{
		Scope:               scope,
		NodeID:              nodeID,
		ExpectedVersion:     expectedVersion,
		ActorPrincipalID:    actorID,
		Reason:              reason,
		IdempotencyEvidence: proof,
	})
	if err != nil {
		t.Fatalf("construct Device revocation command: %v", err)
	}
	return command
}

func loadDeviceRevocationRevisions(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	networkInternalID int64,
) (int64, int64) {
	t.Helper()
	var networkRevision, inventoryRevision int64
	if err := connection.QueryRow(ctx, `SELECT network_revision, inventory_revision
FROM mesh_ops.network_revision
WHERE workspace_id = 103 AND network_id = $1::BIGINT`, networkInternalID).Scan(
		&networkRevision,
		&inventoryRevision,
	); err != nil {
		t.Fatalf("load Device revocation revisions: %v", err)
	}
	return networkRevision, inventoryRevision
}

func assertCommittedDeviceRevocation(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	command revocation.Command,
	result revocation.Result,
	networkInternalID int64,
) {
	t.Helper()
	var deviceCount, machineKeyCount, nodeKeyCount, auditCount, outboxCount, replayCount int
	if err := connection.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*)::INTEGER
     FROM mesh.device
     WHERE workspace_id = 103 AND network_id = $8::BIGINT AND public_id = $1::UUID
       AND state = 'revoked' AND version = $2::BIGINT
       AND session_generation = $3::BIGINT),
    (SELECT pg_catalog.count(*)::INTEGER
     FROM mesh.device_machine_key_epoch AS key_epoch
     JOIN mesh.device AS device ON device.id = key_epoch.device_id
     WHERE device.public_id = $1::UUID AND key_epoch.epoch = device.current_machine_key_epoch
       AND key_epoch.state = 'revoked' AND key_epoch.version = 2
       AND key_epoch.valid_until IS NOT NULL
       AND key_epoch.revocation_reason = $4::TEXT),
    (SELECT pg_catalog.count(*)::INTEGER
     FROM mesh.device_node_key_epoch AS key_epoch
     JOIN mesh.device AS device ON device.id = key_epoch.device_id
     WHERE device.public_id = $1::UUID AND key_epoch.epoch = device.current_node_key_epoch
       AND key_epoch.state = 'revoked' AND key_epoch.version = 2
       AND key_epoch.valid_until IS NOT NULL
       AND key_epoch.revocation_reason = $4::TEXT),
    (SELECT pg_catalog.count(*)::INTEGER
     FROM mesh_audit.audit_event
     WHERE workspace_id = 103 AND network_id = $8::BIGINT
       AND target_kind = 'device' AND target_public_id = $1::UUID
       AND action = 'device.revoked' AND permission = 'device.manage'
       AND correlation_public_id = $5::UUID),
    (SELECT pg_catalog.count(*)::INTEGER
     FROM mesh_ops.outbox_event
     WHERE workspace_id = 103 AND network_id = $8::BIGINT
       AND aggregate_kind = 'device' AND aggregate_public_id = $1::UUID
       AND aggregate_version = $2::BIGINT AND network_revision = $6::BIGINT
       AND event_class = 'network.revision.advanced'
       AND (payload ->> 'inventory_revision')::BIGINT = $7::BIGINT
       AND (payload ->> 'session_generation')::BIGINT = $3::BIGINT
       AND (payload ->> 'terminal')::BOOLEAN),
    (SELECT pg_catalog.count(*)::INTEGER
     FROM mesh_ops.idempotency_record AS record
     JOIN mesh_ops.outbox_event AS event ON event.public_id = record.outbox_public_id
     WHERE record.public_id = $5::UUID
       AND record.workspace_id = 103 AND record.network_id = $8::BIGINT
       AND record.operation = 'device.revoke'
       AND record.digest_algorithm = 'hmac-sha256-v1'
       AND pg_catalog.octet_length(record.key_digest) = 32
       AND pg_catalog.octet_length(record.request_semantic_hash) = 32
       AND record.state = 'completed' AND record.result_kind = 'device_revocation'
       AND record.result_public_id = $1::UUID AND record.result_version = $2::BIGINT
       AND record.result_network_revision = $6::BIGINT
       AND event.aggregate_public_id = record.result_public_id
       AND event.network_revision = record.result_network_revision)`,
		command.NodeID().String(),
		result.DeviceVersion(),
		result.SessionGeneration(),
		command.Reason().String(),
		result.IdempotencyRecordID().String(),
		result.NetworkRevision(),
		result.InventoryRevision(),
		networkInternalID,
	).Scan(
		&deviceCount,
		&machineKeyCount,
		&nodeKeyCount,
		&auditCount,
		&outboxCount,
		&replayCount,
	); err != nil {
		t.Fatalf("query committed Device revocation evidence: %v", err)
	}
	if deviceCount != 1 || machineKeyCount != 1 || nodeKeyCount != 1 || auditCount != 1 ||
		outboxCount != 1 || replayCount != 1 {
		t.Fatalf(
			"revocation evidence device/machine/node/audit/outbox/replay = %d/%d/%d/%d/%d/%d, want all 1",
			deviceCount,
			machineKeyCount,
			nodeKeyCount,
			auditCount,
			outboxCount,
			replayCount,
		)
	}
}

func assertRevokedDeviceExcludedFromMap(
	ctx context.Context,
	t *testing.T,
	runtimePool *postgresadapter.Pool,
	selfIdentity control.AuthenticatedNode,
	wantNetworkRevision int64,
) {
	t.Helper()
	snapshot, err := newPeerCandidateStore(t, runtimePool, 8).Load(ctx, selfIdentity)
	if err != nil {
		t.Fatalf("load map after peer revocation: %v", err)
	}
	if snapshot.NetworkRevision() != wantNetworkRevision || len(snapshot.AuthorizedPeers()) != 0 {
		t.Fatalf(
			"post-revocation map revision/peers = %d/%+v, want %d/no peers",
			snapshot.NetworkRevision(),
			snapshot.AuthorizedPeers(),
			wantNetworkRevision,
		)
	}
}

func assertRevokedDeviceCannotResumeMap(
	ctx context.Context,
	t *testing.T,
	runtimePool *postgresadapter.Pool,
) {
	t.Helper()
	machineKey, err := node.NewMachineKey(filledIntegrationKey(0x85))
	if err != nil {
		t.Fatalf("construct revoked machine key: %v", err)
	}
	nodeKey, err := node.NewKey(filledIntegrationKey(0x86))
	if err != nil {
		t.Fatalf("construct revoked Node key: %v", err)
	}
	machine, err := control.NewAuthenticatedMachine(machineKey)
	if err != nil {
		t.Fatalf("construct revoked authenticated machine: %v", err)
	}
	identityValue, err := machine.BindNodeKey(nodeKey)
	if err != nil {
		t.Fatalf("bind revoked authenticated Node: %v", err)
	}
	if _, err := newPeerCandidateStore(t, runtimePool, 8).Load(ctx, identityValue); !errors.Is(err, mapsession.ErrUnauthorized) {
		t.Fatalf("revoked Device map load error = %v, want ErrUnauthorized", err)
	}
}

func assertDeviceRevocationPrivilegeContract(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
) {
	t.Helper()
	var runtimeTableRead, runtimeTableInsert, runtimeTableUpdate bool
	var runtimeClaim, runtimeLoad, runtimeComplete bool
	var workerClaim, workerLoad, workerComplete bool
	if err := connection.QueryRow(ctx, `SELECT
    pg_catalog.has_table_privilege('mesh_runtime', 'mesh_ops.idempotency_record', 'SELECT'),
    pg_catalog.has_table_privilege('mesh_runtime', 'mesh_ops.idempotency_record', 'INSERT'),
    pg_catalog.has_table_privilege('mesh_runtime', 'mesh_ops.idempotency_record', 'UPDATE'),
    pg_catalog.has_function_privilege('mesh_runtime', 'mesh_ops.claim_network_idempotency(UUID, UUID, TEXT, TEXT, BYTEA, BYTEA, TIMESTAMPTZ, TIMESTAMPTZ)', 'EXECUTE'),
    pg_catalog.has_function_privilege('mesh_runtime', 'mesh_ops.load_network_idempotency(UUID, TEXT, TEXT, BYTEA)', 'EXECUTE'),
    pg_catalog.has_function_privilege('mesh_runtime', 'mesh_ops.complete_network_idempotency(UUID, UUID, TEXT, TEXT, BYTEA, BYTEA, TEXT, UUID, BIGINT, BIGINT, JSONB, UUID, TIMESTAMPTZ)', 'EXECUTE'),
    pg_catalog.has_function_privilege('mesh_worker', 'mesh_ops.claim_network_idempotency(UUID, UUID, TEXT, TEXT, BYTEA, BYTEA, TIMESTAMPTZ, TIMESTAMPTZ)', 'EXECUTE'),
    pg_catalog.has_function_privilege('mesh_worker', 'mesh_ops.load_network_idempotency(UUID, TEXT, TEXT, BYTEA)', 'EXECUTE'),
    pg_catalog.has_function_privilege('mesh_worker', 'mesh_ops.complete_network_idempotency(UUID, UUID, TEXT, TEXT, BYTEA, BYTEA, TEXT, UUID, BIGINT, BIGINT, JSONB, UUID, TIMESTAMPTZ)', 'EXECUTE')`).Scan(
		&runtimeTableRead,
		&runtimeTableInsert,
		&runtimeTableUpdate,
		&runtimeClaim,
		&runtimeLoad,
		&runtimeComplete,
		&workerClaim,
		&workerLoad,
		&workerComplete,
	); err != nil {
		t.Fatalf("query Device revocation privilege contract: %v", err)
	}
	if runtimeTableRead || runtimeTableInsert || runtimeTableUpdate ||
		!runtimeClaim || !runtimeLoad || !runtimeComplete ||
		workerClaim || workerLoad || workerComplete {
		t.Fatalf(
			"revocation privileges table=%t/%t/%t runtime=%t/%t/%t worker=%t/%t/%t",
			runtimeTableRead,
			runtimeTableInsert,
			runtimeTableUpdate,
			runtimeClaim,
			runtimeLoad,
			runtimeComplete,
			workerClaim,
			workerLoad,
			workerComplete,
		)
	}
}
