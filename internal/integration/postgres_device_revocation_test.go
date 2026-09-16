//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/adapter/httpapi"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/control"
	"github.com/meshtransit/meshtransit/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/internal/idempotency"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/node/revocation"
	"github.com/meshtransit/meshtransit/internal/ratelimit"
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
	revokeDeviceOverHTTP(ctx, t, runtimePool, service, command, 1)

	result, err := service.Revoke(ctx, command)
	if err != nil {
		t.Fatalf("replay HTTP Device revocation: %v", err)
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
	assertRoleBindingRevocationDeniesReplay(ctx, t, adminConnection, service, command)
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
	reason, err := revocation.NewReason(reasonValue)
	if err != nil {
		t.Fatalf("construct Device revocation reason: %v", err)
	}
	proof, err := integrationDeviceRevocationDigester(t).Proof(
		integrationDeviceRevocationIdempotencyKey(digestDiscriminator),
	)
	if err != nil {
		t.Fatalf("construct Device revocation idempotency proof: %v", err)
	}
	command, err := revocation.NewCommand(revocation.CommandParams{
		Scope:               scope,
		NodeID:              nodeID,
		ExpectedVersion:     expectedVersion,
		AccountSession:      managementRBACAccountSessionFixture(t),
		Reason:              reason,
		IdempotencyEvidence: proof,
	})
	if err != nil {
		t.Fatalf("construct Device revocation command: %v", err)
	}
	return command
}

func revokeDeviceOverHTTP(
	ctx context.Context,
	t *testing.T,
	runtimePool *postgresadapter.Pool,
	service *revocation.Service,
	command revocation.Command,
	idempotencyDiscriminator byte,
) {
	t.Helper()
	accountSessionStore, err := postgresadapter.NewAccountSessionStore(
		runtimePool,
		postgresadapter.AccountSessionOptions{
			StatementTimeout: 5 * time.Second,
			IdleTimeout:      10 * time.Second,
		},
	)
	if err != nil {
		t.Fatalf("postgres.NewAccountSessionStore() error = %v", err)
	}
	keyring, _, rawToken := integrationManagementAccountSessionSecurity(t)
	sessions, err := accountsession.NewService(keyring, accountSessionStore, accountsession.SystemClock{})
	if err != nil {
		t.Fatalf("accountsession.NewService() error = %v", err)
	}
	rateLimitKeyID, err := ratelimit.NewDigestKeyID("integration-v1")
	if err != nil {
		t.Fatalf("ratelimit.NewDigestKeyID() error = %v", err)
	}
	rateLimitDigester, err := ratelimit.NewDigester(rateLimitKeyID, bytes.Repeat([]byte{0x71}, 32))
	if err != nil {
		t.Fatalf("ratelimit.NewDigester() error = %v", err)
	}
	rateLimitPolicy, err := ratelimit.NewPolicy(100, time.Second)
	if err != nil {
		t.Fatalf("ratelimit.NewPolicy() error = %v", err)
	}
	handler, err := httpapi.NewManagementHandler(httpapi.ManagementHandlerOptions{
		Sessions:              sessions,
		Revocations:           service,
		PolicyPublications:    newIntegrationManagementPolicyPublicationService(t, runtimePool),
		Idempotency:           integrationDeviceRevocationDigester(t),
		RateLimitSubjects:     rateLimitDigester,
		RateLimiter:           integrationAllowAllRateLimiter{},
		SourceRateLimit:       rateLimitPolicy,
		SessionRateLimit:      rateLimitPolicy,
		CorrelationIDs:        httpapi.PublicCorrelationIDGenerator{},
		Logger:                slog.New(slog.NewJSONHandler(io.Discard, nil)),
		RequestTimeout:        10 * time.Second,
		MaxConcurrentRequests: 2,
	})
	if err != nil {
		t.Fatalf("httpapi.NewManagementHandler() error = %v", err)
	}
	path := fmt.Sprintf(
		"/api/v1/workspaces/%s/networks/%s/devices/%s/actions/revoke",
		command.Scope().WorkspaceID().String(),
		command.Scope().NetworkID().String(),
		command.NodeID().String(),
	)
	request := httptest.NewRequestWithContext(
		ctx,
		http.MethodPost,
		path,
		bytes.NewBufferString(`{"reason":"compromised peer"}`),
	)
	request.Header.Set("Authorization", "Bearer "+rawToken)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("If-Match", fmt.Sprintf(`"%d"`, command.ExpectedVersion()))
	request.Header.Set(
		"Idempotency-Key",
		integrationDeviceRevocationIdempotencyKey(idempotencyDiscriminator),
	)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("management HTTP status = %d, want 200; body = %s", response.Code, response.Body.String())
	}
	var payload struct {
		Data struct {
			DeviceID      string `json:"device_id"`
			State         string `json:"state"`
			DeviceVersion int64  `json:"device_version"`
		} `json:"data"`
		CorrelationID string `json:"correlation_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode management HTTP response: %v", err)
	}
	if payload.Data.DeviceID != command.NodeID().String() || payload.Data.State != "revoked" ||
		payload.Data.DeviceVersion != command.ExpectedVersion()+1 || payload.CorrelationID == "" {
		t.Fatalf("management HTTP response = %+v, want committed Device revocation", payload)
	}
}

type integrationAllowAllRateLimiter struct{}

func (integrationAllowAllRateLimiter) Allow(
	_ context.Context,
	_ ratelimit.Subject,
	policy ratelimit.Policy,
) (ratelimit.Decision, error) {
	return ratelimit.NewDecision(true, policy.Capacity(), policy.Capacity()-1, 0)
}

func integrationDeviceRevocationDigester(t *testing.T) *idempotency.Digester {
	t.Helper()
	keyID, err := idempotency.NewDigestKeyID("integration-v1")
	if err != nil {
		t.Fatalf("idempotency.NewDigestKeyID() error = %v", err)
	}
	digester, err := idempotency.NewDigester(keyID, bytes.Repeat([]byte{0x78}, 32))
	if err != nil {
		t.Fatalf("idempotency.NewDigester() error = %v", err)
	}
	return digester
}

func integrationDeviceRevocationIdempotencyKey(discriminator byte) string {
	return fmt.Sprintf("integration-request-%04d", discriminator)
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
	expectedRoleBindingPublicID := integrationRoleBinding203PublicID
	if networkInternalID == 204 {
		expectedRoleBindingPublicID = integrationRoleBinding204PublicID
	}
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
       AND correlation_public_id = $5::UUID
       AND payload ->> 'account_session_public_id' = $9::TEXT
       AND payload ->> 'role_binding_public_id' = $10::TEXT
       AND payload ->> 'role_definition_public_id' = $11::TEXT
       AND (payload ->> 'scope_authority_generation')::BIGINT = 1
       AND (payload ->> 'membership_authority_generation')::BIGINT = 1
       AND (payload ->> 'binding_authority_generation')::BIGINT = 1
       AND (payload ->> 'role_authority_generation')::BIGINT = 1),
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
		integrationManagementSessionPublicID,
		expectedRoleBindingPublicID,
		integrationRoleDefinitionPublicID,
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

func assertRoleBindingRevocationDeniesReplay(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	service *revocation.Service,
	command revocation.Command,
) {
	t.Helper()
	var networkRevision int64
	if err := adminConnection.QueryRow(ctx, `SELECT network_revision
FROM mesh_ops.network_revision
WHERE workspace_id = 103 AND network_id = 203`).Scan(&networkRevision); err != nil {
		t.Fatalf("query Network revision before RoleBinding revocation: %v", err)
	}
	commitAuditedAuthorityFixture(ctx, t, adminConnection, authorityEvidenceFixture{
		changePublicID:         "01890f01-0000-7000-8000-000000000846",
		eventPublicID:          "01890f02-0000-7000-8000-000000000846",
		outboxPublicID:         "01890f03-0000-7000-8000-000000000846",
		streamID:               203,
		aggregateKind:          "role_binding",
		aggregatePublicID:      integrationRoleBinding203PublicID,
		aggregateVersion:       2,
		networkRevision:        networkRevision,
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "role_binding.revoked",
		permission:             "role_binding.manage",
		outboxEventClass:       "role_binding.revoked",
	}, func(transaction pgx.Tx) {
		if _, err := transaction.Exec(ctx, `UPDATE mesh.role_binding
SET state = 'revoked',
    authority_generation = authority_generation + 1,
    version = version + 1,
    updated_at = pg_catalog.transaction_timestamp()
WHERE public_id = $1::UUID`, integrationRoleBinding203PublicID); err != nil {
			t.Fatalf("revoke integration RoleBinding: %v", err)
		}
	})

	if _, err := service.Revoke(ctx, command); !errors.Is(err, revocation.ErrForbidden) {
		t.Fatalf("replay after RoleBinding revocation error = %v, want ErrForbidden", err)
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
