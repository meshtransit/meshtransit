//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/control"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
)

type peerProjectionNodeFixture struct {
	id              int64
	ownerID         int64
	deviceState     string
	nodeKeyState    string
	machineMaterial byte
	nodeMaterial    byte
	address         string
	createdAt       time.Time
	expiresAt       time.Time
}

func assertPostgreSQLPeerCandidateProjection(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	blockerConnection *pgx.Conn,
	runtimePool *postgresadapter.Pool,
) control.AuthenticatedNode {
	t.Helper()
	identity := seedPeerCandidateProjection(ctx, t, adminConnection)
	seedCompiledPacketPolicy(ctx, t, adminConnection)
	store := newPeerCandidateStore(t, runtimePool, 8)

	snapshot, err := store.Load(ctx, identity)
	if err != nil {
		t.Fatalf("load peer candidate snapshot: %v", err)
	}
	candidates := snapshot.PeerCandidates()
	wantNodeIDs := []string{
		integrationPublicID("01890f31-0000-7000-8000-", 920),
		integrationPublicID("01890f31-0000-7000-8000-", 930),
	}
	if len(candidates) != len(wantNodeIDs) {
		t.Fatalf("peer candidates = %+v, want only two active same-scope Nodes", candidates)
	}
	for index, wantNodeID := range wantNodeIDs {
		if candidates[index].NodeID().String() != wantNodeID ||
			candidates[index].Scope() != snapshot.Scope() {
			t.Fatalf("peer candidate %d = %+v, want Node %s in self scope", index, candidates[index], wantNodeID)
		}
	}
	if snapshot.NetworkRevision() != 3 || snapshot.PacketPolicy().Revision() != 2 ||
		len(snapshot.PacketPolicy().Rules()) != 2 {
		t.Fatalf(
			"policy revisions/rules = (%d, %d, %d), want (3, 2, 2)",
			snapshot.NetworkRevision(),
			snapshot.PacketPolicy().Revision(),
			len(snapshot.PacketPolicy().Rules()),
		)
	}
	authorizedPeers := snapshot.AuthorizedPeers()
	if len(authorizedPeers) != 2 ||
		authorizedPeers[0].NodeID().String() != wantNodeIDs[0] ||
		authorizedPeers[1].NodeID().String() != wantNodeIDs[1] {
		t.Fatalf("authorized peers = %+v, want both explicitly connected Nodes", authorizedPeers)
	}

	assertSharedInventoryMatchesDirectRead(ctx, t, runtimePool, store, identity)

	boundedStore := newPeerCandidateStore(t, runtimePool, 1)
	if _, err := boundedStore.Load(ctx, identity); !errors.Is(err, mapsession.ErrPeerCandidateLimit) {
		t.Fatalf("bounded peer candidate Load() error = %v, want ErrPeerCandidateLimit", err)
	}

	assertPeerCandidateRepeatableRead(
		ctx,
		t,
		adminConnection,
		blockerConnection,
		store,
		identity,
		wantNodeIDs[0],
	)
	return identity
}

func seedCompiledPacketPolicy(ctx context.Context, t *testing.T, connection *pgx.Conn) {
	t.Helper()
	releasePublicID := integrationPublicID("01890f50-0000-7000-8000-", 203)
	commitAuditedAuthorityFixture(ctx, t, connection, authorityEvidenceFixture{
		changePublicID:         integrationPublicID("01890f51-0000-7000-8000-", 203),
		eventPublicID:          integrationPublicID("01890f52-0000-7000-8000-", 203),
		outboxPublicID:         integrationPublicID("01890f53-0000-7000-8000-", 203),
		streamID:               203,
		aggregateKind:          "policy_release",
		aggregatePublicID:      releasePublicID,
		aggregateVersion:       1,
		networkRevision:        int64(3),
		actorPrincipalPublicID: integrationPublicID("01890f00-0000-7000-8000-", 11),
		action:                 "policy.published",
		permission:             "policy.publish",
		outboxEventClass:       "network.revision.advanced",
	}, func(transaction pgx.Tx) {
		setIntegrationScope(ctx, t, transaction, 103, 203)
		var networkRevision, policyRevision int64
		if err := transaction.QueryRow(
			ctx,
			`SELECT network_revision, policy_revision
FROM mesh_ops.advance_network_policy_revision()`,
		).Scan(&networkRevision, &policyRevision); err != nil {
			t.Fatalf("advance compiled packet policy revision: %v", err)
		}
		if networkRevision != 3 || policyRevision != 2 {
			t.Fatalf(
				"advanced policy revisions = (%d, %d), want (3, 2)",
				networkRevision,
				policyRevision,
			)
		}
		var releaseID int64
		if err := transaction.QueryRow(ctx, `INSERT INTO mesh.policy_release (
    public_id,
    workspace_id,
    network_id,
    policy_revision,
    semantic_hash,
    compiler_format_version,
    state
) VALUES (
    $1::UUID,
    103,
    203,
    $2::BIGINT,
    pg_catalog.decode(pg_catalog.repeat('a5', 32), 'hex'),
    1,
    'active'
)
RETURNING id`, releasePublicID, policyRevision).Scan(&releaseID); err != nil {
			t.Fatalf("insert compiled packet policy release: %v", err)
		}
		rules := []struct {
			projectionID  string
			accessRuleID  string
			sourceID      int64
			destinationID int64
			protocol      string
			ports         string
		}{
			{
				projectionID:  integrationPublicID("01890f54-0000-7000-8000-", 1),
				accessRuleID:  integrationPublicID("01890f55-0000-7000-8000-", 1),
				sourceID:      910,
				destinationID: 920,
				protocol:      "tcp",
				ports:         "{[80,82),[443,444)}",
			},
			{
				projectionID:  integrationPublicID("01890f54-0000-7000-8000-", 2),
				accessRuleID:  integrationPublicID("01890f55-0000-7000-8000-", 2),
				sourceID:      930,
				destinationID: 910,
				protocol:      "icmp",
				ports:         "{}",
			},
			{
				// A compiled rule may outlive its source Device. It must
				// never appear in the current packet policy projection.
				projectionID:  integrationPublicID("01890f54-0000-7000-8000-", 3),
				accessRuleID:  integrationPublicID("01890f55-0000-7000-8000-", 3),
				sourceID:      955,
				destinationID: 910,
				protocol:      "icmp",
				ports:         "{}",
			},
		}
		for _, rule := range rules {
			if _, err := transaction.Exec(ctx, `INSERT INTO mesh.compiled_policy_rule (
    public_id,
    access_rule_public_id,
    workspace_id,
    network_id,
    policy_release_id,
    policy_revision,
    source_device_id,
    destination_device_id,
    protocol,
    destination_ports
) VALUES (
    $1::UUID,
    $2::UUID,
    103,
    203,
    $3::BIGINT,
    $4::BIGINT,
    $5::BIGINT,
    $6::BIGINT,
    $7::TEXT,
    $8::INT4MULTIRANGE
)`,
				rule.projectionID,
				rule.accessRuleID,
				releaseID,
				policyRevision,
				rule.sourceID,
				rule.destinationID,
				rule.protocol,
				rule.ports,
			); err != nil {
				t.Fatalf("insert compiled packet policy rule: %v", err)
			}
		}
	})
}

func newPeerCandidateStore(
	t *testing.T,
	pool *postgresadapter.Pool,
	limit int,
) mapsession.SnapshotStore {
	t.Helper()
	store, err := postgresadapter.NewMapSessionStore(pool, postgresadapter.MapSessionOptions{
		StatementTimeout:   5 * time.Second,
		IdleTimeout:        5 * time.Second,
		PeerCandidateLimit: limit,
		PolicyRuleLimit:    mapsession.MaximumPacketPolicyRules,
		RelayDirectory:     integrationRelayDirectory(t),
	})
	if err != nil {
		t.Fatalf("postgres.NewMapSessionStore() error = %v", err)
	}
	return store
}

func seedPeerCandidateProjection(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
) control.AuthenticatedNode {
	t.Helper()
	seedWorkspaceAuthority(ctx, t, connection, authorityFixture{
		workspaceID:     103,
		networkID:       203,
		addressRealmID:  303,
		addressPoolID:   403,
		networkPrefixID: 503,
		publicIDSuffix:  "103",
		nameSuffix:      "peer-projection",
	})
	seedPeerProjectionNetwork(ctx, t, connection)
	seedSuspendedPeerOwner(ctx, t, connection)

	now := time.Now().UTC()
	seedPeerProjectionScope(ctx, t, connection, 103, 203, 303, 403, 503, 901, []peerProjectionNodeFixture{
		{id: 910, ownerID: 11, deviceState: "active", nodeKeyState: "active", machineMaterial: 0x81, nodeMaterial: 0x82, address: "100.64.1.10", createdAt: now.Add(-3 * time.Hour), expiresAt: now.Add(2 * time.Hour)},
		{id: 920, ownerID: 11, deviceState: "active", nodeKeyState: "active", machineMaterial: 0x83, nodeMaterial: 0x84, address: "100.64.1.20", createdAt: now.Add(-time.Hour), expiresAt: now.Add(2 * time.Hour)},
		{id: 930, ownerID: 11, deviceState: "active", nodeKeyState: "active", machineMaterial: 0x85, nodeMaterial: 0x86, address: "100.64.1.30", createdAt: now.Add(-2 * time.Hour), expiresAt: now.Add(2 * time.Hour)},
		{id: 940, ownerID: 11, deviceState: "revoked", nodeKeyState: "active", machineMaterial: 0x87, nodeMaterial: 0x88, address: "100.64.1.40", createdAt: now.Add(-time.Hour), expiresAt: now.Add(2 * time.Hour)},
		{id: 950, ownerID: 11, deviceState: "expired", nodeKeyState: "active", machineMaterial: 0x89, nodeMaterial: 0x8a, address: "100.64.1.50", createdAt: now.Add(-time.Hour), expiresAt: now.Add(2 * time.Hour)},
		{id: 955, ownerID: 11, deviceState: "active", nodeKeyState: "active", machineMaterial: 0x8b, nodeMaterial: 0x8c, address: "100.64.1.55", createdAt: now.Add(-3 * time.Hour), expiresAt: now.Add(-time.Hour)},
		{id: 960, ownerID: 12, deviceState: "active", nodeKeyState: "active", machineMaterial: 0x8d, nodeMaterial: 0x8e, address: "100.64.1.60", createdAt: now.Add(-time.Hour), expiresAt: now.Add(2 * time.Hour)},
		{id: 970, ownerID: 11, deviceState: "active", nodeKeyState: "expired", machineMaterial: 0x8f, nodeMaterial: 0x90, address: "100.64.1.70", createdAt: now.Add(-time.Hour), expiresAt: now.Add(2 * time.Hour)},
	})
	seedPeerProjectionScope(ctx, t, connection, 103, 204, 303, 403, 504, 902, []peerProjectionNodeFixture{
		{id: 980, ownerID: 11, deviceState: "active", nodeKeyState: "active", machineMaterial: 0x91, nodeMaterial: 0x92, address: "100.64.2.80", createdAt: now.Add(-time.Hour), expiresAt: now.Add(2 * time.Hour)},
	})
	seedPeerProjectionScope(ctx, t, connection, 102, 202, 302, 402, 502, 903, []peerProjectionNodeFixture{
		{id: 990, ownerID: 11, deviceState: "active", nodeKeyState: "active", machineMaterial: 0x93, nodeMaterial: 0x94, address: "100.64.1.90", createdAt: now.Add(-time.Hour), expiresAt: now.Add(2 * time.Hour)},
	})

	machineKey, err := node.NewMachineKey(filledIntegrationKey(0x81))
	if err != nil {
		t.Fatalf("construct peer projection self machine key: %v", err)
	}
	nodeKey, err := node.NewKey(filledIntegrationKey(0x82))
	if err != nil {
		t.Fatalf("construct peer projection self Node key: %v", err)
	}
	machine, err := control.NewAuthenticatedMachine(machineKey)
	if err != nil {
		t.Fatalf("construct peer projection authenticated machine: %v", err)
	}
	identity, err := machine.BindNodeKey(nodeKey)
	if err != nil {
		t.Fatalf("bind peer projection self Node key: %v", err)
	}
	return identity
}

func seedPeerProjectionNetwork(ctx context.Context, t *testing.T, connection *pgx.Conn) {
	t.Helper()
	commitAuditedAuthorityFixture(ctx, t, connection, authorityEvidenceFixture{
		changePublicID:         integrationPublicID("01890f45-0000-7000-8000-", 204),
		eventPublicID:          integrationPublicID("01890f46-0000-7000-8000-", 204),
		outboxPublicID:         integrationPublicID("01890f47-0000-7000-8000-", 204),
		streamID:               204,
		aggregateKind:          "network",
		aggregatePublicID:      integrationPublicID("01890f00-0000-7000-8000-", 204),
		aggregateVersion:       1,
		networkRevision:        int64(1),
		actorPrincipalPublicID: integrationPublicID("01890f00-0000-7000-8000-", 11),
		action:                 "network.created",
		permission:             "system.bootstrap",
		outboxEventClass:       "network.created",
	}, func(transaction pgx.Tx) {
		setIntegrationScope(ctx, t, transaction, 103, 204)
		statements := []string{
			`INSERT INTO mesh.network (
    id, public_id, workspace_id, display_name, name_key, node_limit, state
) OVERRIDING SYSTEM VALUE VALUES (
    204, '01890f00-0000-7000-8000-000000000204', 103,
    'Peer projection secondary', 'peer-projection-secondary', 1000, 'active'
)`,
			`INSERT INTO mesh.network_prefix (
    id, public_id, workspace_id, network_id, address_realm_id, address_pool_id,
    prefix, family, state
) OVERRIDING SYSTEM VALUE VALUES (
    504, '01890f00-0000-7000-8000-000000000504', 103, 204, 303, 403,
    '100.64.2.0/24', 4, 'active'
)`,
			`INSERT INTO mesh_ops.network_revision (workspace_id, network_id) VALUES (103, 204)`,
			`INSERT INTO mesh_audit.audit_stream (
    id, deployment_id, workspace_id, network_id, scope_kind
) OVERRIDING SYSTEM VALUE VALUES (204, 1, 103, 204, 'network')`,
		}
		for _, statement := range statements {
			if _, err := transaction.Exec(ctx, statement); err != nil {
				t.Fatalf("seed peer projection secondary Network: %v", err)
			}
		}
	})
}

func seedSuspendedPeerOwner(ctx context.Context, t *testing.T, connection *pgx.Conn) {
	t.Helper()
	commitAuditedAuthorityFixture(ctx, t, connection, authorityEvidenceFixture{
		changePublicID:         integrationPublicID("01890f45-0000-7000-8000-", 12),
		eventPublicID:          integrationPublicID("01890f46-0000-7000-8000-", 12),
		outboxPublicID:         integrationPublicID("01890f47-0000-7000-8000-", 12),
		streamID:               1,
		aggregateKind:          "principal",
		aggregatePublicID:      integrationPublicID("01890f00-0000-7000-8000-", 12),
		aggregateVersion:       1,
		actorPrincipalPublicID: integrationPublicID("01890f00-0000-7000-8000-", 11),
		action:                 "principal.created",
		permission:             "system.bootstrap",
		outboxEventClass:       "principal.created",
	}, func(transaction pgx.Tx) {
		_, err := transaction.Exec(ctx, `INSERT INTO mesh.principal (
    id, public_id, deployment_id, kind, state
) OVERRIDING SYSTEM VALUE VALUES (
    12, '01890f00-0000-7000-8000-000000000012', 1, 'account', 'suspended'
)`)
		if err != nil {
			t.Fatalf("seed suspended peer owner: %v", err)
		}
	})
}

func seedPeerProjectionScope(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	workspaceID int64,
	networkID int64,
	realmID int64,
	poolID int64,
	prefixID int64,
	profileID int64,
	nodes []peerProjectionNodeFixture,
) {
	t.Helper()
	commitAuditedAuthorityFixture(ctx, t, connection, authorityEvidenceFixture{
		changePublicID:         integrationPublicID("01890f48-0000-7000-8000-", networkID),
		eventPublicID:          integrationPublicID("01890f49-0000-7000-8000-", networkID),
		outboxPublicID:         integrationPublicID("01890f4a-0000-7000-8000-", networkID),
		streamID:               networkID,
		aggregateKind:          "device",
		aggregatePublicID:      integrationPublicID("01890f31-0000-7000-8000-", nodes[0].id),
		aggregateVersion:       1,
		networkRevision:        int64(2),
		actorPrincipalPublicID: integrationPublicID("01890f00-0000-7000-8000-", 11),
		action:                 "device.registered",
		permission:             "device.register",
		outboxEventClass:       "network.revision.advanced",
	}, func(transaction pgx.Tx) {
		setIntegrationScope(ctx, t, transaction, workspaceID, networkID)
		if _, err := transaction.Exec(ctx, `INSERT INTO mesh.enrollment_profile (
    id, public_id, workspace_id, network_id, created_by_principal_id,
    display_name, name_key, node_lifetime_seconds, ephemeral_mode,
    credential_use_policy, credential_max_uses, state
) OVERRIDING SYSTEM VALUE VALUES (
    $1, $2::UUID, $3, $4, 11, $5, $6, 3600, 'persistent', 'bounded', 1, 'active'
)`,
			profileID,
			integrationPublicID("01890f30-0000-7000-8000-", profileID),
			workspaceID,
			networkID,
			fmt.Sprintf("Peer projection %d", networkID),
			fmt.Sprintf("peer-projection-%d", networkID),
		); err != nil {
			t.Fatalf("seed peer projection profile: %v", err)
		}
		for _, fixture := range nodes {
			seedPeerProjectionNode(
				ctx,
				t,
				transaction,
				workspaceID,
				networkID,
				realmID,
				poolID,
				prefixID,
				profileID,
				fixture,
			)
		}
		if _, err := transaction.Exec(ctx, `UPDATE mesh_ops.network_revision
SET network_revision = network_revision + 1,
    inventory_revision = inventory_revision + 1,
    updated_at = pg_catalog.clock_timestamp()
WHERE workspace_id = $1 AND network_id = $2`, workspaceID, networkID); err != nil {
			t.Fatalf("advance peer projection fixture revision: %v", err)
		}
	})
}

func seedPeerProjectionNode(
	ctx context.Context,
	t *testing.T,
	transaction pgx.Tx,
	workspaceID int64,
	networkID int64,
	realmID int64,
	poolID int64,
	prefixID int64,
	profileID int64,
	fixture peerProjectionNodeFixture,
) {
	t.Helper()
	machineKey, err := node.NewMachineKey(filledIntegrationKey(fixture.machineMaterial))
	if err != nil {
		t.Fatalf("construct fixture machine key: %v", err)
	}
	nodeKey, err := node.NewKey(filledIntegrationKey(fixture.nodeMaterial))
	if err != nil {
		t.Fatalf("construct fixture Node key: %v", err)
	}
	machineBytes := machineKey.Bytes()
	machineFingerprint := machineKey.Fingerprint()
	nodeBytes := nodeKey.Bytes()
	nodeFingerprint := nodeKey.Fingerprint()
	hostname := fmt.Sprintf("peer-%d.example", fixture.id)
	if _, err := transaction.Exec(ctx, `INSERT INTO mesh.device (
    id, public_id, workspace_id, network_id, enrollment_profile_id,
    owner_principal_id, custodian_principal_id, registered_by_kind,
    registered_by_principal_id, hostname, hostname_key, is_ephemeral,
    expires_at, state, created_at
) OVERRIDING SYSTEM VALUE VALUES (
    $1, $2::UUID, $3, $4, $5, $6, 11, 'principal', 11, $7, $7,
    FALSE, $8, $9, $10
)`,
		fixture.id,
		integrationPublicID("01890f31-0000-7000-8000-", fixture.id),
		workspaceID,
		networkID,
		profileID,
		fixture.ownerID,
		hostname,
		fixture.expiresAt,
		fixture.deviceState,
		fixture.createdAt,
	); err != nil {
		t.Fatalf("seed peer projection device %d: %v", fixture.id, err)
	}
	if _, err := transaction.Exec(ctx, `INSERT INTO mesh.device_machine_key_epoch (
    id, public_id, workspace_id, network_id, device_id, epoch, public_key,
    fingerprint, valid_from, state
) OVERRIDING SYSTEM VALUE VALUES (
    $1, $2::UUID, $3, $4, $5, 1, $6::BYTEA, $7::BYTEA, $8, 'active'
)`,
		1000+fixture.id,
		integrationPublicID("01890f32-0000-7000-8000-", fixture.id),
		workspaceID,
		networkID,
		fixture.id,
		machineBytes[:],
		machineFingerprint[:],
		fixture.createdAt,
	); err != nil {
		t.Fatalf("seed peer projection machine key %d: %v", fixture.id, err)
	}
	var nodeValidUntil any
	if fixture.nodeKeyState != "active" {
		nodeValidUntil = fixture.createdAt.Add(time.Minute)
	}
	if _, err := transaction.Exec(ctx, `INSERT INTO mesh.device_node_key_epoch (
    id, public_id, workspace_id, network_id, device_id, epoch, public_key,
    fingerprint, valid_from, valid_until, state
) OVERRIDING SYSTEM VALUE VALUES (
    $1, $2::UUID, $3, $4, $5, 1, $6::BYTEA, $7::BYTEA, $8, $9, $10
)`,
		2000+fixture.id,
		integrationPublicID("01890f33-0000-7000-8000-", fixture.id),
		workspaceID,
		networkID,
		fixture.id,
		nodeBytes[:],
		nodeFingerprint[:],
		fixture.createdAt,
		nodeValidUntil,
		fixture.nodeKeyState,
	); err != nil {
		t.Fatalf("seed peer projection Node key %d: %v", fixture.id, err)
	}
	if _, err := transaction.Exec(ctx, `INSERT INTO mesh.node_address_lease (
    id, public_id, workspace_id, network_id, address_realm_id, address_pool_id,
    network_prefix_id, device_id, address, family, generation, lease_role, state
) OVERRIDING SYSTEM VALUE VALUES (
    $1, $2::UUID, $3, $4, $5, $6, $7, $8, $9::INET, 4, 1, 'primary', 'active'
)`,
		3000+fixture.id,
		integrationPublicID("01890f34-0000-7000-8000-", fixture.id),
		workspaceID,
		networkID,
		realmID,
		poolID,
		prefixID,
		fixture.id,
		fixture.address,
	); err != nil {
		t.Fatalf("seed peer projection lease %d: %v", fixture.id, err)
	}
}

func assertPeerCandidateRepeatableRead(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	blockerConnection *pgx.Conn,
	store mapsession.SnapshotStore,
	identity control.AuthenticatedNode,
	revokedNodeID string,
) {
	t.Helper()
	blocker, err := blockerConnection.Begin(ctx)
	if err != nil {
		t.Fatalf("begin peer projection blocker: %v", err)
	}
	defer rollbackIntegrationTransaction(ctx, t, blocker)
	if _, err := blocker.Exec(ctx, `LOCK TABLE mesh.node_address_lease IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatalf("lock peer projection lease table: %v", err)
	}

	type loadOutcome struct {
		snapshot mapsession.Snapshot
		err      error
	}
	result := make(chan loadOutcome, 1)
	go func() {
		snapshot, loadErr := store.Load(ctx, identity)
		result <- loadOutcome{snapshot: snapshot, err: loadErr}
	}()
	waitForPeerProjectionLock(ctx, t, adminConnection)

	commitAuditedAuthorityFixture(ctx, t, adminConnection, authorityEvidenceFixture{
		changePublicID:         integrationPublicID("01890f4b-0000-7000-8000-", 920),
		eventPublicID:          integrationPublicID("01890f4c-0000-7000-8000-", 920),
		outboxPublicID:         integrationPublicID("01890f4d-0000-7000-8000-", 920),
		streamID:               203,
		aggregateKind:          "device",
		aggregatePublicID:      revokedNodeID,
		aggregateVersion:       2,
		networkRevision:        int64(3),
		actorPrincipalPublicID: integrationPublicID("01890f00-0000-7000-8000-", 11),
		action:                 "device.revoked",
		permission:             "device.revoke",
		outboxEventClass:       "network.revision.advanced",
	}, func(transaction pgx.Tx) {
		setIntegrationScope(ctx, t, transaction, 103, 203)
		if _, err := transaction.Exec(ctx, `UPDATE mesh.device
SET state = 'revoked', version = version + 1, updated_at = pg_catalog.clock_timestamp()
WHERE workspace_id = 103 AND network_id = 203 AND id = 920`); err != nil {
			t.Fatalf("revoke concurrent peer fixture: %v", err)
		}
		if _, err := transaction.Exec(ctx, `UPDATE mesh_ops.network_revision
SET network_revision = network_revision + 1,
    inventory_revision = inventory_revision + 1,
    updated_at = pg_catalog.clock_timestamp()
WHERE workspace_id = 103 AND network_id = 203`); err != nil {
			t.Fatalf("advance concurrent peer fixture revision: %v", err)
		}
	})
	if err := blocker.Commit(ctx); err != nil {
		t.Fatalf("release peer projection blocker: %v", err)
	}

	var first loadOutcome
	select {
	case first = <-result:
	case <-ctx.Done():
		t.Fatalf("wait for repeatable-read peer projection: %v", ctx.Err())
	}
	if first.err != nil {
		t.Fatalf("repeatable-read Load() error = %v", first.err)
	}
	if !containsPeerCandidate(first.snapshot.PeerCandidates(), revokedNodeID) {
		t.Fatal("in-flight repeatable-read snapshot mixed in the concurrent revocation")
	}
	next, err := store.Load(ctx, identity)
	if err != nil {
		t.Fatalf("post-revocation peer candidate Load() error = %v", err)
	}
	if containsPeerCandidate(next.PeerCandidates(), revokedNodeID) {
		t.Fatal("new snapshot retained the revoked peer candidate")
	}
}

func waitForPeerProjectionLock(ctx context.Context, t *testing.T, connection *pgx.Conn) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		if err := connection.QueryRow(ctx, `SELECT EXISTS (
    SELECT 1
    FROM pg_catalog.pg_stat_activity
    WHERE wait_event_type = 'Lock'
      AND query LIKE '%FROM mesh.node_address_lease AS lease%'
)`).Scan(&waiting); err != nil {
			t.Fatalf("observe peer projection lock wait: %v", err)
		}
		if waiting {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("map snapshot did not reach the controlled lease-table lock")
		}
		runtime.Gosched()
	}
}

func containsPeerCandidate(candidates []mapsession.PeerCandidate, nodeID string) bool {
	for _, candidate := range candidates {
		if candidate.NodeID().String() == nodeID {
			return true
		}
	}
	return false
}

func integrationPublicID(prefix string, value int64) string {
	return fmt.Sprintf("%s%012d", prefix, value)
}
