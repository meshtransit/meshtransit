//go:build integration

package integration

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	registrationapp "meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

// assertPostgreSQLNodeAddressQuarantine checks schema 143 (TD-CORE-14):
// every revocation path quarantines the Device's addresses, registration
// skips an address still in quarantine, and reuses it, releasing the old
// lease, once the quarantine ends; a Device revoked before schema 143 that
// still holds an active lease is reclaimed the same way.
func assertPostgreSQLNodeAddressQuarantine(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimeConnection *pgx.Conn,
	runtimePool *postgresadapter.Pool,
) {
	t.Helper()
	assertRevokedDevicesHoldNoActiveLease(ctx, t, adminConnection)
	assertRuntimeCannotQuarantineAcrossNetworks(ctx, t, runtimeConnection)

	held := registerQuarantineNode(ctx, t, adminConnection, runtimePool, 1)
	heldAddress := quarantineLeaseAddress(ctx, t, adminConnection, held)
	// Revoke it as an old revocation would, then quarantine for another hour.
	forceQuarantineFixture(ctx, t, adminConnection, `
UPDATE mesh.device SET state = 'revoked', version = version + 1 WHERE public_id = $1::UUID;
UPDATE mesh.node_address_lease AS lease
SET state = 'quarantined', released_at = pg_catalog.clock_timestamp(),
    quarantine_until = pg_catalog.clock_timestamp() + INTERVAL '1 hour', version = lease.version + 1
FROM mesh.device AS device
WHERE device.id = lease.device_id AND device.public_id = $1::UUID AND lease.state = 'active'`, held)

	skipped := registerQuarantineNode(ctx, t, adminConnection, runtimePool, 2)
	if address := quarantineLeaseAddress(ctx, t, adminConnection, skipped); address == heldAddress {
		t.Fatalf("registration reused %s while its quarantine lasts", address)
	}

	forceQuarantineFixture(ctx, t, adminConnection, `
UPDATE mesh.node_address_lease AS lease
SET released_at = pg_catalog.clock_timestamp() - INTERVAL '25 hours',
    quarantine_until = pg_catalog.clock_timestamp() - INTERVAL '1 hour', version = lease.version + 1
FROM mesh.device AS device
WHERE device.id = lease.device_id AND device.public_id = $1::UUID AND lease.state = 'quarantined'`, held)
	reused := registerQuarantineNode(ctx, t, adminConnection, runtimePool, 3)
	if address := quarantineLeaseAddress(ctx, t, adminConnection, reused); address != heldAddress {
		t.Fatalf("registration took %s, want %s after its quarantine ended", address, heldAddress)
	}
	assertQuarantineLeaseReleased(ctx, t, adminConnection, held)

	legacy := registerQuarantineNode(ctx, t, adminConnection, runtimePool, 4)
	legacyAddress := quarantineLeaseAddress(ctx, t, adminConnection, legacy)
	// Revoked before schema 143: the lease stayed active. Such a lease does
	// not settle the address floor, so schema 157's backfill (or the
	// revocation trigger this fixture switches off) keeps the floor at or
	// below it.
	forceQuarantineFixture(ctx, t, adminConnection, `
UPDATE mesh.device
SET state = 'revoked', version = version + 1,
    updated_at = pg_catalog.clock_timestamp() - INTERVAL '25 hours',
    created_at = LEAST(created_at, pg_catalog.clock_timestamp() - INTERVAL '26 hours')
WHERE public_id = $1::UUID;
UPDATE mesh_ops.registration_address_floor AS address_floor
SET floor_address = lease.address
FROM mesh.node_address_lease AS lease
JOIN mesh.device AS device ON device.id = lease.device_id
WHERE device.public_id = $1::UUID AND lease.state = 'active'
  AND address_floor.network_prefix_id = lease.network_prefix_id
  AND address_floor.floor_address > lease.address`, legacy)
	reclaimed := registerQuarantineNode(ctx, t, adminConnection, runtimePool, 5)
	if address := quarantineLeaseAddress(ctx, t, adminConnection, reclaimed); address != legacyAddress {
		t.Fatalf("registration took %s, want legacy revoked address %s", address, legacyAddress)
	}
	assertQuarantineLeaseReleased(ctx, t, adminConnection, legacy)
}

// assertRevokedDevicesHoldNoActiveLease checks the revocation paths run
// earlier (Console revoke, member removal, logout): every revoked Device's
// leases are quarantined for exactly the quarantine interval. The peer
// candidate fixtures revoke Devices 920 and 940 with raw SQL, not through a
// revocation path, so they keep active leases like pre-143 revocations.
func assertRevokedDevicesHoldNoActiveLease(ctx context.Context, t *testing.T, connection *pgx.Conn) {
	t.Helper()
	var active, quarantined, wrongInterval int
	if err := connection.QueryRow(ctx, `SELECT
    pg_catalog.count(*) FILTER (WHERE lease.state = 'active'),
    pg_catalog.count(*) FILTER (WHERE lease.state = 'quarantined'),
    pg_catalog.count(*) FILTER (WHERE lease.state = 'quarantined'
        AND lease.quarantine_until <> lease.released_at + mesh_ops.node_address_quarantine_v1())
FROM mesh.node_address_lease AS lease
JOIN mesh.device AS device ON device.id = lease.device_id
WHERE device.state = 'revoked' AND device.id NOT IN (920, 940)`).Scan(&active, &quarantined, &wrongInterval); err != nil {
		t.Fatalf("read revoked Device leases: %v", err)
	}
	if active != 0 || quarantined < 3 || wrongInterval != 0 {
		rows, _ := connection.Query(ctx, `SELECT device.id, device.hostname, device.network_id,
    device.updated_at::TEXT, lease.created_at::TEXT
FROM mesh.node_address_lease AS lease
JOIN mesh.device AS device ON device.id = lease.device_id
WHERE device.state = 'revoked' AND lease.state = 'active' AND device.id NOT IN (920, 940)`)
		for rows.Next() {
			var id, networkID int64
			var hostname, updatedAt, leaseCreated string
			_ = rows.Scan(&id, &hostname, &networkID, &updatedAt, &leaseCreated)
			t.Logf("revoked Device %d %s network %d updated %s lease created %s", id, hostname, networkID,
				updatedAt, leaseCreated)
		}
		rows.Close()
		t.Fatalf("revoked Device leases: %d active, %d quarantined, %d with a wrong interval", active,
			quarantined, wrongInterval)
	}
}

// assertRuntimeCannotQuarantineAcrossNetworks checks that the runtime role,
// scoped to Network 201, cannot reach revoked Device 930 of Network 203.
func assertRuntimeCannotQuarantineAcrossNetworks(ctx context.Context, t *testing.T, connection *pgx.Conn) {
	t.Helper()
	transaction, err := connection.Begin(ctx)
	if err != nil {
		t.Fatalf("begin cross-Network quarantine: %v", err)
	}
	defer func() { _ = transaction.Rollback(context.WithoutCancel(ctx)) }()
	setIntegrationScope(ctx, t, transaction, 101, 201)
	var moved int
	err = transaction.QueryRow(ctx, `SELECT mesh_ops.quarantine_device_leases_v1(930, pg_catalog.clock_timestamp())`).
		Scan(&moved)
	var pgError *pgconn.PgError
	if !errors.As(err, &pgError) || pgError.Code != "MTM03" {
		t.Fatalf("cross-Network quarantine = %d, %v; want MTM03", moved, err)
	}
}

// registerQuarantineNode registers one Node in Network 201 through the real
// registration transaction and returns its Node ID.
func registerQuarantineNode(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimePool *postgresadapter.Pool,
	index byte,
) string {
	t.Helper()
	return registerAddressTestNode(ctx, t, adminConnection, runtimePool, index,
		addressTestKeys{authority: 0xA0 + index, machine: 0xB0 + index, node: 0xC0 + index})
}

// addressTestKeys are the bytes a registration fixture's credential, machine
// key and node key are filled with; they must not repeat another fixture's.
type addressTestKeys struct {
	authority, machine, node byte
}

func registerAddressTestNode(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimePool *postgresadapter.Pool,
	index byte,
	keys addressTestKeys,
) string {
	t.Helper()
	command := seedOpenRegistrationFixture(ctx, t, adminConnection, registrationAuthorityFixture{
		authorityInternalID:    7400 + int64(index)*10,
		registrationInternalID: 7405 + int64(index)*10,
		authorityPublicID:      fmt.Sprintf("01890f20-0000-7000-8000-0000000074%02d", index),
		registrationPublicID:   fmt.Sprintf("01890f20-0000-7000-8000-0000000075%02d", index),
		changePublicID:         fmt.Sprintf("01890f21-0000-7000-8000-0000000074%02d", index),
		eventPublicID:          fmt.Sprintf("01890f22-0000-7000-8000-0000000074%02d", index),
		outboxPublicID:         fmt.Sprintf("01890f23-0000-7000-8000-0000000074%02d", index),
		digestLabel:            fmt.Sprintf("integration-address-quarantine-%d", index),
		hostname:               fmt.Sprintf("quarantine-%d.example", index),
		authorityMaterial:      keys.authority,
		machineMaterial:        keys.machine,
		nodeMaterial:           keys.node,
	})
	transactions, err := postgresadapter.NewRegistrationTransactions(
		runtimePool,
		postgresadapter.RegistrationTransactionOptions{
			StatementTimeout:      5 * time.Second,
			LockTimeout:           time.Second,
			IdleTimeout:           10 * time.Second,
			AddressCandidateLimit: 256,
		},
	)
	if err != nil {
		t.Fatalf("postgres.NewRegistrationTransactions() error = %v", err)
	}
	transaction, err := transactions.Begin(ctx, command.Scope)
	if err != nil {
		t.Fatalf("RegistrationTransactions.Begin() error = %v", err)
	}
	committed := false
	defer func() {
		if committed {
			return
		}
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), integrationCleanupTimeout)
		defer cancel()
		_ = transaction.Rollback(rollbackCtx)
	}()
	resolution, err := transaction.Resolve(ctx, command)
	if err != nil {
		t.Fatalf("registration %d Resolve() error = %v", index, err)
	}
	nodeID := fmt.Sprintf("01890f20-0000-7000-8000-0000000076%02d", index)
	change := quarantineRegistrationChange(t, command, resolution, nodeID, index, transaction.DecisionTime())
	if _, err := transaction.Apply(ctx, change); err != nil {
		t.Fatalf("registration %d Apply() error = %v", index, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		t.Fatalf("registration %d Commit() error = %v", index, err)
	}
	committed = true
	return nodeID
}

func quarantineRegistrationChange(
	t *testing.T,
	command registrationapp.Command,
	resolution registrationapp.Resolution,
	nodeValue string,
	index byte,
	occurredAt time.Time,
) registrationapp.Change {
	t.Helper()
	credential, err := resolution.Credential().Consume(occurredAt, command.RecoveryEpoch)
	if err != nil {
		t.Fatalf("consume registration %d credential: %v", index, err)
	}
	registrationValue, err := resolution.Registration().Authorize(occurredAt)
	if err != nil {
		t.Fatalf("authorize registration %d: %v", index, err)
	}
	nodeID, err := node.ParseID(nodeValue)
	if err != nil {
		t.Fatalf("parse registration %d Node ID: %v", index, err)
	}
	if registrationValue, err = registrationValue.Complete(nodeID, occurredAt); err != nil {
		t.Fatalf("complete registration %d: %v", index, err)
	}
	ids := make([]publicid.ID, 8)
	for position := range ids {
		value := fmt.Sprintf("01890f24-0000-7000-8000-00000000%02d%02d", index, position+1)
		if ids[position], err = publicid.Parse(value); err != nil {
			t.Fatalf("parse registration %d mutation ID %q: %v", index, value, err)
		}
	}
	mutationIDs, err := registrationapp.NewMutationIDs(registrationapp.MutationIDParams{
		ChangeID:          ids[0],
		AuditEventID:      ids[1],
		OutboxEventID:     ids[2],
		CredentialUseID:   ids[3],
		MachineKeyEpochID: ids[4],
		NodeKeyEpochID:    ids[5],
		IPv4LeaseID:       ids[6],
		IPv6LeaseID:       ids[7],
	})
	if err != nil {
		t.Fatalf("construct registration %d mutation IDs: %v", index, err)
	}
	change, err := registrationapp.NewChange(registrationapp.ChangeParams{
		Registration: registrationValue,
		Profile:      resolution.Profile(),
		Credential:   credential,
		Identity:     command.Identity,
		OwnerID:      credential.IssuerID(),
		CustodianID:  credential.IssuerID(),
		NodeID:       nodeID,
		Hostname:     command.Hostname,
		Disposition:  registrationapp.DispositionCreated,
		MutationIDs:  mutationIDs,
		OccurredAt:   occurredAt,
	})
	if err != nil {
		t.Fatalf("construct registration %d change: %v", index, err)
	}
	return change
}

// quarantineLeaseAddress returns the Node's IPv4 address from its newest lease.
func quarantineLeaseAddress(ctx context.Context, t *testing.T, connection *pgx.Conn, nodeID string) string {
	t.Helper()
	var address string
	if err := connection.QueryRow(ctx, `SELECT pg_catalog.host(lease.address)
FROM mesh.node_address_lease AS lease
JOIN mesh.device AS device ON device.id = lease.device_id
WHERE device.public_id = $1::UUID AND lease.family = 4
ORDER BY lease.id DESC
LIMIT 1`, nodeID).Scan(&address); err != nil {
		t.Fatalf("read Node %s address: %v", nodeID, err)
	}
	return address
}

func assertQuarantineLeaseReleased(ctx context.Context, t *testing.T, connection *pgx.Conn, nodeID string) {
	t.Helper()
	var state string
	var releasedAt *time.Time
	var quarantineUntil *time.Time
	if err := connection.QueryRow(ctx, `SELECT lease.state, lease.released_at, lease.quarantine_until
FROM mesh.node_address_lease AS lease
JOIN mesh.device AS device ON device.id = lease.device_id
WHERE device.public_id = $1::UUID AND lease.family = 4`, nodeID).Scan(&state, &releasedAt,
		&quarantineUntil); err != nil {
		t.Fatalf("read Node %s lease: %v", nodeID, err)
	}
	if state != "released" || releasedAt == nil || quarantineUntil != nil {
		t.Fatalf("Node %s lease = %s released_at=%v quarantine_until=%v, want released", nodeID, state,
			releasedAt, quarantineUntil)
	}
}

// forceQuarantineFixture rewrites history with triggers off, as other
// integration fixtures do, to stand for time passing or an old revocation.
func forceQuarantineFixture(ctx context.Context, t *testing.T, connection *pgx.Conn, statements, nodeID string) {
	t.Helper()
	transaction, err := connection.Begin(ctx)
	if err != nil {
		t.Fatalf("begin quarantine fixture: %v", err)
	}
	defer func() { _ = transaction.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := transaction.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatalf("disable triggers for quarantine fixture: %v", err)
	}
	for _, statement := range splitQuarantineStatements(statements) {
		if _, err := transaction.Exec(ctx, statement, nodeID); err != nil {
			t.Fatalf("quarantine fixture %q: %v", statement, err)
		}
	}
	if err := transaction.Commit(ctx); err != nil {
		t.Fatalf("commit quarantine fixture: %v", err)
	}
}

func splitQuarantineStatements(statements string) []string {
	var result []string
	start := 0
	for index := 0; index < len(statements); index++ {
		if statements[index] == ';' {
			result = append(result, statements[start:index])
			start = index + 1
		}
	}
	if tail := statements[start:]; len(tail) > 0 {
		result = append(result, tail)
	}
	return result
}
