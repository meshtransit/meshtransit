//go:build integration

package integration

import (
	"context"
	"net/netip"
	"testing"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
)

// referenceLowestFreeAddressSQL is the allocator before schema 157: the
// lowest address of a prefix that no live lease holds, read from every live
// lease of the prefix. Schema 157 must choose the same address.
const referenceLowestFreeAddressSQL = `WITH live AS (
    SELECT lease.address
    FROM mesh.node_address_lease AS lease
    LEFT JOIN mesh.device AS device
      ON device.id = lease.device_id AND device.state = 'revoked'
    WHERE lease.network_prefix_id = $1::BIGINT
      AND lease.state IN ('active', 'quarantined')
      AND NOT ((lease.state = 'quarantined'
            AND lease.quarantine_until <= pg_catalog.clock_timestamp())
        OR (lease.state = 'active' AND device.id IS NOT NULL AND device.state = 'revoked'
            AND device.updated_at + mesh_ops.node_address_quarantine_v1() <= pg_catalog.clock_timestamp()))
)
SELECT pg_catalog.host(candidate.address)
FROM (
    SELECT $2::INET AS address
    UNION
    SELECT live.address + 1
    FROM live
    WHERE pg_catalog.host(live.address) NOT IN (
        '255.255.255.255', 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
    )
) AS candidate
WHERE NOT EXISTS (
    SELECT 1 FROM live WHERE live.address = candidate.address
)
ORDER BY candidate.address
LIMIT 1`

// assertRegistrationAddressFloor checks schema 157: after each kind of change
// that frees an address, registration leases the address the reference
// allocator names, and every stored floor keeps its invariant.
func assertRegistrationAddressFloor(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	runtimePool *postgresadapter.Pool,
) {
	t.Helper()
	register := func(index byte, change string) string {
		t.Helper()
		want := referenceRegistrationAddress(ctx, t, adminConnection)
		// Key bytes no other fixture uses (0xb6-0xbe, 0xf3-0xfb, 0xe3-0xeb).
		offset := index - 10
		nodeID := registerAddressTestNode(ctx, t, adminConnection, runtimePool, index,
			addressTestKeys{authority: 0xb6 + offset, machine: 0xf3 + offset, node: 0xe3 + offset})
		if got := quarantineLeaseAddress(ctx, t, adminConnection, nodeID); got != want {
			t.Fatalf("after %s registration leased %s, the reference allocator %s", change, got, want)
		}
		assertRegistrationAddressFloorsHold(ctx, t, adminConnection, change)
		return nodeID
	}
	first := register(10, "earlier registrations")
	second := register(11, "a registration")
	third := register(12, "a registration")

	// A quarantine that ended below the floor.
	forceQuarantineFixture(ctx, t, adminConnection, `
UPDATE mesh.device SET state = 'revoked', version = version + 1 WHERE public_id = $1::UUID;
UPDATE mesh.node_address_lease AS lease
SET state = 'quarantined', released_at = pg_catalog.clock_timestamp() - INTERVAL '25 hours',
    quarantine_until = pg_catalog.clock_timestamp() - INTERVAL '1 hour', version = lease.version + 1
FROM mesh.device AS device
WHERE device.id = lease.device_id AND device.public_id = $1::UUID AND lease.state = 'active'`, second)
	register(13, "a quarantine ended below the floor")

	// A live lease released: the lease trigger lowers the floor.
	auditedDeviceFixture(ctx, t, adminConnection, third, `
UPDATE mesh.device SET state = 'revoked', version = version + 1,
    updated_at = pg_catalog.clock_timestamp()
WHERE public_id = $1::UUID;
UPDATE mesh.node_address_lease AS lease
SET state = 'released', released_at = pg_catalog.clock_timestamp(), version = lease.version + 1,
    updated_at = pg_catalog.clock_timestamp()
FROM mesh.device AS device
WHERE device.id = lease.device_id AND device.public_id = $1::UUID AND lease.state = 'active'`)
	assertRegistrationAddressFloorsHold(ctx, t, adminConnection, "a lease release")
	register(14, "a lease release")

	// A Device revoked before schema 143 still holds an active lease, which
	// does not settle the floor: the backfill leaves the floor at or below
	// it. The lease is live until a quarantine interval after revocation.
	forceQuarantineFixture(ctx, t, adminConnection, `
UPDATE mesh.device SET state = 'revoked', version = version + 1,
    updated_at = pg_catalog.clock_timestamp()
WHERE public_id = $1::UUID;
UPDATE mesh_ops.registration_address_floor AS address_floor
SET floor_address = lease.address
FROM mesh.node_address_lease AS lease
JOIN mesh.device AS device ON device.id = lease.device_id
WHERE device.public_id = $1::UUID AND lease.state = 'active'
  AND address_floor.network_prefix_id = lease.network_prefix_id
  AND address_floor.floor_address > lease.address`, first)
	assertRegistrationAddressFloorsHold(ctx, t, adminConnection, "a revocation that kept a lease active")
	register(15, "a revocation that kept a lease active")
	forceQuarantineFixture(ctx, t, adminConnection, `
UPDATE mesh.device SET updated_at = pg_catalog.clock_timestamp() - INTERVAL '25 hours',
    created_at = LEAST(created_at, pg_catalog.clock_timestamp() - INTERVAL '26 hours')
WHERE public_id = $1::UUID`, first)
	register(16, "the revoked Device's quarantine interval passed")

	// A missing floor, and a floor lower than it could be.
	if _, err := adminConnection.Exec(ctx, `DELETE FROM mesh_ops.registration_address_floor
WHERE workspace_id = 101 AND network_id = 201`); err != nil {
		t.Fatalf("delete the address floors: %v", err)
	}
	register(17, "the floors were deleted")
	if _, err := adminConnection.Exec(ctx, `UPDATE mesh_ops.registration_address_floor AS address_floor
SET floor_address = pg_catalog.set_masklen(pg_catalog.network(address_floor.prefix)::INET + 1,
    CASE pg_catalog.family(address_floor.prefix) WHEN 4 THEN 32 ELSE 128 END)
WHERE workspace_id = 101 AND network_id = 201`); err != nil {
		t.Fatalf("lower the address floors: %v", err)
	}
	register(18, "the floors were lowered to the first host")
}

// referenceRegistrationAddress returns the address the reference allocator
// gives the next IPv4 Device of Network 201: the lowest free address of the
// first prefix, in allocation order, that has one.
func referenceRegistrationAddress(ctx context.Context, t *testing.T, connection *pgx.Conn) string {
	t.Helper()
	rows, err := connection.Query(ctx, `SELECT prefix.id, prefix.prefix::TEXT
FROM mesh.network_prefix AS prefix
JOIN mesh.address_pool AS pool
  ON pool.workspace_id = prefix.workspace_id AND pool.address_realm_id = prefix.address_realm_id
 AND pool.id = prefix.address_pool_id
JOIN mesh.address_realm AS realm
  ON realm.workspace_id = prefix.workspace_id AND realm.id = prefix.address_realm_id
WHERE prefix.workspace_id = 101 AND prefix.network_id = 201 AND prefix.family = 4
  AND prefix.state = 'active' AND pool.state = 'active' AND pool.purpose = 'node_overlay'
  AND realm.state = 'active'
ORDER BY prefix.family, prefix.id`)
	if err != nil {
		t.Fatalf("read Network 201 prefixes: %v", err)
	}
	type prefixRow struct {
		id     int64
		prefix netip.Prefix
	}
	var prefixes []prefixRow
	for rows.Next() {
		var row prefixRow
		var value string
		if err := rows.Scan(&row.id, &value); err != nil {
			t.Fatalf("scan Network 201 prefix: %v", err)
		}
		row.prefix = netip.MustParsePrefix(value)
		prefixes = append(prefixes, row)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("read Network 201 prefixes: %v", err)
	}
	for _, row := range prefixes {
		first := row.prefix.Addr().Next()
		var value string
		if err := connection.QueryRow(ctx, referenceLowestFreeAddressSQL, row.id,
			netip.PrefixFrom(first, 32).String()).Scan(&value); err != nil {
			t.Fatalf("reference allocator for prefix %d: %v", row.id, err)
		}
		address := netip.MustParseAddr(value)
		if next := address.Next(); row.prefix.Contains(address) && next.IsValid() && row.prefix.Contains(next) {
			return value
		}
	}
	t.Fatal("the reference allocator finds no free IPv4 address in Network 201")
	return ""
}

// assertRegistrationAddressFloorsHold checks every stored floor: each address
// from its prefix's first host up to the floor holds a settled lease.
func assertRegistrationAddressFloorsHold(ctx context.Context, t *testing.T, connection *pgx.Conn, change string) {
	t.Helper()
	rows, err := connection.Query(ctx, `SELECT address_floor.network_prefix_id,
    pg_catalog.host(address_floor.floor_address),
    address_floor.floor_address - bounds.first_host,
    (SELECT pg_catalog.count(*)
     FROM mesh.node_address_lease AS lease
     LEFT JOIN mesh.device AS device ON device.id = lease.device_id AND device.state = 'revoked'
     WHERE lease.network_prefix_id = address_floor.network_prefix_id
       AND lease.state IN ('active', 'quarantined')
       AND NOT (lease.state = 'active' AND device.id IS NOT NULL)
       AND lease.address >= bounds.first_host AND lease.address < address_floor.floor_address)
FROM mesh_ops.registration_address_floor AS address_floor
JOIN mesh.network_prefix AS prefix
  ON prefix.id = address_floor.network_prefix_id AND prefix.prefix = address_floor.prefix
CROSS JOIN LATERAL (
    SELECT pg_catalog.set_masklen(pg_catalog.network(prefix.prefix)::INET + 1,
        CASE pg_catalog.family(prefix.prefix) WHEN 4 THEN 32 ELSE 128 END) AS first_host
) AS bounds
WHERE address_floor.floor_address > bounds.first_host`)
	if err != nil {
		t.Fatalf("read the address floors after %s: %v", change, err)
	}
	defer rows.Close()
	for rows.Next() {
		var prefixID, below, settled int64
		var floor string
		if err := rows.Scan(&prefixID, &floor, &below, &settled); err != nil {
			t.Fatalf("scan an address floor after %s: %v", change, err)
		}
		if settled != below {
			t.Fatalf("after %s prefix %d has floor %s over %d addresses but %d settled leases",
				change, prefixID, floor, below, settled)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read the address floors after %s: %v", change, err)
	}
}

// auditedDeviceFixture runs statements against one Node of Network 201 with
// triggers on, with the evidence and Network revision an authority change
// records.
func auditedDeviceFixture(ctx context.Context, t *testing.T, connection *pgx.Conn, nodeID, statements string) {
	t.Helper()
	var revision, version int64
	if err := connection.QueryRow(ctx, `SELECT revision.network_revision + 1, device.version + 1
FROM mesh_ops.network_revision AS revision
JOIN mesh.device AS device
  ON device.workspace_id = revision.workspace_id AND device.network_id = revision.network_id
WHERE revision.workspace_id = 101 AND revision.network_id = 201 AND device.public_id = $1::UUID`,
		nodeID).Scan(&revision, &version); err != nil {
		t.Fatalf("read Node %s revision: %v", nodeID, err)
	}
	commitAuditedAuthorityFixture(ctx, t, connection, authorityEvidenceFixture{
		changePublicID: newScaleID(t), eventPublicID: newScaleID(t), outboxPublicID: newScaleID(t),
		streamID: 201, aggregateKind: "device", networkRevision: revision,
		aggregatePublicID: nodeID, aggregateVersion: version,
		action: "device.revoked", permission: "system.bootstrap", outboxEventClass: "network.inventory.changed",
	}, func(transaction pgx.Tx) {
		if _, err := transaction.Exec(ctx, `UPDATE mesh_ops.network_revision
SET network_revision = network_revision + 1, inventory_revision = inventory_revision + 1,
    updated_at = clock_timestamp()
WHERE workspace_id = 101 AND network_id = 201`); err != nil {
			t.Fatalf("advance the Network revision for Node %s: %v", nodeID, err)
		}
		for _, statement := range splitQuarantineStatements(statements) {
			if _, err := transaction.Exec(ctx, statement, nodeID); err != nil {
				t.Fatalf("Node %s fixture %q: %v", nodeID, statement, err)
			}
		}
	})
}
