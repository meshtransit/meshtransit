//go:build integration

package integration

import (
	"context"
	"crypto/rand"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/node"
)

// MESHTRANSIT_SCALE_SEED_DEVICES=N adds N live Devices to the fixture
// Network before the scale sessions register, so registration, map opens and
// fan-out are measured in a Network that already holds N Devices. They are
// written by SQL in one audited inventory change, with real keys, and take
// the lowest free IPv4 addresses of the Network's prefixes in allocation
// order, as registered Devices would: the scale sessions then register past
// them, in the prefix that holds the most Devices. The seed writes no address
// floor (schema 157), so the first registration walks the seeded leases.
const (
	scaleSeedEnvironment = "MESHTRANSIT_SCALE_SEED_DEVICES"
	scaleSeedMaximum     = 200_000
	// Internal ID bases past every fixture and the share scale seed.
	scaleSeedDeviceBase  = int64(20_000_000)
	scaleSeedMachineBase = int64(21_000_000)
	scaleSeedNodeBase    = int64(22_000_000)
	scaleSeedLeaseBase   = int64(23_000_000)
)

func scaleSeedCount(t *testing.T) int {
	t.Helper()
	value := os.Getenv(scaleSeedEnvironment)
	if value == "" {
		return 0
	}
	count, err := strconv.Atoi(value)
	if err != nil || count < 0 || count > scaleSeedMaximum {
		t.Fatalf("%s=%q must be 0 to %d", scaleSeedEnvironment, value, scaleSeedMaximum)
	}
	return count
}

// seedScaleNetworkDevices writes count live Devices into the fixture Network
// (101/201) with machine and node keys, and a primary lease each in the
// scale prefix, and returns how long it took.
func seedScaleNetworkDevices(ctx context.Context, t *testing.T, admin *pgx.Conn, count int) time.Duration {
	t.Helper()
	started := time.Now()
	var profileID int64
	if err := admin.QueryRow(ctx, `SELECT profile.id
FROM mesh.enrollment_profile AS profile
WHERE profile.workspace_id = 101 AND profile.network_id = 201
  AND profile.display_name = 'Scale enrollment' AND profile.state = 'active'
ORDER BY profile.id DESC LIMIT 1`).Scan(&profileID); err != nil {
		t.Fatalf("read the scale profile: %v", err)
	}
	seats := scaleSeedSeats(ctx, t, admin, count)
	ids := make([]int64, count)
	publicIDs, hostnames := make([]string, count), make([]string, count)
	machineIDs, nodeIDs, leaseIDs := make([]int64, count), make([]int64, count), make([]int64, count)
	machinePublicIDs, nodePublicIDs, leasePublicIDs := make([]string, count), make([]string, count), make([]string, count)
	machineKeys, machineFingerprints := make([][]byte, count), make([][]byte, count)
	nodeKeys, nodeFingerprints := make([][]byte, count), make([][]byte, count)
	addresses := make([]string, count)
	realmIDs, poolIDs, prefixIDs := make([]int64, count), make([]int64, count), make([]int64, count)
	for index := range count {
		id := scaleSeedDeviceBase + int64(index)
		ids[index] = id
		publicIDs[index] = integrationPublicID("01890f5d-0000-7000-8000-", id)
		hostnames[index] = fmt.Sprintf("seed-%d.example", id)
		machineIDs[index], nodeIDs[index], leaseIDs[index] = scaleSeedMachineBase+int64(index),
			scaleSeedNodeBase+int64(index), scaleSeedLeaseBase+int64(index)
		machinePublicIDs[index], nodePublicIDs[index], leasePublicIDs[index] = newScaleID(t), newScaleID(t), newScaleID(t)
		var machineRaw, keyRaw [32]byte
		if _, err := rand.Read(machineRaw[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(keyRaw[:]); err != nil {
			t.Fatal(err)
		}
		machine, err := node.NewMachineKey(machineRaw)
		if err != nil {
			t.Fatal(err)
		}
		key, err := node.NewKey(keyRaw)
		if err != nil {
			t.Fatal(err)
		}
		machineBytes, keyBytes := machine.Bytes(), key.Bytes()
		machineFingerprint, keyFingerprint := machine.Fingerprint(), key.Fingerprint()
		machineKeys[index], machineFingerprints[index] = machineBytes[:], machineFingerprint[:]
		nodeKeys[index], nodeFingerprints[index] = keyBytes[:], keyFingerprint[:]
		seat := seats[index]
		addresses[index] = netip.PrefixFrom(seat.address, 32).String()
		realmIDs[index], poolIDs[index], prefixIDs[index] = seat.realmID, seat.poolID, seat.prefixID
	}
	var revision int64
	if err := admin.QueryRow(ctx, `SELECT network_revision + 1 FROM mesh_ops.network_revision
WHERE workspace_id = 101 AND network_id = 201`).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
		changePublicID: newScaleID(t), eventPublicID: newScaleID(t), outboxPublicID: newScaleID(t),
		streamID: 201, aggregateKind: "device", networkRevision: revision,
		aggregatePublicID: publicIDs[0], aggregateVersion: 1,
		action: "device.registered", permission: "system.bootstrap", outboxEventClass: "network.inventory.changed",
	}, func(tx pgx.Tx) {
		for _, statement := range []struct {
			name, sql string
			args      []any
		}{
			{"revision", `UPDATE mesh_ops.network_revision SET network_revision = network_revision + 1,
    inventory_revision = inventory_revision + 1, updated_at = clock_timestamp()
WHERE workspace_id = 101 AND network_id = 201`, nil},
			{"Devices", `INSERT INTO mesh.device (id, public_id, workspace_id, network_id, enrollment_profile_id,
    owner_principal_id, custodian_principal_id, registered_by_kind, registered_by_principal_id,
    hostname, hostname_key, is_ephemeral, expires_at, state)
OVERRIDING SYSTEM VALUE
SELECT seeded.id, seeded.public_id::UUID, 101, 201, $3, 11, 11, 'principal', 11, seeded.hostname, seeded.hostname,
    FALSE, clock_timestamp() + interval '4 hours', 'active'
FROM unnest($1::BIGINT[], $2::TEXT[], $4::TEXT[]) AS seeded(id, public_id, hostname)`,
				[]any{ids, publicIDs, profileID, hostnames}},
			{"machine keys", `INSERT INTO mesh.device_machine_key_epoch (id, public_id, workspace_id, network_id,
    device_id, epoch, public_key, fingerprint, valid_from, state)
OVERRIDING SYSTEM VALUE
SELECT seeded.id, seeded.public_id::UUID, 101, 201, seeded.device_id, 1, seeded.public_key, seeded.fingerprint,
    transaction_timestamp(), 'active'
FROM unnest($1::BIGINT[], $2::TEXT[], $3::BIGINT[], $4::BYTEA[], $5::BYTEA[])
    AS seeded(id, public_id, device_id, public_key, fingerprint)`,
				[]any{machineIDs, machinePublicIDs, ids, machineKeys, machineFingerprints}},
			{"node keys", `INSERT INTO mesh.device_node_key_epoch (id, public_id, workspace_id, network_id,
    device_id, epoch, public_key, fingerprint, valid_from, state)
OVERRIDING SYSTEM VALUE
SELECT seeded.id, seeded.public_id::UUID, 101, 201, seeded.device_id, 1, seeded.public_key, seeded.fingerprint,
    transaction_timestamp(), 'active'
FROM unnest($1::BIGINT[], $2::TEXT[], $3::BIGINT[], $4::BYTEA[], $5::BYTEA[])
    AS seeded(id, public_id, device_id, public_key, fingerprint)`,
				[]any{nodeIDs, nodePublicIDs, ids, nodeKeys, nodeFingerprints}},
			{"leases", `INSERT INTO mesh.node_address_lease (id, public_id, workspace_id, network_id, address_realm_id,
    address_pool_id, network_prefix_id, device_id, address, family, generation, lease_role, state, created_at)
OVERRIDING SYSTEM VALUE
SELECT seeded.id, seeded.public_id::UUID, 101, 201, seeded.realm_id, seeded.pool_id, seeded.prefix_id,
    seeded.device_id, seeded.address::INET, 4, 1, 'primary', 'active', transaction_timestamp() - interval '1 second'
FROM unnest($1::BIGINT[], $2::TEXT[], $3::BIGINT[], $4::BIGINT[], $5::BIGINT[], $6::BIGINT[], $7::TEXT[])
    AS seeded(id, public_id, device_id, realm_id, pool_id, prefix_id, address)`,
				[]any{leaseIDs, leasePublicIDs, ids, realmIDs, poolIDs, prefixIDs, addresses}},
		} {
			if _, err := tx.Exec(ctx, statement.sql, statement.args...); err != nil {
				t.Fatalf("seed %d scale %s: %v", count, statement.name, err)
			}
		}
	})
	if _, err := admin.Exec(ctx, `ANALYZE mesh.device, mesh.device_machine_key_epoch, mesh.device_node_key_epoch,
    mesh.node_address_lease`); err != nil {
		t.Fatalf("analyze the seeded tables: %v", err)
	}
	return time.Since(started)
}

// scaleSeedSeat is one seeded Device's address and the prefix it is in.
type scaleSeedSeat struct {
	realmID, poolID, prefixID int64
	address                   netip.Addr
}

// scaleSeedSeats returns count free IPv4 hosts of Network 201's prefixes, in
// allocation order (family, then prefix ID), lowest first.
func scaleSeedSeats(ctx context.Context, t *testing.T, admin *pgx.Conn, count int) []scaleSeedSeat {
	t.Helper()
	type prefixRow struct {
		realmID, poolID, prefixID int64
		prefix                    netip.Prefix
	}
	rows, err := admin.Query(ctx, `SELECT prefix.address_realm_id, prefix.address_pool_id, prefix.id, prefix.prefix::TEXT
FROM mesh.network_prefix AS prefix
WHERE prefix.workspace_id = 101 AND prefix.network_id = 201 AND prefix.family = 4 AND prefix.state = 'active'
ORDER BY prefix.family, prefix.id`)
	if err != nil {
		t.Fatalf("read the Network's prefixes: %v", err)
	}
	var prefixes []prefixRow
	for rows.Next() {
		var row prefixRow
		var value string
		if err := rows.Scan(&row.realmID, &row.poolID, &row.prefixID, &value); err != nil {
			t.Fatalf("scan a prefix: %v", err)
		}
		row.prefix = netip.MustParsePrefix(value)
		prefixes = append(prefixes, row)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("read the Network's prefixes: %v", err)
	}
	seats := make([]scaleSeedSeat, 0, count)
	for _, row := range prefixes {
		held := map[netip.Addr]struct{}{}
		leases, err := admin.Query(ctx, `SELECT pg_catalog.host(address) FROM mesh.node_address_lease
WHERE network_prefix_id = $1 AND state IN ('active', 'quarantined')`, row.prefixID)
		if err != nil {
			t.Fatalf("read prefix %d leases: %v", row.prefixID, err)
		}
		for leases.Next() {
			var value string
			if err := leases.Scan(&value); err != nil {
				t.Fatalf("scan a lease: %v", err)
			}
			held[netip.MustParseAddr(value)] = struct{}{}
		}
		leases.Close()
		if err := leases.Err(); err != nil {
			t.Fatalf("read prefix %d leases: %v", row.prefixID, err)
		}
		// Every host but the network and broadcast addresses.
		for address := row.prefix.Addr().Next(); len(seats) < count; address = address.Next() {
			if next := address.Next(); !row.prefix.Contains(next) {
				break
			}
			if _, taken := held[address]; taken {
				continue
			}
			seats = append(seats, scaleSeedSeat{realmID: row.realmID, poolID: row.poolID,
				prefixID: row.prefixID, address: address})
		}
	}
	if len(seats) < count {
		t.Fatalf("the Network's prefixes hold %d more Devices, not %d", len(seats), count)
	}
	return seats
}
