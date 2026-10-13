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
// written by SQL in one audited inventory change, with real keys and
// addresses from the bottom of the scale prefix, so address allocation works
// as it would in a full Network.
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
	var profileID, realmID, poolID, prefixID int64
	var prefixText string
	if err := admin.QueryRow(ctx, `SELECT profile.id, prefix.address_realm_id, prefix.address_pool_id, prefix.id,
    prefix.prefix::TEXT
FROM mesh.network_prefix AS prefix
JOIN mesh.enrollment_profile AS profile
  ON profile.workspace_id = prefix.workspace_id AND profile.network_id = prefix.network_id
 AND profile.display_name = 'Scale enrollment' AND profile.state = 'active'
WHERE prefix.workspace_id = 101 AND prefix.network_id = 201 AND prefix.prefix = $1::CIDR
ORDER BY profile.id DESC LIMIT 1`, scaleExtraPrefix).Scan(&profileID, &realmID, &poolID, &prefixID, &prefixText); err != nil {
		t.Fatalf("read the scale prefix and profile: %v", err)
	}
	prefix := netip.MustParsePrefix(prefixText)
	ids := make([]int64, count)
	publicIDs, hostnames := make([]string, count), make([]string, count)
	machineIDs, nodeIDs, leaseIDs := make([]int64, count), make([]int64, count), make([]int64, count)
	machinePublicIDs, nodePublicIDs, leasePublicIDs := make([]string, count), make([]string, count), make([]string, count)
	machineKeys, machineFingerprints := make([][]byte, count), make([][]byte, count)
	nodeKeys, nodeFingerprints := make([][]byte, count), make([][]byte, count)
	addresses := make([]string, count)
	address := prefix.Addr().Next()
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
		if !prefix.Contains(address) {
			t.Fatalf("the scale prefix %s holds fewer than %d Devices", prefix, count)
		}
		addresses[index] = netip.PrefixFrom(address, 32).String()
		address = address.Next()
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
SELECT seeded.id, seeded.public_id::UUID, 101, 201, $4, $5, $6, seeded.device_id, seeded.address::INET, 4, 1,
    'primary', 'active', transaction_timestamp() - interval '1 second'
FROM unnest($1::BIGINT[], $2::TEXT[], $3::BIGINT[], $7::TEXT[]) AS seeded(id, public_id, device_id, address)`,
				[]any{leaseIDs, leasePublicIDs, ids, realmID, poolID, prefixID, addresses}},
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
