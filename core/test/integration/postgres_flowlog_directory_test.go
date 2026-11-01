//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/connectionlog"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/workspace"
)

// assertFlowlogDirectory qualifies schema 269 (design §16d, C59–C61) on a
// Network that logs: its directory is read at the Network's revision, lists
// every Device in one snapshot, names a member's Device by the membership's
// pseudonym, and is not found under another Workspace; a membership gets a
// pseudonym on a state change and loses it when revoked, so its Devices
// read as unlinked.
func assertFlowlogDirectory(ctx context.Context, t *testing.T, admin *pgx.Conn,
	store *postgresadapter.FlowlogReceiverStore, scope network.Scope,
) {
	t.Helper()
	directory, err := store.Directory(ctx, scope)
	if err != nil || directory.BuiltAt.IsZero() || len(directory.MeshPrefixes) == 0 {
		t.Fatalf("Directory() = %+v, %v", directory, err)
	}
	if revision := connectionLogRevision(ctx, t, admin, scope); directory.Revision != revision {
		t.Fatalf("directory revision %d, Network revision %d", directory.Revision, revision)
	}
	var devices int
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh.device AS device
JOIN mesh.network AS network ON network.workspace_id = device.workspace_id AND network.id = device.network_id
WHERE network.public_id = $1::UUID
  AND (device.deleted_at IS NULL OR device.deleted_at >= pg_catalog.now() - INTERVAL '25 hours')`,
		scope.NetworkID().String()).Scan(&devices); err != nil || devices == 0 || devices != len(directory.Devices) {
		t.Fatalf("the directory lists %d of %d Devices: %v", len(directory.Devices), devices, err)
	}
	// The fixtures write memberships with triggers off: give those the
	// pseudonyms the backfill would (the trigger itself is checked below).
	if _, err := admin.Exec(ctx, `INSERT INTO mesh.connection_log_owner_pseudonym
    (membership_id, workspace_id, pseudonym, created_at)
SELECT membership.id, membership.workspace_id, pg_catalog.gen_random_uuid(), pg_catalog.now()
FROM mesh.workspace_membership AS membership
WHERE membership.state <> 'revoked'
ON CONFLICT (membership_id) DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	directory, err = store.Directory(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	var device, membership, pseudonym string
	if err := admin.QueryRow(ctx, `SELECT device.public_id::TEXT, membership.public_id::TEXT, pseudonym.pseudonym::TEXT
FROM mesh.device AS device
JOIN mesh.network AS network ON network.workspace_id = device.workspace_id AND network.id = device.network_id
JOIN mesh.workspace_membership AS membership ON membership.workspace_id = device.workspace_id
 AND membership.principal_id = device.owner_principal_id AND membership.state <> 'revoked'
JOIN mesh.connection_log_owner_pseudonym AS pseudonym ON pseudonym.membership_id = membership.id
WHERE network.public_id = $1::UUID AND device.ownership = 'member' AND device.deleted_at IS NULL
ORDER BY device.id LIMIT 1`, scope.NetworkID().String()).Scan(&device, &membership, &pseudonym); err != nil {
		t.Fatalf("a member's Device: %v", err)
	}
	named := false
	for _, entry := range directory.Devices {
		if entry.ID.String() == device {
			named = entry.OwnerKind == connectionlog.OwnerKindMember && entry.Pseudonym != [16]byte{} &&
				formatPseudonym(entry.Pseudonym) == pseudonym && entry.Hostname != ""
		}
	}
	if !named {
		t.Fatalf("Device %s is not named by its owner's pseudonym", device)
	}
	other, err := network.NewScope(workspace.ID(newConnectionLogID(t)), scope.NetworkID())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Directory(ctx, other); !errors.Is(err, postgresadapter.ErrFlowlogNotFound) {
		t.Fatalf("the Network under another Workspace: %v", err)
	}
	if len(directory.ContractAliases) != 0 {
		t.Fatalf("the logging Network consumes no share, yet lists %+v", directory.ContractAliases)
	}
	assertFlowlogContractAliases(ctx, t, admin)
	assertRevokedMembershipUnlinks(ctx, t, admin, scope, device, membership)
}

// assertFlowlogContractAliases compares the share aliases a consumer Network
// lists (C63) with the leases the earlier sharing fixtures left: held ones,
// and quarantined ones of a contract ended within 25 hours.
func assertFlowlogContractAliases(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	rows, err := admin.Query(ctx, `SELECT DISTINCT lease.consumer_workspace_id, lease.consumer_network_id
FROM mesh.device_alias_lease AS lease WHERE lease.state <> 'released'`)
	if err != nil {
		t.Fatal(err)
	}
	type consumer struct{ workspace, network int64 }
	var consumers []consumer
	for rows.Next() {
		var one consumer
		if err := rows.Scan(&one.workspace, &one.network); err != nil {
			t.Fatal(err)
		}
		consumers = append(consumers, one)
	}
	if rows.Close(); rows.Err() != nil {
		t.Fatal(rows.Err())
	}
	if len(consumers) == 0 {
		t.Fatal("no sharing fixture left an alias lease to list")
	}
	for _, one := range consumers {
		var listed, expected, foreign int
		if err := admin.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*) FROM mesh_ops.flowlog_contract_aliases_internal_v1($1, $2, pg_catalog.now())),
    (SELECT pg_catalog.count(DISTINCT (contract.public_id, lease.address)) FROM mesh.device_alias_lease AS lease
     JOIN mesh.private_endpoint AS endpoint ON endpoint.id = lease.private_endpoint_id
     JOIN mesh.trust_contract AS contract ON contract.id = endpoint.trust_contract_id
     WHERE lease.consumer_workspace_id = $1 AND lease.consumer_network_id = $2
       AND (lease.state = 'reserved' OR (lease.state = 'quarantined' AND lease.quarantine_until > pg_catalog.now()
            AND (lease.updated_at >= pg_catalog.now() - INTERVAL '25 hours'
                 OR contract.ended_at >= pg_catalog.now() - INTERVAL '25 hours')))),
    (SELECT pg_catalog.count(*) FROM mesh_ops.flowlog_contract_aliases_internal_v1($1, $2, pg_catalog.now()) AS alias
     WHERE NOT EXISTS (SELECT 1 FROM mesh.trust_contract AS contract
                       WHERE contract.public_id = alias.contract_public_id
                         AND contract.consumer_workspace_id = $1 AND contract.consumer_network_id = $2))`,
			one.workspace, one.network).Scan(&listed, &expected, &foreign); err != nil {
			t.Fatal(err)
		}
		if listed != expected || foreign != 0 {
			t.Fatalf("consumer %d/%d lists %d share aliases, want %d (%d of other contracts)", one.workspace,
				one.network, listed, expected, foreign)
		}
	}
	t.Logf("share aliases: %d consumer Networks checked", len(consumers))
	assertConsumerDirectoryThroughReader(ctx, t, admin, consumers[0].workspace, consumers[0].network)
}

// assertConsumerDirectoryThroughReader gives a consumer Network a
// destination in a transaction it rolls back, then reads its directory as
// the runtime role: through the reader's function and policies it lists the
// share aliases, each (contract, address) once, nothing of the provider
// (review s4c2b H2).
func assertConsumerDirectoryThroughReader(ctx context.Context, t *testing.T, admin *pgx.Conn,
	workspaceID, networkID int64,
) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var workspacePublic, networkPublic string
	var expected int
	if err := tx.QueryRow(ctx, `SELECT workspace.public_id::TEXT, network.public_id::TEXT,
    (SELECT pg_catalog.count(*) FROM (SELECT DISTINCT contract.public_id, lease.address
     FROM mesh.device_alias_lease AS lease
     JOIN mesh.private_endpoint AS endpoint ON endpoint.id = lease.private_endpoint_id
     JOIN mesh.trust_contract AS contract ON contract.id = endpoint.trust_contract_id
     WHERE lease.consumer_workspace_id = $1 AND lease.consumer_network_id = $2
       AND (lease.state = 'reserved' OR (lease.state = 'quarantined' AND lease.quarantine_until > pg_catalog.now()
            AND (lease.updated_at >= pg_catalog.now() - INTERVAL '25 hours'
                 OR contract.ended_at >= pg_catalog.now() - INTERVAL '25 hours')))) AS listed)
FROM mesh.workspace AS workspace JOIN mesh.network AS network ON network.workspace_id = workspace.id
WHERE workspace.id = $1 AND network.id = $2`, workspaceID, networkID).Scan(&workspacePublic, &networkPublic,
		&expected); err != nil {
		t.Fatal(err)
	}
	if expected == 0 {
		t.Fatal("the consumer Network has no share alias to list")
	}
	// Fixture rows, written with triggers off as other fixtures are.
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `WITH credential AS (
    INSERT INTO mesh.storage_credential (public_id, workspace_id, name, provider, access_key_suffix, sealed,
        sealing_key_id, sealed_version, version, created_at, created_by_principal_id, updated_at, updated_by_principal_id)
    VALUES ($3::UUID, $1, 'Consumer logs', 'aws_s3', 'TEST', pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex'),
        'meshflow-test', 1, 1, pg_catalog.now(), 1, pg_catalog.now(), 1)
    RETURNING id)
INSERT INTO mesh.network_connection_log (network_id, public_id, workspace_id, enabled, credential_id, bucket, region,
    prefix, forwarded, window_s, version, updated_at, updated_by_principal_id)
SELECT $2, $4::UUID, $1, FALSE, credential.id, '', '', 'mesh', FALSE, 60, 1, pg_catalog.now(), 1 FROM credential`,
		workspaceID, networkID, newConnectionLogID(t).String(), networkPublic); err != nil {
		t.Fatalf("give the consumer a destination: %v", err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL session_replication_role = origin; SET LOCAL ROLE mesh_runtime`); err != nil {
		t.Fatal(err)
	}
	var count, listed, distinct int
	if err := tx.QueryRow(ctx, `WITH head AS (
    SELECT mesh_ops.flowlog_directory_network_v1($1::UUID, $2::UUID) AS document)
SELECT (head.document ->> 'contract_alias_count')::INTEGER,
    pg_catalog.jsonb_array_length(head.document -> 'contract_aliases'),
    (SELECT pg_catalog.count(DISTINCT alias.value) FROM pg_catalog.jsonb_array_elements(head.document -> 'contract_aliases') AS alias)
FROM head`, workspacePublic, networkPublic).Scan(&count, &listed, &distinct); err != nil {
		t.Fatalf("read the consumer's directory as the runtime role: %v", err)
	}
	if count != expected || listed != expected || distinct != expected {
		t.Fatalf("the consumer's directory lists %d (%d, %d distinct) share aliases, want %d", count, listed, distinct,
			expected)
	}
}

// assertRevokedMembershipUnlinks revokes the membership in a transaction it
// rolls back: the pseudonym goes with it, and the directory reads the
// Device as unlinked.
func assertRevokedMembershipUnlinks(ctx context.Context, t *testing.T, admin *pgx.Conn, scope network.Scope,
	device, membership string,
) {
	t.Helper()
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_catalog.set_config('mesh.change_public_id', $1, TRUE)`,
		newConnectionLogID(t).String()); err != nil {
		t.Fatal(err)
	}
	// A membership without a pseudonym gets one on its next state change;
	// a suspension keeps it.
	if _, err := tx.Exec(ctx, `DELETE FROM mesh.connection_log_owner_pseudonym AS pseudonym
USING mesh.workspace_membership AS membership
WHERE membership.id = pseudonym.membership_id AND membership.public_id = $1::UUID`, membership); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, membershipTransitionSQL, "suspended", membership); err != nil {
		t.Fatalf("suspend the membership: %v", err)
	}
	var created int
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh.connection_log_owner_pseudonym AS pseudonym
JOIN mesh.workspace_membership AS membership ON membership.id = pseudonym.membership_id
WHERE membership.public_id = $1::UUID`, membership).Scan(&created); err != nil || created != 1 {
		t.Fatalf("the trigger made %d pseudonyms: %v", created, err)
	}
	if _, err := tx.Exec(ctx, membershipTransitionSQL, "revoked", membership); err != nil {
		t.Fatalf("revoke the membership: %v", err)
	}
	var left int
	var owner *string
	if err := tx.QueryRow(ctx, `SELECT
    (SELECT pg_catalog.count(*) FROM mesh.connection_log_owner_pseudonym AS pseudonym
     JOIN mesh.workspace_membership AS membership ON membership.id = pseudonym.membership_id
     WHERE membership.public_id = $3::UUID),
    (SELECT listed.value ->> 'pseudonym'
     FROM pg_catalog.jsonb_array_elements(mesh_ops.flowlog_directory_devices_v1($1::UUID, $2::UUID, NULL, 10000)) AS listed
     WHERE listed.value ->> 'id' = $4)`,
		scope.WorkspaceID().String(), scope.NetworkID().String(), membership, device).Scan(&left, &owner); err != nil {
		t.Fatal(err)
	}
	if left != 0 || owner != nil {
		t.Fatalf("a revoked membership keeps %d pseudonyms; the Device reads as owned by %v", left, owner)
	}
}

// membershipTransitionSQL moves a membership as the management RBAC
// transition guard requires (schema 25).
const membershipTransitionSQL = `UPDATE mesh.workspace_membership
SET state = $1, version = version + 1, authority_generation = authority_generation + 1, updated_at = pg_catalog.now()
WHERE public_id = $2::UUID`

func formatPseudonym(value [16]byte) string {
	text := make([]byte, 0, 36)
	const digits = "0123456789abcdef"
	for index, octet := range value {
		if index == 4 || index == 6 || index == 8 || index == 10 {
			text = append(text, '-')
		}
		text = append(text, digits[octet>>4], digits[octet&0x0f])
	}
	return string(text)
}
