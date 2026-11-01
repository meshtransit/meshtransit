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
	assertRevokedMembershipUnlinks(ctx, t, admin, scope, device, membership)
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
