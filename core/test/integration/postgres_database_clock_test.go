//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// databaseClockAggregates names the authority tables whose rows Core writes
// through Go stores, keyed by their audit aggregate kind.
var databaseClockAggregates = map[string]string{
	"share_offer":            "mesh.share_offer",
	"trust_contract":         "mesh.trust_contract",
	"imported_resource":      "mesh.imported_resource",
	"resource":               "mesh.resource",
	"resource_group":         "mesh.resource_group",
	"device":                 "mesh.device",
	"device_node_key_epoch":  "mesh.device_node_key_epoch",
	"pending_registration":   "mesh.pending_registration",
	"workspace_invitation":   "mesh.workspace_invitation",
	"resource_group_version": "mesh.resource_group_version",
}

// assertStampedByDatabaseClock checks that a row's creation and its current
// version were stamped with the database clock of the transactions that
// wrote them: created_at is the transaction time recorded with its insert,
// and updated_at the one recorded with the update that produced its current
// version. A time from any MeshCore host clock would differ.
func assertStampedByDatabaseClock(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	kind, publicID string,
) {
	t.Helper()
	table, ok := databaseClockAggregates[kind]
	if !ok {
		t.Fatalf("no database clock check for aggregate %q", kind)
	}
	var created, updated bool
	if err := admin.QueryRow(ctx, `SELECT
    aggregate.created_at = inserted.occurred_at,
    aggregate.updated_at = current_version.occurred_at
FROM `+table+` AS aggregate
JOIN mesh_audit.authority_mutation AS inserted
  ON inserted.aggregate_kind = $1 AND inserted.row_public_id = aggregate.public_id
 AND inserted.operation = 'insert'
JOIN mesh_audit.authority_mutation AS current_version
  ON current_version.aggregate_kind = $1 AND current_version.row_public_id = aggregate.public_id
 AND current_version.after_version = aggregate.version
WHERE aggregate.public_id = $2::UUID`, kind, publicID).Scan(&created, &updated); err != nil {
		t.Fatalf("read %s %s database clock evidence: %v", kind, publicID, err)
	}
	if !created || !updated {
		t.Fatalf("%s %s times are not the database clock's: created_at=%v updated_at=%v",
			kind, publicID, created, updated)
	}
}

// stampShareAheadOfDatabase stands in for a previous binary whose host clock
// ran ahead of the database: it moves updated_at of a share's contract,
// Imported Resource and Private Endpoint ahead, bypassing the evidence
// triggers only for this fault injection, and returns the contract's new
// updated_at.
func stampShareAheadOfDatabase(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	contractPublicID string,
	ahead time.Duration,
) time.Time {
	t.Helper()
	if _, err := admin.Exec(ctx, `SET session_replication_role = replica`); err != nil {
		t.Fatalf("enable share clock fault injection: %v", err)
	}
	var contractUpdatedAt time.Time
	err := admin.QueryRow(ctx, `WITH contract AS (
    UPDATE mesh.trust_contract SET updated_at = updated_at + $2::INTERVAL
    WHERE public_id = $1::UUID RETURNING id, imported_resource_public_id, updated_at
), imported AS (
    UPDATE mesh.imported_resource AS imported SET updated_at = imported.updated_at + $2::INTERVAL
    FROM contract WHERE imported.public_id = contract.imported_resource_public_id
    RETURNING imported.id
), endpoint AS (
    UPDATE mesh.private_endpoint AS endpoint SET updated_at = endpoint.updated_at + $2::INTERVAL
    FROM contract WHERE endpoint.trust_contract_id = contract.id
    RETURNING endpoint.id
)
SELECT contract.updated_at FROM contract, (SELECT pg_catalog.count(*) FROM imported) AS imported_count,
    (SELECT pg_catalog.count(*) FROM endpoint) AS endpoint_count`, contractPublicID, ahead).Scan(&contractUpdatedAt)
	if _, resetErr := admin.Exec(context.WithoutCancel(ctx), `SET session_replication_role = origin`); resetErr != nil {
		t.Fatalf("disable share clock fault injection: %v", resetErr)
	}
	if err != nil {
		t.Fatalf("stamp share ahead of the database: %v", err)
	}
	return contractUpdatedAt
}

// assertShareUpdatedAtKeptOrder checks schema 172: a write on the database
// clock after a version stamped ahead of it keeps updated_at where it was
// instead of failing.
func assertShareUpdatedAtKeptOrder(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	contractPublicID string,
	previous time.Time,
) {
	t.Helper()
	var updatedAt time.Time
	if err := admin.QueryRow(ctx, `SELECT updated_at FROM mesh.trust_contract WHERE public_id = $1::UUID`,
		contractPublicID).Scan(&updatedAt); err != nil {
		t.Fatalf("read contract updated_at: %v", err)
	}
	if !updatedAt.Equal(previous) {
		t.Fatalf("contract updated_at = %s, want the kept %s", updatedAt, previous)
	}
}

// assertPolicyReleaseOnDatabaseClock checks that a published release's
// creation and activation are its transaction's database time.
func assertPolicyReleaseOnDatabaseClock(ctx context.Context, t *testing.T, admin *pgx.Conn, releasePublicID string) {
	t.Helper()
	var onDatabaseClock bool
	if err := admin.QueryRow(ctx, `SELECT release.created_at = inserted.occurred_at
    AND release.activated_at = inserted.occurred_at
FROM mesh.policy_release AS release
JOIN mesh_audit.authority_mutation AS inserted
  ON inserted.aggregate_kind = 'policy_release' AND inserted.row_public_id = release.public_id
 AND inserted.operation = 'insert'
WHERE release.public_id = $1::UUID`, releasePublicID).Scan(&onDatabaseClock); err != nil {
		t.Fatalf("read policy release %s database clock evidence: %v", releasePublicID, err)
	}
	if !onDatabaseClock {
		t.Fatalf("policy release %s times are not the database clock's", releasePublicID)
	}
}

// assertUpdatedByDatabaseClock checks only the current version of a row Core
// did not create: its updated_at is the database time of the transaction
// that produced that version.
func assertUpdatedByDatabaseClock(ctx context.Context, t *testing.T, admin *pgx.Conn, kind, publicID string) {
	t.Helper()
	table, ok := databaseClockAggregates[kind]
	if !ok {
		t.Fatalf("no database clock check for aggregate %q", kind)
	}
	var updated bool
	if err := admin.QueryRow(ctx, `SELECT aggregate.updated_at = current_version.occurred_at
FROM `+table+` AS aggregate
JOIN mesh_audit.authority_mutation AS current_version
  ON current_version.aggregate_kind = $1 AND current_version.row_public_id = aggregate.public_id
 AND current_version.after_version = aggregate.version
WHERE aggregate.public_id = $2::UUID`, kind, publicID).Scan(&updated); err != nil {
		t.Fatalf("read %s %s database clock evidence: %v", kind, publicID, err)
	}
	if !updated {
		t.Fatalf("%s %s updated_at is not the database clock's", kind, publicID)
	}
}

// assertNewestNodeKeyOnDatabaseClock checks that a rotated Device's newest
// Node key epoch starts, and was created, at the database time of the
// transaction that rotated it.
func assertNewestNodeKeyOnDatabaseClock(ctx context.Context, t *testing.T, admin *pgx.Conn, devicePublicID string) {
	t.Helper()
	var onDatabaseClock bool
	if err := admin.QueryRow(ctx, `SELECT epoch.valid_from = inserted.occurred_at
    AND epoch.created_at = inserted.occurred_at
FROM mesh.device AS device
JOIN mesh.device_node_key_epoch AS epoch ON epoch.device_id = device.id
JOIN mesh_audit.authority_mutation AS inserted
  ON inserted.aggregate_kind = 'device_node_key_epoch' AND inserted.row_public_id = epoch.public_id
 AND inserted.operation = 'insert'
WHERE device.public_id = $1::UUID
ORDER BY epoch.epoch DESC
LIMIT 1`, devicePublicID).Scan(&onDatabaseClock); err != nil {
		t.Fatalf("read Device %s Node key database clock evidence: %v", devicePublicID, err)
	}
	if !onDatabaseClock {
		t.Fatalf("Device %s newest Node key times are not the database clock's", devicePublicID)
	}
}

// assertInvitationExpiryOnDatabaseClock checks that the invitation version
// that rotated its link expires it lifetime after that transaction's
// database time, to the second. A link expiry from a MeshCore host clock
// would follow that host's time instead.
func assertInvitationExpiryOnDatabaseClock(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	invitationPublicID string,
	rotatedVersion int64,
	lifetime time.Duration,
) {
	t.Helper()
	var onDatabaseClock bool
	var expiresAt, writtenAt time.Time
	if err := admin.QueryRow(ctx, `SELECT
    invitation.expires_at = pg_catalog.date_trunc('second', written.occurred_at + $3::INTERVAL),
    invitation.expires_at, written.occurred_at
FROM mesh.workspace_invitation AS invitation
JOIN mesh_audit.authority_mutation AS written
  ON written.aggregate_kind = 'workspace_invitation' AND written.row_public_id = invitation.public_id
 AND written.after_version = $2
WHERE invitation.public_id = $1::UUID`, invitationPublicID, rotatedVersion, lifetime).Scan(
		&onDatabaseClock, &expiresAt, &writtenAt); err != nil {
		t.Fatalf("read invitation %s database clock evidence: %v", invitationPublicID, err)
	}
	if !onDatabaseClock {
		t.Fatalf("invitation %s expires_at %s is not %s after its version %d database time %s",
			invitationPublicID, expiresAt.UTC(), lifetime, rotatedVersion, writtenAt.UTC())
	}
}
