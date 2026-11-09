//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/network/deletion"
	"meshtransit.net/core/internal/domain/network/provisioning"
	"meshtransit.net/core/internal/domain/publicid"
)

// Schema 279 (docs/network-delete-design.md, N1a): only the owner or a
// Workspace-wide network.delete grant deletes a Network, at the version it
// read, with a reason. The Network is deleted at once: its keys end, its
// name is free, its revision advances and one network.deleted event names
// it. A repeat answers with the progress and changes nothing; a Network
// with a live Trust Contract is refused with the list. A Device of a
// deleted Network is told REVOKED on its current keys.
func assertPostgreSQLNetworkDeletion(ctx context.Context, t *testing.T, admin *pgx.Conn,
	runtimePool *postgresadapter.Pool) {
	t.Helper()
	options := postgresadapter.AccountSessionOptions{StatementTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second}
	creationStore, err := postgresadapter.NewNetworkCreationStore(runtimePool, options)
	if err != nil {
		t.Fatal(err)
	}
	creations, err := provisioning.NewService(creationStore, accountsession.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	store, err := postgresadapter.NewNetworkDeletionStore(runtimePool, options)
	if err != nil {
		t.Fatal(err)
	}
	deletions, err := deletion.NewService(store, accountsession.SystemClock{})
	if err != nil {
		t.Fatal(err)
	}
	owner := managementRBACAccountSessionFixture(t)
	member := authorityConfirmerAccountSessionFixture(t)
	setWorkspaceRenameFixtureOwner(ctx, t, admin, 11)
	defer setWorkspaceRenameFixtureOwner(ctx, t, admin, 14)

	created, err := creations.Create(ctx, newNetworkCommand(t, owner, "Short Lived", "100.64.236.0/24",
		"fd42:42:42:236::/64"))
	if err != nil {
		t.Fatal(err)
	}
	workspaceID, _ := owner.LoginWorkspaceID()
	scope, err := network.NewScope(workspaceID, created.NetworkID)
	if err != nil {
		t.Fatal(err)
	}
	command := func(session accountsession.Session, version int64) deletion.Command {
		correlation, err := publicid.New()
		if err != nil {
			t.Fatal(err)
		}
		return deletion.Command{Session: session, Scope: scope, ExpectedVersion: version,
			Reason: "Thử nghiệm xong, không dùng nữa", CorrelationID: correlation}
	}

	if view, err := deletions.Read(ctx, owner, scope); err != nil || view.State != deletion.StateActive ||
		view.Version != created.Version || view.Deletion != nil || view.DisplayCode == "" {
		t.Fatalf("read before = %+v, %v", view, err)
	}
	if _, err := deletions.Delete(ctx, command(member, created.Version)); !errors.Is(err, deletion.ErrForbidden) {
		t.Fatalf("member without network.delete: %v", err)
	}
	if _, err := deletions.Delete(ctx, command(owner, created.Version+1)); !errors.Is(err, deletion.ErrVersionConflict) {
		t.Fatalf("stale version: %v", err)
	}
	var revisionBefore int64
	if err := admin.QueryRow(ctx, `SELECT r.network_revision FROM mesh_ops.network_revision r
 JOIN mesh.network n ON n.id = r.network_id WHERE n.public_id = $1::UUID`, created.NetworkID.String()).Scan(&revisionBefore); err != nil {
		t.Fatal(err)
	}
	outcome, err := deletions.Delete(ctx, command(owner, created.Version))
	if err != nil || outcome.Kind != deletion.OutcomeDeleted || outcome.Version != created.Version+1 ||
		outcome.Progress.DevicesTotal != 0 || outcome.Progress.CompletedAt != nil || outcome.KeysRevoked != 0 {
		t.Fatalf("delete = %+v, %v", outcome, err)
	}
	var state, reason string
	var deletedAt *time.Time
	var revisionAfter, events, outbox int64
	if err := admin.QueryRow(ctx, `SELECT n.state, n.deleted_at, d.reason, r.network_revision,
 (SELECT count(*) FROM mesh_audit.audit_event e WHERE e.target_kind = 'network' AND e.action = 'network.deleted'
    AND e.target_public_id = n.public_id),
 (SELECT count(*) FROM mesh_ops.outbox_event o WHERE o.event_class = 'network.revision.advanced'
    AND o.payload ->> 'network_id' = n.public_id::TEXT AND o.payload ->> 'aggregate_kind' = 'network')
FROM mesh.network n JOIN mesh_ops.network_deletion d ON d.network_id = n.id
JOIN mesh_ops.network_revision r ON r.network_id = n.id
WHERE n.public_id = $1::UUID`, created.NetworkID.String()).Scan(&state, &deletedAt, &reason, &revisionAfter,
		&events, &outbox); err != nil {
		t.Fatal(err)
	}
	if state != "deleted" || deletedAt == nil || reason != "Thử nghiệm xong, không dùng nữa" ||
		revisionAfter != revisionBefore+1 || events != 1 || outbox != 1 {
		t.Fatalf("stored: state=%s deleted_at=%v reason=%q revision %d→%d events=%d outbox=%d", state, deletedAt,
			reason, revisionBefore, revisionAfter, events, outbox)
	}
	// A repeat while phase 2 runs answers with the progress, changes nothing.
	if again, err := deletions.Delete(ctx, command(owner, created.Version)); err != nil ||
		again.Kind != deletion.OutcomeDeleting || again.Progress.NetworkID != created.NetworkID {
		t.Fatalf("repeat = %+v, %v", again, err)
	}
	if view, err := deletions.Read(ctx, owner, scope); err != nil || view.State != deletion.StateDeleting ||
		view.Deletion == nil || view.Deletion.CompletedAt != nil {
		t.Fatalf("read while deleting = %+v, %v", view, err)
	}
	if _, err := deletions.Read(ctx, member, scope); !errors.Is(err, deletion.ErrNotFound) {
		t.Fatalf("member reads a deleted Network: %v", err)
	}
	// The name is free at once; the prefixes stay held until phase 2 ends.
	if _, err := creations.Create(ctx, newNetworkCommand(t, owner, "Short Lived", "100.64.237.0/24",
		"fd42:42:42:237::/64")); err != nil {
		t.Fatalf("name of a deleted Network: %v", err)
	}
	if _, err := creations.Create(ctx, newNetworkCommand(t, owner, "Same Range", "100.64.236.0/24",
		"fd42:42:42:238::/64")); !errors.Is(err, provisioning.ErrPrefixOverlap) {
		t.Fatalf("range of a Network being deleted: %v", err)
	}
	// A deletion that completed reads as gone.
	if _, err := admin.Exec(ctx, `UPDATE mesh_ops.network_deletion SET completed_at = requested_at
 WHERE network_public_id = $1::UUID`, created.NetworkID.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := deletions.Read(ctx, owner, scope); !errors.Is(err, deletion.ErrNotFound) {
		t.Fatalf("read after completion: %v", err)
	}
	if _, err := deletions.Delete(ctx, command(owner, outcome.Version)); !errors.Is(err, deletion.ErrNotFound) {
		t.Fatalf("delete after completion: %v", err)
	}
	assertNetworkDeletionBlocked(ctx, t, admin, deletions, owner)
}

// A Network with a live Trust Contract is refused, named, and unchanged.
func assertNetworkDeletionBlocked(ctx context.Context, t *testing.T, admin *pgx.Conn,
	deletions *deletion.Service, owner accountsession.Session) {
	t.Helper()
	workspaceID, _ := owner.LoginWorkspaceID()
	var networkText, contractText string
	var version int64
	if err := admin.QueryRow(ctx, `SELECT n.public_id::TEXT, n.version, c.public_id::TEXT
FROM mesh.trust_contract c
JOIN mesh.network n ON n.workspace_id = c.provider_workspace_id AND n.id = c.provider_network_id
JOIN mesh.workspace w ON w.id = n.workspace_id
WHERE w.public_id = $1::UUID AND n.state = 'active' AND c.state IN ('activating', 'active')
ORDER BY c.id LIMIT 1`, workspaceID.String()).Scan(&networkText, &version, &contractText); err != nil {
		t.Fatalf("no fixture Network with a live Trust Contract: %v", err)
	}
	networkID, _ := network.ParseID(networkText)
	scope, _ := network.NewScope(workspaceID, networkID)
	correlation, _ := publicid.New()
	outcome, err := deletions.Delete(ctx, deletion.Command{Session: owner, Scope: scope, ExpectedVersion: version,
		Reason: "blocked", CorrelationID: correlation})
	if err != nil || outcome.Kind != deletion.OutcomeBlocked || outcome.Blockers.TrustContracts < 1 {
		t.Fatalf("blocked = %+v, %v", outcome, err)
	}
	named := false
	for _, item := range outcome.Blockers.Items {
		named = named || (item.Kind == deletion.BlockerTrustContract && item.ID.String() == contractText)
	}
	var state string
	var after int64
	if err := admin.QueryRow(ctx, `SELECT state, version FROM mesh.network WHERE public_id = $1::UUID`,
		networkText).Scan(&state, &after); err != nil {
		t.Fatal(err)
	}
	if !named || state != "active" || after != version {
		t.Fatalf("blocked deletion changed the Network or did not name %s: %+v state=%s version=%d",
			contractText, outcome.Blockers, state, after)
	}
}

// A Device of a deleted Network is told REVOKED on its current keys from
// phase 1, before phase 2 revokes it, while schema 161's check still says
// no. Checked in a transaction rolled back, so no fixture Network is lost.
func assertDeletedNetworkMapSessionRevoked(ctx context.Context, t *testing.T, admin *pgx.Conn) {
	t.Helper()
	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	var networkID int64
	var fingerprint, nodeKey []byte
	if err := transaction.QueryRow(ctx, `SELECT n.id, m.fingerprint, k.public_key
FROM mesh.network n
JOIN mesh.device d ON d.network_id = n.id AND d.state = 'active' AND d.deleted_at IS NULL
JOIN mesh.device_machine_key_epoch m ON m.device_id = d.id AND m.epoch = d.current_machine_key_epoch
JOIN mesh.device_node_key_epoch k ON k.device_id = d.id AND k.epoch = d.current_node_key_epoch
WHERE n.state = 'active' ORDER BY n.id, d.id LIMIT 1`).Scan(&networkID, &fingerprint, &nodeKey); err != nil {
		t.Fatalf("no active Device: %v", err)
	}
	check := func() (bool, bool) {
		var v1, v2 bool
		if err := transaction.QueryRow(ctx, `SELECT mesh_ops.map_session_revoked_v1($1, $2),
 mesh_ops.map_session_revoked_v2($1, $2)`, fingerprint, nodeKey).Scan(&v1, &v2); err != nil {
			t.Fatal(err)
		}
		return v1, v2
	}
	if v1, v2 := check(); v1 || v2 {
		t.Fatalf("an active Device of an active Network: v1=%v v2=%v", v1, v2)
	}
	if _, err := transaction.Exec(ctx, `SELECT pg_catalog.set_config('mesh.change_public_id',
 '01890f01-0000-7000-8000-00000000d279', TRUE)`); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(ctx, `UPDATE mesh.network SET state = 'deleted', deleted_at = now(),
 version = version + 1 WHERE id = $1`, networkID); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(ctx, `INSERT INTO mesh_ops.network_deletion (network_id, workspace_id,
 deployment_id, network_public_id, requested_at, requested_by_principal_id, reason, devices_total, updated_at)
SELECT n.id, n.workspace_id, w.deployment_id, n.public_id, now(), w.owner_principal_id, 'test', 1, now()
FROM mesh.network n JOIN mesh.workspace w ON w.id = n.workspace_id WHERE n.id = $1`, networkID); err != nil {
		t.Fatal(err)
	}
	if v1, v2 := check(); v1 || !v2 {
		t.Fatalf("a Device of a deleted Network: v1=%v v2=%v", v1, v2)
	}
	// An old rotated key learns nothing.
	var revokedOld bool
	if err := transaction.QueryRow(ctx, `SELECT mesh_ops.map_session_revoked_v2($1, $2)`, fingerprint,
		make([]byte, 32)).Scan(&revokedOld); err != nil || revokedOld {
		t.Fatalf("another node key: %v %v", revokedOld, err)
	}
}
