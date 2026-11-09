//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/networksummary"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

// Schema 277: the summary worker claims a dirty Network, counts it in one
// snapshot, stores only newer summaries, and keeps a change marked after the
// snapshot pending (TD-CON-48, docs/console-load-design.md §5).
func assertPostgreSQLNetworkSummary(ctx context.Context, t *testing.T, admin *pgx.Conn,
	workerPool *postgresadapter.Pool) {
	t.Helper()
	var installationText string
	if err := admin.QueryRow(ctx, `SELECT installation_public_id::TEXT FROM mesh.deployment WHERE id = 1`).
		Scan(&installationText); err != nil {
		t.Fatal(err)
	}
	installation, err := deployment.ParseID(installationText)
	if err != nil {
		t.Fatal(err)
	}
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000103")
	networkID, _ := network.ParseID("01890f00-0000-7000-8000-000000000203")
	scope, _ := network.NewScope(workspaceID, networkID)
	var internalNetwork int64
	if err := admin.QueryRow(ctx, `SELECT id FROM mesh.network WHERE public_id = $1::UUID`, networkID.String()).
		Scan(&internalNetwork); err != nil {
		t.Fatal(err)
	}
	// Every Network got a queue row; triggers exist on every table that
	// changes a figure without advancing the revision.
	// Networks created after the migration are marked, not queued, until
	// the worker folds the marks.
	var unseen, networks, triggers int
	if err := admin.QueryRow(ctx, `SELECT (SELECT count(*) FROM mesh.network AS network
 WHERE NOT EXISTS (SELECT 1 FROM mesh_ops.network_summary_queue AS queue
   WHERE queue.workspace_id = network.workspace_id AND queue.network_id = network.id)
   AND NOT EXISTS (SELECT 1 FROM mesh_ops.network_summary_mark AS mark
   WHERE mark.workspace_id = network.workspace_id AND mark.network_id = network.id)),
(SELECT count(*) FROM mesh.network),
(SELECT count(*) FROM pg_catalog.pg_trigger WHERE tgname IN ('network_summary_revision_dirty',
 'network_summary_share_offer_dirty', 'network_summary_trust_contract_dirty',
 'network_summary_policy_approval_dirty', 'network_summary_site_dirty', 'network_summary_kubernetes_cluster_dirty'))`).
		Scan(&unseen, &networks, &triggers); err != nil || unseen != 0 || networks == 0 || triggers != 6 {
		t.Fatalf("%d of %d Networks neither queued nor marked, %d triggers (%v)", unseen, networks, triggers, err)
	}

	assertSummaryMarksTakeNoQueueLock(ctx, t, admin, internalNetwork)

	store, err := postgresadapter.NewNetworkSummaryStore(workerPool)
	if err != nil {
		t.Fatal(err)
	}
	first, second := mustWorkerID(t), mustWorkerID(t)
	claimed := claimUntil(ctx, t, store, installation, first, scope)
	// Another worker does not get a Network the first one holds.
	if others, err := store.Claim(ctx, installation, second, 64, 30*time.Second); err != nil || containsScope(others, scope) {
		t.Fatalf("second worker claimed a held Network: %v %v", others, err)
	}
	_ = claimed

	summary, found, err := store.Compute(ctx, installation, scope)
	if err != nil || !found {
		t.Fatalf("compute = %v %v", found, err)
	}
	assertSummaryMatchesTables(ctx, t, admin, internalNetwork, summary)

	// A change marked after the snapshot: the summary is stored, but the
	// Network stays dirty for the next count.
	bumpIntegrationNetworkRevision(ctx, t, admin, internalNetwork)
	if newer, err := store.Save(ctx, installation, first, summary, 3*time.Millisecond, 0); err != nil || !newer {
		t.Fatalf("first save = %v %v", newer, err)
	}
	if dirty := summaryQueueDirty(ctx, t, admin, internalNetwork); !dirty {
		t.Fatal("a change after the snapshot was lost")
	}
	// The same, older snapshot again is not newer.
	if newer, err := store.Save(ctx, installation, first, summary, 3*time.Millisecond, 0); err != nil || newer {
		t.Fatalf("stale save = %v %v", newer, err)
	}
	claimUntil(ctx, t, store, installation, second, scope)
	latest, found, err := store.Compute(ctx, installation, scope)
	if err != nil || !found || latest.NetworkRevision <= summary.NetworkRevision {
		t.Fatalf("recount = %+v %v %v", latest, found, err)
	}
	if newer, err := store.Save(ctx, installation, second, latest, 3*time.Millisecond, 0); err != nil || !newer {
		t.Fatalf("latest save = %v %v", newer, err)
	}
	if dirty := summaryQueueDirty(ctx, t, admin, internalNetwork); dirty {
		t.Fatal("the latest summary left the Network dirty")
	}
	// An older summary never replaces a newer one.
	if newer, err := store.Save(ctx, installation, first, summary, 3*time.Millisecond, 0); err != nil || newer {
		t.Fatalf("older save over newer = %v %v", newer, err)
	}
	var storedRevision int64
	if err := admin.QueryRow(ctx, `SELECT network_revision FROM mesh_ops.network_summary
WHERE workspace_id = 103 AND network_id = $1`, internalNetwork).Scan(&storedRevision); err != nil ||
		storedRevision != latest.NetworkRevision {
		t.Fatalf("stored revision %d, want %d (%v)", storedRevision, latest.NetworkRevision, err)
	}
	// Marks not folded yet show in the lag, then fold exactly once.
	bumpIntegrationNetworkRevision(ctx, t, admin, internalNetwork)
	bumpIntegrationNetworkRevision(ctx, t, admin, internalNetwork)
	if lag, err := store.Lag(ctx, installation); err != nil || lag.Marks < 2 || lag.Oldest <= 0 {
		t.Fatalf("lag before fold = %+v %v", lag, err)
	}
	var generationBefore, generationAfter int64
	if err := admin.QueryRow(ctx, `SELECT dirty_generation FROM mesh_ops.network_summary_queue
WHERE workspace_id = 103 AND network_id = $1`, internalNetwork).Scan(&generationBefore); err != nil {
		t.Fatal(err)
	}
	if folded, err := store.Fold(ctx, 5000); err != nil || folded < 2 {
		t.Fatalf("fold = %d %v", folded, err)
	}
	if folded, err := store.Fold(ctx, 5000); err != nil || folded != 0 {
		t.Fatalf("second fold = %d %v", folded, err)
	}
	if err := admin.QueryRow(ctx, `SELECT dirty_generation FROM mesh_ops.network_summary_queue
WHERE workspace_id = 103 AND network_id = $1`, internalNetwork).Scan(&generationAfter); err != nil ||
		generationAfter != generationBefore+2 {
		t.Fatalf("generation %d -> %d, want +2 (%v)", generationBefore, generationAfter, err)
	}
	if lag, err := store.Lag(ctx, installation); err != nil || lag.Pending < 0 {
		t.Fatalf("lag = %+v %v", lag, err)
	}
	// Only the worker calls these functions.
	var runtimeMay bool
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.has_function_privilege('mesh_runtime',
'mesh_ops.compute_network_summary_v1(uuid,uuid,uuid)', 'EXECUTE')`).Scan(&runtimeMay); err != nil || runtimeMay {
		t.Fatalf("runtime may count summaries: %v %v", runtimeMay, err)
	}
}

func mustWorkerID(t *testing.T) publicid.ID {
	t.Helper()
	id, err := publicid.New()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// claimUntil claims until the wanted Network is among the claims; other
// fixture Networks are released again.
func claimUntil(ctx context.Context, t *testing.T, store *postgresadapter.NetworkSummaryStore,
	installation deployment.ID, worker publicid.ID, want network.Scope) []network.Scope {
	t.Helper()
	for range 20 {
		// As the worker does: fold the change marks, then claim.
		if _, err := store.Fold(ctx, 5000); err != nil {
			t.Fatal("fold", err)
		}
		claimed, err := store.Claim(ctx, installation, worker, 64, 30*time.Second)
		if err != nil {
			t.Fatal("claim", err)
		}
		if containsScope(claimed, want) {
			for _, other := range claimed {
				if other != want {
					if err := store.Release(ctx, installation, worker, other, 0); err != nil {
						t.Fatal("release", err)
					}
				}
			}
			return claimed
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("the dirty Network was never claimed")
	return nil
}

func summaryQueueDirty(ctx context.Context, t *testing.T, admin *pgx.Conn, internalNetwork int64) bool {
	t.Helper()
	var dirty bool
	// Pending: dirty in the queue, or marked and not folded yet.
	if err := admin.QueryRow(ctx, `SELECT (SELECT dirty_generation > computed_generation
 FROM mesh_ops.network_summary_queue WHERE workspace_id = 103 AND network_id = $1)
 OR EXISTS (SELECT 1 FROM mesh_ops.network_summary_mark WHERE workspace_id = 103 AND network_id = $1)`,
		internalNetwork).Scan(&dirty); err != nil {
		t.Fatal(err)
	}
	return dirty
}

// The counts equal what the tables hold, read directly.
func assertSummaryMatchesTables(ctx context.Context, t *testing.T, admin *pgx.Conn, internalNetwork int64,
	summary networksummary.Summary) {
	t.Helper()
	var activeDevices, sites, clusters int64
	if err := admin.QueryRow(ctx, `SELECT
(SELECT count(*) FROM mesh.device WHERE workspace_id = 103 AND network_id = $1 AND state = 'active' AND expires_at > $2),
(SELECT count(*) FROM mesh.network_site WHERE workspace_id = 103 AND network_id = $1 AND state = 'active'),
(SELECT count(*) FROM mesh.kubernetes_cluster WHERE workspace_id = 103 AND network_id = $1 AND state = 'active')`,
		internalNetwork, summary.EvaluatedAt).Scan(&activeDevices, &sites, &clusters); err != nil {
		t.Fatal(err)
	}
	if summary.ActiveDevices != activeDevices || int64(summary.Sites) != sites ||
		int64(summary.KubernetesClusters) != clusters || summary.NetworkID != internalNetwork {
		t.Fatalf("summary %+v, tables: %d active Devices, %d Sites, %d clusters", summary, activeDevices, sites, clusters)
	}
}

// A writer that advances a revision appends a mark and locks no queue row:
// another transaction may lock the queue row while the writer is still open
// (Opus review of C3, B1: no new lock order for writers).
func assertSummaryMarksTakeNoQueueLock(ctx context.Context, t *testing.T, admin *pgx.Conn, internalNetwork int64) {
	t.Helper()
	other, err := pgx.ConnectConfig(ctx, admin.Config().Copy())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close(context.WithoutCancel(ctx)) }()
	writer, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Rollback(context.WithoutCancel(ctx)) }()
	var marksBefore int
	if err := writer.QueryRow(ctx, `SELECT count(*) FROM mesh_ops.network_summary_mark WHERE network_id = $1`,
		internalNetwork).Scan(&marksBefore); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Exec(ctx, `UPDATE mesh_ops.network_revision SET network_revision = network_revision + 1,
updated_at = pg_catalog.now() WHERE workspace_id = 103 AND network_id = $1`, internalNetwork); err != nil {
		t.Fatal(err)
	}
	var marksAfter int
	if err := writer.QueryRow(ctx, `SELECT count(*) FROM mesh_ops.network_summary_mark WHERE network_id = $1`,
		internalNetwork).Scan(&marksAfter); err != nil || marksAfter != marksBefore+1 {
		t.Fatalf("marks %d -> %d (%v)", marksBefore, marksAfter, err)
	}
	lockTx, err := other.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lockTx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := lockTx.Exec(ctx, `SET LOCAL lock_timeout = '500ms'`); err != nil {
		t.Fatal(err)
	}
	if _, err := lockTx.Exec(ctx, `SELECT 1 FROM mesh_ops.network_summary_queue
WHERE workspace_id = 103 AND network_id = $1 FOR UPDATE`, internalNetwork); err != nil {
		t.Fatal("the writer holds the queue row", err)
	}
}
