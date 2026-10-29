//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubeca"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

// Schema 252 (K1d d2a): an approver asks the worker to retire a CA. The
// API records a request and never touches the CA; the worker retires it and
// marks the request done in one transaction, or refuses it. A cluster of
// its own keeps the other CA checks apart.
func assertKubernetesCARetireRequests(ctx context.Context, t *testing.T, admin *pgx.Conn, fixture clusterCAFixture,
	service *kubecluster.Service, owner accountsession.Session) {
	t.Helper()
	clusterID := kubecluster.ID(mustPublicID(t))
	if _, err := service.Create(ctx, kubecluster.Creation{Session: owner, Scope: fixture.scope, ID: clusterID,
		Name: "ca-retire", CorrelationID: newCorrelationID(t)}); err != nil {
		t.Fatal(err)
	}
	read := fixture.read(ctx, t)
	fixture.cluster = publicid.ID(clusterID)
	fixture.dnsName = "ca-retire.kube." + read.WorkspaceCode + "." + read.NetworkCode + ".mesh.internal"
	root := fixture.newRoot(t, fixture.dnsName)
	rootCreation := fixture.creation(t, root, publicid.ID{}, kubeca.StateActive, kubeca.ReasonInitial)
	intermediate := fixture.creation(t, newIntermediate(t, root), rootCreation.ID, kubeca.StateActive,
		kubeca.ReasonInitial)
	fixture.change(ctx, t, kubeca.Changes{
		Steps:     []kubeca.Step{{Create: rootCreation}, {Create: intermediate}},
		Schedules: []kubeca.Schedule{{Cluster: fixture.cluster, At: time.Now().Add(time.Hour)}},
	})
	ask := func(ca publicid.ID, version int64, reason string) (kubecluster.CARetireRequestResult, error) {
		return service.RequestCARetire(ctx, kubecluster.CARetireRequestCommand{Session: owner, Scope: fixture.scope,
			ClusterID: clusterID, CAID: ca, CAVersion: version, Reason: reason, ChangeRef: "INC-252",
			Note: "rotated in a test", CorrelationID: newCorrelationID(t)})
	}

	first, err := ask(intermediate.ID, 1, kubecluster.RetireReasonAdmin)
	if err != nil || !first.Created || first.Request.State != kubecluster.RetireStatePending ||
		!first.Request.ExpiresAt.Equal(first.Request.CreatedAt.Add(time.Hour)) {
		t.Fatalf("RequestCARetire() = %+v, %v", first, err)
	}
	assertClusterCAState(ctx, t, admin, intermediate.ID, "active")
	// The same request waits once; another reason for the same CA waits too.
	again, err := ask(intermediate.ID, 1, kubecluster.RetireReasonAdmin)
	if err != nil || again.Created || again.Request.ID != first.Request.ID {
		t.Fatalf("asking again = %+v, %v", again, err)
	}
	if _, err := ask(intermediate.ID, 1, kubecluster.RetireReasonCompromise); !errors.Is(err,
		kubecluster.ErrRetirePending) {
		t.Fatalf("another reason while one waits: %v", err)
	}
	if _, err := ask(rootCreation.ID, 2, kubecluster.RetireReasonAdmin); !errors.Is(err, kubecluster.ErrConflict) {
		t.Fatalf("a version the root never had: %v", err)
	}
	if _, err := ask(mustPublicID(t), 1, kubecluster.RetireReasonAdmin); !errors.Is(err, kubecluster.ErrNotFound) {
		t.Fatalf("an unknown CA: %v", err)
	}
	assertKubernetesEvent(ctx, t, admin, "kubernetes_ca_retire_request", first.Request.ID.String(),
		"kubernetes_cluster.ca_retire_requested")

	// The worker lists the request with the CA's state, and carries it out:
	// the CA retires and the request ends done in the same transaction.
	queue := fixture.store.RetireQueue()
	waiting, err := queue.List(ctx, fixture.installation, 64)
	if err != nil || !queuedRequest(waiting.Waiting, first.Request.ID, intermediate.ID, kubeca.StateActive) {
		t.Fatalf("the queue = %+v, %v", waiting, err)
	}
	fixture.change(ctx, t, kubeca.Changes{Operator: kubeca.RetireRequestOperator(first.Request.ID),
		Completes: first.Request.ID,
		Steps:     []kubeca.Step{move(intermediate.ID, 1, kubeca.StateRetired, kubeca.ReasonAdmin)}})
	assertClusterCAState(ctx, t, admin, intermediate.ID, "retired")
	assertCARetireRequestState(ctx, t, service, owner, fixture, clusterID, first.Request.ID,
		kubecluster.RetireStateDone, "")
	if _, err := ask(intermediate.ID, 2, kubecluster.RetireReasonAdmin); !errors.Is(err, kubecluster.ErrCARetired) {
		t.Fatalf("a retired CA: %v", err)
	}

	// A request another worker ended takes the change back with it.
	second, err := ask(rootCreation.ID, 1, kubecluster.RetireReasonEmergency)
	if err != nil || !second.Created {
		t.Fatalf("asking for the root = %+v, %v", second, err)
	}
	if refused, err := queue.Refuse(ctx, fixture.installation, fixture.scope, second.Request.ID,
		kubeca.RetireRefusalChanged); err != nil || !refused {
		t.Fatalf("Refuse() = %v, %v", refused, err)
	}
	if refused, err := queue.Refuse(ctx, fixture.installation, fixture.scope, second.Request.ID,
		kubeca.RetireRefusalGuard); err != nil || refused {
		t.Fatalf("refusing an ended request = %v, %v", refused, err)
	}
	fixture.refused(ctx, t, "carrying out a request that no longer waits", kubeca.Changes{
		Operator: kubeca.RetireRequestOperator(second.Request.ID), Completes: second.Request.ID,
		Steps: []kubeca.Step{move(rootCreation.ID, 1, kubeca.StateRetired, kubeca.ReasonEmergency)}})
	assertClusterCAState(ctx, t, admin, rootCreation.ID, "active")
	assertCARetireRequestState(ctx, t, service, owner, fixture, clusterID, second.Request.ID,
		kubecluster.RetireStateRefused, kubecluster.RetireRefusalChanged)

	// Five requests a person an hour: the first two count, three more go,
	// the sixth is refused.
	for index := range 3 {
		asked, err := ask(rootCreation.ID, 1, kubecluster.RetireReasonAdmin)
		if err != nil || !asked.Created {
			t.Fatalf("request %d = %+v, %v", index+3, asked, err)
		}
		if _, err := queue.Refuse(ctx, fixture.installation, fixture.scope, asked.Request.ID,
			kubeca.RetireRefusalExpired); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ask(rootCreation.ID, 1, kubecluster.RetireReasonCompromise); !errors.Is(err,
		kubecluster.ErrRetireRateLimited) {
		t.Fatalf("a sixth request within the hour: %v", err)
	}
	assertClusterCAState(ctx, t, admin, rootCreation.ID, "active")

	// An hour later the person may ask again; a request no worker took past
	// its hour holds nothing and ends expired (review d2a L7).
	if _, err := admin.Exec(ctx, `UPDATE mesh.kubernetes_ca_retire_request
SET created_at = created_at - INTERVAL '2 hours', expires_at = expires_at - INTERVAL '2 hours',
    finished_at = finished_at - INTERVAL '2 hours'`); err != nil {
		t.Fatal(err)
	}
	stale, err := ask(rootCreation.ID, 1, kubecluster.RetireReasonAdmin)
	if err != nil || !stale.Created {
		t.Fatalf("asking after the hour = %+v, %v", stale, err)
	}
	if _, err := admin.Exec(ctx, `UPDATE mesh.kubernetes_ca_retire_request
SET created_at = created_at - INTERVAL '2 hours', expires_at = expires_at - INTERVAL '2 hours'
WHERE public_id = $1::UUID`, stale.Request.ID.String()); err != nil {
		t.Fatal(err)
	}
	fresh, err := ask(rootCreation.ID, 1, kubecluster.RetireReasonCompromise)
	if err != nil || !fresh.Created || fresh.Request.ID == stale.Request.ID {
		t.Fatalf("an expired request held the CA: %+v, %v", fresh, err)
	}
	assertCARetireRequestState(ctx, t, service, owner, fixture, clusterID, stale.Request.ID,
		kubecluster.RetireStateRefused, kubecluster.RetireRefusalExpired)
	// Another Network's scope finds no such request to end.
	foreign, err := network.NewScope(workspace.ID(mustPublicID(t)), network.ID(mustPublicID(t)))
	if err != nil {
		t.Fatal(err)
	}
	if refused, err := queue.Refuse(ctx, fixture.installation, foreign, fresh.Request.ID,
		kubeca.RetireRefusalGone); err != nil || refused {
		t.Fatalf("refusing from another scope = %v, %v", refused, err)
	}
	assertRetireCompletionGuard(ctx, t, admin, fixture, fresh.Request.ID)
}

// While a restore is suspected the database refuses to mark an
// administrator's request done, whatever the worker read (review d2a M2); a
// compromise is marked. In a transaction rolled back.
func assertRetireCompletionGuard(ctx context.Context, t *testing.T, admin *pgx.Conn, fixture clusterCAFixture,
	compromise publicid.ID) {
	t.Helper()
	complete := `SELECT mesh_ops.complete_kubernetes_ca_retire_request_v1($1::UUID,$2::UUID,$3::UUID,$4::UUID)`
	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	// The operator's mark, as after a restore: the guard row may not exist
	// before it.
	if _, err := transaction.Exec(ctx, `SELECT mesh_ops.mark_kubernetes_ca_restored_v1($1::UUID, 'test', 'INC-252')`,
		fixture.installation.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(ctx, `UPDATE mesh.kubernetes_ca_retire_request SET reason = 'admin'
WHERE public_id = $1::UUID`, compromise.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(ctx, "SAVEPOINT admin_request"); err != nil {
		t.Fatal(err)
	}
	var done bool
	err = transaction.QueryRow(ctx, complete, fixture.installation.String(), fixture.scope.WorkspaceID().String(),
		fixture.scope.NetworkID().String(), compromise.String()).Scan(&done)
	var pgError *pgconn.PgError
	if !errors.As(err, &pgError) || pgError.Code != "MTK30" {
		t.Fatalf("marking an administrator's request done under a restore = %v, %v", done, err)
	}
	if _, err := transaction.Exec(ctx, "ROLLBACK TO SAVEPOINT admin_request"); err != nil {
		t.Fatal(err)
	}
	if _, err := transaction.Exec(ctx, `UPDATE mesh.kubernetes_ca_retire_request SET reason = 'compromise'
WHERE public_id = $1::UUID`, compromise.String()); err != nil {
		t.Fatal(err)
	}
	if err := transaction.QueryRow(ctx, complete, fixture.installation.String(),
		fixture.scope.WorkspaceID().String(), fixture.scope.NetworkID().String(),
		compromise.String()).Scan(&done); err != nil || !done {
		t.Fatalf("marking a compromise done under a restore = %v, %v", done, err)
	}
}

func queuedRequest(waiting []kubeca.RetireRequest, request, ca publicid.ID, state kubeca.State) bool {
	for _, queued := range waiting {
		if queued.ID == request {
			return queued.CA == ca && queued.CAState == state && queued.CAVersion == 1 &&
				queued.Reason == kubeca.ReasonAdmin
		}
	}
	return false
}

// assertCARetireRequestState pages the cluster's requests, newest first, and
// finds request ended as want.
func assertCARetireRequestState(ctx context.Context, t *testing.T, service *kubecluster.Service,
	owner accountsession.Session, fixture clusterCAFixture, clusterID kubecluster.ID, request publicid.ID,
	state, refusal string) {
	t.Helper()
	query := kubecluster.PageQuery{Session: owner, Scope: fixture.scope, ClusterID: clusterID, Limit: 1}
	for range 10 {
		page, err := service.ListCARetireRequests(ctx, query)
		if err != nil || len(page.Requests) > 1 {
			t.Fatalf("ListCARetireRequests() = %+v, %v", page, err)
		}
		for _, listed := range page.Requests {
			if listed.ID == request {
				if listed.State != state || listed.Refusal != refusal || listed.FinishedAt.IsZero() ||
					listed.ChangeRef != "INC-252" {
					t.Fatalf("request %s = %+v, want %s %s", request, listed, state, refusal)
				}
				return
			}
		}
		if page.Next.IsZero() {
			break
		}
		query.After = page.Next
	}
	t.Fatalf("request %s is not listed", request)
}
