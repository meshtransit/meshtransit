//go:build integration

package integration

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/network"
)

func assertWorkerOutboxDelivery(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	workerPool *postgresadapter.Pool,
) {
	t.Helper()
	const expectedNetworkRevisionEvents = 4

	store, err := postgresadapter.NewOutboxStore(workerPool)
	if err != nil {
		t.Fatalf("postgres.NewOutboxStore() error = %v", err)
	}
	contendingStore, err := postgresadapter.NewOutboxStore(workerPool)
	if err != nil {
		t.Fatalf("postgres.NewOutboxStore() contender error = %v", err)
	}
	backlog, err := store.ReadNetworkRevisionBacklog(ctx)
	if err != nil {
		t.Fatalf("OutboxStore.ReadNetworkRevisionBacklog() error = %v", err)
	}
	if backlog.Events() != expectedNetworkRevisionEvents || backlog.OldestAge() < 0 {
		t.Fatalf(
			"ready backlog before claim = (%d, %s), want (%d, non-negative)",
			backlog.Events(),
			backlog.OldestAge(),
			expectedNetworkRevisionEvents,
		)
	}
	claims := claimOutboxAcrossReplicas(
		ctx,
		t,
		store,
		contendingStore,
		expectedNetworkRevisionEvents/2,
	)
	if len(claims) != expectedNetworkRevisionEvents {
		t.Fatalf(
			"len(network revision claims) = %d, want %d committed Network changes",
			len(claims),
			expectedNetworkRevisionEvents,
		)
	}
	for index := 1; index < len(claims); index++ {
		if claims[index-1].EventID() >= claims[index].EventID() {
			t.Fatalf(
				"network revision claim order = %d before %d, want increasing event order",
				claims[index-1].EventID(),
				claims[index].EventID(),
			)
		}
	}

	firstRevision, err := store.LoadNetworkRevision(ctx, claims[0])
	if err != nil {
		t.Fatalf("OutboxStore.LoadNetworkRevision() error = %v", err)
	}
	if firstRevision.Number() < claims[0].RecordedRevision() {
		t.Fatalf(
			"current revision = %d, below recorded revision %d",
			firstRevision.Number(),
			claims[0].RecordedRevision(),
		)
	}
	if err := store.MarkRevisionDelivered(ctx, claims[0]); err != nil {
		t.Fatalf("OutboxStore.MarkRevisionDelivered() error = %v", err)
	}
	if err := store.MarkRevisionDelivered(ctx, claims[0]); !errors.Is(err, postgresadapter.ErrOutboxClaimLost) {
		t.Fatalf("second MarkRevisionDelivered() error = %v, want ErrOutboxClaimLost", err)
	}

	if err := store.RetryNetworkRevision(ctx, claims[1], "integration_retry", time.Hour); err != nil {
		t.Fatalf("OutboxStore.RetryNetworkRevision() error = %v", err)
	}
	for _, claim := range claims[2:] {
		if err := store.MarkRevisionDelivered(ctx, claim); err != nil {
			t.Fatalf("OutboxStore.MarkRevisionDelivered(remaining claim) error = %v", err)
		}
	}
	assertOutboxOutcome(ctx, t, adminConnection, claims[0].EventID(), "delivered", "delivered", nil)
	retryClass := "integration_retry"
	assertOutboxOutcome(ctx, t, adminConnection, claims[1].EventID(), "pending", "retry", &retryClass)
	for _, claim := range claims[2:] {
		assertOutboxOutcome(ctx, t, adminConnection, claim.EventID(), "delivered", "delivered", nil)
	}
	backlog, err = store.ReadNetworkRevisionBacklog(ctx)
	if err != nil {
		t.Fatalf("OutboxStore.ReadNetworkRevisionBacklog() after delivery error = %v", err)
	}
	if backlog.Events() != 0 || backlog.OldestAge() != 0 {
		t.Fatalf(
			"ready backlog after delivery = (%d, %s), want empty",
			backlog.Events(),
			backlog.OldestAge(),
		)
	}
	assertUnroutedOutboxRetired(ctx, t, adminConnection, store, claims[1].EventID())
}

// assertUnroutedOutboxRetired closes every pending event without a Network
// scope (deployment and identity events have no consumer) and leaves Network
// events, such as the one waiting for its retry, untouched.
func assertUnroutedOutboxRetired(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	store *postgresadapter.OutboxStore,
	pendingNetworkEventID int64,
) {
	t.Helper()
	const countUnrouted = `SELECT pg_catalog.count(*) FROM mesh_ops.outbox_event
WHERE network_id IS NULL AND completed_at IS NULL`
	var before int
	if err := adminConnection.QueryRow(ctx, countUnrouted).Scan(&before); err != nil {
		t.Fatalf("count unrouted outbox events: %v", err)
	}
	if before == 0 {
		t.Fatal("fixture has no unrouted outbox events (bootstrap writes deployment events)")
	}
	retired, err := store.RetireUnroutedEvents(ctx, "outbox-unrouted", 256)
	if err != nil || retired != before {
		t.Fatalf("RetireUnroutedEvents() = (%d, %v), want (%d, nil)", retired, err, before)
	}
	var open, closed int
	if err := adminConnection.QueryRow(ctx, countUnrouted).Scan(&open); err != nil {
		t.Fatalf("count unrouted outbox events after retire: %v", err)
	}
	if err := adminConnection.QueryRow(ctx, `SELECT pg_catalog.count(*) FROM mesh_ops.outbox_event
WHERE network_id IS NULL AND state = 'terminal' AND last_error_class = 'no_consumer'
  AND claimed_by = 'outbox-unrouted' AND completed_at = claimed_at`).Scan(&closed); err != nil {
		t.Fatalf("count retired outbox events: %v", err)
	}
	if open != 0 || closed != before {
		t.Fatalf("after retire: %d open, %d closed, want 0 and %d", open, closed, before)
	}
	var state string
	if err := adminConnection.QueryRow(ctx, `SELECT state FROM mesh_ops.outbox_event WHERE id = $1`,
		pendingNetworkEventID).Scan(&state); err != nil || state != "pending" {
		t.Fatalf("Network event state after retire = (%q, %v), want pending", state, err)
	}
	if again, err := store.RetireUnroutedEvents(ctx, "outbox-unrouted", 256); err != nil || again != 0 {
		t.Fatalf("second RetireUnroutedEvents() = (%d, %v), want (0, nil)", again, err)
	}
}

func claimOutboxAcrossReplicas(
	ctx context.Context,
	t *testing.T,
	first *postgresadapter.OutboxStore,
	second *postgresadapter.OutboxStore,
	batchSize int,
) []network.RevisionClaim {
	t.Helper()

	type claimResult struct {
		workerID string
		claims   []network.RevisionClaim
		err      error
	}

	start := make(chan struct{})
	results := make(chan claimResult, 2)
	claim := func(store *postgresadapter.OutboxStore, workerID string) {
		<-start
		claims, err := store.ClaimNetworkRevisions(ctx, workerID, batchSize, 30*time.Second)
		results <- claimResult{workerID: workerID, claims: claims, err: err}
	}
	go claim(first, "integration-replica-a")
	go claim(second, "integration-replica-b")
	close(start)

	claims := make([]network.RevisionClaim, 0, batchSize*2)
	seen := make(map[int64]string, batchSize*2)
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("OutboxStore.ClaimNetworkRevisions(%s) error = %v", result.workerID, result.err)
		}
		if len(result.claims) != batchSize {
			t.Fatalf(
				"len(%s claims) = %d, want %d",
				result.workerID,
				len(result.claims),
				batchSize,
			)
		}
		for _, claim := range result.claims {
			if claim.WorkerID() != result.workerID {
				t.Fatalf(
					"claim %d worker = %q, want %q",
					claim.EventID(),
					claim.WorkerID(),
					result.workerID,
				)
			}
			if owner, duplicate := seen[claim.EventID()]; duplicate {
				t.Fatalf(
					"event %d claimed by replicas %q and %q",
					claim.EventID(),
					owner,
					result.workerID,
				)
			}
			seen[claim.EventID()] = result.workerID
			claims = append(claims, claim)
		}
	}
	slices.SortFunc(claims, func(left, right network.RevisionClaim) int {
		return cmp.Compare(left.EventID(), right.EventID())
	})
	return claims
}

func assertOutboxOutcome(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	eventID int64,
	wantState string,
	wantResult string,
	wantErrorClass *string,
) {
	t.Helper()

	var state, result string
	var errorClass *string
	if err := connection.QueryRow(ctx, `SELECT
    event.state,
    attempt.result,
    attempt.error_class
FROM mesh_ops.outbox_event AS event
JOIN mesh_ops.outbox_attempt AS attempt
  ON attempt.outbox_event_id = event.id
WHERE event.id = $1`, eventID).Scan(&state, &result, &errorClass); err != nil {
		t.Fatalf("query outbox delivery outcome: %v", err)
	}
	if state != wantState || result != wantResult || !equalOptionalString(errorClass, wantErrorClass) {
		t.Fatalf(
			"outbox outcome = (%q, %q, %v), want (%q, %q, %v)",
			state,
			result,
			errorClass,
			wantState,
			wantResult,
			wantErrorClass,
		)
	}
}

func equalOptionalString(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
