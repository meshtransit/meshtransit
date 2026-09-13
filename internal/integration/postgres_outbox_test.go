//go:build integration

package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
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
	claims, err := store.ClaimNetworkRevisions(ctx, "integration-worker", 10, 30*time.Second)
	if err != nil {
		t.Fatalf("OutboxStore.ClaimNetworkRevisions() error = %v", err)
	}
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
