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
	t *testing.T,
	ctx context.Context,
	adminConnection *pgx.Conn,
	workerPool *postgresadapter.Pool,
) {
	t.Helper()

	store, err := postgresadapter.NewOutboxStore(workerPool)
	if err != nil {
		t.Fatalf("postgres.NewOutboxStore() error = %v", err)
	}
	claims, err := store.ClaimNetworkRevisions(ctx, "integration-worker", 10, 30*time.Second)
	if err != nil {
		t.Fatalf("OutboxStore.ClaimNetworkRevisions() error = %v", err)
	}
	if len(claims) != 2 {
		t.Fatalf("len(network revision claims) = %d, want 2", len(claims))
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
	assertOutboxOutcome(t, ctx, adminConnection, claims[0].EventID(), "delivered", "delivered", nil)
	retryClass := "integration_retry"
	assertOutboxOutcome(t, ctx, adminConnection, claims[1].EventID(), "pending", "retry", &retryClass)
}

func assertOutboxOutcome(
	t *testing.T,
	ctx context.Context,
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
