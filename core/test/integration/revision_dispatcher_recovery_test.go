//go:build integration

package integration

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/network/revisionworker"
)

func assertRevisionDispatcherRecovery(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	workerPool *postgresadapter.Pool,
) {
	t.Helper()

	eventID, committedRevision := commitIntegrationNetworkRevision(ctx, t, adminConnection, "993")
	outbox, err := postgresadapter.NewOutboxStore(workerPool)
	if err != nil {
		t.Fatalf("postgres.NewOutboxStore() error = %v", err)
	}
	redisClient := openIntegrationRedisClient(ctx, t)
	logger := slog.New(slog.DiscardHandler)

	t.Run("process stops after observable effect before completion", func(t *testing.T) {
		subscription, subscribeErr := redisClient.SubscribeNetworkRevisionAdvanced(ctx)
		if subscribeErr != nil {
			t.Fatalf("redis SubscribeNetworkRevisionAdvanced() error = %v", subscribeErr)
		}
		t.Cleanup(func() {
			if closeErr := subscription.Close(); closeErr != nil {
				t.Errorf("revision subscription Close() error = %v", closeErr)
			}
		})

		telemetry := revisionworker.NewTelemetry()
		dispatcher := newRecoveryDispatcher(
			t,
			completionFailingOutbox{Outbox: outbox},
			redisClient,
			telemetry,
			logger,
		)
		startIntegrationDispatcher(t, dispatcher)

		receiveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		revision, receiveErr := subscription.Receive(receiveCtx)
		if receiveErr != nil {
			t.Fatalf("first revision subscription Receive() error = %v", receiveErr)
		}
		assertIntegrationRevision(t, revision, committedRevision)
		waitForIntegrationOutcome(receiveCtx, t, func() bool {
			return telemetry.Snapshot().FailedTotal == 1
		})

		var state string
		if err := adminConnection.QueryRow(ctx, `SELECT state
FROM mesh_ops.outbox_event
WHERE id = $1`, eventID).Scan(&state); err != nil {
			t.Fatalf("query interrupted outbox state: %v", err)
		}
		if state != "claimed" {
			t.Fatalf("interrupted outbox state = %q, want claimed until lease expiry", state)
		}
	})

	waitForIntegrationLeaseExpiry(ctx, t)

	t.Run("new process replays effect and completes expired claim", func(t *testing.T) {
		subscription, subscribeErr := redisClient.SubscribeNetworkRevisionAdvanced(ctx)
		if subscribeErr != nil {
			t.Fatalf("redis SubscribeNetworkRevisionAdvanced() error = %v", subscribeErr)
		}
		t.Cleanup(func() {
			if closeErr := subscription.Close(); closeErr != nil {
				t.Errorf("revision subscription Close() error = %v", closeErr)
			}
		})

		telemetry := revisionworker.NewTelemetry()
		dispatcher := newRecoveryDispatcher(t, outbox, redisClient, telemetry, logger)
		startIntegrationDispatcher(t, dispatcher)

		receiveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		revision, receiveErr := subscription.Receive(receiveCtx)
		if receiveErr != nil {
			t.Fatalf("replayed revision subscription Receive() error = %v", receiveErr)
		}
		assertIntegrationRevision(t, revision, committedRevision)
		waitForIntegrationOutcome(receiveCtx, t, func() bool {
			return telemetry.Snapshot().DeliveredTotal == 1
		})

		assertOutboxOutcome(ctx, t, adminConnection, eventID, "delivered", "delivered", nil)
		var attemptCount int
		if err := adminConnection.QueryRow(ctx, `SELECT attempt_count
FROM mesh_ops.outbox_event
WHERE id = $1`, eventID).Scan(&attemptCount); err != nil {
			t.Fatalf("query recovered outbox attempt count: %v", err)
		}
		if attemptCount != 2 {
			t.Fatalf("recovered outbox attempt count = %d, want 2", attemptCount)
		}
	})
}

func newRecoveryDispatcher(
	t *testing.T,
	outbox revisionworker.Outbox,
	publisher revisionworker.Publisher,
	telemetry *revisionworker.Telemetry,
	logger *slog.Logger,
) *revisionworker.Dispatcher {
	t.Helper()

	dispatcher, err := revisionworker.New(
		revisionworker.Options{
			WorkerID:         "integration-recovery-worker",
			BatchSize:        1,
			Lease:            2 * time.Second,
			PollInterval:     100 * time.Millisecond,
			RetryDelay:       30 * time.Second,
			OperationTimeout: 500 * time.Millisecond,
		},
		outbox,
		publisher,
		telemetry,
		logger,
	)
	if err != nil {
		t.Fatalf("revisionworker.New() recovery error = %v", err)
	}
	return dispatcher
}

func waitForIntegrationLeaseExpiry(ctx context.Context, t *testing.T) {
	t.Helper()

	timer := time.NewTimer(2200 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		t.Fatalf("wait for outbox lease expiry: %v", ctx.Err())
	}
}

func assertIntegrationRevision(
	t *testing.T,
	revision network.RevisionAdvanced,
	wantNumber int64,
) {
	t.Helper()

	if revision.NetworkPublicID() != integrationNetworkPublicID || revision.Number() != wantNumber {
		t.Fatalf(
			"published revision = (%q, %d), want (%q, %d)",
			revision.NetworkPublicID(),
			revision.Number(),
			integrationNetworkPublicID,
			wantNumber,
		)
	}
}

type completionFailingOutbox struct {
	revisionworker.Outbox
}

func (completionFailingOutbox) MarkRevisionDelivered(
	context.Context,
	network.RevisionClaim,
) error {
	return errors.New("controlled completion failure")
}
