//go:build integration

package integration

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	postgresadapter "github.com/meshtransit/meshtransit/core/internal/adapter/postgres"
	redisadapter "github.com/meshtransit/meshtransit/core/internal/adapter/redis"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/network/revisionworker"
	"github.com/meshtransit/meshtransit/core/internal/platform/config"
	"github.com/meshtransit/meshtransit/core/internal/platform/observability"
)

const integrationNetworkPublicID = "01890f00-0000-7000-8000-000000000201"

func assertRevisionDispatcherDelivery(
	ctx context.Context,
	t *testing.T,
	adminConnection *pgx.Conn,
	workerPool *postgresadapter.Pool,
) {
	t.Helper()

	redisClient := openIntegrationRedisClient(ctx, t)
	outbox, err := postgresadapter.NewOutboxStore(workerPool)
	if err != nil {
		t.Fatalf("postgres.NewOutboxStore() error = %v", err)
	}
	logger, err := observability.NewLogger(io.Discard, slog.LevelDebug)
	if err != nil {
		t.Fatalf("observability.NewLogger() error = %v", err)
	}

	t.Run("publishes committed revision and completes outbox", func(t *testing.T) {
		eventID, committedRevision := commitIntegrationNetworkRevision(ctx, t, adminConnection, "991")
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
		dispatcher := newIntegrationDispatcher(t, outbox, redisClient, telemetry, logger)
		startIntegrationDispatcher(t, dispatcher)

		receiveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		revision, receiveErr := subscription.Receive(receiveCtx)
		if receiveErr != nil {
			t.Fatalf("revision subscription Receive() error = %v", receiveErr)
		}
		if revision.NetworkPublicID() != integrationNetworkPublicID || revision.Number() != committedRevision {
			t.Fatalf(
				"published revision = (%q, %d), want (%q, %d)",
				revision.NetworkPublicID(),
				revision.Number(),
				integrationNetworkPublicID,
				committedRevision,
			)
		}
		waitForIntegrationOutcome(receiveCtx, t, func() bool {
			return telemetry.Snapshot().DeliveredTotal == 1
		})
		assertOutboxOutcome(ctx, t, adminConnection, eventID, "delivered", "delivered", nil)
	})

	t.Run("persists retry when publication fails", func(t *testing.T) {
		eventID, _ := commitIntegrationNetworkRevision(ctx, t, adminConnection, "992")
		publishErr := errors.New("controlled publisher failure")
		telemetry := revisionworker.NewTelemetry()
		dispatcher := newIntegrationDispatcher(
			t,
			outbox,
			failingRevisionPublisher{err: publishErr},
			telemetry,
			logger,
		)
		startIntegrationDispatcher(t, dispatcher)

		waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		waitForIntegrationOutcome(waitCtx, t, func() bool {
			return telemetry.Snapshot().DeferredTotal == 1
		})
		errorClass := "publish_wakeup_failed"
		assertOutboxOutcome(ctx, t, adminConnection, eventID, "pending", "retry", &errorClass)
	})
}

func openIntegrationRedisClient(ctx context.Context, t *testing.T) *redisadapter.Client {
	t.Helper()

	processConfig, err := config.Load(os.LookupEnv)
	if err != nil {
		t.Fatalf("config.Load() Redis settings error = %v", err)
	}
	if processConfig.Storage == nil {
		t.Fatal("integration configuration did not load Redis storage")
	}
	redisConfig := processConfig.Storage.Redis
	client, err := redisadapter.Open(ctx, redisadapter.Options{
		Address:        redisConfig.Address,
		Username:       redisConfig.Username,
		PasswordFile:   redisConfig.PasswordFile,
		CAFile:         redisConfig.CAFile,
		PoolSize:       redisConfig.PoolSize,
		RequestTimeout: processConfig.Dependencies.CheckTimeout,
	})
	if err != nil {
		t.Fatalf("redis.Open() error = %v", err)
	}
	t.Cleanup(func() {
		if closeErr := client.Close(); closeErr != nil {
			t.Errorf("redis Close() error = %v", closeErr)
		}
	})
	return client
}

func newIntegrationDispatcher(
	t *testing.T,
	outbox revisionworker.Outbox,
	publisher revisionworker.Publisher,
	telemetry *revisionworker.Telemetry,
	logger *slog.Logger,
) *revisionworker.Dispatcher {
	t.Helper()

	dispatcher, err := revisionworker.New(
		revisionworker.Options{
			WorkerID:         "integration-revision-worker",
			BatchSize:        1,
			Lease:            5 * time.Second,
			PollInterval:     100 * time.Millisecond,
			RetryDelay:       30 * time.Second,
			OperationTimeout: time.Second,
		},
		outbox,
		publisher,
		telemetry,
		logger,
	)
	if err != nil {
		t.Fatalf("revisionworker.New() error = %v", err)
	}
	return dispatcher
}

func startIntegrationDispatcher(t *testing.T, dispatcher *revisionworker.Dispatcher) {
	t.Helper()

	if err := dispatcher.Start(t.Context()); err != nil {
		t.Fatalf("Dispatcher.Start() error = %v", err)
	}
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := dispatcher.Shutdown(shutdownCtx); err != nil {
			t.Errorf("Dispatcher.Shutdown() error = %v", err)
			return
		}
		select {
		case err := <-dispatcher.Done():
			if err != nil {
				t.Errorf("Dispatcher.Done() error = %v", err)
			}
		case <-shutdownCtx.Done():
			t.Errorf("wait for Dispatcher.Done(): %v", shutdownCtx.Err())
		}
	})
}

func waitForIntegrationOutcome(ctx context.Context, t *testing.T, ready func() bool) {
	t.Helper()

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ready() {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("wait for revision dispatcher outcome: %v", ctx.Err())
		case <-ticker.C:
		}
	}
}

func commitIntegrationNetworkRevision(
	ctx context.Context,
	t *testing.T,
	connection *pgx.Conn,
	publicIDSuffix string,
) (int64, int64) {
	t.Helper()

	var currentRevision int64
	if err := connection.QueryRow(ctx, `SELECT network_revision
FROM mesh_ops.network_revision
WHERE workspace_id = 101 AND network_id = 201`).Scan(&currentRevision); err != nil {
		t.Fatalf("read current integration Network revision: %v", err)
	}
	committedRevision := currentRevision + 1
	outboxPublicID := "01890f03-0000-7000-8000-000000000" + publicIDSuffix
	commitAuditedAuthorityFixture(ctx, t, connection, authorityEvidenceFixture{
		changePublicID:         "01890f01-0000-7000-8000-000000000" + publicIDSuffix,
		eventPublicID:          "01890f02-0000-7000-8000-000000000" + publicIDSuffix,
		outboxPublicID:         outboxPublicID,
		streamID:               201,
		aggregateKind:          "network",
		aggregatePublicID:      integrationNetworkPublicID,
		aggregateVersion:       committedRevision,
		networkRevision:        committedRevision,
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "network.updated",
		permission:             "network.update",
		outboxEventClass:       "network.updated",
	}, func(transaction pgx.Tx) {
		setIntegrationScope(ctx, t, transaction, 101, 201)
		if _, err := transaction.Exec(ctx, `UPDATE mesh.network
SET display_name = 'Network dispatcher integration', version = version + 1
WHERE workspace_id = 101 AND id = 201`); err != nil {
			t.Fatalf("update integration Network: %v", err)
		}
		commandTag, err := transaction.Exec(ctx, `UPDATE mesh_ops.network_revision
SET network_revision = $1,
    updated_at = pg_catalog.clock_timestamp()
WHERE workspace_id = 101 AND network_id = 201
  AND network_revision = $2`, committedRevision, currentRevision)
		if err != nil {
			t.Fatalf("advance integration Network revision: %v", err)
		}
		if commandTag.RowsAffected() != 1 {
			t.Fatalf("advance integration Network revision affected %d rows, want 1", commandTag.RowsAffected())
		}
	})

	var eventID int64
	if err := connection.QueryRow(ctx, `SELECT id
FROM mesh_ops.outbox_event
WHERE public_id = $1`, outboxPublicID).Scan(&eventID); err != nil {
		t.Fatalf("read integration outbox event: %v", err)
	}
	return eventID, committedRevision
}

type failingRevisionPublisher struct {
	err error
}

func (publisher failingRevisionPublisher) PublishNetworkRevisionAdvanced(
	context.Context,
	network.RevisionAdvanced,
) error {
	return publisher.err
}
