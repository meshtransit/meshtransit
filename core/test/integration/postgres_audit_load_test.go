//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"meshtransit.net/core/internal/platform/config"
)

// Opt-in load test of the audit hash chain (TD-CORE-132): every audited
// change locks its stream row until commit, so the changes of one stream
// run one after another. MESHTRANSIT_AUDIT_LOAD=1 runs it at the end of
// TestPostgreSQLMigrations; _EVENTS and _WORKERS size it. It leaves
// fake Device events and pending outbox rows behind, so it must be the last
// test on its database (run-integration-kind.sh refuses other patterns).
const (
	auditLoadEnvironment        = "MESHTRANSIT_AUDIT_LOAD"
	auditLoadEventsEnvironment  = "MESHTRANSIT_AUDIT_LOAD_EVENTS"
	auditLoadWorkersEnvironment = "MESHTRANSIT_AUDIT_LOAD_WORKERS"
	auditLoadPayload            = `{"hostname":"load-node.example","credential_id":` +
		`"01890f20-0000-7000-8000-000000064200","registration_id":"01890f20-0000-7000-8000-000000064600",` +
		`"disposition":"created","device_lifetime":"never","device_expires_at":"2200-01-01T00:00:00Z"}`
)

// auditLoadStream is one chain the load writes to.
type auditLoadStream struct {
	id              int64
	scope           string
	networkRevision any
}

// auditLoadScenario writes events round-robin over streams from workers
// connections; hold is work done between taking the stream lock and
// commit; asyncCommit skips the WAL flush wait at commit.
type auditLoadScenario struct {
	name        string
	streams     []auditLoadStream
	workers     int
	hold        time.Duration
	asyncCommit bool
}

const lockAuditLoadStreamSQL = `SELECT next_sequence, latest_event_hash
FROM mesh_audit.audit_stream WHERE id = $1 FOR UPDATE`

const insertAuditLoadMutationSQL = `INSERT INTO mesh_audit.authority_mutation (
    change_public_id, transaction_id, aggregate_kind, row_public_id, operation, after_version
) VALUES (
    $1::UUID, (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT, 'device', $2::UUID, 'insert', 1
)`

const appendAuditLoadEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
    $1::BIGINT, pg_catalog.uuidv7(), pg_catalog.uuidv7(), $2::BIGINT, $3::BYTEA, $4::BYTEA,
    'device', $5::UUID, 1, $6::BIGINT, '01890f00-0000-7000-8000-000000000011'::UUID,
    'device.registered', 'device.register', NULL::UUID, NULL::BYTEA, NULL::BYTEA,
    $7::JSONB, 'registration.created', '{}'::JSONB
)`

// auditLoadWaitersSQL counts sessions waiting for a row lock right now.
const auditLoadWaitersSQL = `SELECT pg_catalog.count(*)::INTEGER FROM pg_catalog.pg_stat_activity
WHERE wait_event_type = 'Lock' AND wait_event IN ('transactionid', 'tuple')`

func assertAuditStreamLoad(ctx context.Context, t *testing.T, admin *pgx.Conn, adminConfig config.MigrationConfig) {
	t.Helper()
	if os.Getenv(auditLoadEnvironment) != "1" {
		return
	}
	// The migration test's own minute is spent; the load has its own budget.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Minute)
	defer cancel()
	open := func(ctx context.Context) *pgx.Conn {
		return openIntegrationPostgreSQLConnection(ctx, t, adminConfig.PostgreSQL.Address,
			adminConfig.PostgreSQL.Database, adminConfig.PostgreSQL.User, adminConfig.PostgreSQL.PasswordFile,
			adminConfig.PostgreSQL.CAFile, adminConfig.ConnectTimeout)
	}
	events := auditLoadSize(t, auditLoadEventsEnvironment, 2000, 100000)
	workers := auditLoadSize(t, auditLoadWorkersEnvironment, 16, 256)
	streams := readAuditLoadStreams(ctx, t, admin)
	deployment, networks := streams[0], streams[1:]
	if len(networks) == 0 {
		t.Fatal("audit load: no Network stream in the fixture")
	}
	var fsync string
	if err := admin.QueryRow(ctx, `SELECT pg_catalog.current_setting('synchronous_commit') || '/' ||
    pg_catalog.current_setting('fsync')`).Scan(&fsync); err != nil {
		t.Fatalf("audit load: read commit settings: %v", err)
	}
	t.Logf("audit load: %d events per scenario, %d workers, synchronous_commit/fsync %s, %d Network streams",
		events, workers, fsync, len(networks))

	one := networks[:1]
	scenarios := []auditLoadScenario{
		{name: "one Network stream, 1 worker", streams: one, workers: 1},
		{name: "one Network stream", streams: one, workers: workers},
		{name: "one Network stream, async commit", streams: one, workers: workers, asyncCommit: true},
		{name: "one Network stream, 2 ms work under lock", streams: one, workers: workers,
			hold: 2 * time.Millisecond},
		{name: "deployment stream", streams: []auditLoadStream{deployment}, workers: workers},
		{name: fmt.Sprintf("%d Network streams", len(networks)), streams: networks, workers: workers},
	}
	for _, scenario := range scenarios {
		t.Logf("audit load: %s", runAuditLoadScenario(ctx, t, open, scenario, events))
	}
	// The chains the load wrote still verify end to end.
	assertAuditSealV2(ctx, t, admin)
}

func auditLoadSize(t *testing.T, name string, fallback, limit int) int {
	t.Helper()
	text := os.Getenv(name)
	if text == "" {
		return fallback
	}
	value, err := strconv.Atoi(text)
	if err != nil || value < 1 || value > limit {
		t.Fatalf("%s=%q: want 1..%d", name, text, limit)
	}
	return value
}

// readAuditLoadStreams returns the Deployment stream first, then every
// Network stream with its current Network revision.
func readAuditLoadStreams(ctx context.Context, t *testing.T, admin *pgx.Conn) []auditLoadStream {
	t.Helper()
	rows, err := admin.Query(ctx, `SELECT stream.id, stream.scope_kind, revision.network_revision
FROM mesh_audit.audit_stream AS stream
LEFT JOIN mesh_ops.network_revision AS revision
  ON revision.workspace_id = stream.workspace_id AND revision.network_id = stream.network_id
WHERE stream.scope_kind IN ('deployment', 'network')
ORDER BY stream.scope_kind = 'network', stream.id`)
	if err != nil {
		t.Fatalf("audit load: read streams: %v", err)
	}
	streams, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (auditLoadStream, error) {
		var stream auditLoadStream
		var revision *int64
		if err := row.Scan(&stream.id, &stream.scope, &revision); err != nil {
			return stream, err
		}
		if revision != nil {
			stream.networkRevision = *revision
		}
		return stream, nil
	})
	if err != nil {
		t.Fatalf("audit load: scan streams: %v", err)
	}
	if len(streams) == 0 || streams[0].scope != "deployment" {
		t.Fatal("audit load: the Deployment stream is missing")
	}
	return streams
}

func runAuditLoadScenario(ctx context.Context, t *testing.T,
	open func(context.Context) *pgx.Conn, scenario auditLoadScenario, events int) string {
	t.Helper()
	connections := make([]*pgx.Conn, scenario.workers)
	for index := range connections {
		connections[index] = open(ctx)
	}
	defer func() {
		for _, connection := range connections {
			_ = connection.Close(context.WithoutCancel(ctx))
		}
	}()

	// The first failure stops the other workers.
	workCtx, stopWork := context.WithCancel(ctx)
	defer stopWork()
	var next atomic.Int64
	latencies := make([][]time.Duration, scenario.workers)
	failures := make(chan error, scenario.workers)
	sampleCtx, stopSampling := context.WithCancel(ctx)
	waiters := sampleAuditLoadWaiters(sampleCtx, open(ctx))
	started := time.Now()
	var group sync.WaitGroup
	for worker, connection := range connections {
		group.Go(func() {
			for {
				index := next.Add(1) - 1
				if index >= int64(events) || workCtx.Err() != nil {
					return
				}
				stream := scenario.streams[index%int64(len(scenario.streams))]
				began := time.Now()
				if err := writeAuditLoadEvent(workCtx, connection, stream, scenario); err != nil {
					stopWork()
					failures <- fmt.Errorf("event %d on stream %d: %w", index, stream.id, err)
					return
				}
				latencies[worker] = append(latencies[worker], time.Since(began))
			}
		})
	}
	group.Wait()
	elapsed := time.Since(started)
	stopSampling()
	peak, mean := waiters()
	close(failures)
	for err := range failures {
		t.Fatalf("audit load %s: %v", scenario.name, err)
	}
	all := slices.Concat(latencies...)
	slices.Sort(all)
	return fmt.Sprintf("%s: %d events in %v = %.0f/s; latency p50 %v p95 %v p99 %v; lock waiters mean %.1f peak %d",
		scenario.name, len(all), elapsed.Round(time.Millisecond), float64(len(all))/elapsed.Seconds(),
		auditLoadQuantile(all, 0.50), auditLoadQuantile(all, 0.95), auditLoadQuantile(all, 0.99), mean, peak)
}

// writeAuditLoadEvent is the smallest audited change the chain accepts:
// lock the stream head, one authority mutation, one event, commit.
func writeAuditLoadEvent(ctx context.Context, connection *pgx.Conn, stream auditLoadStream,
	scenario auditLoadScenario) error {
	return pgx.BeginFunc(ctx, connection, func(transaction pgx.Tx) error {
		if scenario.asyncCommit {
			if _, err := transaction.Exec(ctx, `SET LOCAL synchronous_commit = off`); err != nil {
				return err
			}
		}
		var change, row string
		if err := transaction.QueryRow(ctx, `SELECT pg_catalog.uuidv7()::TEXT, pg_catalog.uuidv7()::TEXT`).Scan(
			&change, &row); err != nil {
			return err
		}
		if _, err := transaction.Exec(ctx, `SELECT pg_catalog.set_config('mesh.change_public_id', $1, TRUE)`,
			change); err != nil {
			return err
		}
		var sequence int64
		var previous []byte
		if err := transaction.QueryRow(ctx, lockAuditLoadStreamSQL, stream.id).Scan(&sequence, &previous); err != nil {
			return err
		}
		if scenario.hold > 0 {
			if _, err := transaction.Exec(ctx, `SELECT pg_catalog.pg_sleep($1::DOUBLE PRECISION)`,
				scenario.hold.Seconds()); err != nil {
				return err
			}
		}
		if _, err := transaction.Exec(ctx, insertAuditLoadMutationSQL, change, row); err != nil {
			return err
		}
		hash := sha256.Sum256(append(append(slices.Clone(previous), change...), row...))
		var appended int64
		if err := transaction.QueryRow(ctx, appendAuditLoadEvidenceSQL, stream.id, sequence, previous, hash[:],
			row, stream.networkRevision, auditLoadPayload).Scan(&appended); err != nil {
			return err
		}
		if appended != sequence {
			return fmt.Errorf("appended sequence %d, want %d", appended, sequence)
		}
		return nil
	})
}

// sampleAuditLoadWaiters polls the lock waiters every 10 ms on its own
// connection until ctx ends (which closes it) and returns a reader of the
// peak and mean.
func sampleAuditLoadWaiters(ctx context.Context, sampler *pgx.Conn) func() (int, float64) {
	var peak, total, samples int
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { _ = sampler.Close(context.WithoutCancel(ctx)) }()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			var waiting int
			if err := sampler.QueryRow(ctx, auditLoadWaitersSQL).Scan(&waiting); err != nil {
				return
			}
			peak, total, samples = max(peak, waiting), total+waiting, samples+1
		}
	}()
	return func() (int, float64) {
		<-done
		if samples == 0 {
			return 0, 0
		}
		return peak, float64(total) / float64(samples)
	}
}

func auditLoadQuantile(sorted []time.Duration, quantile float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	return sorted[min(len(sorted)-1, int(float64(len(sorted))*quantile))].Round(100 * time.Microsecond)
}
