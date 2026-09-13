package postgres

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestMetricsCollectorExposesBoundedOperationsAndPoolStats(t *testing.T) {
	t.Parallel()

	runtimeMetrics := newPostgresPoolMetrics(PoolRoleRuntime, func() postgresPoolStats {
		return postgresPoolStats{
			AcquireSuccessTotal:  11,
			AcquireCanceledTotal: 2,
			EmptyAcquireTotal:    3,
			AcquireDuration:      250 * time.Millisecond,
			EmptyAcquireWait:     50 * time.Millisecond,
			AcquiredConnections:  3,
			IdleConnections:      4,
			ConstructingConns:    1,
			MaxConnections:       10,
			NewConnectionsTotal:  8,
			IdleDestroyedTotal:   1,
			LifetimeDestroyed:    2,
		}
	})
	workerMetrics := newPostgresPoolMetrics(PoolRoleWorker, func() postgresPoolStats {
		return postgresPoolStats{MaxConnections: 6}
	})
	runtimeMetrics.observeOperation(postgresOperationPing, 10*time.Millisecond, errors.New("private database address"))
	workerMetrics.observeOperation(postgresOperationOutboxClaim, 20*time.Millisecond, nil)

	collector, err := NewMetricsCollector(
		&Pool{role: PoolRoleRuntime, metrics: runtimeMetrics},
		&Pool{role: PoolRoleWorker, metrics: workerMetrics},
	)
	if err != nil {
		t.Fatalf("NewMetricsCollector() error = %v", err)
	}
	body := gatherPostgresMetrics(t, collector)
	for name, value := range map[string]string{
		"runtime ping error":      `meshtransit_postgres_operations_total{operation="ping",pool_role="runtime",result="error"} 1`,
		"worker claim success":    `meshtransit_postgres_operations_total{operation="outbox_claim",pool_role="worker",result="success"} 1`,
		"runtime latency count":   `meshtransit_postgres_operation_duration_seconds_count{operation="ping",pool_role="runtime",result="error"} 1`,
		"acquired connections":    `meshtransit_postgres_pool_connections{pool_role="runtime",state="acquired"} 3`,
		"idle connections":        `meshtransit_postgres_pool_connections{pool_role="runtime",state="idle"} 4`,
		"constructing conns":      `meshtransit_postgres_pool_connections{pool_role="runtime",state="constructing"} 1`,
		"connection limit":        `meshtransit_postgres_pool_connections_max{pool_role="runtime"} 10`,
		"successful acquires":     `meshtransit_postgres_pool_acquires_total{pool_role="runtime",result="success"} 11`,
		"canceled acquires":       `meshtransit_postgres_pool_acquires_total{pool_role="runtime",result="canceled"} 2`,
		"empty acquires":          `meshtransit_postgres_pool_empty_acquires_total{pool_role="runtime"} 3`,
		"acquire duration":        `meshtransit_postgres_pool_acquire_duration_seconds_total{pool_role="runtime"} 0.25`,
		"empty acquire wait":      `meshtransit_postgres_pool_empty_acquire_wait_seconds_total{pool_role="runtime"} 0.05`,
		"connections created":     `meshtransit_postgres_pool_connections_created_total{pool_role="runtime"} 8`,
		"idle connections reaped": `meshtransit_postgres_pool_connections_destroyed_total{pool_role="runtime",reason="idle"} 1`,
		"lifetime reaped":         `meshtransit_postgres_pool_connections_destroyed_total{pool_role="runtime",reason="lifetime"} 2`,
	} {
		if !strings.Contains(body, value) {
			t.Errorf("metrics missing %s %q", name, value)
		}
	}
	if strings.Contains(body, "private database address") {
		t.Fatal("metrics exposed an error value")
	}
	if strings.Contains(body, `operation="outbox_claim",pool_role="runtime"`) {
		t.Fatal("runtime pool exposed an impossible outbox operation series")
	}
}

func TestMetricsCollectorRejectsMissingOrDuplicatePools(t *testing.T) {
	t.Parallel()

	runtimeMetrics := newPostgresPoolMetrics(PoolRoleRuntime, func() postgresPoolStats {
		return postgresPoolStats{}
	})
	tests := []struct {
		name  string
		pools []*Pool
	}{
		{name: "missing pools"},
		{name: "uninitialized pool", pools: []*Pool{{}}},
		{
			name: "duplicate role",
			pools: []*Pool{
				{role: PoolRoleRuntime, metrics: runtimeMetrics},
				{role: PoolRoleRuntime, metrics: runtimeMetrics},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if _, err := NewMetricsCollector(test.pools...); !errors.Is(err, ErrInvalidMetrics) {
				t.Fatalf("NewMetricsCollector() error = %v, want ErrInvalidMetrics", err)
			}
		})
	}
}

func TestPoolCheckRecordsEachAttemptedOperation(t *testing.T) {
	t.Parallel()

	schemaErr := errors.New("schema unavailable")
	metrics := newPostgresPoolMetrics(PoolRoleRuntime, func() postgresPoolStats {
		return postgresPoolStats{MaxConnections: 1}
	})
	pool := &Pool{
		role:        PoolRoleRuntime,
		ping:        func(_ context.Context) error { return nil },
		checkSchema: func(_ context.Context) error { return schemaErr },
		metrics:     metrics,
	}
	if err := pool.Check(t.Context()); !errors.Is(err, schemaErr) {
		t.Fatalf("Pool.Check() error = %v, want schema failure", err)
	}
	collector, err := NewMetricsCollector(pool)
	if err != nil {
		t.Fatalf("NewMetricsCollector() error = %v", err)
	}
	body := gatherPostgresMetrics(t, collector)
	for _, value := range []string{
		`meshtransit_postgres_operations_total{operation="ping",pool_role="runtime",result="success"} 1`,
		`meshtransit_postgres_operations_total{operation="schema_check",pool_role="runtime",result="error"} 1`,
	} {
		if !strings.Contains(body, value) {
			t.Fatalf("metrics missing operation outcome %q", value)
		}
	}
}

func TestOutboxMetricsIncludeRowsIterationAndCompletionOutcomes(t *testing.T) {
	t.Parallel()

	iterationErr := errors.New("iteration failed")
	database := &fakeOutboxDatabase{
		queryRows:    &fakeOutboxRows{err: iterationErr},
		rowsAffected: 1,
	}
	metrics := newPostgresPoolMetrics(PoolRoleWorker, func() postgresPoolStats {
		return postgresPoolStats{MaxConnections: 1}
	})
	store, err := newOutboxStore(
		database,
		func() (string, error) { return testClaimID, nil },
		metrics,
	)
	if err != nil {
		t.Fatalf("newOutboxStore() error = %v", err)
	}
	if _, err := store.ClaimNetworkRevisions(
		t.Context(),
		"worker-1",
		1,
		time.Second,
	); !errors.Is(err, iterationErr) {
		t.Fatalf("ClaimNetworkRevisions() error = %v, want iteration failure", err)
	}
	if err := store.MarkRevisionDelivered(t.Context(), validTestRevisionClaim(t)); err != nil {
		t.Fatalf("MarkRevisionDelivered() error = %v", err)
	}

	collector, err := NewMetricsCollector(&Pool{role: PoolRoleWorker, metrics: metrics})
	if err != nil {
		t.Fatalf("NewMetricsCollector() error = %v", err)
	}
	body := gatherPostgresMetrics(t, collector)
	for _, value := range []string{
		`meshtransit_postgres_operations_total{operation="outbox_claim",pool_role="worker",result="error"} 1`,
		`meshtransit_postgres_operations_total{operation="outbox_mark_delivered",pool_role="worker",result="success"} 1`,
	} {
		if !strings.Contains(body, value) {
			t.Fatalf("metrics missing outbox outcome %q", value)
		}
	}
}

func TestRegistrationReplayMetricsUseRuntimePoolRole(t *testing.T) {
	t.Parallel()

	command := validRegistrationReplayCommand(t)
	transaction := &fakeRegistrationReplayTransaction{
		row: fakeRegistrationReplayRow{record: validRegistrationReplayRecord(t, command)},
	}
	metrics := newPostgresPoolMetrics(PoolRoleRuntime, func() postgresPoolStats {
		return postgresPoolStats{MaxConnections: 1}
	})
	store, err := newRegistrationReplayStore(
		&fakeRegistrationReplayDatabase{transaction: transaction},
		metrics,
	)
	if err != nil {
		t.Fatalf("newRegistrationReplayStore() error = %v", err)
	}
	if _, found, err := store.ResolveCommitted(t.Context(), command); err != nil || !found {
		t.Fatalf("ResolveCommitted() = (found=%t, error=%v), want committed result", found, err)
	}

	collector, err := NewMetricsCollector(&Pool{role: PoolRoleRuntime, metrics: metrics})
	if err != nil {
		t.Fatalf("NewMetricsCollector() error = %v", err)
	}
	body := gatherPostgresMetrics(t, collector)
	want := `meshtransit_postgres_operations_total{operation="registration_replay",pool_role="runtime",result="success"} 1`
	if !strings.Contains(body, want) {
		t.Fatalf("metrics missing registration replay outcome %q", want)
	}
}

func gatherPostgresMetrics(t *testing.T, collector prometheus.Collector) string {
	t.Helper()

	registry := prometheus.NewRegistry()
	if err := registry.Register(collector); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()
	promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, want %d", response.Code, http.StatusOK)
	}
	return response.Body.String()
}
