package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPoolDatabaseClockReturnsUTCAndRecordsTheSample(t *testing.T) {
	t.Parallel()
	metrics := newPostgresPoolMetrics(PoolRoleRuntime, func() postgresPoolStats { return postgresPoolStats{MaxConnections: 1} })
	zone := time.FixedZone("UTC+7", 7*60*60)
	at := time.Date(2030, 1, 2, 10, 4, 5, 6000, zone)
	pool := &Pool{role: PoolRoleRuntime, metrics: metrics, databaseClock: func(context.Context) (time.Time, error) {
		return at, nil
	}}
	got, err := pool.DatabaseClock(t.Context())
	if err != nil || !got.Equal(at) || got.Location() != time.UTC {
		t.Fatalf("DatabaseClock() = %v, %v; want %v in UTC", got, err, at)
	}
	failure := errors.New("connection refused")
	pool.databaseClock = func(context.Context) (time.Time, error) { return time.Time{}, failure }
	if _, err := pool.DatabaseClock(t.Context()); !errors.Is(err, failure) {
		t.Fatalf("DatabaseClock() failure = %v", err)
	}
	collector, err := NewMetricsCollector(pool)
	if err != nil {
		t.Fatal(err)
	}
	body := gatherPostgresMetrics(t, collector)
	for _, want := range []string{
		`meshtransit_postgres_operations_total{operation="clock_sample",pool_role="runtime",result="success"} 1`,
		`meshtransit_postgres_operations_total{operation="clock_sample",pool_role="runtime",result="error"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics missing %q", want)
		}
	}
	var missing *Pool
	if _, err := missing.DatabaseClock(t.Context()); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("nil pool DatabaseClock() = %v", err)
	}
	if _, err := (&Pool{}).DatabaseClock(t.Context()); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("unopened pool DatabaseClock() = %v", err)
	}
}
