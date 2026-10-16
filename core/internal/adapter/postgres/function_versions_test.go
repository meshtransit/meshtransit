package postgres

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/sharing/devicealias"
	"meshtransit.net/core/migrations"
)

// The runtime role may only use a step's functions once the operator granted
// them; the pool reports the version each path selects and names the step.
func TestDeviceAliasWorkerReportsTheSelectedFunctionVersion(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	metrics := newPostgresPoolMetrics(PoolRoleWorker, func() postgresPoolStats { return postgresPoolStats{} })
	metrics.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	for _, version := range []int{3, 3, 5} {
		intent := aliasWorkerIntentFixture(t)
		tx := &aliasWorkTestTransaction{mode: "valid", version: version}
		store := &DeviceAliasWorkerStore{database: &fakeOutboxDatabase{transaction: tx}, metrics: metrics}
		if _, err := store.List(t.Context(), intent.DeploymentID, devicealias.Cursor{}, 1); err != nil {
			t.Fatal(err)
		}
		collector, err := NewMetricsCollector(&Pool{role: PoolRoleWorker, metrics: metrics})
		if err != nil {
			t.Fatal(err)
		}
		want := `meshtransit_postgres_function_version{path="device_alias_worker",pool_role="worker"} ` + strconv.Itoa(version)
		if body := gatherPostgresMetrics(t, collector); !strings.Contains(body, want) {
			t.Fatalf("metrics lack %q:\n%s", want, body)
		}
	}
	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"level":"WARN"`) ||
		!strings.Contains(lines[0], `"operator_step":"000171_device_alias_provider_readmission_ownership"`) ||
		!strings.Contains(lines[0], `"version":3`) || !strings.Contains(lines[1], `"level":"INFO"`) ||
		!strings.Contains(lines[1], `"version":5`) {
		t.Fatalf("logs = %s", logs.String())
	}
}

// A pending operator step never closes readiness: during a rollout it is
// expected. The monitor exposes the count and logs which steps are pending.
func TestOperatorStepMonitorReportsPendingStepsAndFailures(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	metrics := newPostgresPoolMetrics(PoolRoleRuntime, func() postgresPoolStats { return postgresPoolStats{} })
	metrics.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	pending := []string{"000170_device_alias_consumer_readmission_ownership"}
	var probeErr error
	monitor := newOperatorStepMonitor(func(context.Context) ([]string, error) { return pending, probeErr }, metrics, 0)
	pool := &Pool{role: PoolRoleRuntime, metrics: metrics}
	collector, err := NewMetricsCollector(pool)
	if err != nil {
		t.Fatal(err)
	}
	monitor.probe(t.Context())
	if body := gatherPostgresMetrics(t, collector); !strings.Contains(body,
		`meshtransit_postgres_operator_steps_pending{pool_role="runtime"} 1`) {
		t.Fatalf("metrics:\n%s", body)
	}
	if !strings.Contains(logs.String(), `"pending_steps":["000170_device_alias_consumer_readmission_ownership"]`) {
		t.Fatalf("logs = %s", logs.String())
	}
	logs.Reset()
	monitor.probe(t.Context())
	if logs.Len() != 0 {
		t.Fatalf("unchanged pending set logged again: %s", logs.String())
	}
	probeErr = errors.New("synthetic catalog read failure")
	monitor.probe(t.Context())
	if body := gatherPostgresMetrics(t, collector); !strings.Contains(body,
		`meshtransit_postgres_operator_steps_pending{pool_role="runtime"} -1`) {
		t.Fatalf("metrics after a failed read:\n%s", body)
	}
	pending, probeErr = nil, nil
	monitor.probe(t.Context())
	if body := gatherPostgresMetrics(t, collector); !strings.Contains(body,
		`meshtransit_postgres_operator_steps_pending{pool_role="runtime"} 0`) ||
		!strings.Contains(body, `meshtransit_postgres_operations_total{operation="operator_step_check",pool_role="runtime",result="error"} 1`) {
		t.Fatalf("metrics:\n%s", body)
	}
}

// The step read runs in its own goroutine: a readiness check only wakes it,
// never waits for it, and shutdown cancels a read in flight and joins it, so
// no pool connection stays held.
func TestOperatorStepMonitorRunsOffTheCheckPathAndStopsOnShutdown(t *testing.T) {
	t.Parallel()
	started := make(chan struct{}, 1)
	canceled := make(chan struct{})
	probe := func(ctx context.Context) ([]string, error) {
		started <- struct{}{}
		<-ctx.Done()
		close(canceled)
		return nil, ctx.Err()
	}
	metrics := newPostgresPoolMetrics(PoolRoleRuntime, func() postgresPoolStats { return postgresPoolStats{} })
	monitor := newOperatorStepMonitor(probe, metrics, time.Minute)
	monitor.start()
	pool := &Pool{
		role:          PoolRoleRuntime,
		ping:          func(context.Context) error { return nil },
		checkWritable: func(context.Context) error { return nil },
		checkSchema:   func(context.Context) error { return nil },
		reset:         func() {},
		acquired:      func() int32 { return 0 },
		close:         func() {},
		metrics:       metrics,
		stepMonitor:   monitor,
	}
	if err := pool.Check(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the check did not wake the step read")
	}
	if err := pool.Check(t.Context()); err != nil {
		t.Fatal("a check waited for the step read", err)
	}
	if err := pool.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
	default:
		t.Fatal("shutdown returned before the step read was canceled")
	}
}

func TestFunctionPathsNameCatalogSteps(t *testing.T) {
	t.Parallel()
	steps, err := migrations.OperatorSteps()
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, step := range steps {
		known[step.Name] = true
	}
	for path, spec := range functionPathSpecs {
		if spec.newest < 2 || spec.step != "" && !known[spec.step] {
			t.Errorf("%s: %+v", path, spec)
		}
	}
}

func TestOperatorStepMonitorReadsAtMostOncePerInterval(t *testing.T) {
	t.Parallel()
	monitor := newOperatorStepMonitor(nil, nil, time.Minute)
	start := time.Unix(1000, 0)
	if !monitor.due(start) || monitor.due(start.Add(59*time.Second)) || !monitor.due(start.Add(time.Minute)) {
		t.Fatal("operator step read not spaced by its interval")
	}
	every := newOperatorStepMonitor(nil, nil, 0)
	first := every.due(start)
	if second := every.due(start); !first || !second {
		t.Fatal("a zero interval must read on every wake")
	}
}
