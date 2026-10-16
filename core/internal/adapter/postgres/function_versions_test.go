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
// expected. The pool exposes the count and logs which steps are pending.
func TestPoolCheckReportsPendingOperatorStepsWithoutFailing(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	metrics := newPostgresPoolMetrics(PoolRoleRuntime, func() postgresPoolStats { return postgresPoolStats{} })
	metrics.logger = slog.New(slog.NewJSONHandler(&logs, nil))
	pending := []string{"000170_device_alias_consumer_readmission_ownership"}
	var probeErr error
	pool := &Pool{
		role:               PoolRoleRuntime,
		ping:               func(context.Context) error { return nil },
		checkWritable:      func(context.Context) error { return nil },
		checkSchema:        func(context.Context) error { return nil },
		checkOperatorSteps: func(context.Context) ([]string, error) { return pending, probeErr },
		reset:              func() {},
		metrics:            metrics,
	}
	if err := pool.Check(t.Context()); err != nil {
		t.Fatalf("Check() = %v with a pending step", err)
	}
	collector, err := NewMetricsCollector(pool)
	if err != nil {
		t.Fatal(err)
	}
	if body := gatherPostgresMetrics(t, collector); !strings.Contains(body,
		`meshtransit_postgres_operator_steps_pending{pool_role="runtime"} 1`) {
		t.Fatalf("metrics:\n%s", body)
	}
	if !strings.Contains(logs.String(), `"pending_steps":["000170_device_alias_consumer_readmission_ownership"]`) {
		t.Fatalf("logs = %s", logs.String())
	}
	logs.Reset()
	if err := pool.Check(t.Context()); err != nil || logs.Len() != 0 {
		t.Fatalf("unchanged pending set logged again: %v %s", err, logs.String())
	}
	probeErr = errors.New("synthetic catalog read failure")
	if err := pool.Check(t.Context()); err != nil {
		t.Fatalf("Check() = %v when the step probe failed", err)
	}
	pending, probeErr = nil, nil
	if err := pool.Check(t.Context()); err != nil {
		t.Fatal(err)
	}
	if body := gatherPostgresMetrics(t, collector); !strings.Contains(body,
		`meshtransit_postgres_operator_steps_pending{pool_role="runtime"} 0`) ||
		!strings.Contains(body, `meshtransit_postgres_operations_total{operation="operator_step_check",pool_role="runtime",result="error"} 1`) {
		t.Fatalf("metrics:\n%s", body)
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

func TestPoolReadsOperatorStepsAtMostOncePerInterval(t *testing.T) {
	t.Parallel()
	pool := &Pool{operatorStepInterval: time.Minute}
	start := time.Unix(1000, 0)
	if !pool.operatorStepsDue(start) || pool.operatorStepsDue(start.Add(59*time.Second)) ||
		!pool.operatorStepsDue(start.Add(time.Minute)) {
		t.Fatal("operator step probe not spaced by its interval")
	}
	every := &Pool{}
	first := every.operatorStepsDue(start)
	if second := every.operatorStepsDue(start); !first || !second {
		t.Fatal("a zero interval must probe on every check")
	}
}
