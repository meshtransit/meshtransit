package httpapi

import (
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/meshtransit/meshtransit/internal/app"
	"github.com/meshtransit/meshtransit/internal/network/revisionworker"
)

func TestOperatorMetricsExposeBoundedRuntimeSignals(t *testing.T) {
	t.Parallel()

	state := newRuntimeState(t, app.RoleAPI)
	state.SetReady(true)
	metrics, err := newOperatorMetrics(state, testBuildInfo(), nil)
	if err != nil {
		t.Fatalf("newOperatorMetrics() error = %v", err)
	}
	handler := newHealthHandler(state, discardLogger(), metrics)

	if response := request(t, handler, "/live"); response.Code != http.StatusOK {
		t.Fatalf("GET /live status = %d, want %d", response.Code, http.StatusOK)
	}
	if response := request(t, handler, "/ready"); response.Code != http.StatusOK {
		t.Fatalf("GET /ready status = %d, want %d", response.Code, http.StatusOK)
	}

	response := request(t, handler, "/metrics")
	if response.Code != http.StatusOK {
		t.Fatalf("GET /metrics status = %d, want %d", response.Code, http.StatusOK)
	}
	for name, value := range map[string]string{
		"build info":          `meshtransit_build_info{config_schema_version="1",go_version="go1.26.8-test",revision="revision-test",version="version-test"} 1`,
		"runtime readiness":   `meshtransit_runtime_ready 1`,
		"login configured":    `meshtransit_login_configured 0`,
		"login readiness":     `meshtransit_login_ready 0`,
		"api role":            `meshtransit_runtime_role{role="api"} 1`,
		"postgres readiness":  `meshtransit_dependency_ready{component="postgresql"} 1`,
		"redis readiness":     `meshtransit_dependency_ready{component="redis"} 1`,
		"live request count":  `meshtransit_operator_http_requests_total{route="live",status="2xx"} 1`,
		"ready request count": `meshtransit_operator_http_requests_total{route="ready",status="2xx"} 1`,
		"Go runtime metric":   `go_goroutines`,
	} {
		if !strings.Contains(response.Body.String(), value) {
			t.Errorf("metrics missing %s %q", name, value)
		}
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", response.Header().Get("Cache-Control"))
	}
	if response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", response.Header().Get("X-Content-Type-Options"))
	}
}

func TestOperatorMetricsPrivatePrerequisiteRemainsClosedAndObservable(t *testing.T) {
	t.Parallel()
	state, err := app.NewRuntimeState([]app.Role{app.RoleAPI}, app.ComponentPrivateLogin)
	if err != nil {
		t.Fatal(err)
	}
	metrics, err := newOperatorMetrics(state, testBuildInfo(), nil)
	if err != nil {
		t.Fatal("fixed private readiness rejected by operator metrics", err)
	}
	response := request(t, metrics.handler, "/metrics")
	if response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), `meshtransit_dependency_ready{component="private_login"} 0`) ||
		!strings.Contains(response.Body.String(), `meshtransit_login_configured 1`) ||
		!strings.Contains(response.Body.String(), `meshtransit_login_ready 0`) {
		t.Fatal("unknown private prerequisite omitted or reported ready")
	}
	for _, component := range []string{
		"postgresql", "redis", "private_login", "identity_postgresql", "identity_configuration",
		"unknown", "private_Login", "route-123",
	} {
		valid := component == "postgresql" || component == "redis" || component == "private_login" ||
			component == "identity_postgresql" || component == "identity_configuration"
		if validComponentLabel(component) != valid {
			t.Fatal("operator component allowlist changed beyond closed profile")
		}
	}
}

func TestOperatorMetricsExposeIdentityRoleAndStorage(t *testing.T) {
	t.Parallel()

	state := newRuntimeState(t, app.RoleIdentity)
	metrics, err := newOperatorMetrics(state, testBuildInfo(), nil)
	if err != nil {
		t.Fatalf("newOperatorMetrics() error = %v", err)
	}
	response := request(t, metrics.handler, "/metrics")
	for name, value := range map[string]string{
		"identity role":          `meshtransit_runtime_role{role="identity"} 1`,
		"identity storage":       `meshtransit_dependency_ready{component="identity_postgresql"} 1`,
		"identity configuration": `meshtransit_dependency_ready{component="identity_configuration"} 1`,
	} {
		if !strings.Contains(response.Body.String(), value) {
			t.Errorf("metrics missing %s %q: %s", name, value, response.Body.String())
		}
	}
}

func TestOperatorMetricsDoNotExposeUnknownRequestPaths(t *testing.T) {
	t.Parallel()

	const unknownPath = "/private-host.example/resource-123"
	state := newRuntimeState(t, app.RoleRelay)
	metrics, err := newOperatorMetrics(state, testBuildInfo(), nil)
	if err != nil {
		t.Fatalf("newOperatorMetrics() error = %v", err)
	}
	handler := newHealthHandler(state, discardLogger(), metrics)

	if response := request(t, handler, unknownPath); response.Code != http.StatusNotFound {
		t.Fatalf("unknown path status = %d, want %d", response.Code, http.StatusNotFound)
	}
	response := request(t, handler, "/metrics")
	if strings.Contains(response.Body.String(), unknownPath) || strings.Contains(response.Body.String(), "private-host") {
		t.Fatalf("metrics exposed unknown path: %s", response.Body.String())
	}
	if !strings.Contains(
		response.Body.String(),
		`meshtransit_operator_http_requests_total{route="not_found",status="4xx"} 1`,
	) {
		t.Fatalf("metrics missing bounded not-found counter: %s", response.Body.String())
	}
}

func TestNewOperatorMetricsRejectsUnsafeBuildLabels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		build BuildInfo
	}{
		{name: "empty version", build: BuildInfo{Revision: "revision", GoVersion: "go1.26.8", ConfigSchemaVersion: 1}},
		{name: "multiline revision", build: BuildInfo{Version: "version", Revision: "first\nsecond", GoVersion: "go1.26.8", ConfigSchemaVersion: 1}},
		{name: "empty Go version", build: BuildInfo{Version: "version", Revision: "revision", ConfigSchemaVersion: 1}},
		{name: "invalid schema version", build: BuildInfo{Version: "version", Revision: "revision", GoVersion: "go1.26.8"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if _, err := newOperatorMetrics(newRuntimeState(t, app.RoleRelay), test.build, nil); err == nil {
				t.Fatal("newOperatorMetrics() error = nil, want invalid build info")
			}
		})
	}
}

func TestOperatorMetricsUseOneRuntimeSnapshotPerScrape(t *testing.T) {
	t.Parallel()

	state := &countingHealthState{
		snapshot: app.HealthSnapshot{
			Ready: true,
			Roles: []string{"api"},
			Components: map[string]string{
				"postgresql": "ready",
				"redis":      "ready",
			},
		},
	}
	metrics, err := newOperatorMetrics(state, testBuildInfo(), nil)
	if err != nil {
		t.Fatalf("newOperatorMetrics() error = %v", err)
	}

	if response := request(t, metrics.handler, "/metrics"); response.Code != http.StatusOK {
		t.Fatalf("GET /metrics status = %d, want %d", response.Code, http.StatusOK)
	}
	if calls := state.calls.Load(); calls != 2 {
		t.Fatalf("Snapshot() calls = %d, want 2: one validation and one scrape", calls)
	}
}

func TestOperatorMetricsExposeRevisionWorkerTelemetryWithBoundedResults(t *testing.T) {
	t.Parallel()

	state := newRuntimeState(t, app.RoleWorker)
	telemetry := fixedRevisionWorkerTelemetry{snapshot: revisionworker.TelemetrySnapshot{
		ReadyBacklogEvents:  7,
		OldestReadyEventAge: 3 * time.Second,
		BacklogSuccessTotal: 11,
		BacklogErrorTotal:   2,
		ClaimSuccessTotal:   13,
		ClaimErrorTotal:     3,
		ClaimedEventsTotal:  17,
		DeliveredTotal:      14,
		DeferredTotal:       2,
		FailedTotal:         1,
	}}
	metrics, err := newOperatorMetrics(state, testBuildInfo(), telemetry)
	if err != nil {
		t.Fatalf("newOperatorMetrics() error = %v", err)
	}
	response := request(t, metrics.handler, "/metrics")
	if response.Code != http.StatusOK {
		t.Fatalf("GET /metrics status = %d, want %d", response.Code, http.StatusOK)
	}
	for name, value := range map[string]string{
		"ready backlog":      `meshtransit_revision_worker_ready_backlog_events 7`,
		"oldest ready age":   `meshtransit_revision_worker_oldest_ready_event_age_seconds 3`,
		"backlog success":    `meshtransit_revision_worker_backlog_observations_total{result="success"} 11`,
		"backlog error":      `meshtransit_revision_worker_backlog_observations_total{result="error"} 2`,
		"claim success":      `meshtransit_revision_worker_claim_operations_total{result="success"} 13`,
		"claim error":        `meshtransit_revision_worker_claim_operations_total{result="error"} 3`,
		"claimed events":     `meshtransit_revision_worker_claimed_events_total 17`,
		"delivery delivered": `meshtransit_revision_worker_delivery_attempts_total{result="delivered"} 14`,
		"delivery deferred":  `meshtransit_revision_worker_delivery_attempts_total{result="deferred"} 2`,
		"delivery failed":    `meshtransit_revision_worker_delivery_attempts_total{result="failed"} 1`,
	} {
		if !strings.Contains(response.Body.String(), value) {
			t.Errorf("metrics missing %s %q", name, value)
		}
	}
}

func TestOperatorMetricsRegisterAdditionalProcessCollector(t *testing.T) {
	t.Parallel()

	dependencyMetric := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "meshtransit_test_dependency_ready",
		Help: "Test-only dependency signal.",
	})
	dependencyMetric.Set(1)
	metrics, err := newOperatorMetrics(
		newRuntimeState(t, app.RoleAPI),
		testBuildInfo(),
		nil,
		dependencyMetric,
	)
	if err != nil {
		t.Fatalf("newOperatorMetrics() error = %v", err)
	}

	response := request(t, metrics.handler, "/metrics")
	if response.Code != http.StatusOK {
		t.Fatalf("GET /metrics status = %d, want %d", response.Code, http.StatusOK)
	}
	if !strings.Contains(response.Body.String(), `meshtransit_test_dependency_ready 1`) {
		t.Fatalf("metrics missing additional collector: %s", response.Body.String())
	}
}

func TestOperatorMetricsRejectNilAdditionalCollector(t *testing.T) {
	t.Parallel()

	if _, err := newOperatorMetrics(
		newRuntimeState(t, app.RoleAPI),
		testBuildInfo(),
		nil,
		nil,
	); !errors.Is(err, ErrInvalidMetrics) {
		t.Fatalf("newOperatorMetrics() error = %v, want ErrInvalidMetrics", err)
	}
}

type fixedRevisionWorkerTelemetry struct {
	snapshot revisionworker.TelemetrySnapshot
}

func (telemetry fixedRevisionWorkerTelemetry) Snapshot() revisionworker.TelemetrySnapshot {
	return telemetry.snapshot
}

func testBuildInfo() BuildInfo {
	return BuildInfo{
		Version:             "version-test",
		Revision:            "revision-test",
		GoVersion:           "go1.26.8-test",
		ConfigSchemaVersion: 1,
	}
}

type countingHealthState struct {
	calls    atomic.Int32
	snapshot app.HealthSnapshot
}

func (state *countingHealthState) Snapshot() app.HealthSnapshot {
	state.calls.Add(1)
	return state.snapshot
}
