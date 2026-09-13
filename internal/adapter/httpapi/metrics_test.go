package httpapi

import (
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/meshtransit/meshtransit/internal/app"
)

func TestOperatorMetricsExposeBoundedRuntimeSignals(t *testing.T) {
	t.Parallel()

	state := newRuntimeState(t, app.RoleAPI)
	state.SetReady(true)
	metrics, err := newOperatorMetrics(state, testBuildInfo())
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

func TestOperatorMetricsDoNotExposeUnknownRequestPaths(t *testing.T) {
	t.Parallel()

	const unknownPath = "/private-host.example/resource-123"
	state := newRuntimeState(t, app.RoleRelay)
	metrics, err := newOperatorMetrics(state, testBuildInfo())
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

			if _, err := newOperatorMetrics(newRuntimeState(t, app.RoleRelay), test.build); err == nil {
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
	metrics, err := newOperatorMetrics(state, testBuildInfo())
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
