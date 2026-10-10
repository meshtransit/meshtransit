package controllistener

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestTelemetryExposesConnectionSignals(t *testing.T) {
	t.Parallel()

	telemetry, err := NewTelemetry(11)
	if err != nil {
		t.Fatalf("NewTelemetry() error = %v", err)
	}
	telemetry.connectionOpened()
	telemetry.connectionRejected()
	telemetry.connectionClosed()
	body := gatherMetrics(t, telemetry)
	for _, value := range []string{
		`meshtransit_control_connections_limit 11`,
		`meshtransit_control_connections_active 0`,
		`meshtransit_control_connection_rejections_total 1`,
	} {
		if !strings.Contains(body, value) {
			t.Errorf("metrics missing %q", value)
		}
	}
}

func TestNewTelemetryRejectsInvalidLimits(t *testing.T) {
	t.Parallel()

	for _, limit := range []int{0, MaxConnections + 1} {
		if _, err := NewTelemetry(limit); !errors.Is(err, ErrInvalidTelemetry) {
			t.Fatalf("NewTelemetry(%d) error = %v, want ErrInvalidTelemetry", limit, err)
		}
	}
}

func TestMetricsCollectorRejectsUninitializedListener(t *testing.T) {
	t.Parallel()

	if collector := (*Listener)(nil).MetricsCollector(); collector != nil {
		t.Fatalf("nil listener collector = %v, want nil", collector)
	}
	if collector := (&Listener{}).MetricsCollector(); collector != nil {
		t.Fatalf("uninitialized listener collector = %v, want nil", collector)
	}
}

func gatherMetrics(t testing.TB, collector prometheus.Collector) string {
	t.Helper()
	registry := prometheus.NewRegistry()
	if err := registry.Register(collector); err != nil {
		t.Fatalf("registry.Register() error = %v", err)
	}
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()
	promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, want %d", response.Code, http.StatusOK)
	}
	return response.Body.String()
}
