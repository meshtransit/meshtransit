package legacyts2021

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func TestControlTelemetryExposesBoundedIngressSignals(t *testing.T) {
	t.Parallel()

	telemetry, err := NewControlTelemetry(11, 7)
	if err != nil {
		t.Fatalf("NewControlTelemetry() error = %v", err)
	}
	telemetry.connectionOpened()
	telemetry.connectionRejected()
	telemetry.sessionSlotOpened()
	telemetry.recordSessionAttempt(sessionAttemptEstablished)
	telemetry.recordSessionAttempt(sessionAttemptHandshakeFailure)
	telemetry.recordHandshake(250*time.Millisecond, true)
	telemetry.recordHandshake(500*time.Millisecond, false)
	sessionStarted := telemetry.authenticatedSessionOpened()
	telemetry.authenticatedSessionClosed(sessionStarted)
	telemetry.sessionSlotClosed()
	telemetry.connectionClosed()

	body := gatherControlMetrics(t, telemetry)
	for name, value := range map[string]string{
		"connection limit":     `meshtransit_control_connections_limit 11`,
		"connection active":    `meshtransit_control_connections_active 0`,
		"connection rejection": `meshtransit_control_connection_rejections_total 1`,
		"session limit":        `meshtransit_control_sessions_limit 7`,
		"session slots":        `meshtransit_control_session_slots_active 0`,
		"authenticated active": `meshtransit_control_authenticated_sessions_active 0`,
		"established attempt":  `meshtransit_control_session_attempts_total{result="established"} 1`,
		"handshake failure":    `meshtransit_control_session_attempts_total{result="handshake_failure"} 1`,
		"handshake success":    `meshtransit_control_noise_handshake_duration_seconds_count{result="success"} 1`,
		"handshake failed":     `meshtransit_control_noise_handshake_duration_seconds_count{result="failure"} 1`,
		"session duration":     `meshtransit_control_authenticated_session_duration_seconds_count 1`,
	} {
		if !strings.Contains(body, value) {
			t.Errorf("metrics missing %s %q", name, value)
		}
	}
	if strings.Contains(body, "machine") || strings.Contains(body, "example.com") {
		t.Fatalf("control metrics exposed identity or endpoint data: %s", body)
	}
}

func TestControlServerRecordsRejectedSessionWithClosedResult(t *testing.T) {
	t.Parallel()

	server := newControlServerFixture(t, respondingSessionFactory())
	request := newNoiseUpgradeRequest(t)
	request.Method = http.MethodGet
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
	}
	body := gatherControlMetrics(t, server.telemetry)
	if !strings.Contains(
		body,
		`meshtransit_control_session_attempts_total{result="invalid_request"} 1`,
	) {
		t.Fatalf("metrics missing bounded rejection result: %s", body)
	}
}

func TestNewControlTelemetryRejectsInvalidLimits(t *testing.T) {
	t.Parallel()

	for _, limits := range [][2]int{{0, 1}, {1, 0}, {maxControlSessions + 1, 1}, {1, maxControlSessions + 1}} {
		if _, err := NewControlTelemetry(limits[0], limits[1]); !errors.Is(err, ErrInvalidControlTelemetry) {
			t.Fatalf("NewControlTelemetry(%d, %d) error = %v, want invalid telemetry", limits[0], limits[1], err)
		}
	}
}

func TestControlListenerMetricsCollectorRejectsUninitializedListener(t *testing.T) {
	t.Parallel()

	if collector := (*ControlListener)(nil).MetricsCollector(); collector != nil {
		t.Fatalf("nil listener collector = %v, want nil", collector)
	}
	if collector := (&ControlListener{}).MetricsCollector(); collector != nil {
		t.Fatalf("uninitialized listener collector = %v, want nil", collector)
	}
}

func gatherControlMetrics(t testing.TB, collector prometheus.Collector) string {
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
