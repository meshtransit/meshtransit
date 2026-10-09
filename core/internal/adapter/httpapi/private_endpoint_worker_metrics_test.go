package httpapi

import (
	"errors"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/sharing/endpointpublication"
	"meshtransit.net/core/internal/platform/app"
)

func TestPrivateEndpointWorkerMetricsExposeBoundedSignals(t *testing.T) {
	t.Parallel()

	collector, err := NewPrivateEndpointWorkerMetricsCollector(endpointpublication.NewTelemetry())
	if err != nil {
		t.Fatalf("NewPrivateEndpointWorkerMetricsCollector() error = %v", err)
	}
	metrics, err := newOperatorMetrics(
		newRuntimeState(t, app.RoleControl), testBuildInfo(), nil, collector,
	)
	if err != nil {
		t.Fatalf("newOperatorMetrics() error = %v", err)
	}
	response := request(t, metrics.handler, "/metrics")
	for name, value := range map[string]string{ //nolint:gosec // Metric names are public identifiers, not credentials.
		"worker state":           `meshtransit_private_endpoint_worker_running 0`,
		"passes":                 `meshtransit_private_endpoint_worker_passes_total 0`,
		"publication candidates": `meshtransit_private_endpoint_worker_candidates{operation="publication"} 0`,
		"withdrawal candidates":  `meshtransit_private_endpoint_worker_candidates{operation="withdrawal"} 0`,
		"publication deferred":   `meshtransit_private_endpoint_worker_attempts_total{operation="publication",result="deferred"} 0`,
		"withdrawal succeeded":   `meshtransit_private_endpoint_worker_attempts_total{operation="withdrawal",result="succeeded"} 0`,
	} {
		if !strings.Contains(response.Body.String(), value) {
			t.Errorf("metrics missing %s %q", name, value)
		}
	}
}

func TestPrivateEndpointWorkerMetricsRejectNilTelemetry(t *testing.T) {
	t.Parallel()

	collector, err := NewPrivateEndpointWorkerMetricsCollector(nil)
	if collector != nil || !errors.Is(err, ErrInvalidPrivateEndpointWorkerMetrics) {
		t.Fatalf("NewPrivateEndpointWorkerMetricsCollector(nil) = (%v, %v)", collector, err)
	}
}
