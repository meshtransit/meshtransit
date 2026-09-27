package httpapi

import (
	"errors"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/meshtransit/meshtransit/internal/app"
	"github.com/meshtransit/meshtransit/internal/network/revisionfeed"
)

func TestRevisionFeedMetricsExposeBoundedSignals(t *testing.T) {
	t.Parallel()

	telemetry := revisionfeed.NewTelemetry()
	collector, err := NewRevisionFeedMetricsCollector(telemetry)
	if err != nil {
		t.Fatalf("NewRevisionFeedMetricsCollector() error = %v", err)
	}
	metrics, err := newOperatorMetrics(
		newRuntimeState(t, app.RoleControl),
		testBuildInfo(),
		nil,
		collector,
	)
	if err != nil {
		t.Fatalf("newOperatorMetrics() error = %v", err)
	}
	response := request(t, metrics.handler, "/metrics")
	for name, value := range map[string]string{
		"subscriber state":  `meshtransit_revision_feed_subscriber_connected 0`,
		"active watchers":   `meshtransit_revision_feed_watchers_active 0`,
		"received wakeups":  `meshtransit_revision_feed_wakeups_received_total 0`,
		"delivered fanout":  `meshtransit_revision_feed_fanout_total{result="delivered"} 0`,
		"coalesced fanout":  `meshtransit_revision_feed_fanout_total{result="coalesced"} 0`,
		"reconnect attempt": `meshtransit_revision_feed_reconnect_total{result="attempt"} 0`,
		"reconnect success": `meshtransit_revision_feed_reconnect_total{result="success"} 0`,
	} {
		if !strings.Contains(response.Body.String(), value) {
			t.Errorf("metrics missing %s %q", name, value)
		}
	}
}

func TestRevisionFeedMetricsRejectNilTelemetry(t *testing.T) {
	t.Parallel()

	collector, err := NewRevisionFeedMetricsCollector(nil)
	if !errors.Is(err, ErrInvalidMetrics) || collector != nil {
		t.Fatalf("NewRevisionFeedMetricsCollector(nil) = (%v, %v), want nil and ErrInvalidMetrics", collector, err)
	}
}

var _ prometheus.Collector = (*revisionFeedMetricsCollector)(nil)
