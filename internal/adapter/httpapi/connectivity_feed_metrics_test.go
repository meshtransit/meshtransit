package httpapi

import (
	"errors"
	"strings"
	"testing"

	"github.com/meshtransit/meshtransit/internal/app"
	"github.com/meshtransit/meshtransit/internal/control/connectivityfeed"
)

func TestConnectivityFeedMetricsExposeBoundedSignals(t *testing.T) {
	t.Parallel()

	collector, err := NewConnectivityFeedMetricsCollector(connectivityfeed.NewTelemetry())
	if err != nil {
		t.Fatalf("NewConnectivityFeedMetricsCollector() error = %v", err)
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
		"subscriber state":  `meshtransit_connectivity_feed_subscriber_connected 0`,
		"active watchers":   `meshtransit_connectivity_feed_watchers_active 0`,
		"received wakeups":  `meshtransit_connectivity_feed_wakeups_received_total 0`,
		"delivered fanout":  `meshtransit_connectivity_feed_fanout_total{result="delivered"} 0`,
		"coalesced fanout":  `meshtransit_connectivity_feed_fanout_total{result="coalesced"} 0`,
		"reconnect attempt": `meshtransit_connectivity_feed_reconnect_total{result="attempt"} 0`,
		"reconnect success": `meshtransit_connectivity_feed_reconnect_total{result="success"} 0`,
	} {
		if !strings.Contains(response.Body.String(), value) {
			t.Errorf("metrics missing %s %q", name, value)
		}
	}
}

func TestConnectivityFeedMetricsRejectNilTelemetry(t *testing.T) {
	t.Parallel()

	collector, err := NewConnectivityFeedMetricsCollector(nil)
	if !errors.Is(err, ErrInvalidMetrics) || collector != nil {
		t.Fatalf("NewConnectivityFeedMetricsCollector(nil) = (%v, %v)", collector, err)
	}
}
