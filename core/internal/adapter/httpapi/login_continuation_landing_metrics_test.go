package httpapi

import (
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestLoginLandingTelemetryClosedJoinedMetadata(t *testing.T) {
	t.Parallel()
	telemetry := NewLoginLandingTelemetry()
	registry := prometheus.NewRegistry()
	if err := registry.Register(telemetry); err != nil {
		t.Fatal(err)
	}
	var joined sync.WaitGroup
	for _, outcome := range []LoginLandingOutcome{LoginLandingPresented, LoginLandingHeaderOnly, LoginLandingInvalid,
		LoginLandingSaturated, LoginLandingUnavailable, LoginLandingDeliveryFailed, 255} {
		joined.Go(func() {
			telemetry.LandingOpened()
			telemetry.LandingClosed(outcome, -time.Second)
		})
	}
	joined.Wait()
	families, err := registry.Gather()
	if err != nil || len(families) != 3 {
		t.Fatal("isolated presentation collectors unavailable", err)
	}
	for _, family := range families {
		for _, metric := range family.Metric {
			if metric.Gauge != nil {
				if len(metric.Label) != 0 || metric.Gauge.GetValue() != 0 {
					t.Fatal("presentation ownership leaked")
				}
				continue
			}
			if len(metric.Label) != 1 || metric.Label[0].GetName() != "result" {
				t.Fatal("unbounded observation dimension")
			}
			if metric.Counter != nil && metric.Counter.GetValue() != 1 {
				t.Fatal("joined observation missing/duplicated")
			}
			if metric.Histogram != nil && (metric.Histogram.GetSampleCount() != 1 || metric.Histogram.GetSampleSum() != 0) {
				t.Fatal("duration/sample bounds changed")
			}
		}
	}
	if LoginLandingOutcome(255).String() != "unknown" {
		t.Fatal("arbitrary label escaped")
	}
}
