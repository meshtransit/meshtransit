package httpapi

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestBrowserCaptureTelemetryClosedJoinedMetadata(t *testing.T) {
	t.Parallel()
	telemetry := NewBrowserCaptureTelemetry()
	registry := prometheus.NewPedanticRegistry()
	if err := registry.Register(telemetry); err != nil {
		t.Fatal(err)
	}
	errorsToObserve := []error{nil, ErrInvalidBrowserLogin, ErrBrowserCaptureLimited, ErrBrowserCaptureSaturated,
		ErrBrowserCaptureUnavailable, errors.New("private-query-token-cookie")}
	var workers sync.WaitGroup
	for _, err := range errorsToObserve {
		workers.Go(func() { telemetry.opened(); telemetry.closed(err, -time.Second) })
	}
	workers.Wait()
	families, err := registry.Gather()
	if err != nil || len(families) != 3 {
		t.Fatal("invalid isolated capture metric families", err)
	}
	for _, family := range families {
		for _, metric := range family.Metric {
			if family.GetType().String() == "GAUGE" {
				if metric.Gauge.GetValue() != 0 || len(metric.Label) != 0 {
					t.Fatal("active capture lifetime not joined")
				}
				continue
			}
			if len(metric.Label) != 1 || metric.Label[0].GetName() != "result" {
				t.Fatal("unbounded capture labels")
			}
			result := metric.Label[0].GetValue()
			switch result {
			case "submitted", "invalid", "limited", "saturated", "unavailable":
			default:
				t.Fatal("raw capture error became label")
			}
			count := float64(1)
			if result == "unavailable" {
				count = 2
			}
			if metric.Counter != nil && metric.Counter.GetValue() != count {
				t.Fatal("closed capture count incorrect")
			}
			if metric.Histogram != nil &&
				(metric.Histogram.GetSampleCount() != uint64(count) || metric.Histogram.GetSampleSum() != 0) {
				t.Fatal("duration/outcome mismatch or negative duration")
			}
		}
	}
}
