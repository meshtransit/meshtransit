package httpapi

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestBrowserManagementTelemetryHasOnlyClosedJoinedLabels(t *testing.T) {
	t.Parallel()
	telemetry := NewBrowserManagementTelemetry()
	registry := prometheus.NewPedanticRegistry()
	if err := registry.Register(telemetry); err != nil {
		t.Fatal(err)
	}
	var joined sync.WaitGroup
	for _, err := range []error{
		nil, ErrInvalidBrowserManagement, ErrBrowserManagementLimited, ErrBrowserManagementSaturated,
		ErrBrowserManagementUnavailable, ErrBrowserManagementDelivery, errors.New("private arbitrary dependency"),
	} {
		joined.Go(func() { telemetry.opened(); telemetry.closed("private arbitrary operation", err, -time.Second) })
	}
	joined.Wait()
	families, err := registry.Gather()
	if err != nil || len(families) != 3 {
		t.Fatal("isolated private profile telemetry failed", err)
	}
	var total float64
	for _, family := range families {
		for _, metric := range family.Metric {
			if metric.Gauge != nil {
				if metric.Gauge.GetValue() != 0 || len(metric.Label) != 0 {
					t.Fatal("request ownership leaked")
				}
				continue
			}
			invalidLabels := len(metric.Label) != 2 || metric.Label[0].GetName() != "operation" ||
				metric.Label[0].GetValue() != "unknown" || metric.Label[1].GetName() != "result"
			if invalidLabels {
				t.Fatal("unbounded telemetry labels")
			}
			switch metric.Label[1].GetValue() {
			case "submitted", "invalid", "limited", "saturated", "unavailable", "delivery_failed":
			default:
				t.Fatal("raw error escaped metric")
			}
			if metric.Counter != nil {
				total += metric.Counter.GetValue()
			}
			if metric.Histogram != nil && metric.Histogram.GetSampleSum() != 0 {
				t.Fatal("negative duration escaped")
			}
		}
	}
	if total != 7 {
		t.Fatal("joined request outcomes missing/duplicated")
	}
}
