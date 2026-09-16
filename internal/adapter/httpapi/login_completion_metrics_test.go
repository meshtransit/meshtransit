package httpapi

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestLoginCompletionTelemetryClosedPrivateMetadata(t *testing.T) {
	t.Parallel()
	telemetry := NewLoginCompletionTelemetry()
	registry := prometheus.NewRegistry()
	if err := registry.Register(telemetry); err != nil {
		t.Fatal(err)
	}
	var joined sync.WaitGroup
	for _, outcome := range []LoginCompletionOutcome{LoginCompletionIssued, LoginCompletionNoGrant,
		LoginCompletionInvalid, LoginCompletionLimited, LoginCompletionSaturated, LoginCompletionUnavailable,
		LoginCompletionCommitUnknown, LoginCompletionDeliveryFailed, 255} {
		joined.Go(func() {
			telemetry.CompletionOpened()
			telemetry.CompletionClosed(outcome, -time.Second)
		})
	}
	joined.Wait()
	families, err := registry.Gather()
	if err != nil || len(families) != 3 {
		t.Fatal("isolated completion collectors unavailable", err)
	}
	for _, family := range families {
		if !strings.HasPrefix(family.GetName(), "meshtransit_browser_completion_") {
			t.Fatal("unexpected metric")
		}
		for _, metric := range family.Metric {
			if metric.Gauge != nil {
				if len(metric.Label) != 0 || metric.Gauge.GetValue() != 0 {
					t.Fatal("ownership leaked")
				}
				continue
			}
			if len(metric.Label) != 1 || metric.Label[0].GetName() != "result" {
				t.Fatal("unbounded metadata dimension")
			}
			if metric.Histogram != nil && metric.Histogram.GetSampleSum() != 0 {
				t.Fatal("negative duration not bounded")
			}
		}
		if strings.Contains(fmt.Sprint(family), "example.test") {
			t.Fatal("route entered metrics")
		}
	}
	if LoginCompletionOutcome(255).String() != "unknown" {
		t.Fatal("arbitrary metric value escaped closed label set")
	}
}
