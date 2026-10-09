package httpapi

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestLoginHTTPTelemetryHasOnlyClosedLabels(t *testing.T) {
	t.Parallel()
	telemetry := NewLoginHTTPTelemetry()
	registry := prometheus.NewPedanticRegistry()
	if err := registry.Register(telemetry); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for range 10 {
		workers.Go(func() {
			for _, outcome := range []LoginHTTPOutcome{LoginHTTPPrepared, LoginHTTPStarted, LoginHTTPInvalid, LoginHTTPLimited, LoginHTTPUnavailable, 200, 201} {
				telemetry.ObserveLoginHTTP(outcome, time.Millisecond)
			}
		})
	}
	workers.Wait()
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(families) != 2 {
		t.Fatal("unexpected metric families")
	}
	for _, family := range families {
		if len(family.GetMetric()) != 6 {
			t.Fatal("unsupported numeric outcomes created unbounded labels")
		}
		for _, metric := range family.GetMetric() {
			if len(metric.GetLabel()) != 1 || metric.GetLabel()[0].GetName() != "result" {
				t.Fatal("browser identity or secret label included")
			}
			if strings.HasSuffix(family.GetName(), "_total") && metric.GetLabel()[0].GetValue() == "unknown" && metric.GetCounter().GetValue() != 20 {
				t.Fatal("unknown outcomes did not coalesce")
			}
		}
	}
}
