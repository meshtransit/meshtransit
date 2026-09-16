package oidc

import (
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/prometheus/client_golang/prometheus"
)

func TestStartTelemetryBoundsLabelsAndBalancesOwnership(t *testing.T) {
	t.Parallel()
	telemetry := NewStartTelemetry()
	registry := prometheus.NewPedanticRegistry()
	if err := registry.Register(telemetry); err != nil {
		t.Fatal(err)
	}
	for _, outcome := range []oidcauth.StartOutcome{oidcauth.StartOutcomeCommitted, oidcauth.StartOutcomeUncertain, 200, 201} {
		telemetry.StartOpened()
		telemetry.StartClosed(outcome, time.Millisecond)
	}
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(families) != 3 {
		t.Fatalf("metric families = %d, want 3", len(families))
	}
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			if strings.HasSuffix(family.GetName(), "_active") {
				if metric.GetGauge().GetValue() != 0 {
					t.Fatal("active start ownership did not drain")
				}
				continue
			}
			if len(metric.GetLabel()) != 1 || metric.GetLabel()[0].GetName() != "result" {
				t.Fatal("telemetry included a non-outcome label")
			}
			label := metric.GetLabel()[0].GetValue()
			if label != "committed" && label != "uncertain" && label != "unknown" {
				t.Fatalf("unbounded result label = %q", label)
			}
			if strings.HasSuffix(family.GetName(), "_total") && label == "unknown" && metric.GetCounter().GetValue() != 2 {
				t.Fatal("unsupported numeric outcomes did not coalesce")
			}
		}
	}
}
