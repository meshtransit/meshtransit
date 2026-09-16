package oidc

import (
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/prometheus/client_golang/prometheus"
)

func TestSubjectTelemetryBoundsLabelsAndBalancesOwnership(t *testing.T) {
	t.Parallel()
	telemetry := NewSubjectTelemetry()
	registry := prometheus.NewPedanticRegistry()
	if err := registry.Register(telemetry); err != nil {
		t.Fatal(err)
	}
	for _, outcome := range []oidcauth.SubjectResolutionOutcome{oidcauth.SubjectResolutionResolved, oidcauth.SubjectResolutionRejected, oidcauth.SubjectResolutionUnavailable, oidcauth.SubjectResolutionLimited, 200, 201} {
		telemetry.SubjectResolutionOpened()
		telemetry.SubjectResolutionClosed(outcome, time.Millisecond)
	}
	families, err := registry.Gather()
	if err != nil || len(families) != 3 {
		t.Fatal("invalid metric families")
	}
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			if strings.HasSuffix(family.GetName(), "_active") {
				if metric.GetGauge().GetValue() != 0 {
					t.Fatal("ownership did not drain")
				}
				continue
			}
			if len(metric.GetLabel()) != 1 || metric.GetLabel()[0].GetName() != "result" {
				t.Fatal("identity label escaped")
			}
			label := metric.GetLabel()[0].GetValue()
			if label != "resolved" && label != "rejected" && label != "unavailable" && label != "limited" && label != "unknown" {
				t.Fatal("unbounded outcome")
			}
			if strings.HasSuffix(family.GetName(), "_total") && label == "unknown" && metric.GetCounter().GetValue() != 2 {
				t.Fatal("unknown outcomes did not coalesce")
			}
		}
	}
}
