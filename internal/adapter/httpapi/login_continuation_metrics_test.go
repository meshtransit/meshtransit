package httpapi

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestLoginContinuationTelemetryEmitsOnlyClosedAdmissionLabels(t *testing.T) {
	t.Parallel()
	telemetry := NewLoginContinuationTelemetry()
	registry := prometheus.NewPedanticRegistry()
	if err := registry.Register(telemetry); err != nil {
		t.Fatal(err)
	}
	want := make(map[string]uint64)
	for _, operation := range []LoginContinuationOperation{LoginContinuationPrepare, LoginContinuationRead} {
		for _, result := range []LoginContinuationOutcome{LoginContinuationPrepared, LoginContinuationInputReleased,
			LoginContinuationInvalid, LoginContinuationLimited, LoginContinuationSaturated, LoginContinuationUnavailable} {
			telemetry.ObserveLoginContinuation(operation, result, -time.Second)
			want[operation.String()+"/"+result.String()] = 1
		}
	}
	telemetry.ObserveLoginContinuation(LoginContinuationOperation(200), LoginContinuationOutcome(200), -time.Second)
	telemetry.ObserveLoginContinuation(LoginContinuationOperation(201), LoginContinuationOutcome(201), -time.Second)
	want["unknown/unknown"] = 2
	families, err := registry.Gather()
	if err != nil || len(families) != 2 {
		t.Fatal("continuation metric families invalid", err)
	}
	for _, family := range families {
		if len(family.GetMetric()) != len(want) {
			t.Fatal("continuation metrics gained unbounded labels")
		}
		for _, metric := range family.GetMetric() {
			labels := metric.GetLabel()
			if len(labels) != 2 || labels[0].GetName() != "operation" || labels[1].GetName() != "result" {
				t.Fatal("input-derived metric labels")
			}
			count, known := want[labels[0].GetValue()+"/"+labels[1].GetValue()]
			if !known {
				t.Fatal("label outside closed set")
			}
			switch family.GetName() {
			case "meshtransit_browser_continuation_requests_total":
				if metric.GetCounter().GetValue() != float64(count) {
					t.Fatal("continuation counter changed")
				}
			case "meshtransit_browser_continuation_duration_seconds":
				if metric.GetHistogram().GetSampleCount() != count || metric.GetHistogram().GetSampleSum() != 0 {
					t.Fatal("continuation duration invalid")
				}
			default:
				t.Fatal("unexpected metric family")
			}
		}
	}
}
