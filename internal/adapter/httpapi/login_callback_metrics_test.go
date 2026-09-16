package httpapi

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestLoginCallbackTelemetryEmitsOnlyClosedSyntaxCategories(t *testing.T) {
	t.Parallel()
	telemetry := NewLoginCallbackTelemetry()
	registry := prometheus.NewPedanticRegistry()
	if err := registry.Register(telemetry); err != nil {
		t.Fatal(err)
	}
	for _, outcome := range []LoginCallbackOutcome{
		LoginCallbackCodeReceived, LoginCallbackProviderErrorReceived, LoginCallbackInvalid,
		LoginCallbackUnavailable, LoginCallbackOutcome(200), LoginCallbackOutcome(201),
	} {
		telemetry.ObserveLoginCallback(outcome, -time.Second)
	}
	families, err := registry.Gather()
	if err != nil || len(families) != 2 {
		t.Fatal("callback metric families invalid", err)
	}
	want := map[string]uint64{
		"code_received": 1, "provider_error_received": 1, "invalid": 1, "unavailable": 1, "unknown": 2,
	}
	for _, family := range families {
		if len(family.GetMetric()) != len(want) {
			t.Fatal("callback metric gained an unbounded label")
		}
		for _, metric := range family.GetMetric() {
			labels := metric.GetLabel()
			if len(labels) != 1 || labels[0].GetName() != "result" {
				t.Fatal("callback identity/request data entered labels")
			}
			count, known := want[labels[0].GetValue()]
			if !known {
				t.Fatal("callback label outside fixed category set")
			}
			switch family.GetName() {
			case "meshtransit_browser_callback_inputs_total":
				if metric.GetCounter().GetValue() != float64(count) {
					t.Fatal("callback syntax count changed")
				}
			case "meshtransit_browser_callback_input_duration_seconds":
				if metric.GetHistogram().GetSampleCount() != count || metric.GetHistogram().GetSampleSum() != 0 {
					t.Fatal("callback duration/count invalid")
				}
			default:
				t.Fatal("unexpected callback metric name")
			}
		}
	}
}
