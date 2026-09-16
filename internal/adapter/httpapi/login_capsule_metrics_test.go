package httpapi

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func TestLoginCapsuleTelemetryEmitsOnlyClosedTransportLabels(t *testing.T) {
	t.Parallel()
	telemetry := NewLoginCapsuleTelemetry()
	registry := prometheus.NewPedanticRegistry()
	if err := registry.Register(telemetry); err != nil {
		t.Fatal(err)
	}
	want := make(map[string]uint64)
	for _, operation := range []LoginCapsuleOperation{LoginCapsuleCapture, LoginCapsuleOpen} {
		for _, result := range []LoginCapsuleOutcome{LoginCapsuleAccepted, LoginCapsuleInvalid, LoginCapsuleUnavailable} {
			telemetry.ObserveLoginCapsule(operation, result, -time.Second)
			want[operation.String()+"/"+result.String()] = 1
		}
	}
	telemetry.ObserveLoginCapsule(LoginCapsuleOperation(200), LoginCapsuleOutcome(200), -time.Second)
	telemetry.ObserveLoginCapsule(LoginCapsuleOperation(201), LoginCapsuleOutcome(201), -time.Second)
	want["unknown/unknown"] = 2
	families, err := registry.Gather()
	if err != nil || len(families) != 2 {
		t.Fatal("capsule metric families invalid", err)
	}
	for _, family := range families {
		if len(family.GetMetric()) != len(want) {
			t.Fatal("capsule metric gained unbounded labels")
		}
		for _, metric := range family.GetMetric() {
			labels := metric.GetLabel()
			if len(labels) != 2 || labels[0].GetName() != "operation" || labels[1].GetName() != "result" {
				t.Fatal("capsule secret/request data entered labels")
			}
			count, known := want[labels[0].GetValue()+"/"+labels[1].GetValue()]
			if !known {
				t.Fatal("capsule label outside closed sets")
			}
			switch family.GetName() {
			case "meshtransit_browser_callback_capsule_operations_total":
				if metric.GetCounter().GetValue() != float64(count) {
					t.Fatal("capsule count changed")
				}
			case "meshtransit_browser_callback_capsule_duration_seconds":
				if metric.GetHistogram().GetSampleCount() != count || metric.GetHistogram().GetSampleSum() != 0 {
					t.Fatal("capsule count/duration invalid")
				}
			default:
				t.Fatal("unexpected capsule metric")
			}
		}
	}
}
