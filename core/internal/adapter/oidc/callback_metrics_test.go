package oidc

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/identity/oidcauth"
	"github.com/prometheus/client_golang/prometheus"
)

func TestCallbackTelemetryBalancesConcurrentWorkAndBoundsLabels(t *testing.T) {
	t.Parallel()
	telemetry := NewCallbackTelemetry()
	registry := prometheus.NewPedanticRegistry()
	if err := registry.Register(telemetry); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for _, outcome := range []oidcauth.CallbackOutcome{
		oidcauth.CallbackIssued, oidcauth.CallbackFailed, oidcauth.CallbackRejected, oidcauth.CallbackLimited,
		oidcauth.CallbackUnavailable, oidcauth.CallbackCommitUnknown, oidcauth.CallbackCleanupFailed, 200, 201,
	} {
		workers.Go(func() {
			telemetry.CallbackOpened()
			telemetry.CallbackClosed(outcome, -time.Millisecond)
		})
	}
	workers.Wait()
	families, err := registry.Gather()
	if err != nil || len(families) != 3 {
		t.Fatal("invalid callback application metric families")
	}
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			if strings.HasSuffix(family.GetName(), "_active") {
				if metric.GetGauge().GetValue() != 0 || len(metric.GetLabel()) != 0 {
					t.Fatal("callback observation did not drain or exposed input")
				}
				continue
			}
			if len(metric.GetLabel()) != 1 || metric.GetLabel()[0].GetName() != "result" {
				t.Fatal("request/identity data escaped into labels")
			}
			label := metric.GetLabel()[0].GetValue()
			switch label {
			case "issued", "failed", "rejected", "limited", "unavailable", "commit_unknown", "cleanup_failed", "unknown":
			default:
				t.Fatal("unbounded callback result label")
			}
			if strings.HasSuffix(family.GetName(), "_total") && label == "unknown" && metric.GetCounter().GetValue() != 2 {
				t.Fatal("unknown outcomes did not fold into one closed value")
			}
			if metric.GetHistogram() != nil && metric.GetHistogram().GetSampleSum() != 0 {
				t.Fatal("negative duration entered histogram")
			}
		}
	}
}
