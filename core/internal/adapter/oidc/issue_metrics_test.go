package oidc

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"meshtransit.net/core/internal/domain/identity/oidcauth"
)

func TestIssueTelemetryBoundsLabelsAndBalancesConcurrentOwnership(t *testing.T) {
	t.Parallel()
	telemetry := NewIssueTelemetry()
	registry := prometheus.NewPedanticRegistry()
	if err := registry.Register(telemetry); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for _, outcome := range []oidcauth.IssueOutcome{
		oidcauth.IssueConfirmed, oidcauth.IssueRejected, oidcauth.IssueUnavailable,
		oidcauth.IssueLimited, oidcauth.IssueCommitUnknown, oidcauth.IssueCleanupFailed, 200, 201,
	} {
		workers.Go(func() {
			telemetry.IssueOpened()
			telemetry.IssueClosed(outcome, time.Millisecond)
		})
	}
	workers.Wait()
	families, err := registry.Gather()
	if err != nil || len(families) != 3 {
		t.Fatal("invalid issuance metric families")
	}
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			if strings.HasSuffix(family.GetName(), "_active") {
				if metric.GetGauge().GetValue() != 0 {
					t.Fatal("owned work did not drain")
				}
				continue
			}
			if len(metric.GetLabel()) != 1 || metric.GetLabel()[0].GetName() != "result" {
				t.Fatal("request data escaped into labels")
			}
			label := metric.GetLabel()[0].GetValue()
			switch label {
			case "confirmed", "rejected", "unavailable", "limited", "commit_unknown", "cleanup_failed", "unknown":
			default:
				t.Fatal("unbounded issuance result label")
			}
			if strings.HasSuffix(family.GetName(), "_total") && label == "unknown" &&
				metric.GetCounter().GetValue() != 2 {
				t.Fatal("unknown numeric outcomes did not coalesce")
			}
		}
	}
}
