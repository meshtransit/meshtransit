package oidc

import (
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"meshtransit.net/core/internal/domain/identity/authexpiry"
	"meshtransit.net/core/internal/domain/identity/oidcauth"
)

func TestExpiryTelemetryHasOnlyClosedLabelsAndBoundedCounts(t *testing.T) {
	t.Parallel()
	telemetry := NewExpiryTelemetry()
	registry := prometheus.NewPedanticRegistry()
	if err := registry.Register(telemetry); err != nil {
		t.Fatal(err)
	}
	telemetry.WorkerRunning(true)
	for _, outcome := range []authexpiry.Outcome{
		authexpiry.Empty, authexpiry.Confirmed, authexpiry.Unavailable, authexpiry.Deadline,
		authexpiry.CommitUnknown, authexpiry.CleanupFailed, authexpiry.Canceled, authexpiry.Invalid, 200, 201,
	} {
		telemetry.PassOpened()
		telemetry.PassClosed(authexpiry.Observation{
			Outcome: outcome, Pass: oidcauth.ExpiryPass{Attempted: 1, Confirmed: 1}, Elapsed: time.Millisecond,
		})
	}
	telemetry.PassOpened()
	telemetry.PassClosed(authexpiry.Observation{
		Outcome: authexpiry.Confirmed, Pass: oidcauth.ExpiryPass{Attempted: -1, Confirmed: 1},
		Elapsed: -time.Second, BatchLimitReached: true,
	})
	telemetry.WorkerRunning(false)
	families, err := registry.Gather()
	if err != nil || len(families) != 8 {
		t.Fatal("invalid expiry metric families", err)
	}
	for _, family := range families {
		for _, metric := range family.GetMetric() {
			labels := metric.GetLabel()
			if len(labels) == 0 {
				switch {
				case strings.HasSuffix(family.GetName(), "_active"), strings.HasSuffix(family.GetName(), "_running"):
					if metric.GetGauge().GetValue() != 0 {
						t.Fatal("ownership metrics did not drain")
					}
				case strings.HasSuffix(family.GetName(), "_units_attempted_total"),
					strings.HasSuffix(family.GetName(), "_units_confirmed_total"):
					if metric.GetCounter().GetValue() != 10 {
						t.Fatal("invalid counts were exported")
					}
				case strings.HasSuffix(family.GetName(), "_batch_limit_reached_total"):
					if metric.GetCounter().GetValue() != 0 {
						t.Fatal("invalid saturation observation")
					}
				case strings.HasSuffix(family.GetName(), "_last_success_timestamp_seconds"):
					if metric.GetGauge().GetValue() <= 0 {
						t.Fatal("successful pass not observed")
					}
				default:
					t.Fatal("unknown no-label metric")
				}
				continue
			}
			if len(labels) != 1 || labels[0].GetName() != "result" {
				t.Fatal("data label escaped")
			}
			label := labels[0].GetValue()
			switch label {
			case "empty", "confirmed", "unavailable", "deadline", "commit_unknown", "cleanup_failed",
				"canceled", "invalid", "unknown":
			default:
				t.Fatal("unbounded expiry outcome")
			}
			if strings.HasSuffix(family.GetName(), "_passes_total") && label == "unknown" &&
				metric.GetCounter().GetValue() != 2 {
				t.Fatal("unknown categories did not coalesce")
			}
		}
	}
}
