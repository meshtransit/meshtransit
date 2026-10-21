package exitpool

import (
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/node/distribution"
)

func TestElectionHealthReadsTheServedPoolOnly(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.October, 20, 12, 0, 0, 0, time.UTC)
	pool := "01a15307-09d3-76b4-a028-3c21ee7080c0"
	failed := distribution.Observation{Known: true, RouteHealthAt: now.Add(-5 * time.Second),
		ExitHealth: &distribution.ExitHealth{Ref: pool, State: distribution.SiteHealthFailed, Code: "egress_failed"}}
	if report := ElectionHealth(failed, pool, now); report.State != distribution.SiteHealthFailed ||
		report.Code != "egress_failed" || !report.ReportedAt.Equal(failed.RouteHealthAt) {
		t.Fatalf("a failed pool = %+v", report)
	}
	if report := ElectionHealth(failed, "01a15307-09d3-76b4-a028-3c21ee7080c1", now); report.State != "" ||
		!report.ReportedAt.IsZero() {
		t.Fatalf("another pool's health counted: %+v", report)
	}
	// A router's Site health alone says nothing of the pool: never silent.
	sitesOnly := distribution.Observation{Known: true, RouteHealthAt: now.Add(-time.Hour)}
	if report := ElectionHealth(sitesOnly, pool, now); !report.ReportedAt.IsZero() || report.State != "" {
		t.Fatalf("Site health alone = %+v", report)
	}
	stale := failed
	stale.RouteHealthAt = now.Add(-time.Minute)
	if report := ElectionHealth(stale, pool, now); report.State != "" || report.ReportedAt.IsZero() {
		t.Fatalf("stale health = %+v, want no state but the report time for silence", report)
	}
	if report := ElectionHealth(distribution.Observation{}, pool, now); !report.ReportedAt.IsZero() ||
		report.State != "" {
		t.Fatalf("an exit node that never reported = %+v", report)
	}
}

func TestOverloaded(t *testing.T) {
	t.Parallel()
	for code, want := range map[string]bool{"conntrack_high": true, "egress_v4_failed": true,
		"egress_v6_failed": false, "dns_failed": false, "probe_unavailable": false, "ok": false} {
		if Overloaded(code) != want {
			t.Errorf("Overloaded(%q) = %v", code, !want)
		}
	}
}
