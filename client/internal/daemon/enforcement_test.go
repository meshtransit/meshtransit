package daemon

import (
	"testing"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/shared/policydigest"
)

func TestPublishEnforcementKeepsOnlyTheLatestReport(t *testing.T) {
	reports := make(chan controlplane.EnforcementReport, 1)
	first := dataplane.EnforcedPolicy{Digest: policydigest.Digest{1}, Grants: 1, AppliedAt: time.Unix(1, 0)}
	second := dataplane.EnforcedPolicy{Digest: policydigest.Digest{2}, Grants: 2, AppliedAt: time.Unix(2, 0)}
	publishEnforcement(reports, first)
	publishEnforcement(reports, second)
	report := <-reports
	if report.Digest != second.Digest || report.Grants != 2 || !report.AppliedAt.Equal(second.AppliedAt) {
		t.Fatalf("report = %+v, want the second", report)
	}
	select {
	case extra := <-reports:
		t.Fatalf("an older report stayed queued: %+v", extra)
	default:
	}
}
