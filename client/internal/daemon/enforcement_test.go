package daemon

import (
	"sync"
	"testing"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/shared/dnsdigest"
	"meshtransit.net/shared/policydigest"
)

func TestPublishEnforcementKeepsOnlyTheLatestReport(t *testing.T) {
	reports := make(chan controlplane.EnforcementReport, 1)
	first := dataplane.EnforcedPolicy{Digest: policydigest.Digest{1}, Grants: 1, AppliedAt: time.Unix(1, 0)}
	second := dataplane.EnforcedPolicy{Digest: policydigest.Digest{2}, Grants: 2, AppliedAt: time.Unix(2, 0)}
	publishEnforcement(reports, first, dnsEvidence{})
	publishEnforcement(reports, second, dnsEvidence{})
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

type fixedEnforcement struct{ policy dataplane.EnforcedPolicy }

func (f fixedEnforcement) EnforcedPolicy() (dataplane.EnforcedPolicy, bool) { return f.policy, true }

// Whoever publishes last, under any interleaving, leaves the newest DNS
// evidence queued: each publish reads it under the publisher's lock.
func TestEnforcementPublisherQueuesTheNewestEvidence(t *testing.T) {
	t.Parallel()
	service := &Service{}
	reports := make(chan controlplane.EnforcementReport, 1)
	publisher := &enforcementPublisher{
		reports: reports, enforced: fixedEnforcement{dataplane.EnforcedPolicy{Digest: policydigest.Digest{1}}},
		dns: service.currentDNSEvidence,
	}
	service.setDNSRepublish(publisher.publish)
	var wg sync.WaitGroup
	for routes := range 50 {
		wg.Go(func() { publisher.publish() })
		wg.Go(func() {
			service.recordDNSEvidence(dnsEvidence{known: true, digest: dnsdigest.Digest{1}, routes: routes})
		})
	}
	wg.Wait()
	if report := <-reports; report.DNSRoutes != service.currentDNSEvidence().routes {
		t.Fatalf("queued %d routes, newest evidence %d", report.DNSRoutes, service.currentDNSEvidence().routes)
	}
}
