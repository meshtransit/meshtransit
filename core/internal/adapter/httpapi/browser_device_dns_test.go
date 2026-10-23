package httpapi

import (
	"net/netip"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/node/distribution"
	"meshtransit.net/shared/policydigest"
)

func TestDeviceDNSItem(t *testing.T) {
	t.Parallel()
	if item := newDeviceDNSItem(distribution.Device{Observation: distribution.Observation{Known: true}}); item != nil {
		t.Fatalf("a Device without DNS evidence = %+v", item)
	}
	at := time.Date(2026, time.October, 23, 12, 0, 0, 0, time.UTC)
	sent := distribution.DNSSummary{Digest: policydigest.Digest{1}, Routes: 3}
	device := distribution.Device{
		DNSEnforcement: distribution.DNSEnforcement(distribution.EnforcementEnforced),
		DNSHealth: []distribution.ResolverHealth{
			{Resolver: netip.MustParseAddrPort("100.64.0.21:5335"), State: distribution.ResolverOK, LastOK: at},
			{Resolver: netip.MustParseAddrPort("192.0.2.53:53"), State: distribution.ResolverIdle},
		},
		DNSHealthAt: at.Add(time.Minute),
		Observation: distribution.Observation{Known: true, DNS: sent, EnforcedDNS: sent},
	}
	item := newDeviceDNSItem(device)
	if item == nil || item.Enforcement != "enforced" || len(item.Resolvers) != 2 ||
		item.Resolvers[0].Address != "100.64.0.21" || item.Resolvers[0].Port != 5335 || item.Resolvers[0].LastOK == nil ||
		item.Resolvers[1].LastOK != nil || item.HealthReportedAt == nil || *item.DeliveredDigest != *item.EnforcedDigest {
		t.Fatalf("item = %+v", item)
	}
	// Health that went stale is none, with no time.
	device.DNSHealth, device.DNSHealthAt = nil, time.Time{}
	if item := newDeviceDNSItem(device); len(item.Resolvers) != 0 || item.HealthReportedAt != nil {
		t.Fatalf("stale health = %+v", item)
	}
}
