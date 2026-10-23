package distribution

import (
	"testing"
	"time"

	"meshtransit.net/shared/policydigest"
)

func TestClassifyDNSEnforcement(t *testing.T) {
	t.Parallel()
	delivered := time.Date(2026, time.October, 23, 12, 0, 0, 0, time.UTC)
	sent := DNSSummary{Digest: policydigest.Digest{1}, Routes: 3}
	other := DNSSummary{Digest: policydigest.Digest{2}, Routes: 3}
	base := Observation{Known: true, DNS: sent, DeliveredAt: delivered}
	later := delivered.Add(2 * EnforcementGrace)
	for name, test := range map[string]struct {
		change func(*Observation)
		now    time.Time
		want   DNSEnforcement
	}{
		"no evidence":  {func(o *Observation) { o.DNS = DNSSummary{} }, later, ""},
		"unknown":      {func(o *Observation) { o.Known = false }, later, ""},
		"enforced":     {func(o *Observation) { o.EnforcedDNS = sent }, later, DNSEnforcement(EnforcementEnforced)},
		"applying":     {func(o *Observation) { o.EnforcedDNS = other }, delivered, DNSEnforcement(EnforcementApplying)},
		"mismatch":     {func(o *Observation) { o.EnforcedDNS = other }, later, DNSEnforcement(EnforcementMismatch)},
		"not reported": {func(*Observation) {}, later, DNSEnforcement(EnforcementNotReported)},
		"user off":     {func(o *Observation) { o.DNSReason = DNSReasonUserOff }, delivered, DNSEnforcementUserOff},
		"apply failed": {func(o *Observation) { o.DNSReason = DNSReasonApplyFailed }, later, DNSEnforcementApplyFailed},
		"core sent no digest": {func(o *Observation) { o.DNS, o.EnforcedDNS = DNSSummary{}, other }, later,
			DNSEnforcement(EnforcementUnknown)},
	} {
		observation := base
		test.change(&observation)
		if got := ClassifyDNSEnforcement(observation, test.now); got != test.want {
			t.Errorf("%s: %q, want %q", name, got, test.want)
		}
	}
}

func TestCurrentDNSHealth(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, time.October, 23, 12, 0, 0, 0, time.UTC)
	observation := Observation{Known: true, DNSHealthAt: at, DNSHealth: []ResolverHealth{{State: ResolverOK}}}
	if health, current := CurrentDNSHealth(observation, at.Add(DNSHealthStale)); !current || len(health) != 1 {
		t.Fatalf("within the window = %v, %t", health, current)
	}
	if _, current := CurrentDNSHealth(observation, at.Add(DNSHealthStale+time.Second)); current {
		t.Fatal("stale health is current")
	}
	observation.DNSHealth = nil
	if health, current := CurrentDNSHealth(observation, at); !current || health == nil || len(health) != 0 {
		t.Fatalf("a report of no resolver = %v, %t", health, current)
	}
}
