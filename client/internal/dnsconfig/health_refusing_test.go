package dnsconfig

import (
	"net/netip"
	"testing"
	"time"

	"meshtransit.net/client/internal/controlplane"
)

// A resolver that filters names answers REFUSED for those it blocks: it is
// refusing only once it gave no good answer for refusingQuiet (TD-CLI-70).
func TestResolverHealthRefusingNeedsAQuietPeriod(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)
	engine := newResolverEngine()
	engine.health = newResolverHealthTracker(func() time.Time { return now })
	filter := netip.MustParseAddrPort("9.9.9.9:53")
	plan := Plan{Enabled: true, Routes: []Route{{Suffix: "corp.example", Resolvers: []netip.AddrPort{filter}}}}
	state := func() controlplane.ResolverState {
		t.Helper()
		health := engine.resolverHealth(plan, maximumReportedResolvers)
		if len(health) != 1 {
			t.Fatalf("health = %+v", health)
		}
		return health[0].State
	}
	engine.health.answered(filter, false)
	now = now.Add(time.Minute)
	engine.health.answered(filter, true)
	if got := state(); got != controlplane.ResolverOK {
		t.Fatalf("a filter that answered a minute ago is %v", got)
	}
	now = now.Add(refusingQuiet)
	engine.health.answered(filter, true)
	if got := state(); got != controlplane.ResolverRefusing {
		t.Fatalf("a resolver that only refused for %s is %v", refusingQuiet, got)
	}
}
