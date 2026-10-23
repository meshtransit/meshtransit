package dnsconfig

import (
	"errors"
	"net/netip"
	"testing"
)

// A zone's resolver that failed through one exit node is asked again at
// once through another: the relay breaker starts afresh (TD-CLI-72).
func TestRelayBreakerStartsAfreshWithAnotherExitNode(t *testing.T) {
	t.Parallel()
	engine := newResolverEngine()
	x := netip.MustParseAddrPort("9.9.9.9:53")
	planVia := func(forwarder string) Plan {
		return Plan{Exit: &ExitDNS{Resolvers: []netip.AddrPort{netip.MustParseAddrPort(forwarder)}}}
	}
	first := planVia("100.64.0.7:53")
	if via := engine.relayVia(first); via != first.Exit.Resolvers[0] {
		t.Fatalf("relayVia = %v", via)
	}
	for range breakerFailures {
		engine.relayBreaker.record(x, errors.New("no answer"))
	}
	if engine.relayBreaker.allow(x) {
		t.Fatal("the breaker did not open")
	}
	engine.relayVia(first)
	if engine.relayBreaker.allow(x) {
		t.Fatal("the same exit node reset the breaker")
	}
	engine.relayVia(planVia("100.64.0.9:53"))
	if !engine.relayBreaker.allow(x) {
		t.Fatal("another exit node still skips the resolver")
	}
}
