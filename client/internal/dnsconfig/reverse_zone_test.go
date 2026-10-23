package dnsconfig

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// A reverse zone forwards the reverse names of its range; a mesh address's
// reverse name is still answered here (DNS design D5c).
func TestReverseZoneForwardsItsRange(t *testing.T) {
	t.Parallel()
	resolver := startCountingUpstream(t, dnsmessage.RCodeNameError, netip.Addr{}, false)
	plan := Plan{Enabled: true, Routes: []Route{{Suffix: "10.in-addr.arpa", Resolvers: []netip.AddrPort{resolver.address}}}}
	engine := zoneEngine(t)
	if message := resolveName(t, engine, plan, "5.0.35.10.in-addr.arpa.", dnsmessage.TypePTR); message.RCode !=
		dnsmessage.RCodeNameError || resolver.asked.Load() != 1 {
		t.Fatalf("in range: %v, asked %d", message.RCode, resolver.asked.Load())
	}
	if message := resolveName(t, engine, plan, "1.0.168.192.in-addr.arpa.", dnsmessage.TypePTR); resolver.asked.Load() != 1 {
		t.Fatalf("out of range went to the zone: %v", message.RCode)
	}
}
