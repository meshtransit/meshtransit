package endpointpolicy

import (
	"net/netip"
	"testing"
)

func TestUsable(t *testing.T) {
	t.Parallel()
	for address, usable := range map[string]bool{
		"198.51.100.7":        true,
		"8.8.8.8":             true,
		"192.168.1.20":        true, // LAN
		"10.1.2.3":            true,
		"fd12:3456::7":        true, // LAN ULA
		"2001:db8::1":         true,
		"2606:4700::1111":     true,
		"64:ff9b::808:808":    true, // NAT64 to 8.8.8.8
		"100.63.255.255":      true,
		"100.128.0.1":         true,
		"100.64.0.1":          false, // overlay
		"100.127.255.254":     false,
		"0.1.2.3":             false,
		"240.0.0.1":           false,
		"255.255.255.255":     false,
		"127.0.0.1":           false,
		"169.254.1.1":         false,
		"224.0.0.1":           false,
		"::":                  false,
		"::1":                 false,
		"fe80::1":             false,
		"ff02::1":             false,
		"::192.0.2.1":         false, // IPv4-compatible
		"::ffff:0:c000:201":   false, // SIIT
		"::ffff:198.51.100.7": false, // IPv4-mapped is not canonical
		"100::1":              false,
		"2001:0:4136:e378::1": false, // Teredo
		"2002:c000:20a::1":    false, // 6to4
		"64:ff9b::6440:1":     false, // NAT64 to the overlay 100.64.0.1
		"64:ff9b::7f00:1":     false, // NAT64 to loopback
		"64:ff9b::c0a8:114":   false, // NAT64 to a private address
		"64:ff9b::f000:1":     false, // NAT64 to 240.0.0.1
		"fe80::1%en0":         false,
	} {
		if got := Usable(netip.MustParseAddr(address)); got != usable {
			t.Errorf("Usable(%s) = %t, want %t", address, got, usable)
		}
	}
	if Usable(netip.Addr{}) {
		t.Error("the zero address is usable")
	}
}

func TestMatchesTheTranslatedAddress(t *testing.T) {
	t.Parallel()
	relay := netip.MustParseAddr("203.0.113.10")
	isRelay := func(address netip.Addr) bool { return address == relay }
	for address, want := range map[string]bool{
		"203.0.113.10":        true,
		"64:ff9b::cb00:710a":  true, // the relay through NAT64
		"203.0.113.11":        false,
		"2001:db8::cb00:710a": false,
	} {
		if got := Matches(netip.MustParseAddr(address), isRelay); got != want {
			t.Errorf("Matches(%s) = %t, want %t", address, got, want)
		}
	}
	if embedded, ok := EmbeddedIPv4(netip.MustParseAddr("64:ff9b::cb00:710a")); !ok || embedded != relay {
		t.Fatalf("EmbeddedIPv4() = %v, %t", embedded, ok)
	}
}
