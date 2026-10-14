package networkmap

import (
	"net/netip"
	"slices"
	"testing"
)

func TestUsableEndpoint(t *testing.T) {
	t.Parallel()
	for address, usable := range map[string]bool{
		"198.51.100.7:41641":        true,
		"192.168.1.20:41641":        true, // LAN
		"10.1.2.3:41641":            true,
		"[fd12:3456::7]:41641":      true, // LAN ULA
		"[64:ff9b::c000:201]:41641": true, // NAT64
		"[2001:db8::1]:41641":       true,
		"100.64.0.1:41641":          false, // overlay
		"100.127.0.1:41641":         false,
		"0.1.2.3:41641":             false,
		"240.0.0.1:41641":           false,
		"255.255.255.255:41641":     false,
		"127.0.0.1:41641":           false,
		"169.254.1.1:41641":         false,
		"[fe80::1]:41641":           false,
		"[::192.0.2.1]:41641":       false,
		"[100::1]:41641":            false,
		"[::ffff:198.51.100.7]:1":   false,
		"198.51.100.7:0":            false,
	} {
		if got := UsableEndpoint(netip.MustParseAddrPort(address)); got != usable {
			t.Errorf("UsableEndpoint(%s) = %t, want %t", address, got, usable)
		}
	}
}

func TestWithUsableEndpointsKeepsTheRestOfTheMap(t *testing.T) {
	t.Parallel()
	endpoints := func(values ...string) []netip.AddrPort {
		out := make([]netip.AddrPort, len(values))
		for index, value := range values {
			out[index] = netip.MustParseAddrPort(value)
		}
		return out
	}
	snapshot := Snapshot{
		Self: Node{
			ID: 1, Addresses: []netip.Prefix{netip.MustParsePrefix("fd7a::1/128")},
			Endpoints: endpoints("198.51.100.1:41641", "[fd7a::1]:41641"),
		},
		Peers: []Node{{
			ID: 2, Addresses: []netip.Prefix{netip.MustParsePrefix("fd7a::2/128")},
			AllowedIPs: []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			Endpoints: endpoints("100.64.0.9:41641", "[fd7a::1]:41641", "[fd7a::2]:9", "192.168.1.20:41641",
				"203.0.113.5:41641", "203.0.113.5:41641"),
		}},
	}
	original := slices.Clone(snapshot.Peers[0].Endpoints)
	filtered := WithUsableEndpoints(snapshot)
	// A LAN endpoint inside a route the peer advertises is still a LAN path.
	if want := endpoints("192.168.1.20:41641", "203.0.113.5:41641"); !slices.Equal(filtered.Peers[0].Endpoints, want) {
		t.Fatalf("peer endpoints = %v, want %v", filtered.Peers[0].Endpoints, want)
	}
	if want := endpoints("198.51.100.1:41641"); !slices.Equal(filtered.Self.Endpoints, want) {
		t.Fatalf("self endpoints = %v, want %v", filtered.Self.Endpoints, want)
	}
	if !slices.Equal(snapshot.Peers[0].Endpoints, original) {
		t.Fatal("WithUsableEndpoints modified its input")
	}
}

func TestEndpointFilterRefusesRelaysAndOverlayThroughNAT64(t *testing.T) {
	t.Parallel()
	filter := NewEndpointFilter(Snapshot{
		Self:   Node{Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}},
		Peers:  []Node{{Addresses: []netip.Prefix{netip.MustParsePrefix("fd7a::2/128")}}},
		Relays: map[int]RelayRegion{1: {ID: 1, Nodes: []RelayNode{{IPv4: "198.51.100.200", IPv6: "2001:db8::200"}}}},
	})
	for address, allowed := range map[string]bool{
		"198.51.100.200:3478":        false,
		"[2001:db8::200]:3478":       false,
		"[64:ff9b::c633:64c8]:3478":  false, // the relay through NAT64
		"[fd7a::2]:41641":            false,
		"198.51.100.201:41641":       true,
		"[64:ff9b::c633:64c9]:41641": true,
	} {
		if got := filter.Allows(netip.MustParseAddrPort(address)); got != allowed {
			t.Errorf("Allows(%s) = %t, want %t", address, got, allowed)
		}
	}
	// The zero filter still applies the static policy.
	if (EndpointFilter{}).Allows(netip.MustParseAddrPort("100.64.0.9:41641")) {
		t.Fatal("the zero filter allows an overlay range address")
	}
}
