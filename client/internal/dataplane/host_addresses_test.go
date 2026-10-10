package dataplane

import (
	"net"
	"net/netip"
	"testing"
)

func TestHostAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  net.Addr
		want netip.Addr
		ok   bool
	}{
		{
			name: "ipv4 network",
			raw: &net.IPNet{
				IP:   net.ParseIP("192.0.2.10"),
				Mask: net.CIDRMask(24, 32),
			},
			want: netip.MustParseAddr("192.0.2.10"),
			ok:   true,
		},
		{
			name: "ipv6 address",
			raw:  &net.IPAddr{IP: net.ParseIP("2001:db8::10")},
			want: netip.MustParseAddr("2001:db8::10"),
			ok:   true,
		},
		{
			name: "zoned address",
			raw:  &net.IPAddr{IP: net.ParseIP("fe80::1"), Zone: "en0"},
		},
		{
			name: "unsupported address",
			raw:  &net.UnixAddr{Name: "/tmp/socket", Net: "unix"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, ok := hostAddress(test.raw)
			if ok != test.ok || got != test.want {
				t.Fatalf("hostAddress() = %v, %t, want %v, %t", got, ok, test.want, test.ok)
			}
		})
	}
}

func TestUsableHostAddressesExcludeTunnelsAndMeshOverlays(t *testing.T) {
	t.Parallel()

	ipNet := func(value string, bits int) net.Addr {
		ip := net.ParseIP(value)
		size := 128
		if ip.To4() != nil {
			size = 32
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, size)}
	}
	interfaces := []hostInterface{
		{
			name:  "eth0",
			flags: net.FlagUp | net.FlagBroadcast,
			addresses: []net.Addr{
				ipNet("203.0.113.10", 20), ipNet("10.15.0.6", 16), ipNet("2001:db8::10", 64),
			},
		},
		// Another mesh client on this host, here an Isolation Network TUN.
		{name: "meshiso0", flags: net.FlagUp | net.FlagPointToPoint, addresses: []net.Addr{
			ipNet("100.64.30.1", 32), ipNet("fd07:d4de:9d87:3::1", 128),
		}},
		// The local DNS link of a mesh client.
		{name: "meshdns0", flags: net.FlagUp | net.FlagPointToPoint, addresses: []net.Addr{
			ipNet("192.0.2.55", 32),
		}},
		// A mesh IPv4 overlay address that a non-tunnel interface still
		// carries is skipped; a ULA there is a LAN path like any other.
		{name: "bridge0", flags: net.FlagUp | net.FlagBroadcast, addresses: []net.Addr{
			ipNet("172.17.0.1", 16), ipNet("100.70.0.9", 24), ipNet("fd12:3456:789a::1", 64),
		}},
		{name: "lo", flags: net.FlagUp | net.FlagLoopback, addresses: []net.Addr{ipNet("127.0.0.1", 8)}},
		{name: "eth9", flags: net.FlagBroadcast, addresses: []net.Addr{ipNet("198.51.100.7", 24)}},
	}

	got := usableHostAddresses(interfaces)
	want := []netip.Addr{
		netip.MustParseAddr("203.0.113.10"),
		netip.MustParseAddr("10.15.0.6"),
		netip.MustParseAddr("2001:db8::10"),
		netip.MustParseAddr("172.17.0.1"),
		netip.MustParseAddr("fd12:3456:789a::1"),
	}
	if len(got) != len(want) {
		t.Fatalf("usableHostAddresses() = %v, want %v", got, want)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("usableHostAddresses() = %v, want %v", got, want)
		}
	}
}
