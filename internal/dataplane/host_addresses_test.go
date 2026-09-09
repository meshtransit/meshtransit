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
