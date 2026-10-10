package netadmin

import (
	"net/netip"
	"slices"
	"testing"
)

func TestSafeOverlayFrame(t *testing.T) {
	t.Parallel()

	want := []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("fd00::/8"),
	}
	got := SafeOverlayFrame()
	if !slices.Equal(got, want) {
		t.Fatalf("SafeOverlayFrame() = %v, want %v", got, want)
	}
	got[0] = netip.MustParsePrefix("10.0.0.0/8")
	if SafeOverlayFrame()[0] != want[0] {
		t.Fatal("SafeOverlayFrame() returned shared storage")
	}
}

func TestWithinSafeOverlayFrame(t *testing.T) {
	t.Parallel()

	tests := []struct {
		prefix string
		want   bool
	}{
		{prefix: "100.64.0.0/10", want: true},
		{prefix: "100.100.1.0/24", want: true},
		{prefix: "198.18.0.0/15", want: true},
		{prefix: "198.19.0.0/16", want: true},
		{prefix: "fd00::/8", want: true},
		{prefix: "fd07:d4de:9d87::/48", want: true},
		{prefix: "fd02:48de:ec1b:1::/96", want: true},
		{prefix: "100.0.0.0/8", want: false},
		{prefix: "198.16.0.0/14", want: false},
		{prefix: "198.20.0.0/16", want: false},
		{prefix: "10.0.0.0/8", want: false},
		{prefix: "192.168.1.0/24", want: false},
		{prefix: "fc00::/7", want: false},
		{prefix: "fc00::/8", want: false},
		{prefix: "2001:db8::/32", want: false},
		{prefix: "::/0", want: false},
		{prefix: "0.0.0.0/0", want: false},
	}
	for _, test := range tests {
		t.Run(test.prefix, func(t *testing.T) {
			t.Parallel()

			if got := withinSafeOverlayFrame(netip.MustParsePrefix(test.prefix)); got != test.want {
				t.Fatalf("withinSafeOverlayFrame(%s) = %t, want %t", test.prefix, got, test.want)
			}
		})
	}
}
