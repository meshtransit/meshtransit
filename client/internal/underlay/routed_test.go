package underlay

import (
	"net/netip"
	"testing"
)

// Not parallel: the recorded routes are process-wide.
func TestRouted(t *testing.T) {
	t.Cleanup(func() { SetRouted(nil) })
	if Routed(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("Routed() before any route = true")
	}
	SetRouted([]netip.Prefix{
		netip.MustParsePrefix("10.1.0.0/16"),
		netip.MustParsePrefix("192.168.7.9/32"),
		netip.MustParsePrefix("fd12:3456::/32"),
		netip.MustParsePrefix("10.200.0.1/8"), // not canonical: masked
	})
	for _, test := range []struct {
		address string
		want    bool
	}{
		{"10.1.2.3", true},
		{"10.2.0.1", true}, // 10.0.0.0/8
		{"11.0.0.1", false},
		{"192.168.7.9", true},
		{"192.168.7.10", false},
		{"::ffff:10.1.0.1", true},
		{"fd12:3456::1", true},
		{"fd12:3457::1", false},
		{"2001:db8::1", false},
	} {
		if got := Routed(netip.MustParseAddr(test.address)); got != test.want {
			t.Errorf("Routed(%s) = %t, want %t", test.address, got, test.want)
		}
	}
	if Routed(netip.Addr{}) {
		t.Error("Routed(invalid) = true")
	}
	SetRouted(nil)
	if Routed(netip.MustParseAddr("10.1.2.3")) {
		t.Error("Routed() after clearing = true")
	}
}
