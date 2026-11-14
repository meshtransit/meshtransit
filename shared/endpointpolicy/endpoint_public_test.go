package endpointpolicy

import (
	"net/netip"
	"testing"
)

func TestPublicLeavesOutEveryLANAddress(t *testing.T) {
	t.Parallel()
	for text, want := range map[string]bool{
		"203.0.113.9": true, "2001:db8::10": true, "8.8.8.8": true,
		"192.168.1.20": false, "10.0.0.1": false, "172.16.0.1": false, "fd00::1": false,
		"100.64.0.1": false, "169.254.1.1": false, "fe80::1": false, "127.0.0.1": false,
		"64:ff9b::c0a8:114": false, // NAT64 of 192.168.1.20
	} {
		if got := Public(netip.MustParseAddr(text)); got != want {
			t.Errorf("Public(%s) = %v, want %v", text, got, want)
		}
	}
}
