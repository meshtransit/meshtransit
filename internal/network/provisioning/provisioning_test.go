package provisioning_test

import (
	"net/netip"
	"testing"

	"github.com/meshtransit/meshtransit/internal/network/provisioning"
)

func TestValidPrefixes(t *testing.T) {
	t.Parallel()
	v6 := netip.MustParsePrefix("fd42:42:42:1::/64")
	for _, test := range []struct {
		ipv4, ipv6 string
		valid      bool
	}{
		{"100.64.1.0/24", "fd42:42:42:1::/64", true},
		{"100.127.255.240/28", "fd42:42:42:1::/64", true},
		{"100.64.0.0/16", "fd42:42:42::/56", true},
		{"100.128.0.0/24", "fd42:42:42:1::/64", false}, // outside 100.64.0.0/10
		{"10.0.0.0/24", "fd42:42:42:1::/64", false},
		{"100.64.0.0/10", "fd42:42:42:1::/64", false}, // larger than /16
		{"100.64.1.0/29", "fd42:42:42:1::/64", false},
		{"100.64.1.1/24", "fd42:42:42:1::/64", false}, // host bits
		{"100.64.1.0/24", "fd42:42:42::/48", false},
		{"100.64.1.0/24", "::ffff:100.64.1.0/120", false},
	} {
		ipv4 := netip.MustParsePrefix(test.ipv4)
		ipv6 := netip.MustParsePrefix(test.ipv6)
		if provisioning.ValidPrefixes(ipv4, ipv6) != test.valid {
			t.Errorf("%s %s: want %v", test.ipv4, test.ipv6, test.valid)
		}
	}
	if provisioning.ValidPrefixes(netip.Prefix{}, v6) {
		t.Fatal("zero prefix accepted")
	}
}
