package overlayframe

import (
	"net/netip"
	"testing"
)

func TestContains(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		prefix string
		inside bool
	}{
		{"100.64.0.1/32", true},
		{"100.64.0.0/10", true},
		{"100.0.0.0/8", false},
		{"198.18.0.4/32", true},
		{"198.20.0.0/32", false},
		{"fd07:d4de:9d87::2/128", true},
		{"fc00::1/128", false},
		{"192.168.1.20/32", false},
		{"0.0.0.0/0", false},
		{"::/0", false},
		{"::ffff:100.64.0.1/128", false},
	} {
		if got := Contains(netip.MustParsePrefix(test.prefix)); got != test.inside {
			t.Errorf("Contains(%s) = %v, want %v", test.prefix, got, test.inside)
		}
	}
	if Contains(netip.Prefix{}) {
		t.Error("Contains(zero prefix) = true")
	}
	copied := Prefixes()
	copied[0] = netip.MustParsePrefix("0.0.0.0/0")
	if Contains(netip.MustParsePrefix("10.0.0.0/8")) {
		t.Error("Prefixes() exposed the frame")
	}
}

func TestSelfTestAddressesAreTheFrameNetworkAddresses(t *testing.T) {
	t.Parallel()
	for _, address := range []netip.Addr{SelfTestIPv4, SelfTestIPv6} {
		if !IsSelfTest(address) || !Contains(netip.PrefixFrom(address, address.BitLen())) {
			t.Errorf("%s is not a self-test address inside the frame", address)
		}
	}
	if Prefixes()[0].Addr() != SelfTestIPv4 || Prefixes()[2].Addr() != SelfTestIPv6 {
		t.Error("the self-test addresses are not the first addresses of the frame")
	}
	if IsSelfTest(netip.MustParseAddr("100.64.0.1")) {
		t.Error("a Device address counts as a self-test address")
	}
}
