package internet

import (
	"net/netip"
	"slices"
	"testing"
)

func TestContains(t *testing.T) {
	t.Parallel()
	for address, internet := range map[string]bool{
		"8.8.8.8":         true,
		"1.1.1.1":         true,
		"198.51.99.255":   true, // just below TEST-NET-2
		"203.0.112.255":   true,
		"172.15.255.255":  true,
		"172.32.0.0":      true,
		"100.63.255.255":  true,
		"100.128.0.0":     true,
		"223.255.255.255": true,
		"168.63.129.15":   true,
		"2606:4700::1111": true,
		"2001:4860::8888": true,
		"2001:db9::1":     true,
		"3fff:1000::1":    true, // just past 3fff::/20

		"0.0.0.0":         false,
		"10.1.2.3":        false,
		"100.64.0.1":      false, // overlay and CGNAT
		"127.0.0.1":       false,
		"169.254.169.254": false, // cloud metadata
		"172.16.0.1":      false,
		"192.0.0.9":       false,
		"192.0.2.1":       false,
		"192.31.196.1":    false,
		"192.52.193.1":    false,
		"192.88.99.1":     false,
		"192.168.1.1":     false,
		"198.18.0.1":      false, // alias range
		"198.51.100.7":    false,
		"203.0.113.9":     false,
		"224.0.0.251":     false,
		"240.0.0.1":       false,
		"255.255.255.255": false,
		"168.63.129.16":   false, // Azure wire server

		"::":                   false,
		"::1":                  false,
		"::ffff:8.8.8.8":       false, // IPv4-mapped
		"::ffff:10.0.0.1":      false,
		"64:ff9b::a00:1":       false, // NAT64 of 10.0.0.1
		"64:ff9b:1::1":         false,
		"100::1":               false,
		"fd00:ec2::254":        false, // AWS metadata
		"fd7a:115c:a1e0::1":    false,
		"fe80::1":              false,
		"ff02::1":              false,
		"2001:db8::1":          false,
		"3fff::1":              false,
		"2002:a00:1::1":        false, // 6to4 of 10.0.0.1
		"2001:0:4136:e378::1":  false, // Teredo
		"2001:2::1":            false,
		"2001:10::1":           false,
		"2001:20::1":           false,
		"4000::1":              false, // outside 2000::/3
		"fe80::1%eth0":         false,
		"2606:4700::1111%eth0": false,
	} {
		if got := Contains(netip.MustParseAddr(address)); got != internet {
			t.Errorf("Contains(%s) = %v, want %v", address, got, internet)
		}
	}
	if Contains(netip.Addr{}) {
		t.Error("the zero address is on the Internet")
	}
}

func TestExcludedIsCanonicalAndCopied(t *testing.T) {
	t.Parallel()
	excluded := Excluded()
	if len(excluded) == 0 {
		t.Fatal("no excluded prefixes")
	}
	for _, prefix := range excluded {
		if !prefix.IsValid() || prefix != prefix.Masked() {
			t.Errorf("excluded prefix %s is not canonical", prefix)
		}
		if Contains(prefix.Addr()) {
			t.Errorf("first address of excluded prefix %s is on the Internet", prefix)
		}
	}
	excluded[0] = netip.MustParsePrefix("8.8.8.0/24")
	if !Contains(netip.MustParseAddr("8.8.8.8")) {
		t.Error("changing the returned slice changed the set")
	}
}

func TestOnlyInternetPrefixes(t *testing.T) {
	t.Parallel()
	for prefix, internet := range map[string]bool{
		"8.8.8.0/24":      true,
		"2606:4700::/32":  true,
		"0.0.0.0/0":       false,
		"10.0.0.0/8":      false,
		"8.0.0.0/7":       true,
		"192.0.0.0/16":    false, // contains 192.0.2.0/24
		"2000::/3":        false, // contains 2001:db8::/32
		"168.63.129.0/24": false,
		"8.8.8.8/32":      true,
	} {
		if got := OnlyInternet(netip.MustParsePrefix(prefix)); got != internet {
			t.Errorf("OnlyInternet(%s) = %v, want %v", prefix, got, internet)
		}
	}
}

func TestNotInternetCoversExactlyWhatContainsRefuses(t *testing.T) {
	t.Parallel()
	ranges := NotInternet()
	for _, text := range []string{
		"8.8.8.8", "1.1.1.1", "2606:4700::1111", "2a00:1450::1", "10.0.0.1",
		"169.254.169.254", "100.64.0.1", "fd00::1", "fe80::1", "::1", "64:ff9b::808:808", "ff02::1",
		"2001:db8::1", "2002::1", "3fff::1", "4000::1", "8000::1", "224.0.0.1", "255.255.255.255",
	} {
		address := netip.MustParseAddr(text)
		covered := slices.ContainsFunc(ranges, func(prefix netip.Prefix) bool { return prefix.Contains(address) })
		if covered == Contains(address) {
			t.Errorf("%s: NotInternet covers it %t, Contains %t", text, covered, Contains(address))
		}
	}
}
