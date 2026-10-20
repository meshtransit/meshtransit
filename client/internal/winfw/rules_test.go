package winfw

import (
	"net/netip"
	"testing"
)

func TestRulesPermitOnlyTheExceptionsBeforeBlocking(t *testing.T) {
	rules := Rules(Config{Adapter: 42})
	if len(rules) > maximumRules {
		t.Fatalf("%d rules exceed %d", len(rules), maximumRules)
	}
	last := rules[len(rules)-2:]
	for _, rule := range last {
		if !rule.Block || rule.Weight != weightBlock || rule.Service || rule.Adapter != 0 || len(rule.Remote) != 0 {
			t.Fatalf("last rules must block everything: %+v", rule)
		}
	}
	if last[0].IPv6 == last[1].IPv6 {
		t.Fatal("blocking must cover both families")
	}
	var service, adapter, loopback int
	for _, rule := range rules[:len(rules)-2] {
		if rule.Block {
			t.Fatalf("only the last rules block: %+v", rule)
		}
		if rule.Weight <= weightBlock {
			t.Fatalf("a permit must outweigh the block: %+v", rule)
		}
		switch {
		case rule.Service:
			service++
		case rule.Adapter == 42:
			adapter++
		case rule.Loopback:
			loopback++
		}
	}
	if service != 2 || adapter != 2 || loopback != 2 {
		t.Fatalf("service %d adapter %d loopback %d rules, want 2 each", service, adapter, loopback)
	}
}

func TestRulesWithoutAdapterKeepTheHostClosed(t *testing.T) {
	for _, rule := range Rules(Config{}) {
		if rule.Adapter != 0 {
			t.Fatalf("no adapter rule without an adapter: %+v", rule)
		}
		if !rule.Block && !rule.Service && !rule.Loopback && rule.Protocol == 0 && len(rule.Remote) == 0 {
			t.Fatalf("a permit matches everything: %+v", rule)
		}
	}
}

func TestRulesAdmitTheLANByFamilyBounded(t *testing.T) {
	lan := []netip.Prefix{
		netip.MustParsePrefix("192.168.1.7/24"), netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("fd00:1::/64"),
		{},
	}
	for range 100 {
		lan = append(lan, netip.MustParsePrefix("10.1.0.0/16"))
	}
	var v4, v6 []netip.Prefix
	for _, rule := range Rules(Config{LAN: lan}) {
		if len(rule.Remote) == 0 {
			continue
		}
		if rule.IPv6 {
			v6 = rule.Remote
		} else {
			v4 = rule.Remote
		}
	}
	want4 := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("10.1.0.0/16")}
	if len(v4) != len(want4) || v4[0] != want4[0] || v4[1] != want4[1] {
		t.Fatalf("IPv4 LAN = %v, want %v", v4, want4)
	}
	if len(v6) != 1 || v6[0] != netip.MustParsePrefix("fd00:1::/64") {
		t.Fatalf("IPv6 LAN = %v", v6)
	}
	many := make([]netip.Prefix, 0, 200)
	for index := range 200 {
		many = append(many, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(index), 0, 0}), 16))
	}
	four, six := splitFamilies(many)
	if len(four)+len(six) != maximumLAN {
		t.Fatalf("kept %d LAN prefixes, want %d", len(four)+len(six), maximumLAN)
	}
}
