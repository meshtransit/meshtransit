package winfw

import (
	"net/netip"
	"slices"
	"testing"
)

func TestRulesPermitOnlyTheExceptionsBeforeBlocking(t *testing.T) {
	all := Rules(Config{Adapter: 42, LAN: []netip.Prefix{
		netip.MustParsePrefix("192.168.1.0/24"), netip.MustParsePrefix("fd00:1::/64"),
	}})
	if len(all) > maximumRules {
		t.Fatalf("%d rules exceed %d", len(all), maximumRules)
	}
	var rules []Rule
	for _, rule := range all {
		if !rule.Forward {
			rules = append(rules, rule)
		}
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

// What the host forwards for others leaves only into the adapter, or the
// LAN when allowed; everything else forwarded is blocked in both families.
func TestRulesForwardOnlyIntoTheAdapterOrTheLAN(t *testing.T) {
	lan := []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}
	var permits, blocks []Rule
	for _, rule := range Rules(Config{Adapter: 42, LAN: lan}) {
		switch {
		case !rule.Forward:
		case rule.Block:
			blocks = append(blocks, rule)
		default:
			permits = append(permits, rule)
		}
	}
	if len(blocks) != 2 || blocks[0].IPv6 == blocks[1].IPv6 || blocks[0].Adapter != 0 || len(blocks[0].Remote) != 0 {
		t.Fatalf("forwarding blocks %+v", blocks)
	}
	if len(permits) != 7 {
		t.Fatalf("forwarding permits %+v, want into and from the adapter, both families, and the IPv4 LAN", permits)
	}
	from := 0
	for _, rule := range permits {
		if rule.Weight <= weightBlock || (rule.Adapter != 42 && rule.Arrival != 42 && rule.ArrivalLocal != 42 &&
			len(rule.Remote) == 0) || rule.Service || rule.Loopback || rule.Protocol != 0 {
			t.Fatalf("forwarding permit %+v", rule)
		}
		if rule.Arrival == 42 || rule.ArrivalLocal == 42 {
			from++
		}
	}
	// The answers to what the host forwarded into the tunnel come back.
	if from != 4 {
		t.Fatalf("%d permits for what comes back from the adapter, want 4", from)
	}
	for _, rule := range Rules(Config{}) {
		if rule.Forward && !rule.Block {
			t.Fatalf("forwarding permitted without an adapter or LAN: %+v", rule)
		}
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

// Azure's WireServer is reachable only on its own ports: off Azure it is a
// public address no other traffic may reach outside the tunnel.
func TestRulesOpenTheWireServerOnItsPortsOnly(t *testing.T) {
	ports := 0
	for _, rule := range Rules(Config{}) {
		if !slices.Contains(rule.Remote, azureWireServer) {
			continue
		}
		if rule.RemotePort == 0 || rule.Protocol == 0 || len(rule.Remote) != 1 || rule.Forward {
			t.Fatalf("WireServer rule %+v opens more than a port", rule)
		}
		ports++
	}
	if ports != len(azureWireServerPorts) {
		t.Fatalf("%d WireServer rules, want %d", ports, len(azureWireServerPorts))
	}
}
