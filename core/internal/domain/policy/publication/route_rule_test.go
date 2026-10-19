package publication

import (
	"errors"
	"net/netip"
	"testing"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/devicetag"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/site"
)

func testRouteRule(t *testing.T, siteID site.ID, prefixes ...string) RouteRule {
	t.Helper()
	ruleID, _ := publicid.New()
	group, _ := publicid.New()
	parsed := make([]netip.Prefix, len(prefixes))
	for index, text := range prefixes {
		parsed[index] = netip.MustParsePrefix(text)
	}
	rule, err := NewRouteRule(RouteRuleParams{
		RuleID: policy.RuleID(ruleID), SourceGroupID: devicegroup.ID(group), SiteID: siteID,
		Prefixes: parsed, Protocol: policy.ProtocolTCP,
		DestinationPortRanges: []policy.PortRange{mustPortRange(t, 443, 443)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return rule
}

func mustPortRange(t *testing.T, first, last uint16) policy.PortRange {
	t.Helper()
	portRange, err := policy.NewPortRange(first, last)
	if err != nil {
		t.Fatal(err)
	}
	return portRange
}

func newSiteID(t *testing.T) site.ID {
	t.Helper()
	id, _ := publicid.New()
	return site.ID(id)
}

func TestNewRouteRuleCanonicalizes(t *testing.T) {
	t.Parallel()
	rule := testRouteRule(t, newSiteID(t), "2001:db8::/32", "10.20.0.0/16", "10.20.0.0/16")
	if got := rule.Prefixes(); len(got) != 2 || got[0].String() != "10.20.0.0/16" || got[1].String() != "2001:db8::/32" {
		t.Fatalf("prefixes = %v", got)
	}
	ruleID, _ := publicid.New()
	for name, params := range map[string]RouteRuleParams{
		"no source": {RuleID: policy.RuleID(ruleID), SiteID: newSiteID(t),
			Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, Protocol: policy.ProtocolICMP},
		"no prefixes": {RuleID: policy.RuleID(ruleID), SourceGroupID: devicegroup.ID(ruleID), SiteID: newSiteID(t),
			Protocol: policy.ProtocolICMP},
		"nested prefixes": {RuleID: policy.RuleID(ruleID), SourceGroupID: devicegroup.ID(ruleID), SiteID: newSiteID(t),
			Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("10.1.0.0/16")},
			Protocol: policy.ProtocolICMP},
		"host bits": {RuleID: policy.RuleID(ruleID), SourceGroupID: devicegroup.ID(ruleID), SiteID: newSiteID(t),
			Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/8")}, Protocol: policy.ProtocolICMP},
		"no Site": {RuleID: policy.RuleID(ruleID), SourceGroupID: devicegroup.ID(ruleID),
			Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, Protocol: policy.ProtocolICMP},
		"IPv4-mapped IPv6": {RuleID: policy.RuleID(ruleID), SourceGroupID: devicegroup.ID(ruleID), SiteID: newSiteID(t),
			Prefixes: []netip.Prefix{netip.MustParsePrefix("::ffff:10.0.0.0/104")}, Protocol: policy.ProtocolICMP},
		"two sources": {RuleID: policy.RuleID(ruleID), SourceGroupID: devicegroup.ID(ruleID),
			SourceTagID: devicetag.ID(ruleID), SiteID: newSiteID(t),
			Prefixes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, Protocol: policy.ProtocolICMP},
	} {
		if _, err := NewRouteRule(params); !errors.Is(err, ErrInvalidRouteRule) {
			t.Errorf("%s: error = %v", name, err)
		}
	}
}

func TestCheckRouteOverlap(t *testing.T) {
	t.Parallel()
	hq, lab := newSiteID(t), newSiteID(t)
	for _, test := range []struct {
		name    string
		rules   []RouteRule
		overlap bool
	}{
		{"same Site twice", []RouteRule{testRouteRule(t, hq, "10.20.0.0/16"), testRouteRule(t, hq, "10.20.5.0/24")}, false},
		{"disjoint Sites", []RouteRule{testRouteRule(t, hq, "10.20.0.0/16"), testRouteRule(t, lab, "10.21.0.0/16")}, false},
		{"equal prefixes", []RouteRule{testRouteRule(t, hq, "10.20.0.0/16"), testRouteRule(t, lab, "10.20.0.0/16")}, true},
		{"nested across Sites", []RouteRule{testRouteRule(t, hq, "10.0.0.0/8"), testRouteRule(t, lab, "10.20.5.0/24")}, true},
		{"nested under a sibling", []RouteRule{
			testRouteRule(t, hq, "10.0.0.0/8"), testRouteRule(t, hq, "10.20.0.0/16"), testRouteRule(t, lab, "10.30.0.0/16"),
		}, true},
		{"IPv6 disjoint", []RouteRule{testRouteRule(t, hq, "2001:db8:1::/48"), testRouteRule(t, lab, "2001:db8:2::/48")}, false},
		{"IPv6 nested", []RouteRule{testRouteRule(t, hq, "2001:db8::/32"), testRouteRule(t, lab, "2001:db8:2::/48")}, true},
		{"IPv4 and IPv6", []RouteRule{
			testRouteRule(t, hq, "10.0.0.0/8", "2001:db8:1::/48"), testRouteRule(t, lab, "2001:db8:2::/48", "11.0.0.0/8"),
		}, false},
		{"three Sites in a chain", []RouteRule{
			testRouteRule(t, hq, "10.0.0.0/8"), testRouteRule(t, hq, "10.20.0.0/16"),
			testRouteRule(t, lab, "10.30.0.0/16"), testRouteRule(t, newSiteID(t), "10.40.0.0/16"),
		}, true},
	} {
		if err := CheckRouteOverlap(test.rules); errors.Is(err, ErrRouteOverlap) != test.overlap {
			t.Errorf("%s: error = %v, overlap %v", test.name, err, test.overlap)
		}
	}
}

func BenchmarkCheckRouteOverlap(b *testing.B) {
	rules := make([]RouteRule, 0, 1000)
	t := &testing.T{}
	for index := range 1000 {
		siteID := newSiteID(t)
		rules = append(rules, testRouteRule(t, siteID,
			netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(index >> 8), byte(index), 0}), 24).String()))
	}
	b.ResetTimer()
	for b.Loop() {
		if err := CheckRouteOverlap(rules); err != nil {
			b.Fatal(err)
		}
	}
}

// TestCheckRouteOverlapBoundsGrantedPrefixes refuses more granted prefixes
// than a release may hold before sorting them.
func TestCheckRouteOverlapBoundsGrantedPrefixes(t *testing.T) {
	t.Parallel()
	hq := newSiteID(t)
	rules := make([]RouteRule, 0, 17)
	for block := range 17 {
		prefixes := make([]string, 0, site.MaximumPrefixesPerSite)
		for index := range site.MaximumPrefixesPerSite {
			prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom4(
				[4]byte{10, byte(block), byte(index / 4), byte(index % 4 * 64)}), 26).String())
		}
		rules = append(rules, testRouteRule(t, hq, prefixes...))
	}
	if got := GrantedRoutePrefixes(rules); got != 17*site.MaximumPrefixesPerSite {
		t.Fatalf("granted = %d", got)
	}
	if err := CheckRouteOverlap(rules); !errors.Is(err, ErrRoutePrefixLimit) {
		t.Fatalf("17408 granted prefixes: %v", err)
	}
	if err := CheckRouteOverlap(rules[:16]); err != nil {
		t.Fatalf("16384 granted prefixes: %v", err)
	}
}
