package windns

import (
	"errors"
	"net/netip"
	"slices"
	"testing"

	"meshtransit.net/client/internal/dnsconfig"
)

func TestRuleFromPlanCollectsRouteAndSearchDomains(t *testing.T) {
	t.Parallel()
	plan := dnsconfig.Plan{
		Enabled: true,
		Routes: []dnsconfig.Route{
			{Suffix: "shared.mesh"},
			{Suffix: "corp.example", Resolvers: []netip.AddrPort{netip.MustParseAddrPort("10.0.0.53:53")}},
		},
		SearchDomains: []string{"shared.mesh"},
	}

	rule, err := RuleFromPlan(plan, ResolverAddress.Addr())
	if err != nil {
		t.Fatalf("RuleFromPlan() error = %v", err)
	}
	want := []string{".corp.example", ".shared.mesh"}
	if !slices.Equal(rule.Namespaces, want) || rule.Server != ResolverAddress.Addr() {
		t.Fatalf("RuleFromPlan() = %+v, want namespaces %v on %s", rule, want, ResolverAddress.Addr())
	}
}

func TestRuleFromPlanRefusesAllNames(t *testing.T) {
	t.Parallel()
	plan := dnsconfig.Plan{
		Enabled:          true,
		DefaultResolvers: []netip.AddrPort{netip.MustParseAddrPort("1.1.1.1:53")},
		Routes:           []dnsconfig.Route{{Suffix: "shared.mesh"}},
	}
	if _, err := RuleFromPlan(plan, ResolverAddress.Addr()); !errors.Is(err, ErrAllNames) {
		t.Fatalf("RuleFromPlan() error = %v, want ErrAllNames", err)
	}
}

func TestRuleFromPlanRejectsUnsafeDomains(t *testing.T) {
	t.Parallel()
	for _, domain := range []string{"", ".", "a..b", "Upper.mesh", "bad_label.mesh", "-a.mesh", "a\x00b", "a;b.mesh"} {
		plan := dnsconfig.Plan{Enabled: true, Routes: []dnsconfig.Route{{Suffix: domain}}}
		if _, err := RuleFromPlan(plan, ResolverAddress.Addr()); err == nil {
			t.Errorf("RuleFromPlan(%q) error = nil", domain)
		}
	}
	if _, err := RuleFromPlan(dnsconfig.Plan{Enabled: true}, ResolverAddress.Addr()); err == nil {
		t.Error("RuleFromPlan() without domains error = nil")
	}
	plan := dnsconfig.Plan{Enabled: true, Routes: []dnsconfig.Route{{Suffix: "shared.mesh"}}}
	if _, err := RuleFromPlan(plan, netip.MustParseAddr("::1")); err == nil {
		t.Error("RuleFromPlan() with an IPv6 server error = nil")
	}
}

func TestRuleEqual(t *testing.T) {
	t.Parallel()
	left := Rule{Namespaces: []string{".shared.mesh"}, Server: ResolverAddress.Addr()}
	right := Rule{Namespaces: []string{".shared.mesh"}, Server: ResolverAddress.Addr()}
	if !left.Equal(right) {
		t.Fatal("equal rules differ")
	}
	right.Namespaces = []string{".other.mesh"}
	if left.Equal(right) {
		t.Fatal("different rules are equal")
	}
}
