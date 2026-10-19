package compilation_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/site"
)

type siteResolverFixture struct {
	sites []site.Site
	calls int
}

func (fixture *siteResolverFixture) ResolvePolicySites(_ context.Context, _ accountsession.Session, _ network.Scope,
	ids []site.ID) ([]site.Site, error) {
	fixture.calls++
	var found []site.Site
	for _, value := range fixture.sites {
		for _, id := range ids {
			if value.ID == id {
				found = append(found, value)
			}
		}
	}
	return found, nil
}

func siteFixture(t *testing.T, suffix string, prefixes ...string) site.Site {
	t.Helper()
	id, err := site.ParseID("01890f00-0000-7000-8000-" + suffix)
	if err != nil {
		t.Fatal(err)
	}
	value := site.Site{ID: id, Version: 1}
	for _, text := range prefixes {
		value.Prefixes = append(value.Prefixes, netip.MustParsePrefix(text))
	}
	return value
}

func siteIntent(t *testing.T, ruleSuffix string, siteID site.ID, prefixes ...string) compilation.RuleIntent {
	t.Helper()
	ruleID, _ := policy.ParseRuleID("01890f00-0000-7000-8000-" + ruleSuffix)
	group, _ := devicegroup.ParseID("01890f00-0000-7000-8000-000000000a01")
	https, _ := policy.NewPortRange(443, 443)
	params := compilation.RuleIntentParams{
		ID: ruleID, Scope: compilationScopeFixture(t), SourceGroupID: group, DestinationSiteID: siteID,
		Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{https},
	}
	for _, text := range prefixes {
		params.DestinationPrefixes = append(params.DestinationPrefixes, netip.MustParsePrefix(text))
	}
	intent, err := compilation.NewRuleIntent(params)
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

func compileSiteRules(t *testing.T, service *compilation.Service, intents ...compilation.RuleIntent) error {
	t.Helper()
	request, err := compilation.NewRequest(compilation.RequestParams{
		Scope: compilationScopeFixture(t), Revision: 2, Rules: intents,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.Compile(t.Context(), compilationSessionFixture(t), request)
	return err
}

func TestServiceCompilesSiteDestinations(t *testing.T) {
	t.Parallel()
	hq := siteFixture(t, "000000000c01", "10.20.0.0/16", "2001:db8:20::/48")
	lab := siteFixture(t, "000000000c02", "10.20.0.0/16")
	resolver := &compilationResourceResolverFixture{err: errors.New("unexpected Resource resolution")}
	base, err := compilation.NewService(resolver)
	if err != nil {
		t.Fatal(err)
	}
	if err := compileSiteRules(t, base, siteIntent(t, "000000000801", hq.ID)); !errors.Is(err, compilation.ErrSiteRoutesDisabled) {
		t.Fatalf("Site rule without routes enabled: %v", err)
	}
	sites := &siteResolverFixture{sites: []site.Site{hq, lab}}
	service, err := base.WithSites(sites)
	if err != nil {
		t.Fatal(err)
	}
	request, err := compilation.NewRequest(compilation.RequestParams{
		Scope: compilationScopeFixture(t), Revision: 2, Rules: []compilation.RuleIntent{
			siteIntent(t, "000000000801", hq.ID), siteIntent(t, "000000000802", hq.ID, "10.20.5.0/24"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := service.Compile(t.Context(), compilationSessionFixture(t), request)
	if err != nil || sites.calls != 1 || len(candidate.RouteRules()) != 2 || len(candidate.Snapshot().Rules()) != 0 {
		t.Fatalf("Compile() = %+v, %v (calls %d)", candidate, err, sites.calls)
	}
	if whole := candidate.RouteRules()[0].Prefixes(); len(whole) != 2 {
		t.Fatalf("a rule without prefixes granted %v, want the whole Site", whole)
	}
	if err := compileSiteRules(t, service, siteIntent(t, "000000000801", hq.ID, "10.21.0.0/24")); !errors.Is(err, compilation.ErrOutsideSite) {
		t.Fatalf("prefix outside the Site: %v", err)
	}
	if err := compileSiteRules(t, service, siteIntent(t, "000000000801", hq.ID),
		siteIntent(t, "000000000802", lab.ID)); !errors.Is(err, compilation.ErrRouteOverlap) {
		t.Fatalf("two Sites with the same prefixes: %v", err)
	}
	gone := siteFixture(t, "000000000c09", "10.99.0.0/16")
	if err := compileSiteRules(t, service, siteIntent(t, "000000000801", gone.ID)); !errors.Is(err, compilation.ErrResourceConflict) {
		t.Fatalf("an unknown Site: %v", err)
	}
}

// TestServiceBoundsGrantedRoutePrefixes stops compiling once rules to Sites
// grant more prefixes than a release may hold: each whole-Site rule grants
// all the Site's prefixes.
func TestServiceBoundsGrantedRoutePrefixes(t *testing.T) {
	t.Parallel()
	prefixes := make([]string, 0, site.MaximumPrefixesPerSite)
	for index := range site.MaximumPrefixesPerSite {
		prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom4(
			[4]byte{10, 20, byte(index / 4), byte(index % 4 * 64)}), 26).String())
	}
	hq := siteFixture(t, "000000000c01", prefixes...)
	base, err := compilation.NewService(&compilationResourceResolverFixture{err: errors.New("unexpected Resource resolution")})
	if err != nil {
		t.Fatal(err)
	}
	service, err := base.WithSites(&siteResolverFixture{sites: []site.Site{hq}})
	if err != nil {
		t.Fatal(err)
	}
	intents := make([]compilation.RuleIntent, 0, 17)
	for index := range 17 {
		intents = append(intents, siteIntent(t, fmt.Sprintf("%012x", 0x801+index), hq.ID))
	}
	if err := compileSiteRules(t, service, intents...); !errors.Is(err, compilation.ErrRoutePrefixLimit) {
		t.Fatalf("17 whole-Site rules of 1024 prefixes: %v", err)
	}
	if err := compileSiteRules(t, service, intents[:16]...); err != nil {
		t.Fatalf("16 whole-Site rules of 1024 prefixes: %v", err)
	}
}
