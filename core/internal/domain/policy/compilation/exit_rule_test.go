package compilation_test

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/exitpool"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/site"
)

type exitPoolResolverFixture struct {
	pools []exitpool.Pool
	err   error
	calls int
}

func (fixture *exitPoolResolverFixture) ResolvePolicyExitPools(_ context.Context, _ accountsession.Session,
	_ network.Scope, ids []exitpool.ID) ([]exitpool.Pool, error) {
	fixture.calls++
	var found []exitpool.Pool
	for _, pool := range fixture.pools {
		for _, id := range ids {
			if pool.ID == id {
				found = append(found, pool)
			}
		}
	}
	return found, fixture.err
}

func exitPoolFixture(t *testing.T, suffix string) exitpool.Pool {
	t.Helper()
	id, err := exitpool.ParseID("01890f00-0000-7000-8000-" + suffix)
	if err != nil {
		t.Fatal(err)
	}
	return exitpool.Pool{ID: id, Version: 1}
}

func exitIntent(t *testing.T, ruleSuffix string, poolID exitpool.ID) compilation.RuleIntent {
	t.Helper()
	ruleID, _ := policy.ParseRuleID("01890f00-0000-7000-8000-" + ruleSuffix)
	group, _ := devicegroup.ParseID("01890f00-0000-7000-8000-000000000a01")
	https, _ := policy.NewPortRange(443, 443)
	intent, err := compilation.NewRuleIntent(compilation.RuleIntentParams{
		ID: ruleID, Scope: compilationScopeFixture(t), SourceGroupID: group, DestinationExitPoolID: poolID,
		Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{https},
	})
	if err != nil {
		t.Fatal(err)
	}
	return intent
}

func TestRuleIntentToAnExitPoolTakesNoPrefixesOrSecondDestination(t *testing.T) {
	t.Parallel()
	pool := exitPoolFixture(t, "000000000e01")
	lan := siteFixture(t, "000000000c01", "10.20.0.0/16")
	ruleID, _ := policy.ParseRuleID("01890f00-0000-7000-8000-000000000801")
	group, _ := devicegroup.ParseID("01890f00-0000-7000-8000-000000000a01")
	https, _ := policy.NewPortRange(443, 443)
	base := compilation.RuleIntentParams{ID: ruleID, Scope: compilationScopeFixture(t), SourceGroupID: group,
		DestinationExitPoolID: pool.ID, Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{https}}
	withPrefixes := base
	withPrefixes.DestinationPrefixes = []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24")}
	withSite := base
	withSite.DestinationSiteID = lan.ID
	for name, params := range map[string]compilation.RuleIntentParams{"prefixes": withPrefixes, "Site": withSite} {
		if _, err := compilation.NewRuleIntent(params); !errors.Is(err, compilation.ErrInvalidRequest) {
			t.Errorf("an Exit Pool rule with %s: %v", name, err)
		}
	}
	intent, err := compilation.NewRuleIntent(base)
	if err != nil || intent.SelectsDeviceGroup() || intent.DestinationExitPoolID() != pool.ID {
		t.Fatalf("an Exit Pool intent = %+v, %v", intent, err)
	}
}

func TestServiceCompilesExitPoolDestinations(t *testing.T) {
	t.Parallel()
	singapore, frankfurt := exitPoolFixture(t, "000000000e01"), exitPoolFixture(t, "000000000e02")
	hq := siteFixture(t, "000000000c01", "10.20.0.0/16")
	base, err := compilation.NewService(&compilationResourceResolverFixture{err: errors.New("unexpected Resource resolution")})
	if err != nil {
		t.Fatal(err)
	}
	if err := compileSiteRules(t, base, exitIntent(t, "000000000801", singapore.ID)); !errors.Is(err,
		compilation.ErrExitPoolsDisabled) {
		t.Fatalf("an Exit Pool rule without Exit Pools: %v", err)
	}
	pools := &exitPoolResolverFixture{pools: []exitpool.Pool{singapore, frankfurt}}
	withSites, err := base.WithSites(&siteResolverFixture{sites: []site.Site{hq}})
	if err != nil {
		t.Fatal(err)
	}
	service, err := withSites.WithExitPools(pools)
	if err != nil {
		t.Fatal(err)
	}
	request, err := compilation.NewRequest(compilation.RequestParams{
		Scope: compilationScopeFixture(t), Revision: 2, Rules: []compilation.RuleIntent{
			exitIntent(t, "000000000801", singapore.ID), exitIntent(t, "000000000802", singapore.ID),
			exitIntent(t, "000000000803", frankfurt.ID), siteIntent(t, "000000000804", hq.ID),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := service.Compile(t.Context(), compilationSessionFixture(t), request)
	if err != nil || pools.calls != 1 || len(candidate.ExitRules()) != 3 || len(candidate.RouteRules()) != 1 ||
		len(candidate.Snapshot().Rules()) != 0 {
		t.Fatalf("Compile() = %+v, %v (calls %d)", candidate, err, pools.calls)
	}
	gone := exitPoolFixture(t, "000000000e09")
	if err := compileSiteRules(t, service, exitIntent(t, "000000000801", gone.ID)); !errors.Is(err,
		compilation.ErrResourceConflict) {
		t.Fatalf("an unknown Exit Pool: %v", err)
	}
	denied := &exitPoolResolverFixture{err: exitpool.ErrForbidden}
	refused, err := base.WithExitPools(denied)
	if err != nil {
		t.Fatal(err)
	}
	if err := compileSiteRules(t, refused, exitIntent(t, "000000000801", singapore.ID)); !errors.Is(err,
		compilation.ErrForbidden) {
		t.Fatalf("an Exit Pool the reader may not read: %v", err)
	}
}
