package publication_test

import (
	"errors"
	"net/netip"
	"testing"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/site"
)

func routeRuleFixture(t *testing.T, ruleSuffix string, source devicegroup.ID, siteSuffix string,
	prefix string) publication.RouteRule {
	t.Helper()
	ruleID, err := policy.ParseRuleID("01890f00-0000-7000-8000-" + ruleSuffix)
	if err != nil {
		t.Fatal(err)
	}
	siteID, err := site.ParseID("01890f00-0000-7000-8000-" + siteSuffix)
	if err != nil {
		t.Fatal(err)
	}
	https, _ := policy.NewPortRange(443, 443)
	rule, err := publication.NewRouteRule(publication.RouteRuleParams{
		RuleID: ruleID, SourceGroupID: source, SiteID: siteID,
		Prefixes: []netip.Prefix{netip.MustParsePrefix(prefix)}, Protocol: policy.ProtocolTCP,
		DestinationPortRanges: []policy.PortRange{https},
	})
	if err != nil {
		t.Fatal(err)
	}
	return rule
}

func TestCandidateCarriesRouteRules(t *testing.T) {
	t.Parallel()
	clients, servers := mustGroupID(t, "000000000a01"), mustGroupID(t, "000000000a02")
	direct := publicationRuleFixture(t, "000000000801", "000000000701", "000000000702", 443)
	base := publicationCandidateFixture(t, 2, []policy.Rule{direct})
	withGroups, err := base.WithGroupRules([]publication.GroupRule{groupRuleFixture(t, "000000000901", clients, servers, 22)})
	if err != nil {
		t.Fatal(err)
	}
	hq := routeRuleFixture(t, "000000000b01", clients, "000000000c01", "10.20.0.0/16")
	routed, err := withGroups.WithRouteRules([]publication.RouteRule{hq})
	if err != nil || routed.ProjectionCount() != 3 || len(routed.RouteRules()) != 1 {
		t.Fatalf("WithRouteRules() = %+v, %v", routed, err)
	}
	if routed.SemanticHash() == withGroups.SemanticHash() {
		t.Fatal("a route rule must change the semantic hash")
	}
	narrower, err := withGroups.WithRouteRules([]publication.RouteRule{
		routeRuleFixture(t, "000000000b01", clients, "000000000c01", "10.20.5.0/24")})
	if err != nil || narrower.SemanticHash() == routed.SemanticHash() {
		t.Fatal("other granted prefixes must change the semantic hash")
	}
	if _, err := routed.WithRouteRules(nil); !errors.Is(err, publication.ErrInvalidCandidate) {
		t.Fatal("route rules may be attached once")
	}
	if _, err := withGroups.WithRouteRules([]publication.RouteRule{
		routeRuleFixture(t, "000000000901", clients, "000000000c01", "10.20.0.0/16")}); !errors.Is(err, publication.ErrInvalidCandidate) {
		t.Fatal("a route rule may not reuse a group rule's identity")
	}
	lab := routeRuleFixture(t, "000000000b02", servers, "000000000c02", "10.20.9.0/24")
	if _, err := withGroups.WithRouteRules([]publication.RouteRule{hq, lab}); !errors.Is(err, publication.ErrRouteOverlap) {
		t.Fatalf("overlapping Sites: %v", err)
	}
	fingerprints, err := publication.FingerprintRules(routed)
	if err != nil || fingerprints.Len() != 3 {
		t.Fatalf("FingerprintRules() = %d, %v", fingerprints.Len(), err)
	}
	narrowerFingerprints, err := publication.FingerprintRules(narrower)
	if err != nil || string(narrowerFingerprints.MarshalBinary()) == string(fingerprints.MarshalBinary()) {
		t.Fatal("other granted prefixes must change the rule fingerprint")
	}
	again, err := withGroups.WithRouteRules([]publication.RouteRule{
		routeRuleFixture(t, "000000000b01", clients, "000000000c01", "10.20.0.0/16")})
	if err != nil || again.SemanticHash() != routed.SemanticHash() {
		t.Fatal("the same route rules must hash the same")
	}
	for name, other := range map[string]publication.RouteRule{
		"Site":   routeRuleFixture(t, "000000000b01", clients, "000000000c02", "10.20.0.0/16"),
		"source": routeRuleFixture(t, "000000000b01", servers, "000000000c01", "10.20.0.0/16"),
		"rule":   routeRuleFixture(t, "000000000b03", clients, "000000000c01", "10.20.0.0/16"),
	} {
		changed, err := withGroups.WithRouteRules([]publication.RouteRule{other})
		if err != nil || changed.SemanticHash() == routed.SemanticHash() {
			t.Errorf("another %s must change the semantic hash", name)
		}
	}
	// Without group rules the same route rule hashes apart: section tags
	// keep the encodings distinct.
	alone, err := base.WithRouteRules([]publication.RouteRule{hq})
	if err != nil || alone.SemanticHash() == routed.SemanticHash() {
		t.Fatal("dropping the group rule must change the semantic hash")
	}
}
