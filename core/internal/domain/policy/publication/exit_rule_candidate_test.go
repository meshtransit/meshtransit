package publication_test

import (
	"errors"
	"testing"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/exitpool"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
)

func exitRuleFixture(t *testing.T, ruleSuffix string, source devicegroup.ID, poolSuffix string,
	port uint16) publication.ExitRule {
	t.Helper()
	ruleID, err := policy.ParseRuleID("01890f00-0000-7000-8000-" + ruleSuffix)
	if err != nil {
		t.Fatal(err)
	}
	poolID, err := exitpool.ParseID("01890f00-0000-7000-8000-" + poolSuffix)
	if err != nil {
		t.Fatal(err)
	}
	ports, _ := policy.NewPortRange(port, port)
	rule, err := publication.NewExitRule(publication.ExitRuleParams{
		RuleID: ruleID, SourceGroupID: source, PoolID: poolID, Protocol: policy.ProtocolTCP,
		DestinationPortRanges: []policy.PortRange{ports},
	})
	if err != nil {
		t.Fatal(err)
	}
	return rule
}

func TestNewExitRuleRefusesAnIncompleteRule(t *testing.T) {
	t.Parallel()
	clients := mustGroupID(t, "000000000a01")
	ruleID, _ := policy.ParseRuleID("01890f00-0000-7000-8000-000000000d01")
	poolID, _ := exitpool.ParseID("01890f00-0000-7000-8000-000000000e01")
	https, _ := policy.NewPortRange(443, 443)
	for name, params := range map[string]publication.ExitRuleParams{
		"no pool":   {RuleID: ruleID, SourceGroupID: clients, Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{https}},
		"no source": {RuleID: ruleID, PoolID: poolID, Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{https}},
		"no rule":   {SourceGroupID: clients, PoolID: poolID, Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{https}},
		"tcp without ports": {RuleID: ruleID, SourceGroupID: clients, PoolID: poolID,
			Protocol: policy.ProtocolTCP},
		"icmp with ports": {RuleID: ruleID, SourceGroupID: clients, PoolID: poolID, Protocol: policy.ProtocolICMP,
			DestinationPortRanges: []policy.PortRange{https}},
	} {
		if _, err := publication.NewExitRule(params); !errors.Is(err, publication.ErrInvalidExitRule) {
			t.Errorf("%s: NewExitRule = %v", name, err)
		}
	}
	icmp, err := publication.NewExitRule(publication.ExitRuleParams{RuleID: ruleID, SourceGroupID: clients,
		PoolID: poolID, Protocol: policy.ProtocolICMP})
	if err != nil || icmp.PoolID() != poolID || icmp.Source().ID().String() != clients.String() {
		t.Fatalf("an ICMP rule = %+v, %v", icmp, err)
	}
}

func TestCandidateCarriesExitRules(t *testing.T) {
	t.Parallel()
	clients, servers := mustGroupID(t, "000000000a01"), mustGroupID(t, "000000000a02")
	direct := publicationRuleFixture(t, "000000000801", "000000000701", "000000000702", 443)
	base := publicationCandidateFixture(t, 2, []policy.Rule{direct})
	routed, err := base.WithRouteRules([]publication.RouteRule{
		routeRuleFixture(t, "000000000b01", clients, "000000000c01", "10.20.0.0/16")})
	if err != nil {
		t.Fatal(err)
	}
	internet := exitRuleFixture(t, "000000000d01", clients, "000000000e01", 443)
	exits, err := routed.WithExitRules([]publication.ExitRule{internet})
	if err != nil || exits.ProjectionCount() != 3 || len(exits.ExitRules()) != 1 ||
		len(exits.RouteRules()) != 1 {
		t.Fatalf("WithExitRules() = %+v, %v", exits, err)
	}
	if exits.SemanticHash() == routed.SemanticHash() {
		t.Fatal("an exit rule must change the semantic hash")
	}
	if _, err := exits.WithExitRules(nil); !errors.Is(err, publication.ErrInvalidCandidate) {
		t.Fatal("exit rules may be attached once")
	}
	if _, err := routed.WithExitRules([]publication.ExitRule{
		exitRuleFixture(t, "000000000b01", clients, "000000000e01", 443)}); !errors.Is(err,
		publication.ErrInvalidCandidate) {
		t.Fatal("an exit rule may not reuse a route rule's identity")
	}
	again, err := routed.WithExitRules([]publication.ExitRule{
		exitRuleFixture(t, "000000000d01", clients, "000000000e01", 443)})
	if err != nil || again.SemanticHash() != exits.SemanticHash() {
		t.Fatal("the same exit rules must hash the same")
	}
	for name, other := range map[string]publication.ExitRule{
		"pool":   exitRuleFixture(t, "000000000d01", clients, "000000000e02", 443),
		"source": exitRuleFixture(t, "000000000d01", servers, "000000000e01", 443),
		"rule":   exitRuleFixture(t, "000000000d02", clients, "000000000e01", 443),
		"port":   exitRuleFixture(t, "000000000d01", clients, "000000000e01", 80),
	} {
		changed, err := routed.WithExitRules([]publication.ExitRule{other})
		if err != nil || changed.SemanticHash() == exits.SemanticHash() {
			t.Errorf("another %s must change the semantic hash", name)
		}
	}
	// Without route rules the same exit rule hashes apart: section tags
	// keep the encodings distinct.
	alone, err := base.WithExitRules([]publication.ExitRule{internet})
	if err != nil || alone.SemanticHash() == exits.SemanticHash() || alone.SemanticHash() == base.SemanticHash() {
		t.Fatal("dropping the route rule must change the semantic hash")
	}
	// Route rules attach before exit rules.
	if _, err := alone.WithRouteRules([]publication.RouteRule{
		routeRuleFixture(t, "000000000b01", clients, "000000000c01", "10.20.0.0/16")}); !errors.Is(err,
		publication.ErrInvalidCandidate) {
		t.Fatal("route rules were attached after exit rules")
	}
	fingerprints, err := publication.FingerprintRules(exits)
	if err != nil || fingerprints.Len() != 3 {
		t.Fatalf("FingerprintRules() = %d, %v", fingerprints.Len(), err)
	}
	otherPort, err := routed.WithExitRules([]publication.ExitRule{
		exitRuleFixture(t, "000000000d01", clients, "000000000e01", 80)})
	if err != nil {
		t.Fatal(err)
	}
	otherFingerprints, err := publication.FingerprintRules(otherPort)
	if err != nil || string(otherFingerprints.MarshalBinary()) == string(fingerprints.MarshalBinary()) {
		t.Fatal("other ports must change the rule fingerprint")
	}
}
