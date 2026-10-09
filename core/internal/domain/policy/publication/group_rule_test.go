package publication_test

import (
	"errors"
	"testing"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/devicetag"
	"meshtransit.net/core/internal/domain/identitygroup"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	publication "meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/publicid"
)

func groupRuleFixture(t *testing.T, ruleSuffix string, source, destination devicegroup.ID, port uint16) publication.GroupRule {
	t.Helper()
	ruleID, err := policy.ParseRuleID("01890f00-0000-7000-8000-" + ruleSuffix)
	if err != nil {
		t.Fatal(err)
	}
	ports, err := policy.NewPortRange(port, port)
	if err != nil {
		t.Fatal(err)
	}
	rule, err := publication.NewGroupRule(publication.GroupRuleParams{
		RuleID: ruleID, SourceGroupID: source, DestinationGroupID: destination,
		Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{ports},
	})
	if err != nil {
		t.Fatal(err)
	}
	return rule
}

func mustGroupID(t *testing.T, suffix string) devicegroup.ID {
	t.Helper()
	id, err := devicegroup.ParseID("01890f00-0000-7000-8000-" + suffix)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestGroupRuleNeedsOneSourceOneDestinationAndAGroup(t *testing.T) {
	t.Parallel()
	ruleID, _ := policy.ParseRuleID("01890f00-0000-7000-8000-000000000901")
	device, _ := node.ParseID("01890f00-0000-7000-8000-000000000701")
	group := mustGroupID(t, "000000000a01")
	ssh, _ := policy.NewPortRange(22, 22)
	tcp, icmp, ports := policy.ProtocolTCP, policy.ProtocolICMP, []policy.PortRange{ssh}
	cases := map[string]publication.GroupRuleParams{
		"devices only": {RuleID: ruleID, SourceNodeID: device, DestinationNodeID: device,
			Protocol: tcp, DestinationPortRanges: ports},
		"two sources": {RuleID: ruleID, SourceNodeID: device, SourceGroupID: group, DestinationGroupID: group,
			Protocol: tcp, DestinationPortRanges: ports},
		"no destination":    {RuleID: ruleID, SourceGroupID: group, Protocol: tcp, DestinationPortRanges: ports},
		"icmp with ports":   {RuleID: ruleID, SourceGroupID: group, DestinationGroupID: group, Protocol: icmp, DestinationPortRanges: ports},
		"tcp without ports": {RuleID: ruleID, SourceGroupID: group, DestinationGroupID: group, Protocol: tcp},
		"unknown protocol":  {RuleID: ruleID, SourceGroupID: group, DestinationGroupID: group, DestinationPortRanges: ports},
		"missing identity":  {SourceGroupID: group, DestinationGroupID: group, Protocol: tcp, DestinationPortRanges: ports},
	}
	for name, params := range cases {
		if _, err := publication.NewGroupRule(params); !errors.Is(err, publication.ErrInvalidGroupRule) {
			t.Errorf("%s: error = %v, want ErrInvalidGroupRule", name, err)
		}
	}
	if _, err := publication.NewGroupRule(publication.GroupRuleParams{RuleID: ruleID, SourceNodeID: device,
		DestinationGroupID: group, Protocol: icmp}); err != nil {
		t.Fatalf("Device to group ICMP rule: %v", err)
	}
}

func TestCandidateHashCoversGroupRulesAndRejectsSharedRuleIDs(t *testing.T) {
	t.Parallel()
	clients, servers := mustGroupID(t, "000000000a01"), mustGroupID(t, "000000000a02")
	direct := publicationRuleFixture(t, "000000000801", "000000000701", "000000000702", 443)
	base := publicationCandidateFixture(t, 2, []policy.Rule{direct})

	ssh, err := base.WithGroupRules([]publication.GroupRule{groupRuleFixture(t, "000000000901", clients, servers, 22)})
	if err != nil || ssh.ProjectionCount() != 2 || len(ssh.GroupRules()) != 1 {
		t.Fatalf("WithGroupRules() = %+v, %v", ssh, err)
	}
	if ssh.SemanticHash() == base.SemanticHash() {
		t.Fatal("a group rule must change the semantic hash")
	}
	swapped, err := base.WithGroupRules([]publication.GroupRule{groupRuleFixture(t, "000000000901", servers, clients, 22)})
	if err != nil || swapped.SemanticHash() == ssh.SemanticHash() {
		t.Fatal("swapping source and destination groups must change the semantic hash")
	}
	if _, err := ssh.WithGroupRules(nil); !errors.Is(err, publication.ErrInvalidCandidate) {
		t.Fatal("group rules may be attached once")
	}
	if _, err := base.WithGroupRules([]publication.GroupRule{groupRuleFixture(t, "000000000801", clients, servers, 22)}); !errors.Is(err, publication.ErrInvalidCandidate) {
		t.Fatal("a group rule may not reuse a Device rule's identity")
	}
	duplicate := groupRuleFixture(t, "000000000902", clients, servers, 22)
	if _, err := base.WithGroupRules([]publication.GroupRule{duplicate, duplicate}); !errors.Is(err, publication.ErrInvalidCandidate) {
		t.Fatal("group rule identities must be unique")
	}
}

func TestGroupRuleIdentityGroupAndTagSides(t *testing.T) {
	t.Parallel()
	ruleID, _ := policy.ParseRuleID("01890f00-0000-7000-8000-000000000901")
	device, _ := node.ParseID("01890f00-0000-7000-8000-000000000701")
	group := mustGroupID(t, "000000000a01")
	people, _ := identitygroup.ParseID("01890f00-0000-7000-8000-000000000d01")
	servers, _ := devicetag.ParseID("01890f00-0000-7000-8000-000000000e01")
	ssh, _ := policy.NewPortRange(22, 22)
	base := publication.GroupRuleParams{RuleID: ruleID, Protocol: policy.ProtocolTCP,
		DestinationPortRanges: []policy.PortRange{ssh}}
	with := func(change func(*publication.GroupRuleParams)) publication.GroupRuleParams {
		params := base
		change(&params)
		return params
	}
	valid := map[string]struct {
		params      publication.GroupRuleParams
		source      publication.SideKind
		destination publication.SideKind
	}{
		"identity group to tag": {with(func(p *publication.GroupRuleParams) {
			p.SourceIdentityGroupID, p.DestinationTagID = people, servers
		}), publication.SideIdentityGroup, publication.SideDeviceTag},
		"identity group to Device": {with(func(p *publication.GroupRuleParams) {
			p.SourceIdentityGroupID, p.DestinationNodeID = people, device
		}), publication.SideIdentityGroup, publication.SideDevice},
		"tag to Device group": {with(func(p *publication.GroupRuleParams) {
			p.SourceTagID, p.DestinationGroupID = servers, group
		}), publication.SideDeviceTag, publication.SideDeviceGroup},
		"Device to tag": {with(func(p *publication.GroupRuleParams) {
			p.SourceNodeID, p.DestinationTagID = device, servers
		}), publication.SideDevice, publication.SideDeviceTag},
	}
	for name, test := range valid {
		rule, err := publication.NewGroupRule(test.params)
		if err != nil || rule.Source().Kind() != test.source || rule.Destination().Kind() != test.destination {
			t.Errorf("%s: NewGroupRule() = %+v, %v", name, rule, err)
		}
	}
	rule, _ := publication.NewGroupRule(valid["identity group to tag"].params)
	if rule.SourceIdentityGroupID() != people || rule.DestinationTagID() != servers ||
		rule.SourceGroupID().IsValid() || rule.SourceTagID().IsValid() || rule.DestinationNodeID().IsValid() {
		t.Fatalf("typed side accessors = %+v", rule)
	}
	invalid := map[string]publication.GroupRuleParams{
		"identity group and tag sources": with(func(p *publication.GroupRuleParams) {
			p.SourceIdentityGroupID, p.SourceTagID, p.DestinationTagID = people, servers, servers
		}),
		"group and tag destinations": with(func(p *publication.GroupRuleParams) {
			p.SourceIdentityGroupID, p.DestinationGroupID, p.DestinationTagID = people, group, servers
		}),
		"identity group without destination": with(func(p *publication.GroupRuleParams) { p.SourceIdentityGroupID = people }),
	}
	for name, params := range invalid {
		if _, err := publication.NewGroupRule(params); !errors.Is(err, publication.ErrInvalidGroupRule) {
			t.Errorf("%s: error = %v, want ErrInvalidGroupRule", name, err)
		}
	}
	if _, err := publication.NewRuleSide(publication.SideIdentityGroup, publicid.ID(people)); err != nil {
		t.Fatalf("NewRuleSide(identity group) = %v", err)
	}
	if _, err := publication.NewRuleSide(publication.SideUnknown, publicid.ID(people)); !errors.Is(err, publication.ErrInvalidGroupRule) {
		t.Fatal("an unknown side kind must be rejected")
	}
}

func TestCandidateHashSeparatesSideKindsWithTheSameIdentity(t *testing.T) {
	t.Parallel()
	ruleID, _ := policy.ParseRuleID("01890f00-0000-7000-8000-000000000901")
	device, _ := node.ParseID("01890f00-0000-7000-8000-000000000701")
	const shared = "01890f00-0000-7000-8000-000000000f01"
	group, _ := devicegroup.ParseID(shared)
	tag, _ := devicetag.ParseID(shared)
	people, _ := identitygroup.ParseID(shared)
	base := publicationCandidateFixture(t, 2, nil)
	hashes := map[publication.SemanticHash]bool{}
	for name, params := range map[string]publication.GroupRuleParams{
		"device group": {SourceGroupID: group}, "tag": {SourceTagID: tag}, "identity group": {SourceIdentityGroupID: people},
	} {
		params.RuleID, params.DestinationNodeID, params.Protocol = ruleID, device, policy.ProtocolICMP
		rule, err := publication.NewGroupRule(params)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		candidate, err := base.WithGroupRules([]publication.GroupRule{rule})
		if err != nil {
			t.Fatalf("%s: WithGroupRules() = %v", name, err)
		}
		hashes[candidate.SemanticHash()] = true
	}
	if len(hashes) != 3 {
		t.Fatalf("side kinds sharing one identity hashed to %d values, want 3", len(hashes))
	}
}
