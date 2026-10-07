package publication_test

import (
	"errors"
	"testing"

	"github.com/meshtransit/meshtransit/internal/devicegroup"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
	publication "github.com/meshtransit/meshtransit/internal/policy/publication"
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
