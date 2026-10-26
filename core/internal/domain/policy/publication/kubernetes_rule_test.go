package publication_test

import (
	"errors"
	"testing"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/devicetag"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/policy"
	publication "meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/publicid"
)

func clusterRuleParams(t *testing.T, protocol policy.Protocol, first, last uint16) publication.GroupRuleParams {
	t.Helper()
	ruleID, err := policy.ParseRuleID("01890f00-0000-7000-8000-000000000901")
	if err != nil {
		t.Fatal(err)
	}
	ports, err := policy.NewPortRange(first, last)
	if err != nil {
		t.Fatal(err)
	}
	cluster, err := kubecluster.ParseID("01890f00-0000-7000-8000-000000000b01")
	if err != nil {
		t.Fatal(err)
	}
	return publication.GroupRuleParams{
		RuleID: ruleID, SourceGroupID: mustGroupID(t, "000000000a01"),
		DestinationGroupID: mustGroupID(t, "000000000a02"), DestinationKubernetesClusterID: cluster,
		Protocol: protocol, DestinationPortRanges: []policy.PortRange{ports},
	}
}

// A rule to a Kubernetes cluster is a rule to the cluster's own group, on
// TCP 443 only, and names the cluster in fingerprints, not the group.
func TestClusterRuleIsAGroupRuleOnTCP443(t *testing.T) {
	t.Parallel()
	rule, err := publication.NewGroupRule(clusterRuleParams(t, policy.ProtocolTCP, 443, 443))
	if err != nil {
		t.Fatalf("cluster rule: %v", err)
	}
	if rule.DestinationKubernetesClusterID().String() != "01890f00-0000-7000-8000-000000000b01" ||
		rule.DestinationGroupID() != mustGroupID(t, "000000000a02") {
		t.Fatalf("rule = %+v", rule)
	}
	for name, params := range map[string]publication.GroupRuleParams{
		"udp":          clusterRuleParams(t, policy.ProtocolUDP, 443, 443),
		"another port": clusterRuleParams(t, policy.ProtocolTCP, 6443, 6443),
		"a port range": clusterRuleParams(t, policy.ProtocolTCP, 443, 444),
		"without its group": func() publication.GroupRuleParams {
			params := clusterRuleParams(t, policy.ProtocolTCP, 443, 443)
			params.DestinationGroupID, params.DestinationTagID = devicegroup.ID{}, mustTagID(t)
			return params
		}(),
	} {
		if _, err := publication.NewGroupRule(params); !errors.Is(err, publication.ErrInvalidGroupRule) {
			t.Errorf("%s: error = %v, want ErrInvalidGroupRule", name, err)
		}
	}

	base := publicationCandidateFixture(t, 2, nil)
	candidate, err := base.WithGroupRules([]publication.GroupRule{rule})
	if err != nil {
		t.Fatal(err)
	}
	unlabelled, err := publication.NewGroupRule(func() publication.GroupRuleParams {
		params := clusterRuleParams(t, policy.ProtocolTCP, 443, 443)
		params.DestinationKubernetesClusterID = kubecluster.ID{}
		return params
	}())
	if err != nil {
		t.Fatal(err)
	}
	plain, err := base.WithGroupRules([]publication.GroupRule{unlabelled})
	if err != nil {
		t.Fatal(err)
	}
	// The label names the destination; what the release grants is the same.
	if candidate.SemanticHash() != plain.SemanticHash() {
		t.Fatal("the cluster label changed the release semantic hash")
	}
	summary := publication.SummarizeRuleChanges(publication.RuleFingerprintSet{}, publication.RuleBaselineNone,
		ruleFingerprintsFixture(t, candidate))
	if summary.Added() != 1 || summary.Rules()[0].DestinationKind() != publication.DestinationKubernetesCluster ||
		summary.Rules()[0].DestinationID() != publicid.ID(rule.DestinationKubernetesClusterID()) ||
		publication.DestinationKubernetesCluster.String() != "kubernetes_cluster" {
		t.Fatalf("summary = %+v", summary.Rules())
	}
	// A fingerprint set with the new kind decodes.
	set := ruleFingerprintsFixture(t, candidate)
	if decoded, err := publication.ParseRuleFingerprintSet(set.MarshalBinary()); err != nil || decoded.Len() != 1 {
		t.Fatalf("decode = %v, %v", decoded.Len(), err)
	}
}

func mustTagID(t *testing.T) devicetag.ID {
	t.Helper()
	id, err := devicetag.ParseID("01890f00-0000-7000-8000-000000000c01")
	if err != nil {
		t.Fatal(err)
	}
	return id
}
