package simulation

import (
	"testing"

	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/workspace"
)

// A release a Core before K1a3 published carries the groups the database
// kept for it under the hash without them: the baseline accepts that hash
// for a candidate with groups, and no other wrong hash (K1a3 §12.1).
func TestBaselineAcceptsTheLegacyHashOfARuleWithGroups(t *testing.T) {
	t.Parallel()
	workspaceID, _ := workspace.ParseID(siteAccessFixture(t, 101))
	networkID, _ := network.ParseID(siteAccessFixture(t, 201))
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	users, _ := devicegroup.ParseID(siteAccessFixture(t, 501))
	clusterGroup, _ := devicegroup.ParseID(siteAccessFixture(t, 502))
	cluster, _ := kubecluster.ParseID(siteAccessFixture(t, 503))
	ruleID, _ := policy.ParseRuleID(siteAccessFixture(t, 701))
	https, _ := policy.NewPortRange(443, 443)
	candidate := func(groups []string) publication.Candidate {
		t.Helper()
		snapshot, err := policy.NewSnapshot(policy.SnapshotParams{Scope: scope, Revision: 6, Rules: []policy.Rule{}})
		if err != nil {
			t.Fatal(err)
		}
		value, err := publication.NewCandidate(snapshot, 1)
		if err != nil {
			t.Fatal(err)
		}
		rule, err := publication.NewGroupRule(publication.GroupRuleParams{RuleID: ruleID, SourceGroupID: users,
			DestinationGroupID: clusterGroup, DestinationKubernetesClusterID: cluster, KubernetesGroups: groups,
			Protocol: policy.ProtocolTCP, DestinationPortRanges: []policy.PortRange{https}})
		if err != nil {
			t.Fatal(err)
		}
		if value, err = value.WithGroupRules([]publication.GroupRule{rule}); err != nil {
			t.Fatal(err)
		}
		return value
	}
	vector, err := accessgraph.NewRevisionVector(accessgraph.RevisionVectorParams{
		NetworkRevision: 12, InventoryRevision: 8, GroupRevision: 9, PolicyRevision: 6,
		DNSRevision: 2, RouteRevision: 2, SharingRevision: 2, IsolationGeneration: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	releaseID, _ := publication.ParseReleaseID(siteAccessFixture(t, 901))
	baseline := func(current publication.Candidate, hash publication.SemanticHash) error {
		_, err := NewBaseline(BaselineParams{Scope: scope, RevisionVector: vector, HasActiveRelease: true,
			ReleaseID: releaseID, SemanticHash: hash, Candidate: current})
		return err
	}
	viewing, editing := candidate([]string{"view"}), candidate([]string{"edit"})
	for name, test := range map[string]struct {
		current publication.Candidate
		hash    publication.SemanticHash
		valid   bool
	}{
		"hashed with groups":         {viewing, viewing.SemanticHash(), true},
		"hashed without groups":      {viewing, viewing.LegacySemanticHash(), true},
		"another release's groups":   {viewing, editing.SemanticHash(), false},
		"no groups, legacy hash":     {candidate(nil), candidate(nil).SemanticHash(), true},
		"another candidate's legacy": {viewing, candidate(nil).LegacySemanticHash(), true},
	} {
		if err := baseline(test.current, test.hash); (err == nil) != test.valid {
			t.Errorf("%s: error = %v, want valid %t", name, err, test.valid)
		}
	}
}
