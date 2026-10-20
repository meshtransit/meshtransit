package simulation

import (
	"slices"
	"testing"

	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/exitpool"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

// A preview whose baseline or proposal holds rules to Exit Pools says it
// does not list their Internet access, so it never reads as no impact.
func TestResultFlagsExitRules(t *testing.T) {
	t.Parallel()
	workspaceID, _ := workspace.ParseID(siteAccessFixture(t, 101))
	networkID, _ := network.ParseID(siteAccessFixture(t, 201))
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	group, _ := devicegroup.ParseID(siteAccessFixture(t, 501))
	side, err := publication.NewRuleSide(publication.SideDeviceGroup, publicid.ID(group))
	if err != nil {
		t.Fatal(err)
	}
	member, _ := node.ParseID(siteAccessFixture(t, 301))
	ruleID, _ := policy.ParseRuleID(siteAccessFixture(t, 701))
	poolID, _ := exitpool.ParseID(siteAccessFixture(t, 801))
	rule, err := publication.NewExitRule(publication.ExitRuleParams{
		RuleID: ruleID, SourceGroupID: group, PoolID: poolID, Protocol: policy.ProtocolICMP,
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate := func(revision int64, rules []publication.ExitRule) publication.Candidate {
		snapshot, err := policy.NewSnapshot(policy.SnapshotParams{Scope: scope, Revision: revision, Rules: []policy.Rule{}})
		if err != nil {
			t.Fatal(err)
		}
		value, err := publication.NewCandidate(snapshot, 1)
		if err != nil {
			t.Fatal(err)
		}
		if len(rules) > 0 {
			if value, err = value.WithExitRules(rules); err != nil {
				t.Fatal(err)
			}
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
	baselineFor := func(current publication.Candidate) Baseline {
		releaseID, _ := publication.ParseReleaseID(siteAccessFixture(t, 901))
		baseline, err := NewBaseline(BaselineParams{
			Scope: scope, RevisionVector: vector, HasActiveRelease: true, ReleaseID: releaseID,
			SemanticHash: current.SemanticHash(), Candidate: current,
			SelectorMembers: map[publication.RuleSide][]node.ID{side: {member}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return baseline
	}
	flagged := func(result Result) bool {
		return slices.Contains(result.unsupported, UnsupportedCapabilityExitRules)
	}
	plain, err := newResult(baselineFor(candidate(6, nil)), candidate(7, nil))
	if err != nil || flagged(plain) {
		t.Fatalf("a preview without exit rules flagged them: %v", err)
	}
	added, err := newResult(baselineFor(candidate(6, nil)), candidate(7, []publication.ExitRule{rule}))
	if err != nil || !flagged(added) || !added.IsValid() || added.ImpactHash() == plain.ImpactHash() {
		t.Fatalf("a proposal adding an exit rule was not flagged: %v", err)
	}
	kept, err := newResult(baselineFor(candidate(6, []publication.ExitRule{rule})), candidate(7, nil))
	if err != nil || !flagged(kept) {
		t.Fatalf("a proposal removing an exit rule was not flagged: %v", err)
	}
	if UnsupportedCapabilityExitRules.String() != "exit_rules" || !UnsupportedCapabilityExitRules.isValid() {
		t.Fatal("exit_rules is not a valid capability")
	}
}
