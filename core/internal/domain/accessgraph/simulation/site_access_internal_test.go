package simulation

import (
	"fmt"
	"net/netip"
	"testing"

	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/site"
	"meshtransit.net/core/internal/domain/workspace"
)

func siteAccessFixture(t *testing.T, suffix int) string {
	t.Helper()
	return fmt.Sprintf("01890f00-0000-7000-8000-%012d", suffix)
}

// A rule to a Site grants each Device of its source access to the Site: a
// proposal adding one lists that access per Device, counts the Devices as
// affected and changes the impact hash; one without Site changes keeps the
// hash it had before Sites were simulated.
func TestResultListsSiteAccessChanges(t *testing.T) {
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
	first, _ := node.ParseID(siteAccessFixture(t, 301))
	second, _ := node.ParseID(siteAccessFixture(t, 302))
	ruleID, _ := policy.ParseRuleID(siteAccessFixture(t, 701))
	siteID, _ := site.ParseID(siteAccessFixture(t, 801))
	rule, err := publication.NewRouteRule(publication.RouteRuleParams{
		RuleID: ruleID, SourceGroupID: group, SiteID: siteID,
		Prefixes: []netip.Prefix{netip.MustParsePrefix("10.35.0.0/17")}, Protocol: policy.ProtocolICMP,
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate := func(revision int64, rules []publication.RouteRule) publication.Candidate {
		snapshot, err := policy.NewSnapshot(policy.SnapshotParams{Scope: scope, Revision: revision, Rules: []policy.Rule{}})
		if err != nil {
			t.Fatal(err)
		}
		value, err := publication.NewCandidate(snapshot, 1)
		if err != nil {
			t.Fatal(err)
		}
		if value, err = value.WithRouteRules(rules); err != nil {
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
	current := candidate(6, nil)
	releaseID, _ := publication.ParseReleaseID(siteAccessFixture(t, 901))
	baseline, err := NewBaseline(BaselineParams{
		Scope: scope, RevisionVector: vector, HasActiveRelease: true, ReleaseID: releaseID,
		SemanticHash: current.SemanticHash(), Candidate: current,
		SelectorMembers: map[publication.RuleSide][]node.ID{side: {first, second}},
	})
	if err != nil {
		t.Fatal(err)
	}

	added, err := newResult(baseline, candidate(7, []publication.RouteRule{rule}))
	if err != nil {
		t.Fatal(err)
	}
	access := added.AddedSiteAccess()
	if len(access) != 2 || access[0].SourceNodeID() != first || access[1].SourceNodeID() != second ||
		access[0].SiteID() != siteID || access[0].RuleID() != ruleID ||
		access[0].Prefixes()[0] != netip.MustParsePrefix("10.35.0.0/17") || len(added.RemovedSiteAccess()) != 0 ||
		added.AffectedDeviceCount() != 2 || !added.IsValid() {
		t.Fatalf("added access = %+v, affected %d", access, added.AffectedDeviceCount())
	}
	unchanged, err := newResult(baseline, candidate(7, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(unchanged.AddedSiteAccess()) != 0 || unchanged.ImpactHash() == added.ImpactHash() {
		t.Fatal("a proposal without Site changes listed access or shared the hash")
	}
}
