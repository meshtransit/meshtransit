package legacyts2021

import (
	"strconv"
	"testing"

	"tailscale.com/tailcfg"

	"github.com/meshtransit/meshtransit/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
)

func TestSplitFilterSourcesRespectsTheClientLimit(t *testing.T) {
	t.Parallel()
	sources := make([]string, 2*maxFilterRuleSources+3)
	for index := range sources {
		sources[index] = "100.64.0." + strconv.Itoa(index)
	}
	runs := splitFilterSources(sources)
	if len(runs) != 3 || len(runs[0]) != maxFilterRuleSources || len(runs[1]) != maxFilterRuleSources ||
		len(runs[2]) != 3 || runs[2][2] != sources[len(sources)-1] {
		t.Fatalf("runs = %d, sizes %d/%d/%d", len(runs), len(runs[0]), len(runs[1]), len(runs[2]))
	}
	runs[0][0] = "changed"
	if sources[0] == "changed" {
		t.Fatal("runs must not alias the input")
	}
	if len(splitFilterSources(nil)) != 0 {
		t.Fatal("no sources gives no rule")
	}
}

func TestPacketFilterMergesRulesThatOpenTheSameTraffic(t *testing.T) {
	t.Parallel()
	base := mapSnapshotWithCandidateFixture(t)
	candidate := base.PeerCandidates()[0]
	rules := make([]policy.Rule, 0, 2)
	for _, id := range []string{"01890f00-0000-7000-8000-000000000801", "01890f00-0000-7000-8000-000000000802"} {
		rule, err := policy.NewRule(policy.RuleParams{
			ID: mapRuleIDFixture(t, id), Scope: base.Scope(), SourceNodeID: candidate.NodeID(),
			DestinationNodeID: base.NodeID(), Protocol: policy.ProtocolTCP,
			DestinationPortRanges: []policy.PortRange{mapPortRangeFixture(t, 22, 22)},
		})
		if err != nil {
			t.Fatal(err)
		}
		rules = append(rules, rule)
	}
	snapshot := mapSnapshotWithRulesFixture(t, base, rules)
	filter, err := fullMapPacketFilter(snapshot, candidatesByNode(snapshot))
	if err != nil {
		t.Fatal(err)
	}
	if len(filter) != 1 || len(filter[0].SrcIPs) != len(candidate.Addresses()) {
		t.Fatalf("filter = %+v, want one merged rule with each source address once", filter)
	}
	if filter[0].DstPorts[0].Ports != (tailcfg.PortRange{First: 22, Last: 22}) {
		t.Fatalf("merged traffic = %+v", filter[0].DstPorts)
	}
}

func mapSnapshotWithRulesFixture(t *testing.T, base mapsession.Snapshot, rules []policy.Rule) mapsession.Snapshot {
	t.Helper()
	packetPolicy, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope: base.Scope(), Revision: base.PacketPolicy().Revision(), Rules: rules,
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := mapsession.NewSnapshot(mapsession.SnapshotParams{
		Scope: base.Scope(), NetworkName: base.NetworkName(), NetworkRevision: base.NetworkRevision(),
		RecoveryEpoch: base.RecoveryEpoch(), SessionGeneration: base.SessionGeneration(),
		NumericNodeID: base.NumericNodeID(), NumericOwnerID: base.NumericOwnerID(), NodeID: base.NodeID(),
		Hostname: base.Hostname(), MachineKey: base.MachineKey(), NodeKey: base.NodeKey(),
		Addresses: base.Addresses(), CreatedAt: base.CreatedAt(), KeyExpiry: base.KeyExpiry(),
		PeerCandidates: base.PeerCandidates(), PacketPolicy: packetPolicy, RelayDirectory: base.RelayDirectory(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func candidatesByNode(snapshot mapsession.Snapshot) map[node.ID]mapsession.PeerCandidate {
	candidates := make(map[node.ID]mapsession.PeerCandidate)
	for _, candidate := range snapshot.AuthorizedPeers() {
		candidates[candidate.NodeID()] = candidate
	}
	return candidates
}
