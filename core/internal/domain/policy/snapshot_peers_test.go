package policy

import (
	"slices"
	"testing"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/workspace"
)

func TestSnapshotPeersOf(t *testing.T) {
	t.Parallel()
	workspaceID, _ := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	networkID, _ := network.ParseID("01890f00-0000-7000-8000-000000000201")
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]node.ID, 4)
	for index := range ids {
		ids[index], err = node.ParseID("01890f00-0000-7000-8000-00000000070" + string(rune('1'+index)))
		if err != nil {
			t.Fatal(err)
		}
	}
	rule := func(id string, source, destination node.ID) Rule {
		ruleID, err := ParseRuleID(id)
		if err != nil {
			t.Fatal(err)
		}
		value, err := NewRule(RuleParams{ID: ruleID, Scope: scope, SourceNodeID: source, DestinationNodeID: destination, Protocol: ProtocolICMP})
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	snapshot, err := NewSnapshot(SnapshotParams{Scope: scope, Revision: 3, Rules: []Rule{
		rule("01890f00-0000-7000-8000-000000000801", ids[0], ids[1]),
		rule("01890f00-0000-7000-8000-000000000802", ids[2], ids[0]),
		rule("01890f00-0000-7000-8000-000000000803", ids[0], ids[1]), // duplicate pair
		rule("01890f00-0000-7000-8000-000000000804", ids[2], ids[3]), // not self
	}})
	if err != nil {
		t.Fatal(err)
	}
	got := snapshot.PeersOf(ids[0])
	want := []node.ID{ids[1], ids[2]}
	if !slices.Equal(got, want) {
		t.Fatalf("PeersOf() = %v, want %v", got, want)
	}
	for _, peer := range want {
		if !snapshot.AllowsPeer(ids[0], peer) {
			t.Fatalf("AllowsPeer(self, %v) = false", peer)
		}
	}
	if len((Snapshot{}).PeersOf(ids[0])) != 0 {
		t.Fatal("an invalid snapshot listed peers")
	}
}
