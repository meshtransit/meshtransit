package mapsession

import (
	"slices"
	"testing"

	"meshtransit.net/core/internal/domain/node"
)

// TestExitSpreadScoreIsFixed pins the score, so every Core version that
// computes assignment version 1 assigns alike (exit node design §16.4); the
// value was computed apart, with Python's hashlib.
func TestExitSpreadScoreIsFixed(t *testing.T) {
	t.Parallel()
	consumer, _ := node.ParseID("01890f00-0000-7000-8000-000000000001")
	exitNode, _ := node.ParseID("01890f00-0000-7000-8000-000000000002")
	var salt [16]byte
	copy(salt[:], []byte("0123456789abcdef"))
	got := exitSpreadScore(salt, consumer, exitNode)
	again := exitSpreadScore(salt, consumer, exitNode)
	other := exitSpreadScore([16]byte{}, consumer, exitNode)
	if got != again || got == other || got != 0x744f00e7ff5e4f98 {
		t.Fatalf("score = %#x (again %#x, another salt %#x)", got, again, other)
	}
}

// spreadFixture is the exit fixture with pool 500 spread over exit nodes 7
// and 8 at one priority, and Devices 1..4 its consumers.
func spreadFixture(t *testing.T) *exitFixture {
	t.Helper()
	fixture := newExitFixture(t)
	fixture.params.ExitPools[0].Spread = true
	copy(fixture.params.ExitPools[0].Salt[:], []byte("spread-salt-0001"))
	fixture.params.ExitPools[0].Serving = []int64{7, 8}
	for index := range fixture.params.ExitNodes {
		fixture.params.ExitNodes[index].Priority = 1
	}
	return fixture
}

func expectedSpread(fixture *exitFixture, consumer int64, serving ...int64) node.ID {
	var best node.ID
	var top uint64
	for _, device := range serving {
		score := exitSpreadScore(fixture.params.ExitPools[0].Salt, fixture.ids[consumer], fixture.ids[device])
		if !best.IsValid() || score > top {
			best, top = fixture.ids[device], score
		}
	}
	return best
}

func TestRoutesForSpreadExitPools(t *testing.T) {
	t.Parallel()
	fixture := spreadFixture(t)
	ids := fixture.ids
	networkPolicy := fixture.policy(t)
	assigned := map[node.ID]int{}
	for _, consumer := range []int64{1, 2, 3, 4} {
		pools := networkPolicy.RoutesFor(ids[consumer], policyNow).Exits()
		want := expectedSpread(fixture, consumer, 7, 8)
		if len(pools) != 1 || !pools[0].Spread || pools[0].Primary != want || pools[0].Status != RouteServed ||
			pools[0].Candidates[0] != want || len(pools[0].Candidates) != 2 {
			t.Fatalf("consumer %d pools = %+v, want primary %s", consumer, pools, want)
		}
		assigned[want]++
	}
	t.Logf("assignments %v", assigned)

	// An exit node out of the serving set takes no consumer; it stays a
	// candidate after the set.
	fixture.params.ExitPools[0].Serving = []int64{8}
	pools := fixture.policy(t).RoutesFor(ids[1], policyNow).Exits()
	if pools[0].Primary != ids[8] || !slices.Equal(pools[0].Candidates, []node.ID{ids[8], ids[7]}) {
		t.Fatalf("one serving = %+v", pools[0])
	}
	// Priority tiers come first in the order.
	fixture.params.ExitNodes[1].Priority = 0 // Device 7
	pools = fixture.policy(t).RoutesFor(ids[1], policyNow).Exits()
	if pools[0].Primary != ids[8] || !slices.Equal(pools[0].Candidates, []node.ID{ids[7], ids[8]}) {
		t.Fatalf("tiers = %+v", pools[0])
	}
	// A draining exit node is marked and never assigned.
	fixture = spreadFixture(t)
	fixture.params.ExitNodes[0].Active = false // Device 8
	pools = fixture.policy(t).RoutesFor(ids[2], policyNow).Exits()
	if pools[0].Primary != ids[7] || !slices.Equal(pools[0].Draining, []node.ID{ids[8]}) {
		t.Fatalf("draining = %+v", pools[0])
	}
	// No member of the set can serve: the pool serves as failover.
	fixture = spreadFixture(t)
	fixture.params.ExitPools[0].Serving = nil
	pools = fixture.policy(t).RoutesFor(ids[1], policyNow).Exits()
	if pools[0].Spread || pools[0].Primary != ids[7] {
		t.Fatalf("an empty set = %+v", pools[0])
	}
	fixture = spreadFixture(t)
	for index := range fixture.params.ExitNodes {
		fixture.params.ExitNodes[index].Offered = false
	}
	pools = fixture.policy(t).RoutesFor(ids[1], policyNow).Exits()
	if pools[0].Spread || pools[0].Status == RouteServed {
		t.Fatalf("no member serves = %+v", pools[0])
	}
	// A different set or salt is a different policy.
	if spreadFixture(t).policy(t).Equal(newExitFixture(t).policy(t)) {
		t.Fatal("spread and failover policies compare equal")
	}
	changed := spreadFixture(t)
	changed.params.ExitPools[0].Salt[0] ^= 1
	if changed.policy(t).Equal(spreadFixture(t).policy(t)) {
		t.Fatal("another salt compares equal")
	}
}

// TestSpreadIsEven: with four exit nodes and 2000 consumers each node gets
// near a quarter, and removing one moves only its own consumers.
func TestSpreadIsEven(t *testing.T) {
	t.Parallel()
	var salt [16]byte
	copy(salt[:], []byte("even-spread-salt"))
	nodes := make([]node.ID, 4)
	for index := range nodes {
		nodes[index], _ = node.ParseID("01890f00-0000-7000-8000-0000000009" + string("0123"[index]) + "0")
	}
	assign := func(consumer node.ID, members []node.ID) node.ID {
		var best node.ID
		var top uint64
		for _, member := range members {
			if score := exitSpreadScore(salt, consumer, member); !best.IsValid() || score > top {
				best, top = member, score
			}
		}
		return best
	}
	counts := map[node.ID]int{}
	moved := 0
	for index := range 2000 {
		consumer := node.ID{byte(index >> 8), byte(index), 0x70, 7}
		before := assign(consumer, nodes)
		counts[before]++
		after := assign(consumer, nodes[:3])
		if before != nodes[3] && after != before {
			moved++
		}
	}
	for member, count := range counts {
		if count < 400 || count > 600 {
			t.Errorf("node %s got %d of 2000", member, count)
		}
	}
	if moved != 0 {
		t.Fatalf("%d consumers of the remaining nodes moved", moved)
	}
}
