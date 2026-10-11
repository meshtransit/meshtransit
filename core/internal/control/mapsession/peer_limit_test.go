package mapsession

import (
	"slices"
	"testing"
)

// limitedNetworkFixture is a map of peers authorized peers whose
// connectivity marks the peers at the online indexes online.
func limitedNetworkFixture(t *testing.T, peers int, online ...int) (Snapshot, []PeerCandidate) {
	t.Helper()
	params, list := largeNetworkFixture(t, peers, peers)
	base, err := NewSnapshot(params)
	if err != nil {
		t.Fatal(err)
	}
	values := []Connectivity{connectivityMapValue(t, base.NodeID(), base.SessionGeneration(), true)}
	for index, peer := range list {
		values = append(values, connectivityMapValue(t, peer.NodeID(), peer.SessionGeneration(),
			slices.Contains(online, index)))
	}
	withConnectivity, err := base.WithConnectivity(values)
	if err != nil {
		t.Fatal(err)
	}
	return withConnectivity, list
}

func TestPeerLimitKeepsOnlinePeersThenStableOrder(t *testing.T) {
	t.Parallel()

	snapshot, list := limitedNetworkFixture(t, 10, 7, 9)
	if same := snapshot.withPeerLimit(10); !sameAuthorizedPeers(same, snapshot) || same.authorizedTotal != 0 {
		t.Fatal("a map within the limit changed")
	}
	limited := snapshot.withPeerLimit(4)
	sent, authorized := limited.PeerLimit()
	if sent != 4 || authorized != 10 {
		t.Fatalf("PeerLimit() = %d, %d, want 4 of 10", sent, authorized)
	}
	// Online peers 7 and 9, then the lowest numeric identifiers 0 and 1.
	want := []PeerCandidate{list[0], list[1], list[7], list[9]}
	slices.SortFunc(want, comparePeerCandidates)
	if !equalPeerCandidates(limited.AuthorizedPeers(), want) {
		t.Fatalf("limited peers differ from online-first, stable order")
	}
	if len(limited.connectivity) != 5 || !hasCompleteMapConnectivity(limited) {
		t.Fatalf("limited map keeps %d connectivity values, want self and 4 peers", len(limited.connectivity))
	}
	if _, found := limited.ConnectivityFor(list[2].NodeID()); found {
		t.Fatal("a peer left out of the map still shows connectivity")
	}
}

func TestPeerLimitSubsetChangeIsASameRevisionAuthorityDelta(t *testing.T) {
	t.Parallel()

	before, list := limitedNetworkFixture(t, 6, 5)
	after, _ := limitedNetworkFixture(t, 6, 4)
	current, next := before.withPeerLimit(3), after.withPeerLimit(3)
	if sameAuthorizedPeers(current, next) {
		t.Fatal("presence did not change the chosen peers")
	}
	delta, err := NewAuthorityDelta(current, next)
	if err != nil {
		t.Fatalf("NewAuthorityDelta(same revision subset) error = %v", err)
	}
	changed, removed := delta.ChangedPeers(), delta.RemovedPeerNumericIDs()
	if len(changed) != 1 || changed[0].NodeID() != list[4].NodeID() ||
		len(removed) != 1 || removed[0] != list[5].NumericNodeID() {
		t.Fatalf("delta = +%v -%v, want +peer 4 -peer 5", changed, removed)
	}
	// Without a limit, the same revision still never delta-encodes authority.
	if _, err := NewAuthorityDelta(before, after); err == nil {
		t.Fatal("NewAuthorityDelta() accepted an unlimited same-revision map")
	}
}
