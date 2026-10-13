package mapsession

import (
	"fmt"
	"testing"
)

// sharedTableFixture is one Network's table on a replica, without a feed.
func sharedTableFixture(t testing.TB, values ...Connectivity) *networkConnectivity {
	t.Helper()
	table := &networkConnectivity{subscribers: make(map[uint64]*connectivitySubscriber)}
	table.current.Store(&connectivityVersion{table: table})
	table.apply(values, true)
	return table
}

func TestSharedConnectivityDeltaMatchesAPrivateRead(t *testing.T) {
	t.Parallel()

	base, peer := snapshotWithAuthorizedPeerFixture(t)
	self := connectivityFixture(t, base.NodeID(), base.SessionGeneration(), 3, "198.51.100.1:41641", true)
	peerBefore := connectivityFixture(t, peer.NodeID(), peer.SessionGeneration(), 4, "198.51.100.2:41641", false)
	peerAfter := connectivityFixture(t, peer.NodeID(), peer.SessionGeneration(), 4, "198.51.100.3:41641", true)
	// A Node the policy does not pair with self, in the same table.
	stranger := connectivityMapValue(t, connectivityMapNodeID(t, 99), 1, true)

	table := sharedTableFixture(t, self, peerBefore, stranger)
	before := table.current.Load()
	after, _ := table.apply([]Connectivity{peerAfter}, true)

	sharedCurrent, err := base.withSharedConnectivity(before)
	if err != nil {
		t.Fatal(err)
	}
	sharedNext, err := base.withSharedConnectivity(after)
	if err != nil {
		t.Fatal(err)
	}
	privateCurrent, err := base.WithConnectivity([]Connectivity{self, peerBefore})
	if err != nil {
		t.Fatal(err)
	}
	privateNext, err := base.WithConnectivity([]Connectivity{self, peerAfter})
	if err != nil {
		t.Fatal(err)
	}

	for _, view := range []struct {
		name   string
		shared Snapshot
		direct Snapshot
	}{{"current", sharedCurrent, privateCurrent}, {"next", sharedNext, privateNext}} {
		for _, id := range []Connectivity{self, peerBefore} {
			got, gotFound := view.shared.ConnectivityFor(id.Key().NodeID())
			want, wantFound := view.direct.ConnectivityFor(id.Key().NodeID())
			if gotFound != wantFound || !got.equal(want) {
				t.Fatalf("%s ConnectivityFor(%s) = %+v, want %+v", view.name, id.Key().NodeID(), got, want)
			}
		}
	}
	if _, found := sharedNext.ConnectivityFor(stranger.Key().NodeID()); found {
		t.Fatal("a shared table showed a Node the snapshot does not authorize")
	}

	if sameMapConnectivity(sharedCurrent, sharedNext) || !sameMapConnectivity(sharedNext, sharedNext) {
		t.Fatal("sameMapConnectivity() disagrees with the table versions")
	}
	sharedDelta, err := NewConnectivityDelta(sharedCurrent, sharedNext)
	if err != nil {
		t.Fatalf("NewConnectivityDelta(shared) error = %v", err)
	}
	privateDelta, err := NewConnectivityDelta(privateCurrent, privateNext)
	if err != nil {
		t.Fatal(err)
	}
	sharedPeers, privatePeers := sharedDelta.ChangedPeers(), privateDelta.ChangedPeers()
	if !sharedDelta.IsValid() || sharedDelta.SelfChanged() != privateDelta.SelfChanged() ||
		len(sharedPeers) != 1 || len(privatePeers) != 1 || sharedPeers[0].NodeID() != privatePeers[0].NodeID() {
		t.Fatalf("shared delta = %+v, private delta = %+v", sharedPeers, privatePeers)
	}

	// A version change that touches only a stranger sends nothing.
	unrelated, _ := table.apply([]Connectivity{connectivityMapValue(t, stranger.Key().NodeID(), 1, false)}, true)
	sharedLater, err := base.withSharedConnectivity(unrelated)
	if err != nil {
		t.Fatal(err)
	}
	if !sameMapConnectivity(sharedNext, sharedLater) {
		t.Fatal("a stranger's change counted as a change of this map")
	}
}

// BenchmarkConnectivityChange measures what one peer's connectivity change
// costs one stream of a Network: rebuilding the map from a full read
// (before S3) or moving to the next version of the shared table.
func BenchmarkConnectivityChange(b *testing.B) {
	for _, peers := range []int{1000, 5000} {
		params, list := largeNetworkFixture(b, peers, peers)
		base, err := NewSnapshot(params)
		if err != nil {
			b.Fatal(err)
		}
		values := make([]Connectivity, 0, peers+1)
		values = append(values, connectivityMapValue(b, base.NodeID(), base.SessionGeneration(), true))
		for _, peer := range list {
			values = append(values, connectivityMapValue(b, peer.NodeID(), peer.SessionGeneration(), false))
		}
		changed := slicesWith(values, 1, connectivityMapValue(b, list[0].NodeID(), list[0].SessionGeneration(), true))

		b.Run(fmt.Sprintf("full-read/peers=%d", peers), func(b *testing.B) {
			current, err := base.WithConnectivity(values)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				next, err := current.WithConnectivity(changed)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := NewConnectivityDelta(current, next); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("shared-table/peers=%d", peers), func(b *testing.B) {
			table := sharedTableFixture(b, values...)
			current, err := base.withSharedConnectivity(table.current.Load())
			if err != nil {
				b.Fatal(err)
			}
			version, _ := table.apply(changed[1:2], true)
			next, err := base.withSharedConnectivity(version)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			for b.Loop() {
				moved, err := current.withSharedConnectivity(next.sharedConnectivity)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := NewConnectivityDelta(current, moved); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func slicesWith(values []Connectivity, index int, value Connectivity) []Connectivity {
	copied := append([]Connectivity(nil), values...)
	copied[index] = value
	return copied
}
