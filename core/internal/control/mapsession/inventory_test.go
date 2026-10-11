package mapsession

import (
	"errors"
	"fmt"
	"slices"
	"testing"
)

// selfAsCandidate is self expressed as an inventory entry.
func selfAsCandidate(t testing.TB, params SnapshotParams, ownerOf PeerCandidate) PeerCandidate {
	t.Helper()
	self, err := NewPeerCandidate(PeerCandidateParams{
		NumericNodeID: params.NumericNodeID, NumericOwnerID: params.NumericOwnerID, Scope: params.Scope,
		NodeID: params.NodeID, OwnerID: ownerOf.OwnerID(), Hostname: params.Hostname, MachineKey: params.MachineKey,
		NodeKey: params.NodeKey, SessionGeneration: params.SessionGeneration, Addresses: params.Addresses,
		CreatedAt: params.CreatedAt, KeyExpiry: params.KeyExpiry,
	})
	if err != nil {
		t.Fatal(err)
	}
	return self
}

// A snapshot built from the shared Network inventory (self included) must
// equal one built from the candidate list without self.
func TestSnapshotFromInventoryEqualsSnapshotFromCandidates(t *testing.T) {
	t.Parallel()
	params, candidates := largeNetworkFixture(t, 300, 40)
	reference, err := NewSnapshot(params)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := NewNetworkInventory(params.Scope, append(slices.Clone(candidates), selfAsCandidate(t, params, candidates[0])))
	if err != nil {
		t.Fatal(err)
	}
	shared := params
	shared.PeerCandidates, shared.Inventory = nil, inventory
	derived, err := NewSnapshot(shared)
	if err != nil {
		t.Fatal(err)
	}
	if !equalPeerCandidates(derived.PeerCandidates(), reference.PeerCandidates()) ||
		!equalPeerCandidates(derived.AuthorizedPeers(), reference.AuthorizedPeers()) || len(derived.AuthorizedPeers()) != 40 {
		t.Fatalf("derived snapshot differs: %d candidates, %d peers", len(derived.PeerCandidates()), len(derived.AuthorizedPeers()))
	}
	for _, candidate := range derived.PeerCandidates() {
		if candidate.NodeID() == derived.NodeID() {
			t.Fatal("self listed among its own candidates")
		}
	}
	if !streamCanAdvance(reference, derived) || !streamCanAdvance(derived, reference) {
		t.Fatal("equal snapshots cannot advance to each other")
	}
	// Derived copies keep sharing the inventory instead of copying it.
	next, err := derived.WithConnectivity(nil)
	if err != nil {
		t.Fatal(err)
	}
	if next.candidates.inventory != derived.candidates.inventory || !next.candidates.shared {
		t.Fatal("a derived snapshot copied the shared inventory")
	}
}

func TestWithInventoryEqualsTheCandidateRead(t *testing.T) {
	t.Parallel()
	params, candidates := largeNetworkFixture(t, 50, 10)
	reference, err := NewSnapshot(params)
	if err != nil {
		t.Fatal(err)
	}
	own := params
	own.PeerCandidates = []PeerCandidate{}
	alone, err := NewSnapshot(own)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := NewNetworkInventory(params.Scope, append(slices.Clone(candidates), selfAsCandidate(t, params, candidates[0])))
	if err != nil {
		t.Fatal(err)
	}
	completed, err := alone.WithInventory(inventory)
	if err != nil {
		t.Fatal(err)
	}
	if !equalPeerCandidates(completed.AuthorizedPeers(), reference.AuthorizedPeers()) ||
		!equalPeerCandidates(completed.PeerCandidates(), reference.PeerCandidates()) {
		t.Fatal("completing with the inventory differs from reading the candidates")
	}
	if _, err := alone.WithInventory(NetworkInventory{}); err == nil {
		t.Fatal("an invalid inventory was accepted")
	}
}

func TestSnapshotRejectsAnInventoryThatContradictsSelf(t *testing.T) {
	t.Parallel()
	params, candidates := largeNetworkFixture(t, 5, 1)
	self := selfAsCandidate(t, params, candidates[0])
	// Another Device holding self's node key.
	collided := candidates[1].params()
	collided.NodeKey = params.NodeKey
	collidingPeer, err := NewPeerCandidate(collided)
	if err != nil {
		t.Fatal(err)
	}
	list := slices.Clone(candidates)
	list[1] = collidingPeer
	inventory, err := NewNetworkInventory(params.Scope, append(list, self))
	if err == nil {
		shared := params
		shared.PeerCandidates, shared.Inventory = nil, inventory
		if _, err := NewSnapshot(shared); err == nil {
			t.Fatal("a Device sharing self's node key was accepted")
		}
	}
	// Self listed with a different numeric ID.
	wrong := self.params()
	wrong.NumericNodeID = 999_999
	wrongSelf, err := NewPeerCandidate(wrong)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err = NewNetworkInventory(params.Scope, append(slices.Clone(candidates), wrongSelf))
	if err != nil {
		t.Fatal(err)
	}
	shared := params
	shared.PeerCandidates, shared.Inventory = nil, inventory
	if _, err := NewSnapshot(shared); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("an inventory contradicting self was accepted: %v", err)
	}
	// A private candidate list may not list self at all.
	private := params
	private.PeerCandidates = append(slices.Clone(candidates), self)
	if _, err := NewSnapshot(private); err == nil {
		t.Fatal("a candidate list containing self was accepted")
	}
}

func TestNetworkInventoryRejectsDuplicates(t *testing.T) {
	t.Parallel()
	params, candidates := largeNetworkFixture(t, 3, 0)
	if _, err := NewNetworkInventory(params.Scope, append(slices.Clone(candidates), candidates[0])); !errors.Is(err, ErrInvalidInventory) {
		t.Fatalf("duplicate Device accepted: %v", err)
	}
	if (NetworkInventory{}).IsValid() || (NetworkInventory{}).Len() != 0 {
		t.Fatal("zero inventory is usable")
	}
	inventory, err := NewNetworkInventory(params.Scope, candidates)
	if err != nil || inventory.Len() != 3 {
		t.Fatalf("NewNetworkInventory() = %d, %v", inventory.Len(), err)
	}
	if got, found := inventory.Device(candidates[2].NodeID()); !found || got.NodeID() != candidates[2].NodeID() {
		t.Fatal("Device() lookup failed")
	}
}

// BenchmarkSnapshotFromInventory measures a stream refresh on the shared
// inventory: per Device, no copy or validation of the Network's Devices.
func BenchmarkSnapshotFromInventory(b *testing.B) {
	for _, size := range []struct{ devices, peers int }{{10000, 50}, {10000, 500}, {100000, 500}} {
		b.Run(fmt.Sprintf("devices=%d/peers=%d", size.devices, size.peers), func(b *testing.B) {
			params, candidates := largeNetworkFixture(b, size.devices, size.peers)
			inventory, err := NewNetworkInventory(params.Scope, append(candidates, selfAsCandidate(b, params, candidates[0])))
			if err != nil {
				b.Fatal(err)
			}
			params.PeerCandidates, params.Inventory = nil, inventory
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				snapshot, err := NewSnapshot(params)
				if err != nil {
					b.Fatal(err)
				}
				if !snapshot.IsValid() || len(snapshot.AuthorizedPeers()) != size.peers {
					b.Fatal("unexpected snapshot")
				}
			}
		})
	}
}
