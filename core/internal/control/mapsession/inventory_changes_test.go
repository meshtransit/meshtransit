package mapsession

import (
	"errors"
	"testing"
	"time"
)

func TestInventoryWithoutChangesIsTheSameObject(t *testing.T) {
	t.Parallel()
	params, candidates := largeNetworkFixture(t, 4, 0)
	inventory, err := NewNetworkInventory(params.Scope, candidates)
	if err != nil {
		t.Fatal(err)
	}
	next, err := inventory.WithChanges(nil, candidates[0].CreatedAt())
	if err != nil || !next.Same(inventory) {
		t.Fatalf("WithChanges(nil) = new inventory (err %v), want the same object", err)
	}
}

func TestInventoryAppliesChangesInOrder(t *testing.T) {
	t.Parallel()
	params, candidates := largeNetworkFixture(t, 5, 0)
	inventory, err := NewNetworkInventory(params.Scope, candidates[:4])
	if err != nil {
		t.Fatal(err)
	}
	now := candidates[0].CreatedAt()
	next, err := inventory.WithChanges([]InventoryChange{
		{NumericNodeID: candidates[4].NumericNodeID(), Device: candidates[4]}, // joined
		{NumericNodeID: candidates[0].NumericNodeID(), Removed: true},         // revoked
		{NumericNodeID: candidates[1].NumericNodeID(), Removed: true},         // revoked, then
		{NumericNodeID: candidates[1].NumericNodeID(), Device: candidates[1]}, // restored
		{NumericNodeID: 1 << 40, Removed: true},                               // never listed
		{NumericNodeID: candidates[2].NumericNodeID(), Device: candidates[2]}, // unchanged row
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if next.Same(inventory) || next.Len() != 4 {
		t.Fatalf("Len() = %d, want 4 in a new inventory", next.Len())
	}
	if _, found := next.Device(candidates[0].NodeID()); found {
		t.Fatal("a removed Device is still listed")
	}
	for _, kept := range []PeerCandidate{candidates[1], candidates[2], candidates[3], candidates[4]} {
		if _, found := next.Device(kept.NodeID()); !found {
			t.Fatalf("Device %d missing", kept.NumericNodeID())
		}
	}
	reference, err := NewNetworkInventory(params.Scope, candidates[1:])
	if err != nil || !next.Equal(reference) {
		t.Fatalf("result differs from a full read of the same Devices (err %v)", err)
	}
}

func TestInventoryDropsExpiredDevices(t *testing.T) {
	t.Parallel()
	params, candidates := largeNetworkFixture(t, 3, 0)
	inventory, err := NewNetworkInventory(params.Scope, candidates)
	if err != nil {
		t.Fatal(err)
	}
	// candidates[1] expires one second after candidates[0].
	next, err := inventory.WithChanges(nil, candidates[0].KeyExpiry())
	if err != nil || next.Same(inventory) || next.Len() != 2 {
		t.Fatalf("WithChanges at the first expiry = %d Devices (err %v), want 2", next.Len(), err)
	}
	if _, found := next.Device(candidates[0].NodeID()); found {
		t.Fatal("an expired Device is still listed")
	}
	joined, err := inventory.WithChanges([]InventoryChange{
		{NumericNodeID: candidates[2].NumericNodeID(), Device: candidates[2]},
	}, candidates[2].KeyExpiry().Add(time.Second))
	if err != nil || joined.Len() != 0 {
		t.Fatalf("an expired change was listed: %d Devices (err %v)", joined.Len(), err)
	}
}

func TestInventoryRejectsInvalidChanges(t *testing.T) {
	t.Parallel()
	params, candidates := largeNetworkFixture(t, 3, 0)
	inventory, err := NewNetworkInventory(params.Scope, candidates[:2])
	if err != nil {
		t.Fatal(err)
	}
	now := candidates[0].CreatedAt()
	for name, changes := range map[string][]InventoryChange{
		"numeric ID mismatch": {{NumericNodeID: candidates[2].NumericNodeID() + 1, Device: candidates[2]}},
		"no Device":           {{NumericNodeID: candidates[2].NumericNodeID()}},
		"zero numeric ID":     {{NumericNodeID: 0, Removed: true}},
	} {
		if _, err := inventory.WithChanges(changes, now); !errors.Is(err, ErrInvalidInventory) {
			t.Errorf("%s: err = %v, want ErrInvalidInventory", name, err)
		}
	}
	if _, err := (NetworkInventory{}).WithChanges(nil, now); !errors.Is(err, ErrInvalidInventory) {
		t.Errorf("zero inventory: err = %v", err)
	}
}
