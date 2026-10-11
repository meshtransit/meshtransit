package mapsession

import (
	"errors"
	"slices"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

// MaximumNetworkDevices bounds one Network inventory: the live Devices one
// Network revision may hold (scale-out target 100,000, with headroom).
const MaximumNetworkDevices = 200_000

// ErrInvalidInventory reports a Network inventory that is incomplete,
// mixed-scope, over its bound or holds a duplicate Device identity.
var ErrInvalidInventory = errors.New("map session: invalid network inventory")

// NetworkInventory is the validated, immutable list of one Network's live
// Devices at one revision. It is built and checked once and then shared by
// every Device's snapshot of that revision: a snapshot leaves its own Device
// out of its candidates instead of copying the list, so building a Device's
// snapshot no longer costs O(Devices) in copies and validation.
//
// Its zero value is invalid.
type NetworkInventory struct {
	inner *networkInventory
}

type networkInventory struct {
	scope      network.Scope
	candidates []PeerCandidate // sorted by node ID, each valid and in scope
	byNodeID   map[node.ID]int
	byNumeric  map[int64]int
	byMachine  map[node.MachineKey]int
	byNodeKey  map[node.Key]int
}

// NewNetworkInventory validates and indexes one Network's live Devices.
// Every Device must be valid, in scope and unique by node ID, numeric ID,
// machine key and node key.
func NewNetworkInventory(scope network.Scope, devices []PeerCandidate) (NetworkInventory, error) {
	inner, err := newNetworkInventory(scope, devices)
	if err != nil {
		return NetworkInventory{}, err
	}
	return NetworkInventory{inner: inner}, nil
}

func newNetworkInventory(scope network.Scope, devices []PeerCandidate) (*networkInventory, error) {
	if !scope.IsValid() || len(devices) > MaximumNetworkDevices {
		return nil, ErrInvalidInventory
	}
	candidates := canonicalPeerCandidates(devices)
	inventory := &networkInventory{
		scope:      scope,
		candidates: candidates,
		byNodeID:   make(map[node.ID]int, len(candidates)),
		byNumeric:  make(map[int64]int, len(candidates)),
		byMachine:  make(map[node.MachineKey]int, len(candidates)),
		byNodeKey:  make(map[node.Key]int, len(candidates)),
	}
	for index, candidate := range candidates {
		if !candidate.IsValid() || candidate.scope != scope {
			return nil, ErrInvalidInventory
		}
		if !inventory.claim(index, candidate) {
			return nil, ErrInvalidInventory
		}
	}
	return inventory, nil
}

// claim indexes candidate at index, reporting false on any duplicate identity.
func (inventory *networkInventory) claim(index int, candidate PeerCandidate) bool {
	if _, exists := inventory.byNodeID[candidate.nodeID]; exists {
		return false
	}
	if _, exists := inventory.byNumeric[candidate.numericNodeID]; exists {
		return false
	}
	if _, exists := inventory.byMachine[candidate.machineKey]; exists {
		return false
	}
	if _, exists := inventory.byNodeKey[candidate.nodeKey]; exists {
		return false
	}
	inventory.byNodeID[candidate.nodeID] = index
	inventory.byNumeric[candidate.numericNodeID] = index
	inventory.byMachine[candidate.machineKey] = index
	inventory.byNodeKey[candidate.nodeKey] = index
	return true
}

// IsValid reports whether the inventory was built by NewNetworkInventory.
func (inventory NetworkInventory) IsValid() bool { return inventory.inner != nil }

// Equal reports whether two inventories list the same Devices with the same
// facts (a reread of an unchanged Network).
func (inventory NetworkInventory) Equal(other NetworkInventory) bool {
	if inventory.inner == nil || other.inner == nil {
		return inventory.inner == other.inner
	}
	return inventory.inner == other.inner || inventory.inner.scope == other.inner.scope &&
		equalPeerCandidates(inventory.inner.candidates, other.inner.candidates)
}

// Same reports whether both are the very same inventory object.
func (inventory NetworkInventory) Same(other NetworkInventory) bool {
	return inventory.inner != nil && inventory.inner == other.inner
}

// Scope returns the inventory's exact Network scope.
func (inventory NetworkInventory) Scope() network.Scope {
	if inventory.inner == nil {
		return network.Scope{}
	}
	return inventory.inner.scope
}

// Len returns the number of live Devices.
func (inventory NetworkInventory) Len() int {
	if inventory.inner == nil {
		return 0
	}
	return len(inventory.inner.candidates)
}

// Device returns the live Device with nodeID.
func (inventory NetworkInventory) Device(nodeID node.ID) (PeerCandidate, bool) {
	if inventory.inner == nil {
		return PeerCandidate{}, false
	}
	index, found := inventory.inner.byNodeID[nodeID]
	if !found {
		return PeerCandidate{}, false
	}
	return inventory.inner.candidates[index], true
}

// snapshotCandidates is a snapshot's view of an inventory: every Device but
// self (self is index, or -1 when absent).
type snapshotCandidates struct {
	inventory *networkInventory
	self      int
	// shared marks a Network inventory shared between snapshots; a private
	// one was built from a snapshot's own candidate list.
	shared bool
}

// selfIdentity is what a snapshot must not share with any other candidate.
type selfIdentity struct {
	scope      network.Scope
	nodeID     node.ID
	numericID  int64
	machineKey node.MachineKey
	nodeKey    node.Key
}

// bindCandidates places self in inventory. A shared inventory may list self
// (it lists the whole Network), but then exactly as self; no other entry may
// share self's identity. A private inventory built from a candidate list must
// not list self at all.
func bindCandidates(inventory *networkInventory, self selfIdentity, shared bool) (snapshotCandidates, bool) {
	if inventory == nil || inventory.scope != self.scope {
		return snapshotCandidates{}, false
	}
	position := -1
	if index, found := inventory.byNodeID[self.nodeID]; found {
		entry := inventory.candidates[index]
		if !shared || entry.numericNodeID != self.numericID || entry.machineKey != self.machineKey ||
			entry.nodeKey != self.nodeKey {
			return snapshotCandidates{}, false
		}
		position = index
	}
	for _, hit := range []indexHit{
		lookupIndex(inventory.byNumeric, self.numericID),
		lookupIndex(inventory.byMachine, self.machineKey),
		lookupIndex(inventory.byNodeKey, self.nodeKey),
	} {
		if hit.found && hit.index != position {
			return snapshotCandidates{}, false
		}
	}
	return snapshotCandidates{inventory: inventory, self: position, shared: shared}, true
}

type indexHit struct {
	index int
	found bool
}

func lookupIndex[K comparable](index map[K]int, key K) indexHit {
	value, found := index[key]
	return indexHit{index: value, found: found}
}

// len returns the number of candidates (self excluded).
func (candidates snapshotCandidates) len() int {
	if candidates.inventory == nil {
		return 0
	}
	if candidates.self >= 0 {
		return len(candidates.inventory.candidates) - 1
	}
	return len(candidates.inventory.candidates)
}

// list returns a caller-owned, ordered copy of the candidates.
func (candidates snapshotCandidates) list() []PeerCandidate {
	if candidates.inventory == nil {
		return []PeerCandidate{}
	}
	all := candidates.inventory.candidates
	if candidates.self < 0 {
		return slices.Clone(all)
	}
	list := make([]PeerCandidate, 0, len(all)-1)
	list = append(list, all[:candidates.self]...)
	return append(list, all[candidates.self+1:]...)
}

// lookup returns the candidate with nodeID; self is never a candidate.
func (candidates snapshotCandidates) lookup(nodeID node.ID) (PeerCandidate, bool) {
	if candidates.inventory == nil {
		return PeerCandidate{}, false
	}
	index, found := candidates.inventory.byNodeID[nodeID]
	if !found || index == candidates.self {
		return PeerCandidate{}, false
	}
	return candidates.inventory.candidates[index], true
}

// each calls visit for every candidate in order until it returns false.
func (candidates snapshotCandidates) each(visit func(PeerCandidate) bool) {
	if candidates.inventory == nil {
		return
	}
	for index, candidate := range candidates.inventory.candidates {
		if index == candidates.self {
			continue
		}
		if !visit(candidate) {
			return
		}
	}
}

// equal reports whether two candidate views hold the same facts. Views of
// one inventory with self at the same place are equal without a scan.
func (candidates snapshotCandidates) equal(other snapshotCandidates) bool {
	if candidates.inventory == other.inventory && candidates.self == other.self {
		return true
	}
	return equalPeerCandidates(candidates.list(), other.list())
}

// privateList returns the candidate list of a private inventory, or nil for
// a shared one (params then carry the shared inventory, not a copy).
func (candidates snapshotCandidates) privateList() []PeerCandidate {
	if candidates.shared {
		return nil
	}
	return candidates.list()
}

// sharedInventory returns the shared Network inventory, if any.
func (candidates snapshotCandidates) sharedInventory() NetworkInventory {
	if !candidates.shared {
		return NetworkInventory{}
	}
	return NetworkInventory{inner: candidates.inventory}
}

// limit is the candidate ceiling: a whole shared Network inventory may hold
// up to MaximumNetworkDevices; a per-Device candidate list keeps the bound
// of the query that reads it.
func (candidates snapshotCandidates) limit() int {
	if candidates.shared {
		return MaximumNetworkDevices
	}
	return MaximumPeerCandidates
}

// WithInventory returns the snapshot with its candidates taken from the
// shared Network inventory instead of its own list, revalidating self and
// any direct projection against the whole Network. The store uses it to
// complete a Device's facts, read on their own, with the inventory read
// once for that exact revision.
func (snapshot Snapshot) WithInventory(inventory NetworkInventory) (Snapshot, error) {
	if !snapshot.valid || !inventory.IsValid() {
		return Snapshot{}, ErrInvalidSnapshot
	}
	params := snapshot.params()
	params.PeerCandidates, params.Inventory = nil, inventory
	next, err := NewSnapshot(params)
	if err != nil {
		return Snapshot{}, err
	}
	next.relayGrant = snapshot.relayGrant
	return next, nil
}
