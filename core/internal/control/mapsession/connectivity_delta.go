package mapsession

import (
	"errors"
	"slices"

	"meshtransit.net/core/internal/domain/node"
)

// ErrInvalidConnectivityDelta reports an empty update, incomplete transient
// projection, or attempted authority change encoded as connectivity-only.
var ErrInvalidConnectivityDelta = errors.New("map session: invalid connectivity delta")

// ConnectivityDelta is one immutable same-authority routing update. It names
// only self or authorized peers whose wire-visible transient state changed.
type ConnectivityDelta struct {
	snapshot      Snapshot
	isSelfChanged bool
	changedPeers  []PeerCandidate
}

// NewConnectivityDelta validates two complete same-revision projections and
// returns their bounded wire-visible connectivity difference.
func NewConnectivityDelta(current, next Snapshot) (ConnectivityDelta, error) {
	if !current.IsValid() || !next.IsValid() ||
		current.NetworkRevision() != next.NetworkRevision() ||
		!streamCanAdvance(current, next) ||
		relayDirectoryChanged(current, next) ||
		!equalDirectDeviceProjections(current.directDeviceProjections, next.directDeviceProjections) ||
		!hasCompleteMapConnectivity(current) || !hasCompleteMapConnectivity(next) {
		return ConnectivityDelta{}, ErrInvalidConnectivityDelta
	}

	isSelfChanged := !equalProjectedConnectivity(
		current,
		next,
		current.NodeID(),
		true,
	)
	changedPeers := make([]PeerCandidate, 0, 1)
	for _, nodeID := range connectivityCandidates(current, next) {
		if nodeID == next.nodeID {
			continue
		}
		peer, authorized := next.authorizedPeer(nodeID)
		if authorized && !equalProjectedConnectivity(current, next, nodeID, false) {
			changedPeers = append(changedPeers, peer)
		}
	}
	if !isSelfChanged && len(changedPeers) == 0 {
		return ConnectivityDelta{}, ErrInvalidConnectivityDelta
	}

	return ConnectivityDelta{
		snapshot:      next,
		isSelfChanged: isSelfChanged,
		changedPeers:  changedPeers,
	}, nil
}

// Snapshot returns the complete post-update projection. Its accessors retain
// ownership of mutable collections.
func (delta ConnectivityDelta) Snapshot() Snapshot { return delta.snapshot }

// SelfChanged reports whether self routing observations changed.
// Self presence is intentionally not client-visible.
func (delta ConnectivityDelta) SelfChanged() bool { return delta.isSelfChanged }

// ChangedPeers returns complete authorized peer identities for each changed
// endpoint, discovery-key, or online projection.
func (delta ConnectivityDelta) ChangedPeers() []PeerCandidate {
	return slices.Clone(delta.changedPeers)
}

// IsValid reports whether the delta is bounded, complete, and encodable without
// changing durable authority.
func (delta ConnectivityDelta) IsValid() bool {
	if !delta.snapshot.IsValid() || !hasCompleteMapConnectivity(delta.snapshot) ||
		!delta.isSelfChanged && len(delta.changedPeers) == 0 {
		return false
	}
	if len(delta.changedPeers) > len(delta.snapshot.authorized) {
		return false
	}
	for index, peer := range delta.changedPeers {
		if !peer.IsValid() || index > 0 &&
			compareNodeIDs(delta.changedPeers[index-1].nodeID, peer.nodeID) >= 0 {
			return false
		}
		candidate, found := delta.snapshot.authorizedPeer(peer.nodeID)
		if !found || !equalPeerCandidates([]PeerCandidate{candidate}, []PeerCandidate{peer}) {
			return false
		}
	}
	return true
}

// connectivityCandidates returns, sorted, the Nodes whose connectivity may
// differ between current and next: the change log between two versions of
// one shared table, or else self and every authorized peer of next.
func connectivityCandidates(current, next Snapshot) []node.ID {
	if from, to := current.sharedConnectivity, next.sharedConnectivity; from != nil && to != nil {
		if changed, ok := from.changesTo(to); ok {
			return changed
		}
	}
	candidates := make([]node.ID, 0, len(next.authorized)+1)
	for _, peer := range next.authorized {
		candidates = append(candidates, peer.nodeID)
	}
	position, _ := slices.BinarySearchFunc(candidates, next.nodeID, compareNodeIDs)
	return slices.Insert(candidates, position, next.nodeID)
}

func hasCompleteMapConnectivity(snapshot Snapshot) bool {
	if snapshot.sharedConnectivity != nil {
		return true // every self or peer lookup answers, offline when unreported
	}
	if _, found := snapshot.ConnectivityFor(snapshot.NodeID()); !found {
		return false
	}
	peers := snapshot.AuthorizedPeers()
	if len(snapshot.connectivity) != len(peers)+1 {
		return false
	}
	for _, peer := range peers {
		if _, found := snapshot.ConnectivityFor(peer.NodeID()); !found {
			return false
		}
	}
	return true
}

func equalProjectedConnectivity(
	current Snapshot,
	next Snapshot,
	nodeID node.ID,
	self bool,
) bool {
	currentValue, currentFound := current.ConnectivityFor(nodeID)
	nextValue, nextFound := next.ConnectivityFor(nodeID)
	if currentFound != nextFound || !currentFound {
		return currentFound == nextFound
	}
	if !self {
		return currentValue.equal(nextValue)
	}
	if currentValue.key != nextValue.key ||
		currentValue.endpointSetPresent != nextValue.endpointSetPresent ||
		currentValue.preferredRelay != nextValue.preferredRelay ||
		currentValue.preferredRelayPresent != nextValue.preferredRelayPresent {
		return false
	}
	return !currentValue.endpointSetPresent ||
		currentValue.endpointSet.Equal(nextValue.endpointSet)
}
