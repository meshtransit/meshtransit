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
	peers := next.AuthorizedPeers()
	changedPeers := make([]PeerCandidate, 0, len(peers))
	for _, peer := range peers {
		if !equalProjectedConnectivity(current, next, peer.NodeID(), false) {
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
	authorized := delta.snapshot.AuthorizedPeers()
	if len(delta.changedPeers) > len(authorized) {
		return false
	}
	for index, peer := range delta.changedPeers {
		if !peer.IsValid() || index > 0 &&
			delta.changedPeers[index-1].NodeID().String() >= peer.NodeID().String() {
			return false
		}
		found := false
		for _, candidate := range authorized {
			if candidate.NodeID() == peer.NodeID() {
				found = equalPeerCandidates(
					[]PeerCandidate{candidate},
					[]PeerCandidate{peer},
				)
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func hasCompleteMapConnectivity(snapshot Snapshot) bool {
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
