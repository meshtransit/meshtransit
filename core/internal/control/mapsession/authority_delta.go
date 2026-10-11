package mapsession

import (
	"errors"
	"slices"

	"meshtransit.net/core/internal/domain/node"
)

// ErrInvalidAuthorityDelta reports a non-contiguous, incomplete, or ambiguous
// attempt to delta-encode durable map authority.
var ErrInvalidAuthorityDelta = errors.New("map session: invalid authority delta")

// AuthorityDelta is one immutable contiguous authority update. It carries a
// complete post-update policy plus complete replacements for every changed or
// newly authorized peer, so adapters can publish one atomic wire frame.
type AuthorityDelta struct {
	current               Snapshot
	snapshot              Snapshot
	isSelfChanged         bool
	changedPeers          []PeerCandidate
	removedPeerNumericIDs []int64
}

// NewAuthorityDelta validates two complete consecutive projections and
// computes their bounded client-visible difference. Self authority must remain
// stable; coincident transient connectivity changes are included.
func NewAuthorityDelta(current, next Snapshot) (AuthorityDelta, error) {
	isSelfChanged, changedPeers, removedPeerNumericIDs, err := projectAuthorityDelta(
		current,
		next,
	)
	if err != nil {
		return AuthorityDelta{}, err
	}
	return AuthorityDelta{
		current:               current,
		snapshot:              next,
		isSelfChanged:         isSelfChanged,
		changedPeers:          changedPeers,
		removedPeerNumericIDs: removedPeerNumericIDs,
	}, nil
}

// Snapshot returns the complete post-update projection.
func (delta AuthorityDelta) Snapshot() Snapshot { return delta.snapshot }

// SelfChanged reports whether self routing observations changed with the
// authority revision. Self durable authority is never delta-encoded.
func (delta AuthorityDelta) SelfChanged() bool { return delta.isSelfChanged }

// ChangedPeers returns complete replacements for added or changed peers,
// ordered by stable numeric wire identifier.
func (delta AuthorityDelta) ChangedPeers() []PeerCandidate {
	return slices.Clone(delta.changedPeers)
}

// RemovedPeerNumericIDs returns withdrawn wire peer identifiers in ascending
// order. The result never aliases delta-owned storage.
func (delta AuthorityDelta) RemovedPeerNumericIDs() []int64 {
	return slices.Clone(delta.removedPeerNumericIDs)
}

// IsValid reports whether the delta exactly represents its immutable before
// and after snapshots without numeric peer-ID ambiguity.
func (delta AuthorityDelta) IsValid() bool {
	isSelfChanged, changedPeers, removedPeerNumericIDs, err := projectAuthorityDelta(
		delta.current,
		delta.snapshot,
	)
	return err == nil && isSelfChanged == delta.isSelfChanged &&
		equalPeerCandidates(changedPeers, delta.changedPeers) &&
		slices.Equal(removedPeerNumericIDs, delta.removedPeerNumericIDs)
}

func projectAuthorityDelta(
	current Snapshot,
	next Snapshot,
) (bool, []PeerCandidate, []int64, error) {
	// The next revision, or the same one when only a peer limit's subset
	// changed.
	sameRevisionSubset := next.NetworkRevision() == current.NetworkRevision() &&
		(current.authorizedTotal != 0 || next.authorizedTotal != 0) && !sameAuthorizedPeers(current, next)
	if !streamCanAdvance(current, next) ||
		(next.NetworkRevision() != current.NetworkRevision()+1 && !sameRevisionSubset) ||
		relayDirectoryChanged(current, next) ||
		!stableSelfAuthority(current, next) ||
		!hasCompleteMapConnectivity(current) || !hasCompleteMapConnectivity(next) {
		return false, nil, nil, ErrInvalidAuthorityDelta
	}

	currentPeers := current.AuthorizedPeers()
	nextPeers := next.AuthorizedPeers()
	if current.PacketPolicy().Equal(next.PacketPolicy()) &&
		equalDirectDeviceProjections(current.directDeviceProjections, next.directDeviceProjections) &&
		equalPeerCandidates(currentPeers, nextPeers) {
		return false, nil, nil, ErrInvalidAuthorityDelta
	}
	currentByID := make(map[node.ID]PeerCandidate, len(currentPeers))
	nextByID := make(map[node.ID]PeerCandidate, len(nextPeers))
	for _, peer := range currentPeers {
		currentByID[peer.NodeID()] = peer
	}
	for _, peer := range nextPeers {
		nextByID[peer.NodeID()] = peer
	}

	changedPeers := make([]PeerCandidate, 0, len(nextPeers))
	changedNumericIDs := make(map[int64]struct{}, len(nextPeers))
	for _, peer := range nextPeers {
		currentPeer, found := currentByID[peer.NodeID()]
		isConnectivityChanged := found && !equalProjectedConnectivity(
			current,
			next,
			peer.NodeID(),
			false,
		)
		if found && equalPeerCandidate(currentPeer, peer) && !isConnectivityChanged && !aliasGrantChanged(current, next, peer.NodeID()) {
			continue
		}
		changedPeers = append(changedPeers, peer)
		changedNumericIDs[peer.NumericNodeID()] = struct{}{}
	}
	slices.SortFunc(changedPeers, compareNumericPeerIDs)

	removedPeerNumericIDs := make([]int64, 0, len(currentPeers))
	for _, peer := range currentPeers {
		nextPeer, found := nextByID[peer.NodeID()]
		if found && nextPeer.NumericNodeID() == peer.NumericNodeID() {
			continue
		}
		removedPeerNumericIDs = append(removedPeerNumericIDs, peer.NumericNodeID())
	}
	slices.Sort(removedPeerNumericIDs)
	for _, numericID := range removedPeerNumericIDs {
		if _, collides := changedNumericIDs[numericID]; collides {
			return false, nil, nil, ErrInvalidAuthorityDelta
		}
	}

	return !equalProjectedConnectivity(current, next, current.NodeID(), true),
		changedPeers,
		removedPeerNumericIDs,
		nil
}

func stableSelfAuthority(current, next Snapshot) bool {
	return current.KeyExpiry().Equal(next.KeyExpiry()) &&
		current.NumericOwnerID() == next.NumericOwnerID() &&
		current.NetworkName() == next.NetworkName() &&
		current.Hostname() == next.Hostname() &&
		slices.Equal(current.Addresses(), next.Addresses())
}

func equalPeerCandidate(first, second PeerCandidate) bool {
	return equalPeerCandidates(
		[]PeerCandidate{first},
		[]PeerCandidate{second},
	)
}

func compareNumericPeerIDs(first, second PeerCandidate) int {
	switch {
	case first.NumericNodeID() < second.NumericNodeID():
		return -1
	case first.NumericNodeID() > second.NumericNodeID():
		return 1
	default:
		return 0
	}
}
