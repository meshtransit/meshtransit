package mapsession

import (
	"slices"

	"github.com/meshtransit/meshtransit/internal/node"
)

func streamCanAdvance(current, next Snapshot) bool {
	if !current.IsValid() || !next.IsValid() ||
		next.NetworkRevision() < current.NetworkRevision() ||
		next.Scope() != current.Scope() || next.NodeID() != current.NodeID() ||
		next.NumericNodeID() != current.NumericNodeID() ||
		next.MachineKey() != current.MachineKey() || next.NodeKey() != current.NodeKey() ||
		next.RecoveryEpoch() != current.RecoveryEpoch() ||
		next.SessionGeneration() != current.SessionGeneration() ||
		!next.CreatedAt().Equal(current.CreatedAt()) ||
		!next.KeyExpiry().Equal(current.KeyExpiry()) {
		return false
	}
	if next.NetworkRevision() > current.NetworkRevision() {
		return true
	}
	return next.NumericOwnerID() == current.NumericOwnerID() &&
		next.NetworkName() == current.NetworkName() &&
		next.Hostname() == current.Hostname() &&
		slices.Equal(next.Addresses(), current.Addresses()) &&
		equalPeerCandidates(next.peerCandidates, current.peerCandidates) &&
		next.packetPolicy.Equal(current.packetPolicy)
}

func streamSnapshotChanged(current, next Snapshot) bool {
	return current.NetworkRevision() != next.NetworkRevision() ||
		!equalMapConnectivity(current.NodeID(), current.connectivity, next.connectivity)
}

func equalMapConnectivity(self node.ID, first, second []Connectivity) bool {
	return slices.EqualFunc(first, second, func(left, right Connectivity) bool {
		if left.key != right.key || left.endpointSetPresent != right.endpointSetPresent ||
			left.key.NodeID() != self && left.online != right.online {
			return false
		}
		return !left.endpointSetPresent || left.endpointSet.Equal(right.endpointSet)
	})
}

func streamTracksConnectivity(snapshot Snapshot, change ConnectivityChanged) bool {
	if !snapshot.IsValid() || !change.IsValid() {
		return false
	}
	key := change.Key()
	if key.NodeID() == snapshot.NodeID() {
		return change.Kind() == ConnectivityChangeEndpoints &&
			key.Generation() == snapshot.SessionGeneration()
	}
	for _, peer := range snapshot.AuthorizedPeers() {
		if peer.NodeID() == key.NodeID() {
			return peer.SessionGeneration() == key.Generation()
		}
	}
	return false
}
