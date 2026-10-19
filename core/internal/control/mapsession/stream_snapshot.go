package mapsession

import (
	"slices"

	"meshtransit.net/core/internal/domain/node"
)

func streamCanAdvance(current, next Snapshot) bool {
	if !current.IsValid() || !next.IsValid() ||
		next.NetworkRevision() < current.NetworkRevision() ||
		next.PacketPolicy().Revision() < current.PacketPolicy().Revision() ||
		next.Scope() != current.Scope() || next.NodeID() != current.NodeID() ||
		next.NumericNodeID() != current.NumericNodeID() ||
		next.MachineKey() != current.MachineKey() || next.NodeKey() != current.NodeKey() ||
		next.RecoveryEpoch() != current.RecoveryEpoch() ||
		next.SessionGeneration() != current.SessionGeneration() ||
		!next.CreatedAt().Equal(current.CreatedAt()) ||
		!relayDirectoryCanAdvance(current, next) || !directDeviceProjectionsCanAdvance(current, next) {
		return false
	}
	if next.NetworkRevision() > current.NetworkRevision() {
		return true
	}
	// A new deadline always comes with a new revision (transfer, extension).
	return next.KeyExpiry().Equal(current.KeyExpiry()) &&
		next.NumericOwnerID() == current.NumericOwnerID() &&
		next.NetworkName() == current.NetworkName() &&
		next.Hostname() == current.Hostname() &&
		slices.Equal(next.Addresses(), current.Addresses()) &&
		next.candidates.equal(current.candidates) &&
		next.packetPolicy.Equal(current.packetPolicy)
}

func streamSnapshotChanged(current, next Snapshot) bool {
	return current.NetworkRevision() != next.NetworkRevision() ||
		relayDirectoryChanged(current, next) ||
		!equalDirectDeviceProjections(current.directDeviceProjections, next.directDeviceProjections) ||
		!current.routes.Equal(next.routes) ||
		!sameMapConnectivity(current, next)
}

// sameMapConnectivity reports whether two maps show the same transient
// state; between two versions of one shared table it compares only the
// Nodes the change log names.
func sameMapConnectivity(current, next Snapshot) bool {
	if current.sharedConnectivity == nil && next.sharedConnectivity == nil {
		return equalMapConnectivity(current.NodeID(), current.connectivity, next.connectivity)
	}
	for _, nodeID := range connectivityCandidates(current, next) {
		if !equalProjectedConnectivity(current, next, nodeID, nodeID == current.nodeID) {
			return false
		}
	}
	return true
}

func relayDirectoryCanAdvance(current, next Snapshot) bool {
	currentDirectory := current.RelayDirectory()
	nextDirectory := next.RelayDirectory()
	if nextDirectory.Revision() < currentDirectory.Revision() {
		return false
	}
	return nextDirectory.Revision() != currentDirectory.Revision() ||
		nextDirectory.Fingerprint() == currentDirectory.Fingerprint()
}

func relayDirectoryChanged(current, next Snapshot) bool {
	currentDirectory := current.RelayDirectory()
	nextDirectory := next.RelayDirectory()
	return nextDirectory.Revision() != currentDirectory.Revision() ||
		nextDirectory.Fingerprint() != currentDirectory.Fingerprint()
}

// equalMapConnectivity compares what a map shows of each node's transient
// state: endpoints, home relay and, for peers, presence. A home relay change
// alone must reach the node (its data plane follows it) and its peers.
func equalMapConnectivity(self node.ID, first, second []Connectivity) bool {
	return slices.EqualFunc(first, second, func(left, right Connectivity) bool {
		if left.key != right.key || left.endpointSetPresent != right.endpointSetPresent ||
			left.preferredRelay != right.preferredRelay ||
			left.preferredRelayPresent != right.preferredRelayPresent ||
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
	peer, found := snapshot.authorizedPeer(key.NodeID())
	return found && peer.SessionGeneration() == key.Generation()
}
