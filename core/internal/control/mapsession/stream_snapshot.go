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
		equalPeerCandidates(next.peerCandidates, current.peerCandidates) &&
		next.packetPolicy.Equal(current.packetPolicy)
}

func streamSnapshotChanged(current, next Snapshot) bool {
	return current.NetworkRevision() != next.NetworkRevision() ||
		relayDirectoryChanged(current, next) ||
		!equalDirectDeviceProjections(current.directDeviceProjections, next.directDeviceProjections) ||
		!equalMapConnectivity(current.NodeID(), current.connectivity, next.connectivity)
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
