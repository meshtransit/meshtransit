package mapsession

import "slices"

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
		next.Hostname() == current.Hostname() &&
		slices.Equal(next.Addresses(), current.Addresses())
}
