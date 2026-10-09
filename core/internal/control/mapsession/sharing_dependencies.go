package mapsession

import (
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"strings"
)

// WithSharingDependencies attaches bounded, authoritative accepted-contract
// scopes used only to refresh this snapshot when the first consumer rule appears.
// It never adds a peer or a packet rule.
func (snapshot Snapshot) WithSharingDependencies(scopes []network.Scope) (Snapshot, error) {
	params := snapshot.params()
	params.SharingDependencies = scopes
	return NewSnapshot(params)
}

func compareSharingScopes(left, right network.Scope) int {
	return strings.Compare(left.NetworkID().String(), right.NetworkID().String())
}

func validSharingDependencies(params SnapshotParams) bool {
	if len(params.SharingDependencies) > MaximumDirectDeviceProjections {
		return false
	}
	seen := make(map[network.ID]network.Scope, len(params.SharingDependencies)+len(params.DirectDeviceProjections))
	for _, scope := range params.SharingDependencies {
		if !scope.IsValid() || scope.NetworkID() == params.Scope.NetworkID() {
			return false
		}
		if _, exists := seen[scope.NetworkID()]; exists {
			return false
		}
		seen[scope.NetworkID()] = scope
	}
	for _, projection := range params.DirectDeviceProjections {
		scope := projection.Peer().Scope()
		if previous, exists := seen[scope.NetworkID()]; exists && previous != scope {
			return false
		}
		seen[scope.NetworkID()] = scope
	}
	return len(seen) <= MaximumDirectDeviceProjections
}
