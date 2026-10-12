//go:build windows

package netwatch

import "meshtransit.net/client/internal/winadapter"

// ignorePointToPoint is false: the Wintun adapter is recognised by its GUID.
const ignorePointToPoint = false

// platformExcludedIndexes returns the MeshTransit adapter's index. It is
// found by the adapter's fixed GUID, so renaming the adapter in Network
// Connections does not make meshd's own address changes look like a host
// network change.
func platformExcludedIndexes() []int {
	index, ok := winadapter.Index()
	if !ok {
		return nil
	}

	return []int{index}
}
