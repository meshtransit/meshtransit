package legacyts2021

import (
	"encoding/json"
	"slices"

	"tailscale.com/tailcfg"

	"github.com/meshtransit/meshtransit/internal/control/mapsession"
)

type connectivityDeltaMapResponseWire struct {
	Node         *tailcfg.Node   `json:"Node,omitempty"`
	PeersChanged []*tailcfg.Node `json:"PeersChanged,omitempty"`
}

// EncodeConnectivityDeltaMapResponse encodes one same-authority transient
// update. Changed peers are complete replacements so empty endpoints withdraw
// previous connectivity without omitted-field ambiguity.
func EncodeConnectivityDeltaMapResponse(
	delta mapsession.ConnectivityDelta,
	capabilityVersion int,
) ([]byte, error) {
	if !delta.IsValid() || capabilityVersion != supportedCapabilityVersion {
		return nil, ErrMapResponse
	}
	snapshot := delta.Snapshot()
	var self *tailcfg.Node
	var err error
	if delta.SelfChanged() {
		self, err = fullMapNode(snapshot, capabilityVersion)
		if err != nil {
			return nil, err
		}
	}
	changed := delta.ChangedPeers()
	peers := make([]*tailcfg.Node, 0, len(changed))
	for _, candidate := range changed {
		connectivity, found := snapshot.ConnectivityFor(candidate.NodeID())
		if !found {
			return nil, ErrMapResponse
		}
		peer, peerErr := fullMapPeer(
			candidate,
			connectivity,
			true,
			capabilityVersion,
		)
		if peerErr != nil {
			return nil, peerErr
		}
		peers = append(peers, peer)
	}
	slices.SortFunc(peers, func(first, second *tailcfg.Node) int {
		switch {
		case first.ID < second.ID:
			return -1
		case first.ID > second.ID:
			return 1
		default:
			return 0
		}
	})
	document, err := json.Marshal(connectivityDeltaMapResponseWire{
		Node:         self,
		PeersChanged: peers,
	})
	if err != nil {
		clear(document)
		return nil, ErrMapResponse
	}
	return encodeMapDocument(document)
}
