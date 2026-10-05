package legacyts2021

import (
	"encoding/json"
	"slices"

	"tailscale.com/tailcfg"

	"github.com/meshtransit/meshtransit/internal/control/mapsession"
	"github.com/meshtransit/meshtransit/internal/node"
)

type authorityDeltaMapResponseWire struct {
	Node         *tailcfg.Node        `json:"Node,omitempty"`
	PeersChanged []*tailcfg.Node      `json:"PeersChanged,omitempty"`
	PeersRemoved []tailcfg.NodeID     `json:"PeersRemoved,omitempty"`
	PacketFilter []tailcfg.FilterRule `json:"PacketFilter"`
	DNSConfig    *tailcfg.DNSConfig   `json:"DNSConfig"`
}

// EncodeAuthorityDeltaMapResponse encodes one contiguous durable authority
// update. Peer additions, replacements, removals, and the complete packet
// filter share one frame so clients apply the transition atomically.
func EncodeAuthorityDeltaMapResponse(
	delta mapsession.AuthorityDelta,
	capabilityVersion int,
) ([]byte, error) {
	return encodeAuthorityDeltaMapResponse(
		delta,
		capabilityVersion,
		mapResponseCompressionZstd,
	)
}

func encodeAuthorityDeltaMapResponse(
	delta mapsession.AuthorityDelta,
	capabilityVersion int,
	compression mapResponseCompression,
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
			snapshot,
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
	slices.SortFunc(peers, compareMapNodeIDs)

	removedNumericIDs := delta.RemovedPeerNumericIDs()
	removed := make([]tailcfg.NodeID, 0, len(removedNumericIDs))
	for _, numericID := range removedNumericIDs {
		removed = append(removed, tailcfg.NodeID(numericID))
	}

	authorized := snapshot.AuthorizedPeers()
	candidates := make(map[node.ID]mapsession.PeerCandidate, len(authorized))
	for _, candidate := range authorized {
		candidates[candidate.NodeID()] = candidate
	}
	packetFilter, err := fullMapPacketFilter(snapshot, candidates)
	if err != nil {
		return nil, err
	}
	dnsConfig, err := mapDNSConfig(snapshot)
	if err != nil {
		return nil, err
	}
	document, err := json.Marshal(authorityDeltaMapResponseWire{
		Node:         self,
		PeersChanged: peers,
		PeersRemoved: removed,
		PacketFilter: packetFilter,
		DNSConfig:    dnsConfig,
	})
	if err != nil {
		clear(document)
		return nil, ErrMapResponse
	}
	return encodeMapDocument(document, compression)
}

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
	return encodeConnectivityDeltaMapResponse(
		delta,
		capabilityVersion,
		mapResponseCompressionZstd,
	)
}

func encodeConnectivityDeltaMapResponse(
	delta mapsession.ConnectivityDelta,
	capabilityVersion int,
	compression mapResponseCompression,
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
			snapshot,
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
	slices.SortFunc(peers, compareMapNodeIDs)
	document, err := json.Marshal(connectivityDeltaMapResponseWire{
		Node:         self,
		PeersChanged: peers,
	})
	if err != nil {
		clear(document)
		return nil, ErrMapResponse
	}
	return encodeMapDocument(document, compression)
}

func compareMapNodeIDs(first, second *tailcfg.Node) int {
	switch {
	case first.ID < second.ID:
		return -1
	case first.ID > second.ID:
		return 1
	default:
		return 0
	}
}
