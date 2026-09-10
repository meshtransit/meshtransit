package dataplane

import (
	"encoding/hex"
	"errors"
	"net/netip"
	"strconv"
	"strings"

	"github.com/meshtransit/meshd/internal/relay"
)

const relayEndpointPrefix = "relay:"

type relayEndpoint struct {
	regionID int
	peerKey  relay.Key
	peerIP   netip.Addr
}

func (*relayEndpoint) ClearSrc() {}

func (*relayEndpoint) SrcToString() string { return "" }

func (e *relayEndpoint) DstToString() string {
	if e == nil {
		return ""
	}

	return formatRelayEndpoint(e.regionID, e.peerKey)
}

func (e *relayEndpoint) DstToBytes() []byte {
	if e == nil {
		return nil
	}

	return []byte(e.DstToString())
}

func (e *relayEndpoint) DstIP() netip.Addr {
	if e == nil {
		return netip.Addr{}
	}

	return e.peerIP
}

func (*relayEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

func formatRelayEndpoint(regionID int, peerKey relay.Key) string {
	return relayEndpointPrefix + strconv.Itoa(regionID) + ":" + hex.EncodeToString(peerKey[:])
}

func parseRelayEndpoint(value string, pool *relay.Pool) (*relayEndpoint, error) {
	if pool == nil || !strings.HasPrefix(value, relayEndpointPrefix) {
		return nil, errors.New("dataplane: relay endpoint is unavailable")
	}
	regionText, keyText, found := strings.Cut(
		strings.TrimPrefix(value, relayEndpointPrefix),
		":",
	)
	if !found || regionText == "" || len(keyText) != 64 || keyText != strings.ToLower(keyText) {
		return nil, errors.New("dataplane: relay endpoint is malformed")
	}
	regionValue, err := strconv.ParseUint(regionText, 10, 31)
	if err != nil || regionValue == 0 || strconv.FormatUint(regionValue, 10) != regionText {
		return nil, errors.New("dataplane: relay region is malformed")
	}
	var peerKey relay.Key
	if _, err := hex.Decode(peerKey[:], []byte(keyText)); err != nil || peerKey == (relay.Key{}) {
		return nil, errors.New("dataplane: relay peer key is malformed")
	}
	peer, peerExists := pool.Peer(peerKey)
	_, regionExists := pool.Region(int(regionValue))
	if !peerExists || !regionExists || peer.HomeRegion != int(regionValue) {
		return nil, errors.New("dataplane: relay endpoint is unauthorized")
	}

	return &relayEndpoint{
		regionID: int(regionValue),
		peerKey:  peerKey,
		peerIP:   peer.Address,
	}, nil
}

func receivedRelayEndpoint(packet relay.Packet, pool *relay.Pool) (*relayEndpoint, error) {
	if pool == nil || packet.RegionID <= 0 || packet.Source == (relay.Key{}) {
		return nil, errors.New("dataplane: received relay endpoint is invalid")
	}
	peer, peerExists := pool.Peer(packet.Source)
	_, regionExists := pool.Region(packet.RegionID)
	if !peerExists || !regionExists {
		return nil, errors.New("dataplane: received relay endpoint is unauthorized")
	}

	return &relayEndpoint{
		regionID: packet.RegionID,
		peerKey:  packet.Source,
		peerIP:   peer.Address,
	}, nil
}
