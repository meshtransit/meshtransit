//go:build integration

package protocoltest

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"slices"

	"tailscale.com/tailcfg"
	"tailscale.com/util/zstdframe"
)

// PeerConnectivityDelta is one complete peer replacement carried by a
// connectivity-only stream update.
type PeerConnectivityDelta struct {
	NodeID       int64
	DiscoveryKey [32]byte
	Endpoints    []netip.AddrPort
	Online       bool
	OnlineKnown  bool
}

// ConnectivityDelta is protocol-neutral evidence from one same-authority
// stream update.
type ConnectivityDelta struct {
	SelfChanged  bool
	SelfNodeID   int64
	DiscoveryKey [32]byte
	Endpoints    []netip.AddrPort
	PeersChanged []PeerConnectivityDelta
}

func decodeConnectivityDelta(frame []byte) (ConnectivityDelta, error) {
	if len(frame) < 5 || int64(binary.LittleEndian.Uint32(frame[:4])) != int64(len(frame)-4) {
		return ConnectivityDelta{}, ErrInvalidClient
	}
	document, err := zstdframe.AppendDecode(
		nil,
		frame[4:],
		zstdframe.MaxDecodedSize(maximumDecodedMapBytes),
	)
	if err != nil {
		return ConnectivityDelta{}, fmt.Errorf("decode map compression: %w", err)
	}
	defer clear(document)
	var fields map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fields); err != nil {
		return ConnectivityDelta{}, fmt.Errorf("decode delta fields: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ConnectivityDelta{}, ErrInvalidClient
	}
	for name := range fields {
		if name != "Node" && name != "PeersChanged" {
			return ConnectivityDelta{}, ErrInvalidClient
		}
	}
	var response tailcfg.MapResponse
	decoder = json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		return ConnectivityDelta{}, fmt.Errorf("decode delta document: %w", err)
	}
	result := ConnectivityDelta{PeersChanged: make([]PeerConnectivityDelta, 0, len(response.PeersChanged))}
	if response.Node != nil {
		if response.Node.ID <= 0 {
			return ConnectivityDelta{}, ErrInvalidClient
		}
		result.SelfChanged = true
		result.SelfNodeID = int64(response.Node.ID)
		result.Endpoints = slices.Clone(response.Node.Endpoints)
		if !response.Node.DiscoKey.IsZero() {
			result.DiscoveryKey, err = rawDiscoveryPublic(response.Node.DiscoKey)
			if err != nil {
				return ConnectivityDelta{}, fmt.Errorf("decode self discovery identity: %w", err)
			}
		}
	}
	var previousPeerID tailcfg.NodeID
	for _, peer := range response.PeersChanged {
		if peer == nil || peer.ID <= 0 || peer.Online == nil {
			return ConnectivityDelta{}, ErrInvalidClient
		}
		if previousPeerID != 0 && peer.ID <= previousPeerID {
			return ConnectivityDelta{}, ErrInvalidClient
		}
		previousPeerID = peer.ID
		changed := PeerConnectivityDelta{
			NodeID:      int64(peer.ID),
			Endpoints:   slices.Clone(peer.Endpoints),
			Online:      *peer.Online,
			OnlineKnown: true,
		}
		if !peer.DiscoKey.IsZero() {
			changed.DiscoveryKey, err = rawDiscoveryPublic(peer.DiscoKey)
			if err != nil {
				return ConnectivityDelta{}, fmt.Errorf("decode peer discovery identity: %w", err)
			}
		}
		result.PeersChanged = append(result.PeersChanged, changed)
	}
	if !result.SelfChanged && len(result.PeersChanged) == 0 {
		return ConnectivityDelta{}, ErrInvalidClient
	}
	return result, nil
}
