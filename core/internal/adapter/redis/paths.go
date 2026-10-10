package redis

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
)

// maximumPathsBytes bounds one stored path report.
const maximumPathsBytes = 64 << 10

// pathsWire is the stored form of a path report.
type pathsWire struct {
	ReportedAt int64          `json:"at"`
	IntervalS  int64          `json:"interval_s"`
	Peers      []peerPathWire `json:"peers"`
}

type peerPathWire struct {
	PeerID      string `json:"id"`
	External    bool   `json:"ext,omitempty"`
	Kind        string `json:"kind"`
	RelayRegion int    `json:"region,omitempty"`
	RelayCode   string `json:"code,omitempty"`
	RelayReason string `json:"why,omitempty"`
	DirectBytes uint64 `json:"direct,omitempty"`
	RelayBytes  uint64 `json:"relay,omitempty"`
}

// RecordPaths stores a Device's path report for its current session
// generation; a report of an older session is dropped.
func (client *Client) RecordPaths(ctx context.Context, nodeID node.ID, sessionGeneration int64,
	report distribution.PathReport) error {
	if ctx == nil || client == nil || client.recordPaths == nil || !nodeID.IsValid() || sessionGeneration < 1 ||
		!report.IsValid() {
		return ErrInvalidOptions
	}
	wire := pathsWire{ReportedAt: report.ReportedAt.UnixMilli(), IntervalS: int64(report.Interval / time.Second)}
	for _, peer := range report.Peers {
		wire.Peers = append(wire.Peers, peerPathWire{PeerID: peer.PeerID.String(), External: peer.External,
			Kind:        string(peer.Kind),
			RelayRegion: peer.RelayRegion, RelayCode: peer.RelayCode, RelayReason: string(peer.RelayReason),
			DirectBytes: peer.DirectBytes, RelayBytes: peer.RelayBytes})
	}
	encoded, err := json.Marshal(wire)
	if err != nil || len(encoded) > maximumPathsBytes {
		return ErrInvalidOptions
	}
	startedAt := time.Now()
	result, err := client.recordPaths(ctx, deliveryKeyForNode(nodeID), sessionGeneration, string(encoded), deliveryTTL)
	if err == nil && result != 0 && result != 1 {
		err = errors.New("unexpected path record result")
	}
	client.metrics.observeCommand(redisCommandRecordPaths, startedAt, err)
	if err != nil {
		return errors.Join(ErrRecordDelivery, err)
	}
	return nil
}

// decodePaths reads a stored path report; empty means none.
func decodePaths(text string) (*distribution.PathReport, error) {
	if text == "" {
		return nil, nil
	}
	if len(text) > maximumPathsBytes {
		return nil, errors.New("path report too large")
	}
	var wire pathsWire
	if err := json.Unmarshal([]byte(text), &wire); err != nil || wire.ReportedAt <= 0 || wire.IntervalS <= 0 {
		return nil, errors.New("malformed path report")
	}
	report := distribution.PathReport{ReportedAt: time.UnixMilli(wire.ReportedAt).UTC(),
		Interval: time.Duration(wire.IntervalS) * time.Second}
	for _, peer := range wire.Peers {
		id, err := node.ParseID(peer.PeerID)
		if err != nil {
			return nil, errors.New("malformed path report peer")
		}
		report.Peers = append(report.Peers, distribution.PeerPath{PeerID: id, External: peer.External,
			Kind:        distribution.PathKind(peer.Kind),
			RelayRegion: peer.RelayRegion, RelayCode: peer.RelayCode, RelayReason: distribution.RelayReason(peer.RelayReason),
			DirectBytes: peer.DirectBytes, RelayBytes: peer.RelayBytes})
	}
	if !report.IsValid() {
		return nil, errors.New("inconsistent path report")
	}
	return &report, nil
}
