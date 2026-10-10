package redis

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
)

// maximumConnectivityBytes bounds one stored connectivity report.
const maximumConnectivityBytes = 1 << 10

// connectivityWire is the stored form of a connectivity report.
type connectivityWire struct {
	ReportedAt  int64            `json:"at"`
	NAT         *natWire         `json:"nat,omitempty"`
	IPv6Global  bool             `json:"v6,omitempty"`
	IPv6STUN    bool             `json:"v6stun,omitempty"`
	PortMapping *portMappingWire `json:"pm,omitempty"`
}

type natWire struct {
	Mapping    string `json:"map"`
	Filtering  string `json:"filter"`
	Allocation string `json:"alloc"`
	Step       uint16 `json:"step,omitempty"`
	ObservedAt int64  `json:"at,omitempty"`
}

type portMappingWire struct {
	Protocol  string `json:"proto"`
	State     string `json:"state"`
	ExpiresAt int64  `json:"exp,omitempty"`
}

// RecordConnectivity stores a Device's connectivity report for its current
// session generation; a report of an older session is dropped.
func (client *Client) RecordConnectivity(ctx context.Context, nodeID node.ID, sessionGeneration int64,
	report distribution.Connectivity) error {
	if ctx == nil || client == nil || client.recordConnectivity == nil || !nodeID.IsValid() ||
		sessionGeneration < 1 || !report.IsValid() {
		return ErrInvalidOptions
	}
	wire := connectivityWire{ReportedAt: report.ReportedAt.UnixMilli(), IPv6Global: report.IPv6Global,
		IPv6STUN: report.IPv6STUN}
	if nat := report.NAT; nat != nil {
		wire.NAT = &natWire{Mapping: string(nat.Mapping), Filtering: string(nat.Filtering),
			Allocation: string(nat.Allocation), Step: nat.SequentialStep, ObservedAt: unixMilliOrZero(nat.ObservedAt)}
	}
	if mapping := report.PortMapping; mapping != nil {
		wire.PortMapping = &portMappingWire{Protocol: string(mapping.Protocol), State: string(mapping.State),
			ExpiresAt: unixMilliOrZero(mapping.ExpiresAt)}
	}
	encoded, err := json.Marshal(wire)
	if err != nil || len(encoded) > maximumConnectivityBytes {
		return ErrInvalidOptions
	}
	startedAt := time.Now()
	result, err := client.recordConnectivity(ctx, deliveryKeyForNode(nodeID), sessionGeneration, string(encoded),
		deliveryTTL)
	if err == nil && result != 0 && result != 1 {
		err = errors.New("unexpected connectivity record result")
	}
	client.metrics.observeCommand(redisCommandRecordConnectivity, startedAt, err)
	if err != nil {
		return errors.Join(ErrRecordDelivery, err)
	}
	return nil
}

// decodeConnectivity reads a stored connectivity report; empty means none.
func decodeConnectivity(text string) (*distribution.Connectivity, error) {
	if text == "" {
		return nil, nil
	}
	if len(text) > maximumConnectivityBytes {
		return nil, errors.New("connectivity report too large")
	}
	var wire connectivityWire
	if err := json.Unmarshal([]byte(text), &wire); err != nil || wire.ReportedAt <= 0 {
		return nil, errors.New("malformed connectivity report")
	}
	report := distribution.Connectivity{ReportedAt: time.UnixMilli(wire.ReportedAt).UTC(),
		IPv6Global: wire.IPv6Global, IPv6STUN: wire.IPv6STUN}
	if nat := wire.NAT; nat != nil {
		report.NAT = &distribution.NATClass{Mapping: distribution.NATMapping(nat.Mapping),
			Filtering: distribution.NATFiltering(nat.Filtering), Allocation: distribution.NATAllocation(nat.Allocation),
			SequentialStep: nat.Step, ObservedAt: timeOrZero(nat.ObservedAt)}
	}
	if mapping := wire.PortMapping; mapping != nil {
		report.PortMapping = &distribution.PortMapping{Protocol: distribution.PortMappingProtocol(mapping.Protocol),
			State: distribution.PortMappingState(mapping.State), ExpiresAt: timeOrZero(mapping.ExpiresAt)}
	}
	if !report.IsValid() {
		return nil, errors.New("inconsistent connectivity report")
	}
	return &report, nil
}

func unixMilliOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func timeOrZero(ms int64) time.Time {
	if ms <= 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}
