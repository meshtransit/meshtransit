package redis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"time"

	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/node/distribution"
)

// A stored connectivity report, with its public addresses and the
// session's platform, is written within the 1 KiB a Core before them reads,
// so a rollback still reads every record; it is read up to twice that.
const (
	maximumConnectivityWriteBytes = 1 << 10
	maximumConnectivityBytes      = 2 << 10
)

// connectivityWire is the stored form of a connectivity report.
type connectivityWire struct {
	ReportedAt  int64            `json:"at"`
	NAT         *natWire         `json:"nat,omitempty"`
	IPv6Global  bool             `json:"v6,omitempty"`
	IPv6STUN    bool             `json:"v6stun,omitempty"`
	PortMapping *portMappingWire `json:"pm,omitempty"`
	Public      []string         `json:"pub,omitempty"`
	Platform    *platformWire    `json:"os,omitempty"`
}

// platformWire is the session's platform, stored with its connectivity.
type platformWire struct {
	OS            string `json:"os"`
	OSVersion     string `json:"ver,omitempty"`
	Arch          string `json:"arch,omitempty"`
	ClientVersion string `json:"client,omitempty"`
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

// RecordConnectivity stores a Device's connectivity report, with the
// platform its session runs on (nil: unknown), for its current session
// generation, and reports whether it was stored: a report of another
// session generation is dropped. A platform that would not fit is left out.
func (client *Client) RecordConnectivity(ctx context.Context, nodeID node.ID, sessionGeneration int64,
	report distribution.Connectivity, platform *distribution.Platform) (bool, error) {
	if ctx == nil || client == nil || client.recordConnectivity == nil || !nodeID.IsValid() ||
		sessionGeneration < 1 || !report.IsValid() || (platform != nil && !platform.IsValid()) {
		return false, ErrInvalidOptions
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
	for _, address := range report.PublicAddresses {
		wire.Public = append(wire.Public, address.String())
	}
	if platform != nil {
		wire.Platform = &platformWire{OS: platform.OS, OSVersion: platform.OSVersion, Arch: platform.Arch,
			ClientVersion: platform.ClientVersion}
	}
	encoded, err := encodeConnectivity(wire)
	if err == nil && len(encoded) > maximumConnectivityWriteBytes {
		wire.Platform = nil
		encoded, err = encodeConnectivity(wire)
	}
	if err != nil || len(encoded) > maximumConnectivityWriteBytes {
		return false, ErrInvalidOptions
	}
	startedAt := time.Now()
	result, err := client.recordConnectivity(ctx, deliveryKeyForNode(nodeID), sessionGeneration, string(encoded),
		deliveryTTL)
	if err == nil && result != 0 && result != 1 {
		err = errors.New("unexpected connectivity record result")
	}
	client.metrics.observeCommand(redisCommandRecordConnectivity, startedAt, err)
	if err != nil {
		return false, errors.Join(ErrRecordDelivery, err)
	}
	return result == 1, nil
}

// encodeConnectivity writes the stored form without HTML escaping, so a
// client-named field costs its own bytes.
func encodeConnectivity(wire connectivityWire) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(wire); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buffer.Bytes(), []byte("\n")), nil
}

// decodeConnectivity reads a stored connectivity report and the platform
// stored with it; empty means none.
func decodeConnectivity(text string) (*distribution.Connectivity, *distribution.Platform, error) {
	if text == "" {
		return nil, nil, nil
	}
	if len(text) > maximumConnectivityBytes {
		return nil, nil, errors.New("connectivity report too large")
	}
	var wire connectivityWire
	if err := json.Unmarshal([]byte(text), &wire); err != nil || wire.ReportedAt <= 0 {
		return nil, nil, errors.New("malformed connectivity report")
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
		return nil, nil, errors.New("inconsistent connectivity report")
	}
	// Public addresses and the platform are shown, never relied on: a value
	// a later rule no longer accepts is left out rather than failing the
	// whole page of Devices the record is read with.
	report.PublicAddresses = decodePublicAddresses(wire.Public)
	var platform *distribution.Platform
	if value := wire.Platform; value != nil {
		platform = &distribution.Platform{OS: value.OS, OSVersion: value.OSVersion, Arch: value.Arch,
			ClientVersion: value.ClientVersion}
		if !platform.IsValid() {
			platform = nil
		}
	}
	return &report, platform, nil
}

// decodePublicAddresses keeps the stored addresses that are still public,
// distinct and in order, at most distribution.MaximumPublicAddresses.
func decodePublicAddresses(texts []string) []netip.Addr {
	var addresses []netip.Addr
	for _, text := range texts {
		address, err := netip.ParseAddr(text)
		if err == nil && distribution.IsPublicAddress(address) && !slices.Contains(addresses, address) {
			addresses = append(addresses, address)
		}
	}
	slices.SortFunc(addresses, netip.Addr.Compare)
	if len(addresses) > distribution.MaximumPublicAddresses {
		addresses = addresses[:distribution.MaximumPublicAddresses]
	}
	return addresses
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
