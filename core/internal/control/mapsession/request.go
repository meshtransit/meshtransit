// Package mapsession opens authenticated client sessions from immutable,
// authoritative Network snapshots.
package mapsession

import (
	"errors"

	"meshtransit.net/core/internal/domain/node"
)

// ErrInvalidRequest reports an incomplete or unsupported map-session request.
var ErrInvalidRequest = errors.New("map session: invalid request")

// Request is the protocol-independent identity and connectivity input needed
// to open one map session.
type Request struct {
	nodeKey            node.Key
	deviceAliasVersion uint8
	relayZones         bool
	largeMap           bool
	endpointSet        node.EndpointSet
	hasEndpointSet     bool
	preferredRelay     int
	hasPreferredRelay  bool
}

// WithPreferredRelay returns a validated request carrying the complete client
// home-relay observation. Region zero is an explicit managed withdrawal.
func (request Request) WithPreferredRelay(regionID int) (Request, error) {
	request.preferredRelay = regionID
	request.hasPreferredRelay = true
	if !request.IsValid() {
		return Request{}, ErrInvalidRequest
	}
	return request, nil
}

// NewRequest validates an untrusted Node key.
func NewRequest(nodeKey node.Key) (Request, error) {
	request := Request{nodeKey: nodeKey}
	if !request.IsValid() {
		return Request{}, ErrInvalidRequest
	}
	return request, nil
}

// NodeKey returns the Node key claimed by this request.
func (request Request) NodeKey() node.Key { return request.nodeKey }

// WithEndpointSet returns a validated request carrying one transient client
// connectivity report. The original request remains unchanged.
func (request Request) WithEndpointSet(set node.EndpointSet) (Request, error) {
	request.endpointSet = set
	request.hasEndpointSet = true
	if !request.IsValid() {
		return Request{}, ErrInvalidRequest
	}
	return request, nil
}

// EndpointSet returns the client connectivity report when this request is an
// endpoint update. The returned set is immutable and protocol independent.
func (request Request) EndpointSet() (node.EndpointSet, bool) {
	return request.endpointSet, request.hasEndpointSet
}

// PreferredRelay returns the reported home relay when present. A present zero
// is an explicit withdrawal, not an omitted observation.
func (request Request) PreferredRelay() (int, bool) {
	return request.preferredRelay, request.hasPreferredRelay
}

// IsValid reports whether the request is safe to authorize.
func (request Request) IsValid() bool {
	if request.deviceAliasVersion > 1 || !request.nodeKey.IsValid() ||
		request.preferredRelay < 0 || request.preferredRelay > node.MaximumRelayRegionID ||
		(!request.hasPreferredRelay && request.preferredRelay != 0) ||
		request.hasPreferredRelay && !request.hasEndpointSet {
		return false
	}
	return !request.hasEndpointSet || request.endpointSet.IsValid()
}

// WithDeviceAliasVersion records an untrusted compatibility declaration.
// Only versions zero (unsupported) and one have an owned contract; neither
// grants access or substitutes for the authenticated bilateral reader.
func (request Request) WithDeviceAliasVersion(version uint8) (Request, error) {
	if version > 1 {
		return Request{}, ErrInvalidRequest
	}
	request.deviceAliasVersion = version
	if !request.IsValid() {
		return Request{}, ErrInvalidRequest
	}
	return request, nil
}

// DeviceAliasVersion returns the declared compatibility contract, or zero.
func (request Request) DeviceAliasVersion() uint8 { return request.deviceAliasVersion }

// WithLargeMap records the client's declaration (MTCP map.large1) that it
// applies maps of up to MaximumPeerCandidates peers. Without it a map carries
// at most LegacyPeerLimit peers; the declaration only raises that bound and
// grants no access.
func (request Request) WithLargeMap() Request {
	request.largeMap = true
	return request
}

// LargeMap reports whether the client declared large maps.
func (request Request) LargeMap() bool { return request.largeMap }

// WithRelayZones records that the client and Core negotiated relay.zones2:
// the client hands relays MTT2 tickets and their zone lists, so its relay
// grant may name every share instead of the oldest 31.
func (request Request) WithRelayZones() Request {
	request.relayZones = true
	return request
}

// RelayZones reports whether the session negotiated relay.zones2.
func (request Request) RelayZones() bool { return request.relayZones }
