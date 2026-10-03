// Package mapsession opens authenticated client sessions from immutable,
// authoritative Network snapshots.
package mapsession

import (
	"errors"

	"github.com/meshtransit/meshtransit/internal/node"
)

const maximumCapabilityVersion = 1<<16 - 1

// ErrInvalidRequest reports an incomplete or unsupported map-session request.
var ErrInvalidRequest = errors.New("map session: invalid request")

// Request is the protocol-independent identity and compatibility input needed
// to open one map session.
type Request struct {
	nodeKey            node.Key
	capabilityVersion  int
	deviceAliasVersion uint8
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

// NewRequest validates an untrusted Node key and bounded compatibility version.
func NewRequest(nodeKey node.Key, capabilityVersion int) (Request, error) {
	request := Request{nodeKey: nodeKey, capabilityVersion: capabilityVersion}
	if !request.IsValid() {
		return Request{}, ErrInvalidRequest
	}
	return request, nil
}

// NodeKey returns the Node key claimed by this request.
func (request Request) NodeKey() node.Key { return request.nodeKey }

// CapabilityVersion returns the positive bounded client compatibility version.
func (request Request) CapabilityVersion() int { return request.capabilityVersion }

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
	if request.deviceAliasVersion > 1 || !request.nodeKey.IsValid() || request.capabilityVersion <= 0 ||
		request.capabilityVersion > maximumCapabilityVersion ||
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
