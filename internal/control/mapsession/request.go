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
	nodeKey           node.Key
	capabilityVersion int
	endpointSet       node.EndpointSet
	hasEndpointSet    bool
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

// IsValid reports whether the request is safe to authorize.
func (request Request) IsValid() bool {
	if !request.nodeKey.IsValid() || request.capabilityVersion <= 0 ||
		request.capabilityVersion > maximumCapabilityVersion {
		return false
	}
	return !request.hasEndpointSet || request.endpointSet.IsValid()
}
