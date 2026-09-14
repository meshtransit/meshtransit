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

// IsValid reports whether the request is safe to authorize.
func (request Request) IsValid() bool {
	return request.nodeKey.IsValid() && request.capabilityVersion > 0 &&
		request.capabilityVersion <= maximumCapabilityVersion
}
