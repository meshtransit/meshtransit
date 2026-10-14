package node

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"

	"meshtransit.net/shared/endpointpolicy"
)

const maximumEndpointCount = 64

var (
	// ErrInvalidEndpoint reports an unusable client endpoint.
	ErrInvalidEndpoint = errors.New("node: invalid endpoint")
	// ErrUndistributableEndpoint reports a well-formed endpoint that peers
	// are never sent, such as a loopback or overlay address; it wraps
	// ErrInvalidEndpoint.
	ErrUndistributableEndpoint = fmt.Errorf("%w: not distributed to peers", ErrInvalidEndpoint)
	// ErrInvalidEndpointSet reports an incomplete or unsafe endpoint set.
	ErrInvalidEndpointSet = errors.New("node: invalid endpoint set")
)

// EndpointSource identifies how a client discovered an endpoint.
type EndpointSource uint8

const (
	// EndpointSourceUnknown is the invalid zero-value endpoint source.
	EndpointSourceUnknown EndpointSource = iota
	// EndpointSourceLocal identifies an address observed on a local interface.
	EndpointSourceLocal
	// EndpointSourceSTUN identifies a reflexive address discovered through STUN.
	EndpointSourceSTUN
	// EndpointSourcePortMapped identifies an address created by port mapping.
	EndpointSourcePortMapped
	// EndpointSourceSTUNLocalPort combines a reflexive address with a fixed local port.
	EndpointSourceSTUNLocalPort
	// EndpointSourceConfigured identifies an explicitly configured address.
	EndpointSourceConfigured
)

// IsValid reports whether the source is supported by the current product profile.
func (source EndpointSource) IsValid() bool {
	return source >= EndpointSourceLocal && source <= EndpointSourceConfigured
}

// Endpoint is one validated UDP address and its discovery source.
type Endpoint struct {
	address netip.AddrPort
	source  EndpointSource
}

// NewEndpoint validates one client-reported UDP endpoint. A well-formed
// endpoint that peers are never sent fails with ErrUndistributableEndpoint.
func NewEndpoint(address netip.AddrPort, source EndpointSource) (Endpoint, error) {
	if !wellFormedEndpointAddress(address) || !source.IsValid() {
		return Endpoint{}, ErrInvalidEndpoint
	}
	if !distributableAddress(address.Addr()) {
		return Endpoint{}, ErrUndistributableEndpoint
	}
	return Endpoint{address: address, source: source}, nil
}

// Address returns the canonical IP and UDP port.
func (endpoint Endpoint) Address() netip.AddrPort { return endpoint.address }

// Source returns how the endpoint was discovered.
func (endpoint Endpoint) Source() EndpointSource { return endpoint.source }

// IsValid reports whether the endpoint is safe for transient coordination.
func (endpoint Endpoint) IsValid() bool {
	return validEndpointAddress(endpoint.address) && endpoint.source.IsValid()
}

// EndpointSet is an immutable, canonical client connectivity report.
type EndpointSet struct {
	discoveryKey DiscoveryKey
	endpoints    []Endpoint
}

// NewEndpointSet validates, copies, sorts, and deduplicates a bounded report.
func NewEndpointSet(discoveryKey DiscoveryKey, endpoints []Endpoint) (EndpointSet, error) {
	if !discoveryKey.IsValid() || len(endpoints) > maximumEndpointCount {
		return EndpointSet{}, ErrInvalidEndpointSet
	}
	canonical := slices.Clone(endpoints)
	for _, endpoint := range canonical {
		if !endpoint.IsValid() {
			return EndpointSet{}, ErrInvalidEndpointSet
		}
	}
	slices.SortFunc(canonical, compareEndpoints)
	for index := 1; index < len(canonical); index++ {
		if canonical[index-1].Address() == canonical[index].Address() {
			return EndpointSet{}, ErrInvalidEndpointSet
		}
	}
	return EndpointSet{discoveryKey: discoveryKey, endpoints: canonical}, nil
}

// DiscoveryKey returns the public key attached to this endpoint report.
func (set EndpointSet) DiscoveryKey() DiscoveryKey { return set.discoveryKey }

// Endpoints returns a caller-owned copy in canonical order.
func (set EndpointSet) Endpoints() []Endpoint { return slices.Clone(set.endpoints) }

// IsValid reports whether this set satisfies the bounded canonical contract.
func (set EndpointSet) IsValid() bool {
	if !set.discoveryKey.IsValid() || len(set.endpoints) > maximumEndpointCount {
		return false
	}
	for index, endpoint := range set.endpoints {
		if !endpoint.IsValid() {
			return false
		}
		if index > 0 && compareEndpoints(set.endpoints[index-1], endpoint) >= 0 {
			return false
		}
	}
	return true
}

// Equal reports whether both immutable reports contain the same discovery key
// and canonical endpoint sequence.
func (set EndpointSet) Equal(other EndpointSet) bool {
	return set.discoveryKey == other.discoveryKey && slices.Equal(set.endpoints, other.endpoints)
}

func validEndpointAddress(address netip.AddrPort) bool {
	return wellFormedEndpointAddress(address) && distributableAddress(address.Addr())
}

func wellFormedEndpointAddress(address netip.AddrPort) bool {
	endpointAddress := address.Addr()
	return address.IsValid() && address.Port() != 0 && endpointAddress.IsValid() &&
		endpointAddress.Zone() == "" && endpointAddress == endpointAddress.Unmap()
}

// distributableAddress is the shared probe policy (mtcp-v1 §8.1), so Core
// and nodes drop the same addresses.
func distributableAddress(address netip.Addr) bool { return endpointpolicy.Usable(address) }

func compareEndpoints(left, right Endpoint) int {
	if compared := left.Address().Compare(right.Address()); compared != 0 {
		return compared
	}
	return int(left.Source()) - int(right.Source())
}
