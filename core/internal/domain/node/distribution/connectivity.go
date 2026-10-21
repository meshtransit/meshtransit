package distribution

import (
	"net/netip"
	"slices"
	"time"
)

// NATMapping is a Device's NAT mapping behaviour (RFC 4787 terms).
type NATMapping string

// NAT mapping behaviours.
const (
	NATMappingUnknown                 NATMapping = "unknown"
	NATMappingNone                    NATMapping = "none" // no translation: public address
	NATMappingEndpointIndependent     NATMapping = "endpoint_independent"
	NATMappingAddressDependent        NATMapping = "address_dependent"
	NATMappingAddressAndPortDependent NATMapping = "address_and_port_dependent"
)

// NATFiltering is a Device's NAT filtering behaviour.
type NATFiltering string

// NAT filtering behaviours.
const (
	NATFilteringUnknown                 NATFiltering = "unknown"
	NATFilteringEndpointIndependent     NATFiltering = "endpoint_independent"
	NATFilteringAddressDependent        NATFiltering = "address_dependent"
	NATFilteringAddressAndPortDependent NATFiltering = "address_and_port_dependent"
)

// NATAllocation is how a Device's NAT chooses external ports.
type NATAllocation string

// NAT port allocation patterns.
const (
	NATAllocationUnknown    NATAllocation = "unknown"
	NATAllocationPreserving NATAllocation = "preserving"
	NATAllocationSequential NATAllocation = "sequential"
	NATAllocationRandom     NATAllocation = "random"
)

// PortMappingProtocol is the protocol a Device's gateway mapping uses.
type PortMappingProtocol string

// Port mapping protocols.
const (
	PortMappingProtocolUnknown PortMappingProtocol = "unknown"
	PortMappingProtocolPCP     PortMappingProtocol = "pcp"
	PortMappingProtocolNATPMP  PortMappingProtocol = "nat_pmp"
	PortMappingProtocolUPnP    PortMappingProtocol = "upnp"
)

// PortMappingState is the state of a Device's gateway mapping.
type PortMappingState string

// Port mapping states.
const (
	PortMappingUnknown     PortMappingState = "unknown"
	PortMappingOff         PortMappingState = "off"
	PortMappingSearching   PortMappingState = "searching"
	PortMappingMapped      PortMappingState = "mapped"
	PortMappingDoubleNAT   PortMappingState = "double_nat"
	PortMappingUnavailable PortMappingState = "unavailable"
	PortMappingFailed      PortMappingState = "failed"
)

// NATClass is a Device's NAT classification.
type NATClass struct {
	Mapping        NATMapping
	Filtering      NATFiltering
	Allocation     NATAllocation
	SequentialStep uint16
	ObservedAt     time.Time // zero when the Device did not say
}

// PortMapping is a Device's gateway mapping, without its address.
type PortMapping struct {
	Protocol  PortMappingProtocol
	State     PortMappingState
	ExpiresAt time.Time // zero for a permanent mapping or none
}

// Connectivity is how a Device reaches the Internet, from its latest
// endpoint report: NAT classification, IPv6 reachability, port mapping and
// its public addresses.
type Connectivity struct {
	ReportedAt  time.Time
	NAT         *NATClass // nil: not classified
	IPv6Global  bool      // the Device has a global IPv6 address
	IPv6STUN    bool      // STUN over IPv6 succeeded
	PortMapping *PortMapping
	// PublicAddresses are the Device's addresses on the Internet: what STUN
	// saw, what its gateway mapped and public addresses of its interfaces,
	// in address order (IPv4 first), at most MaximumPublicAddresses.
	PublicAddresses []netip.Addr
}

// IsValid reports whether every value is one of the defined ones.
func (c Connectivity) IsValid() bool {
	if c.ReportedAt.IsZero() || (c.IPv6STUN && !c.IPv6Global) || !validPublicAddresses(c.PublicAddresses) {
		return false
	}
	if c.NAT != nil {
		switch {
		case !oneOf(c.NAT.Mapping, NATMappingUnknown, NATMappingNone, NATMappingEndpointIndependent,
			NATMappingAddressDependent, NATMappingAddressAndPortDependent):
			return false
		case !oneOf(c.NAT.Filtering, NATFilteringUnknown, NATFilteringEndpointIndependent,
			NATFilteringAddressDependent, NATFilteringAddressAndPortDependent):
			return false
		case !oneOf(c.NAT.Allocation, NATAllocationUnknown, NATAllocationPreserving,
			NATAllocationSequential, NATAllocationRandom):
			return false
		}
	}
	if c.PortMapping != nil {
		if !oneOf(c.PortMapping.Protocol, PortMappingProtocolUnknown, PortMappingProtocolPCP,
			PortMappingProtocolNATPMP, PortMappingProtocolUPnP) ||
			!oneOf(c.PortMapping.State, PortMappingUnknown, PortMappingOff, PortMappingSearching,
				PortMappingMapped, PortMappingDoubleNAT, PortMappingUnavailable, PortMappingFailed) {
			return false
		}
	}
	return true
}

// SameAs reports whether c and other describe the same connectivity,
// ignoring when they were reported.
func (c Connectivity) SameAs(other Connectivity) bool {
	if c.IPv6Global != other.IPv6Global || c.IPv6STUN != other.IPv6STUN ||
		!slices.Equal(c.PublicAddresses, other.PublicAddresses) ||
		(c.NAT == nil) != (other.NAT == nil) || (c.PortMapping == nil) != (other.PortMapping == nil) {
		return false
	}
	if c.NAT != nil && *c.NAT != *other.NAT {
		return false
	}
	return c.PortMapping == nil || *c.PortMapping == *other.PortMapping
}

func oneOf[T comparable](value T, allowed ...T) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
