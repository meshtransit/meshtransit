// Package netcheck classifies the NAT in front of a UDP socket, following
// docs/protocol/nat-classification.md.
//
// The classification functions are pure: they turn observations into
// disco.NATInfo values and are tested exhaustively. Prober gathers the
// observations with STUN over a socket the caller owns.
package netcheck

import (
	"net/netip"
	"slices"
	"time"

	"meshtransit.net/shared/disco"
)

const (
	// maxSequentialStep is the largest port delta still read as sequential
	// allocation (nat-classification §2.2).
	maxSequentialStep = 8
	// minAllocationSamples is the number of distinct mappings needed to
	// judge an endpoint-dependent allocator.
	minAllocationSamples = 3
	// MaxReportAge is how long a classification stays valid (§4).
	MaxReportAge = 10 * time.Minute
)

// Observation is one STUN answer: the server endpoint probed and the mapped
// address it reported.
type Observation struct {
	Server netip.AddrPort
	Mapped netip.AddrPort
}

// Probe is the outcome of one RFC 5780 filtering probe.
type Probe uint8

// Probe outcomes.
const (
	ProbeNotTried Probe = iota // the server cannot answer this probe
	ProbeReceived              // the response came back from the changed address
	ProbeLost                  // no valid response before the deadline
)

// ClassifyMapping derives the mapping behaviour from observations made from
// one local socket, in the order they were made. local lists the socket's
// own addresses (interface address plus bound port).
//
// Only observations of the same address family are compared: a dual-stack
// socket is NATed on IPv4 and usually not on IPv6.
//
// Without a same-IP/different-port pair, an address-dependent result cannot
// be told apart from address-and-port-dependent; the stricter value is
// reported so that peers never rely on port reuse that may not exist.
func ClassifyMapping(local []netip.AddrPort, obs []Observation) disco.Mapping {
	if len(obs) == 0 {
		return disco.MappingUnknown
	}
	allLocal := true
	for _, o := range obs {
		if !slices.Contains(local, o.Mapped) {
			allLocal = false
			break
		}
	}
	var portPair, sameMappingAcrossIPs, differentAcrossIPs bool
	for i, a := range obs {
		for _, b := range obs[i+1:] {
			if a.Server.Addr().Is4() != b.Server.Addr().Is4() {
				continue
			}
			sameIP := a.Server.Addr() == b.Server.Addr()
			switch {
			case sameIP && a.Server.Port() != b.Server.Port():
				if a.Mapped != b.Mapped {
					return disco.MappingAddressAndPortDependent
				}
				portPair = true
			case !sameIP && a.Mapped == b.Mapped:
				sameMappingAcrossIPs = true
			case !sameIP:
				differentAcrossIPs = true
			}
		}
	}
	switch {
	case differentAcrossIPs && portPair:
		return disco.MappingAddressDependent
	case differentAcrossIPs:
		return disco.MappingAddressAndPortDependent
	case !sameMappingAcrossIPs:
		return disco.MappingUnknown // fewer than two server addresses answered
	case allLocal:
		return disco.MappingNone
	default:
		return disco.MappingEndpointIndependent
	}
}

// ClassifyAllocation derives the port allocation pattern. mapped lists the
// mapped ports in the order the destinations were first contacted; repeated
// mappings are ignored. It returns the median step for sequential allocators.
func ClassifyAllocation(m disco.Mapping, localPort uint16, mapped []uint16) (disco.Allocation, uint16) {
	switch {
	case m.Easy():
		if len(mapped) == 0 {
			return disco.AllocationUnknown, 0
		}
		if mapped[0] == localPort {
			return disco.AllocationPreserving, 0
		}
		return disco.AllocationRandom, 0
	case !m.Hard():
		return disco.AllocationUnknown, 0
	}
	ports := distinctInOrder(mapped)
	if len(ports) < minAllocationSamples {
		return disco.AllocationUnknown, 0
	}
	steps := make([]uint16, 0, len(ports)-1)
	for i := 1; i < len(ports); i++ {
		step := ports[i] - ports[i-1] // wraps modulo 2^16 by design
		if step == 0 || step > maxSequentialStep {
			return disco.AllocationRandom, 0
		}
		steps = append(steps, step)
	}
	slices.Sort(steps)
	return disco.AllocationSequential, steps[len(steps)/2]
}

func distinctInOrder(ports []uint16) []uint16 {
	out := make([]uint16, 0, len(ports))
	for _, p := range ports {
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// ClassifyFiltering derives the filtering behaviour from the change-IP-and-port
// probe and the change-port probe (nat-classification §2.3). Contradictory
// results resolve to the stricter class.
func ClassifyFiltering(changeBoth, changePort Probe) disco.Filtering {
	switch changePort {
	case ProbeLost:
		return disco.FilteringAddressAndPortDependent
	case ProbeReceived:
		if changeBoth == ProbeReceived {
			return disco.FilteringEndpointIndependent
		}
		return disco.FilteringAddressDependent
	}
	switch changeBoth {
	case ProbeReceived:
		return disco.FilteringEndpointIndependent
	default:
		return disco.FilteringUnknown
	}
}

// RefineMapping applies peer observations (§3): peers that saw different
// ports for the same local socket prove an endpoint-dependent mapping.
func RefineMapping(m disco.Mapping, peerObserved []netip.AddrPort) disco.Mapping {
	if m.Hard() {
		return m
	}
	for i := 1; i < len(peerObserved); i++ {
		if peerObserved[i].Port() != peerObserved[0].Port() {
			return disco.MappingAddressAndPortDependent
		}
	}
	return m
}
