// Package policy owns product packet-policy intent, compilation inputs, and
// deterministic authorization decisions independently of client wire formats.
package policy

import (
	"errors"
	"slices"
)

const (
	// MaximumPortRangesPerRule bounds normalized destination-port work.
	MaximumPortRangesPerRule = 64
)

var (
	// ErrInvalidPortRange reports an absent or descending destination-port range.
	ErrInvalidPortRange = errors.New("policy: invalid destination port range")
)

// Protocol is one explicitly supported packet protocol. There is no wildcard.
type Protocol uint8

const (
	// ProtocolUnknown is the invalid zero-value protocol.
	ProtocolUnknown Protocol = iota
	// ProtocolTCP authorizes one TCP destination-port set.
	ProtocolTCP
	// ProtocolUDP authorizes one UDP destination-port set.
	ProtocolUDP
	// ProtocolICMP authorizes the fixed v1 echo request/reply profile.
	ProtocolICMP
)

// IsValid reports whether the protocol has explicit v1 semantics.
func (protocol Protocol) IsValid() bool {
	return protocol == ProtocolTCP || protocol == ProtocolUDP || protocol == ProtocolICMP
}

// String returns the stable lower-case protocol name.
func (protocol Protocol) String() string {
	switch protocol {
	case ProtocolTCP:
		return "tcp"
	case ProtocolUDP:
		return "udp"
	case ProtocolICMP:
		return "icmp"
	default:
		return "unknown"
	}
}

// PortRange is one inclusive normalized TCP or UDP destination-port interval.
type PortRange struct {
	first uint16
	last  uint16
}

// NewPortRange validates one inclusive destination-port interval.
func NewPortRange(first, last uint16) (PortRange, error) {
	if first == 0 || last < first {
		return PortRange{}, ErrInvalidPortRange
	}
	return PortRange{first: first, last: last}, nil
}

// First returns the inclusive lower destination port.
func (portRange PortRange) First() uint16 { return portRange.first }

// Last returns the inclusive upper destination port.
func (portRange PortRange) Last() uint16 { return portRange.last }

func (portRange PortRange) isValid() bool {
	return portRange.first > 0 && portRange.last >= portRange.first
}

func canonicalPortRanges(ranges []PortRange) []PortRange {
	canonical := slices.Clone(ranges)
	slices.SortFunc(canonical, comparePortRanges)
	merged := make([]PortRange, 0, len(canonical))
	for _, current := range canonical {
		if len(merged) == 0 {
			merged = append(merged, current)
			continue
		}
		previous := &merged[len(merged)-1]
		isAdjacent := previous.last != ^uint16(0) && current.first == previous.last+1
		if current.first <= previous.last || isAdjacent {
			if current.last > previous.last {
				previous.last = current.last
			}
			continue
		}
		merged = append(merged, current)
	}
	return merged
}

func comparePortRanges(first, second PortRange) int {
	switch {
	case first.first < second.first:
		return -1
	case first.first > second.first:
		return 1
	case first.last < second.last:
		return -1
	case first.last > second.last:
		return 1
	default:
		return 0
	}
}

func validCanonicalPortRanges(ranges []PortRange) bool {
	if len(ranges) == 0 || len(ranges) > MaximumPortRangesPerRule {
		return false
	}
	for index, current := range ranges {
		if !current.isValid() {
			return false
		}
		if index == 0 {
			continue
		}
		previous := ranges[index-1]
		if current.first <= previous.last ||
			previous.last != ^uint16(0) && current.first == previous.last+1 {
			return false
		}
	}
	return true
}

// CanonicalTraffic validates one rule's protocol and destination ports and
// returns the ports sorted and merged as every compiled rule stores them.
// ICMP takes no ports; TCP and UDP take 1 to MaximumPortRangesPerRule.
func CanonicalTraffic(protocol Protocol, ranges []PortRange) ([]PortRange, bool) {
	if !protocol.IsValid() || len(ranges) > MaximumPortRangesPerRule {
		return nil, false
	}
	ports := canonicalPortRanges(ranges)
	if protocol == ProtocolICMP {
		return ports, len(ports) == 0
	}
	return ports, validCanonicalPortRanges(ports)
}

// KubernetesClusterPort is the only port a rule to a Kubernetes cluster
// allows: the cluster's API server, reached through its gateways.
const KubernetesClusterPort = 443

// IsKubernetesTraffic reports exactly TCP to KubernetesClusterPort, the only
// traffic a rule to a Kubernetes cluster may allow.
func IsKubernetesTraffic(protocol Protocol, ranges []PortRange) bool {
	return protocol == ProtocolTCP && len(ranges) == 1 &&
		ranges[0].First() == KubernetesClusterPort && ranges[0].Last() == KubernetesClusterPort
}
