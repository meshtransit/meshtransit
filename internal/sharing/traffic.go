package sharing

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"

	"github.com/meshtransit/meshtransit/internal/policy"
)

const (
	// MaximumTrafficConstraints bounds one external traffic-set input.
	MaximumTrafficConstraints = 64
	trafficHashDomain         = "meshtransit/sharing/traffic/v1\x00"
)

var (
	// ErrInvalidTrafficConstraint reports unsupported or malformed traffic authority.
	ErrInvalidTrafficConstraint = errors.New("sharing: invalid traffic constraint")
	// ErrInvalidTrafficSet reports an empty, malformed, or excessive traffic set.
	ErrInvalidTrafficSet = errors.New("sharing: invalid traffic set")
)

// TrafficConstraintParams contains one protocol-specific provider or consumer ceiling.
type TrafficConstraintParams struct {
	Protocol              policy.Protocol
	DestinationPortRanges []policy.PortRange
}

// TrafficConstraint is one canonical protocol and destination-port set.
type TrafficConstraint struct {
	protocol              policy.Protocol
	destinationPortRanges []policy.PortRange
}

// NewTrafficConstraint validates and canonicalizes one traffic constraint.
func NewTrafficConstraint(params TrafficConstraintParams) (TrafficConstraint, error) {
	constraint := TrafficConstraint{
		protocol:              params.Protocol,
		destinationPortRanges: canonicalizePortRanges(params.DestinationPortRanges),
	}
	if !constraint.IsValid() {
		return TrafficConstraint{}, ErrInvalidTrafficConstraint
	}
	return constraint, nil
}

// Protocol returns the explicit packet protocol.
func (constraint TrafficConstraint) Protocol() policy.Protocol { return constraint.protocol }

// DestinationPortRanges returns caller-owned inclusive destination-port intervals.
func (constraint TrafficConstraint) DestinationPortRanges() []policy.PortRange {
	return slices.Clone(constraint.destinationPortRanges)
}

// IsValid reports whether protocol and ports have explicit canonical semantics.
func (constraint TrafficConstraint) IsValid() bool {
	if !constraint.protocol.IsValid() ||
		len(constraint.destinationPortRanges) > policy.MaximumPortRangesPerRule {
		return false
	}
	if constraint.protocol == policy.ProtocolICMP {
		return len(constraint.destinationPortRanges) == 0
	}
	return validCanonicalPortRanges(constraint.destinationPortRanges)
}

// TrafficSet is a non-empty canonical union with at most one row per protocol.
type TrafficSet struct{ constraints []TrafficConstraint }

// NewTrafficSet validates, merges, and orders a bounded set of traffic constraints.
func NewTrafficSet(values []TrafficConstraint) (TrafficSet, error) {
	if len(values) == 0 || len(values) > MaximumTrafficConstraints {
		return TrafficSet{}, ErrInvalidTrafficSet
	}

	byProtocol := make(map[policy.Protocol][]policy.PortRange, 3)
	for _, value := range values {
		if !value.IsValid() {
			return TrafficSet{}, ErrInvalidTrafficSet
		}
		byProtocol[value.protocol] = append(
			byProtocol[value.protocol],
			value.destinationPortRanges...,
		)
	}

	constraints := make([]TrafficConstraint, 0, len(byProtocol))
	for _, protocol := range []policy.Protocol{
		policy.ProtocolTCP,
		policy.ProtocolUDP,
		policy.ProtocolICMP,
	} {
		ranges, found := byProtocol[protocol]
		if !found {
			continue
		}
		if protocol == policy.ProtocolICMP {
			constraints = append(constraints, TrafficConstraint{protocol: protocol})
			continue
		}
		canonical := canonicalizePortRanges(ranges)
		if len(canonical) > policy.MaximumPortRangesPerRule {
			return TrafficSet{}, ErrInvalidTrafficSet
		}
		constraints = append(constraints, TrafficConstraint{
			protocol: protocol, destinationPortRanges: canonical,
		})
	}

	set := TrafficSet{constraints: constraints}
	if !set.IsValid() {
		return TrafficSet{}, ErrInvalidTrafficSet
	}
	return set, nil
}

// Constraints returns caller-owned canonical traffic rows ordered TCP, UDP, ICMP.
func (set TrafficSet) Constraints() []TrafficConstraint {
	cloned := make([]TrafficConstraint, len(set.constraints))
	for index, value := range set.constraints {
		cloned[index] = TrafficConstraint{
			protocol:              value.protocol,
			destinationPortRanges: slices.Clone(value.destinationPortRanges),
		}
	}
	return cloned
}

// IsValid reports whether the set is non-empty, ordered, unique, and canonical.
func (set TrafficSet) IsValid() bool {
	if len(set.constraints) == 0 || len(set.constraints) > 3 {
		return false
	}
	previous := policy.ProtocolUnknown
	for _, constraint := range set.constraints {
		if !constraint.IsValid() || constraint.protocol <= previous {
			return false
		}
		previous = constraint.protocol
	}
	return true
}

// Allows reports whether the canonical set permits one exact protocol and port.
func (set TrafficSet) Allows(protocol policy.Protocol, destinationPort uint16) bool {
	if !set.IsValid() || !protocol.IsValid() {
		return false
	}
	for _, constraint := range set.constraints {
		if constraint.protocol != protocol {
			continue
		}
		if protocol == policy.ProtocolICMP {
			return destinationPort == 0
		}
		for _, portRange := range constraint.destinationPortRanges {
			if destinationPort >= portRange.First() && destinationPort <= portRange.Last() {
				return true
			}
		}
		return false
	}
	return false
}

// IsSubsetOf reports whether every permission in this set is within maximum.
func (set TrafficSet) IsSubsetOf(maximum TrafficSet) bool {
	if !set.IsValid() || !maximum.IsValid() {
		return false
	}
	intersection, ok := IntersectTraffic(set, maximum)
	return ok && equalTrafficSets(set, intersection)
}

// Hash returns a deterministic SHA-256 digest of canonical traffic authority.
func (set TrafficSet) Hash() [sha256.Size]byte {
	encoded := make([]byte, 0, 64)
	encoded = append(encoded, trafficHashDomain...)
	encoded = appendUint64(encoded, uint64(len(set.constraints)))
	for _, constraint := range set.constraints {
		encoded = append(encoded, byte(constraint.protocol))
		encoded = appendUint64(encoded, uint64(len(constraint.destinationPortRanges)))
		for _, portRange := range constraint.destinationPortRanges {
			var ports [4]byte
			binary.BigEndian.PutUint16(ports[0:2], portRange.First())
			binary.BigEndian.PutUint16(ports[2:4], portRange.Last())
			encoded = append(encoded, ports[:]...)
		}
	}
	return sha256.Sum256(encoded)
}

// IntersectTraffic returns the exact common authority and false when it is empty.
func IntersectTraffic(left, right TrafficSet) (TrafficSet, bool) {
	if !left.IsValid() || !right.IsValid() {
		return TrafficSet{}, false
	}

	constraints := make([]TrafficConstraint, 0, 3)
	for _, leftConstraint := range left.constraints {
		for _, rightConstraint := range right.constraints {
			if leftConstraint.protocol != rightConstraint.protocol {
				continue
			}
			if leftConstraint.protocol == policy.ProtocolICMP {
				constraints = append(constraints, TrafficConstraint{protocol: policy.ProtocolICMP})
				break
			}
			ranges := intersectPortRanges(
				leftConstraint.destinationPortRanges,
				rightConstraint.destinationPortRanges,
			)
			if len(ranges) > 0 {
				constraints = append(constraints, TrafficConstraint{
					protocol: leftConstraint.protocol, destinationPortRanges: ranges,
				})
			}
			break
		}
	}
	if len(constraints) == 0 {
		return TrafficSet{}, false
	}
	return TrafficSet{constraints: constraints}, true
}

func canonicalizePortRanges(values []policy.PortRange) []policy.PortRange {
	canonical := slices.Clone(values)
	slices.SortFunc(canonical, func(left, right policy.PortRange) int {
		switch {
		case left.First() < right.First():
			return -1
		case left.First() > right.First():
			return 1
		case left.Last() < right.Last():
			return -1
		case left.Last() > right.Last():
			return 1
		default:
			return 0
		}
	})

	merged := make([]policy.PortRange, 0, len(canonical))
	for _, current := range canonical {
		if current.First() == 0 || current.Last() < current.First() {
			return nil
		}
		if len(merged) == 0 {
			merged = append(merged, current)
			continue
		}
		previous := merged[len(merged)-1]
		adjacent := previous.Last() != ^uint16(0) && current.First() == previous.Last()+1
		if current.First() <= previous.Last() || adjacent {
			last := previous.Last()
			if current.Last() > last {
				last = current.Last()
			}
			merged[len(merged)-1], _ = policy.NewPortRange(previous.First(), last)
			continue
		}
		merged = append(merged, current)
	}
	return merged
}

func validCanonicalPortRanges(values []policy.PortRange) bool {
	if len(values) == 0 || len(values) > policy.MaximumPortRangesPerRule {
		return false
	}
	for index, current := range values {
		if current.First() == 0 || current.Last() < current.First() {
			return false
		}
		if index == 0 {
			continue
		}
		previous := values[index-1]
		if current.First() <= previous.Last() ||
			previous.Last() != ^uint16(0) && current.First() == previous.Last()+1 {
			return false
		}
	}
	return true
}

func intersectPortRanges(left, right []policy.PortRange) []policy.PortRange {
	intersection := make([]policy.PortRange, 0, min(len(left), len(right)))
	leftIndex, rightIndex := 0, 0
	for leftIndex < len(left) && rightIndex < len(right) {
		first := max(left[leftIndex].First(), right[rightIndex].First())
		last := min(left[leftIndex].Last(), right[rightIndex].Last())
		if first <= last {
			value, _ := policy.NewPortRange(first, last)
			intersection = append(intersection, value)
		}
		if left[leftIndex].Last() < right[rightIndex].Last() {
			leftIndex++
		} else {
			rightIndex++
		}
	}
	return intersection
}

func equalTrafficSets(left, right TrafficSet) bool {
	if len(left.constraints) != len(right.constraints) {
		return false
	}
	for index := range left.constraints {
		if left.constraints[index].protocol != right.constraints[index].protocol ||
			!slices.Equal(
				left.constraints[index].destinationPortRanges,
				right.constraints[index].destinationPortRanges,
			) {
			return false
		}
	}
	return true
}

func appendUint64(output []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(output, encoded[:]...)
}
