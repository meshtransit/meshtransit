// Package pathdiscovery owns protocol-independent direct-path candidates.
package pathdiscovery

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
)

const (
	// MaxCandidates is the maximum number of endpoints published for one
	// active profile. Callers must reduce larger observations deliberately.
	MaxCandidates = 16

	maxCandidateInputs = 64
)

// ErrTooManyCandidates reports an observation that exceeds a fixed bound.
var ErrTooManyCandidates = errors.New("pathdiscovery: candidate count exceeds limit")

// Source identifies how a local direct-path candidate was learned.
type Source uint8

const (
	SourceUnknown Source = iota
	SourceHost
	SourceServerReflexive
	SourcePortMapping
	SourceConfigured
)

// String returns a product-owned diagnostic name without protocol terminology.
func (s Source) String() string {
	switch s {
	case SourceHost:
		return "host"
	case SourceServerReflexive:
		return "server_reflexive"
	case SourcePortMapping:
		return "port_mapping"
	case SourceConfigured:
		return "configured"
	default:
		return "unknown"
	}
}

// Candidate is an immutable, validated UDP endpoint and its discovery source.
type Candidate struct {
	endpoint netip.AddrPort
	source   Source
}

// NewCandidate validates one endpoint at the local discovery boundary.
func NewCandidate(endpoint netip.AddrPort, source Source) (Candidate, error) {
	candidate := Candidate{
		endpoint: endpoint,
		source:   source,
	}
	if err := candidate.validate(); err != nil {
		return Candidate{}, err
	}

	return candidate, nil
}

// Endpoint returns the canonical UDP address.
func (c Candidate) Endpoint() netip.AddrPort { return c.endpoint }

// Source returns how the endpoint was learned.
func (c Candidate) Source() Source { return c.source }

func (c Candidate) validate() error {
	switch c.source {
	case SourceHost, SourceServerReflexive, SourcePortMapping, SourceConfigured:
	default:
		return errors.New("pathdiscovery: candidate source is invalid")
	}

	address := c.endpoint.Addr()
	if !c.endpoint.IsValid() || c.endpoint.Port() == 0 || !address.IsValid() {
		return errors.New("pathdiscovery: candidate endpoint is invalid")
	}
	if address.Is4In6() || address.Zone() != "" || address != address.Unmap() {
		return errors.New("pathdiscovery: candidate endpoint is not canonical")
	}
	if !address.IsGlobalUnicast() || address.IsUnspecified() || address.IsMulticast() ||
		address.IsLoopback() || address.IsLinkLocalUnicast() {
		return errors.New("pathdiscovery: candidate address is unsafe")
	}

	return nil
}

// Set is a deterministic, immutable-by-convention candidate collection.
// Duplicate endpoints keep the source with the highest publication priority.
type Set struct {
	candidates []Candidate
}

// NewSet validates, orders, and deduplicates one complete observation.
func NewSet(candidates []Candidate) (Set, error) {
	if len(candidates) > maxCandidateInputs {
		return Set{}, fmt.Errorf(
			"%w: received %d inputs, maximum is %d",
			ErrTooManyCandidates,
			len(candidates),
			maxCandidateInputs,
		)
	}

	normalized := slices.Clone(candidates)
	for _, candidate := range normalized {
		if err := candidate.validate(); err != nil {
			return Set{}, err
		}
	}
	slices.SortFunc(normalized, compareCandidates)
	normalized = compactEndpoints(normalized)
	if len(normalized) > MaxCandidates {
		return Set{}, fmt.Errorf(
			"%w: received %d unique endpoints, maximum is %d",
			ErrTooManyCandidates,
			len(normalized),
			MaxCandidates,
		)
	}

	return Set{candidates: normalized}, nil
}

// Candidates returns a defensive copy in publication-priority order.
func (s Set) Candidates() []Candidate { return slices.Clone(s.candidates) }

// Endpoints returns a new address slice in publication-priority order.
func (s Set) Endpoints() []netip.AddrPort {
	endpoints := make([]netip.AddrPort, len(s.candidates))
	for index, candidate := range s.candidates {
		endpoints[index] = candidate.endpoint
	}

	return endpoints
}

// Len returns the number of unique candidates.
func (s Set) Len() int { return len(s.candidates) }

// Equal reports whether two normalized sets contain the same ordered values.
func (s Set) Equal(other Set) bool { return slices.Equal(s.candidates, other.candidates) }

func compareCandidates(left, right Candidate) int {
	if comparison := sourcePriority(left.source) - sourcePriority(right.source); comparison != 0 {
		return comparison
	}
	if left.endpoint.Addr().Is4() != right.endpoint.Addr().Is4() {
		if left.endpoint.Addr().Is4() {
			return -1
		}

		return 1
	}

	return left.endpoint.Compare(right.endpoint)
}

func sourcePriority(source Source) int {
	switch source {
	case SourcePortMapping:
		return 1
	case SourceServerReflexive:
		return 2
	case SourceConfigured:
		return 3
	case SourceHost:
		return 4
	default:
		return 5
	}
}

func compactEndpoints(candidates []Candidate) []Candidate {
	if len(candidates) < 2 {
		return candidates
	}

	result := candidates[:0]
	seen := make(map[netip.AddrPort]struct{}, len(candidates))
	for _, candidate := range candidates {
		if _, exists := seen[candidate.endpoint]; exists {
			continue
		}
		seen[candidate.endpoint] = struct{}{}
		result = append(result, candidate)
	}

	return result
}
