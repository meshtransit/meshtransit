package pathdiscovery

import (
	"errors"
	"net/netip"
	"slices"
)

const maxHostAddressInputs = 256

// HostCandidates builds a bounded set from local interface addresses while
// excluding addresses owned by the overlay interface.
func HostCandidates(
	addresses []netip.Addr,
	port uint16,
	excluded []netip.Prefix,
) (Set, error) {
	if port == 0 {
		return Set{}, errors.New("pathdiscovery: host candidate port is invalid")
	}
	if len(addresses) > maxHostAddressInputs {
		return Set{}, errors.New("pathdiscovery: host address count exceeds limit")
	}
	for _, prefix := range excluded {
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() ||
			prefix.Addr().Zone() != "" {
			return Set{}, errors.New("pathdiscovery: excluded host prefix is invalid")
		}
	}

	candidates := make([]Candidate, 0, len(addresses))
	for _, address := range addresses {
		address = address.Unmap()
		if excludedHostAddress(address, excluded) {
			continue
		}
		candidate, err := NewCandidate(
			netip.AddrPortFrom(address, port),
			SourceHost,
		)
		if err != nil {
			continue
		}
		candidates = append(candidates, candidate)
	}
	slices.SortFunc(candidates, compareCandidates)
	candidates = compactEndpoints(candidates)
	if len(candidates) > MaxCandidates {
		candidates = candidates[:MaxCandidates]
	}

	return Set{candidates: candidates}, nil
}

func excludedHostAddress(address netip.Addr, excluded []netip.Prefix) bool {
	if !address.IsValid() {
		return false
	}
	for _, prefix := range excluded {
		if prefix.Contains(address) {
			return true
		}
	}

	return false
}
