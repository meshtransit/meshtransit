// Package ipam owns deterministic address-allocation invariants.
package ipam

import (
	"errors"
	"net/netip"
)

// MaxCandidateLimit is the hard upper bound for one allocation attempt.
const MaxCandidateLimit = 65536

var (
	// ErrInvalidAllocation reports a malformed prefix, snapshot, or resource bound.
	ErrInvalidAllocation = errors.New("ipam: invalid address allocation")
	// ErrAddressExhausted reports that no usable address exists inside the bounded search window.
	ErrAddressExhausted = errors.New("ipam: address allocation exhausted")
)

// NextAvailableAddress returns the lowest usable address not present in the
// immutable occupied snapshot. The caller must load the snapshot while holding
// the durable allocator lock; a database uniqueness constraint remains the
// final concurrency arbiter.
func NextAvailableAddress(
	prefix netip.Prefix,
	occupied []netip.Addr,
	candidateLimit int,
) (netip.Addr, error) {
	return NextAvailableAddressFrom(prefix, netip.Addr{}, occupied, candidateLimit)
}

// NextAvailableAddressFrom is NextAvailableAddress searching from start (the
// first host when start is unset or before it). The store passes the lowest
// free address it found, so a prefix holding more Devices than one search
// window still allocates; occupied then needs only addresses from start on.
func NextAvailableAddressFrom(
	prefix netip.Prefix,
	start netip.Addr,
	occupied []netip.Addr,
	candidateLimit int,
) (netip.Addr, error) {
	if start.IsValid() && (start.Is4() != prefix.Addr().Is4() || start.Is4In6()) {
		return netip.Addr{}, ErrInvalidAllocation
	}
	if !prefix.IsValid() || prefix != prefix.Masked() || candidateLimit <= 0 ||
		candidateLimit > MaxCandidateLimit || len(occupied) > candidateLimit {
		return netip.Addr{}, ErrInvalidAllocation
	}

	used := make(map[netip.Addr]struct{}, len(occupied))
	for _, address := range occupied {
		if !address.IsValid() || address.Is4() != prefix.Addr().Is4() ||
			!prefix.Contains(address) || address.Is4In6() {
			return netip.Addr{}, ErrInvalidAllocation
		}
		used[address] = struct{}{}
	}

	candidate := prefix.Addr().Next()
	if start.IsValid() && start.Compare(candidate) > 0 {
		candidate = start
	}
	for range candidateLimit {
		if !candidate.IsValid() || !prefix.Contains(candidate) || isIPv4Broadcast(prefix, candidate) {
			return netip.Addr{}, ErrAddressExhausted
		}
		if _, exists := used[candidate]; !exists {
			return candidate, nil
		}
		candidate = candidate.Next()
	}
	return netip.Addr{}, ErrAddressExhausted
}

func isIPv4Broadcast(prefix netip.Prefix, address netip.Addr) bool {
	if !address.Is4() {
		return false
	}
	next := address.Next()
	return !next.IsValid() || !prefix.Contains(next)
}
