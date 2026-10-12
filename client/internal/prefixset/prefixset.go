// Package prefixset aggregates IP prefixes exactly: the result covers every
// address of the input and no other address. meshd installs it as the
// overlay routes, so thousands of peer host routes become a handful of
// prefixes without routing anything that is not a peer to the tunnel.
package prefixset

import (
	"net/netip"
	"slices"
)

// Summarize returns the fewest non-overlapping prefixes whose union is the
// union of prefixes, IPv4 first, each family in address order. Invalid
// prefixes are skipped; IPv4-mapped IPv6 prefixes count as IPv4.
func Summarize(prefixes []netip.Prefix) []netip.Prefix {
	canonical := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			continue
		}
		address, bits := prefix.Addr(), prefix.Bits()
		if address.Is4In6() {
			if bits < 96 {
				continue
			}
			address, bits = address.Unmap(), bits-96
		}
		canonical = append(canonical, netip.PrefixFrom(address, bits).Masked())
	}
	slices.SortFunc(canonical, compare)

	merged := make([]netip.Prefix, 0, len(canonical))
	for _, prefix := range canonical {
		if last := len(merged) - 1; last >= 0 && covers(merged[last], prefix) {
			continue // sorted by address then length, so a cover comes first
		}
		merged = append(merged, prefix)
		for len(merged) >= 2 {
			lower, upper := merged[len(merged)-2], merged[len(merged)-1]
			parent, ok := siblings(lower, upper)
			if !ok {
				break
			}
			merged = append(merged[:len(merged)-2], parent)
		}
	}
	return merged
}

// covers reports whether outer contains all of inner.
func covers(outer, inner netip.Prefix) bool {
	return outer.Addr().BitLen() == inner.Addr().BitLen() && outer.Bits() <= inner.Bits() &&
		outer.Contains(inner.Addr())
}

// siblings reports whether lower and upper are the two halves of one parent
// prefix, lower first, and returns that parent.
func siblings(lower, upper netip.Prefix) (netip.Prefix, bool) {
	if lower.Bits() != upper.Bits() || lower.Bits() == 0 || lower.Addr().BitLen() != upper.Addr().BitLen() ||
		lower == upper {
		return netip.Prefix{}, false
	}
	parent := netip.PrefixFrom(lower.Addr(), lower.Bits()-1).Masked()
	if parent != netip.PrefixFrom(upper.Addr(), upper.Bits()-1).Masked() || parent.Addr() != lower.Addr() {
		return netip.Prefix{}, false
	}
	return parent, true
}

func compare(left, right netip.Prefix) int {
	if left.Addr().BitLen() != right.Addr().BitLen() {
		return left.Addr().BitLen() - right.Addr().BitLen()
	}
	if order := left.Addr().Compare(right.Addr()); order != 0 {
		return order
	}
	return left.Bits() - right.Bits()
}
