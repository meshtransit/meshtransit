package site

import (
	"cmp"
	"net/netip"
	"slices"
)

// MaximumOfferedPrefixes bounds what one Device reports it offers to
// forward (mtcp-v1 §8.2).
const MaximumOfferedPrefixes = 256

// ParseOffer keeps the prefixes of a Device's offer that could serve a
// Site, canonical and sorted IPv4 before IPv6, then by address and length,
// without duplicates, and counts the entries it dropped: host bits set,
// IPv4-mapped, a default or very wide route, the overlay frame or another
// range a Site may not use. Offering grants nothing; an entry dropped here
// could never have served a Site.
func ParseOffer(prefixes []netip.Prefix) (kept []netip.Prefix, dropped int) {
	kept = make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		if ValidatePrefix(prefix, nil) != nil {
			dropped++
			continue
		}
		kept = append(kept, prefix)
	}
	return CanonicalOffer(kept), dropped
}

// CanonicalOffer sorts prefixes IPv4 before IPv6, then by address and
// length, and drops duplicates.
func CanonicalOffer(prefixes []netip.Prefix) []netip.Prefix {
	sorted := slices.Clone(prefixes)
	slices.SortFunc(sorted, func(first, second netip.Prefix) int {
		return cmp.Or(first.Addr().Compare(second.Addr()), cmp.Compare(first.Bits(), second.Bits()))
	})
	return slices.Compact(sorted)
}
