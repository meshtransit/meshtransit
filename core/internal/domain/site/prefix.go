package site

import (
	"net/netip"
	"slices"
)

const (
	minimumIPv4Bits = 8
	minimumIPv6Bits = 32
)

// unusable lists ranges a Site prefix may never touch: the client overlay
// frame (100.64.0.0/10, 198.18.0.0/15 and fd00::/8, which also keeps IPv6
// unique local Sites out until clients narrow the frame to their Workspace)
// and addresses that are never routed to a LAN.
var unusable = [...]netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("fd00::/8"),
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// ValidatePrefix accepts one canonical Site prefix: not a default or very
// wide route, outside the overlay frame and special ranges, and not covering
// any of denied (the addresses clients dial: relays and the control
// endpoint).
func ValidatePrefix(prefix netip.Prefix, denied []netip.Prefix) error {
	if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
		return ErrInvalidPrefix
	}
	minimum := minimumIPv6Bits
	if prefix.Addr().Is4() {
		minimum = minimumIPv4Bits
	}
	if prefix.Bits() < minimum {
		return ErrInvalidPrefix
	}
	for _, reserved := range unusable {
		if prefix.Overlaps(reserved) {
			return ErrInvalidPrefix
		}
	}
	for _, address := range denied {
		if address.IsValid() && prefix.Overlaps(address) {
			return ErrInvalidPrefix
		}
	}
	return nil
}

// ValidatePrefixSet accepts the prefixes of one Site: at least one, at most
// limit, each valid, none overlapping another (a router could not tell which
// one a packet is for).
func ValidatePrefixSet(prefixes []netip.Prefix, denied []netip.Prefix, limit int) error {
	if len(prefixes) == 0 {
		return ErrInvalidPrefix
	}
	if len(prefixes) > limit {
		return ErrPrefixLimit
	}
	for index, prefix := range prefixes {
		if err := ValidatePrefix(prefix, denied); err != nil {
			return err
		}
		for _, other := range prefixes[:index] {
			if prefix.Overlaps(other) {
				return ErrInvalidPrefix
			}
		}
	}
	return nil
}

// Covers reports whether every prefix of wanted lies inside one prefix of
// offered: a router's offer covers a Site.
func Covers(offered, wanted []netip.Prefix) bool {
	return !slices.ContainsFunc(wanted, func(prefix netip.Prefix) bool {
		return !slices.ContainsFunc(offered, func(outer netip.Prefix) bool {
			return outer.Bits() <= prefix.Bits() && outer.Contains(prefix.Addr())
		})
	})
}

// Overlaps reports whether any prefix of first overlaps any of second.
func Overlaps(first, second []netip.Prefix) bool {
	return slices.ContainsFunc(first, func(prefix netip.Prefix) bool {
		return slices.ContainsFunc(second, prefix.Overlaps)
	})
}
