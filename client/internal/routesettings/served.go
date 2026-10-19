package routesettings

import (
	"net/netip"
	"slices"
)

// Reasons a served route is not forwarded into.
const (
	// ReasonRouterOff: the host's router mode is off.
	ReasonRouterOff = "router_off"
	// ReasonNotAdvertised: the host does not offer the prefix (mtcp-v1
	// §7.6, health prefix_not_advertised).
	ReasonNotAdvertised = "not_advertised"
)

// ServedEntry is one prefix of one Site a router forwards into.
type ServedEntry struct {
	SiteRef    string
	Prefix     netip.Prefix
	Masquerade bool
}

// AdmitServed returns what the host forwards into of the served entries Core
// sends (mtcp-v1 §7.6): nothing unless router mode is on; otherwise, for
// each served prefix inside an advertised one, the served prefix, and for
// each advertised prefix inside a served one, the advertised one. A served
// prefix the host offers nothing of is refused, and so is any beyond
// MaximumRoutes. The result is sorted and its prefixes never overlap.
func AdmitServed(settings Settings, served []ServedEntry) ([]ServedEntry, []Refusal) {
	var admitted []ServedEntry
	var refused []Refusal
	for _, entry := range served {
		if !settings.RouterMode {
			refused = append(refused, Refusal{Prefix: entry.Prefix, Reason: ReasonRouterOff})
			continue
		}
		if reason := Usable(entry.Prefix); reason != "" {
			refused = append(refused, Refusal{Prefix: entry.Prefix, Reason: reason})
			continue
		}
		var parts []netip.Prefix
		for _, offered := range settings.AdvertiseRoutes {
			switch {
			case contains(offered, entry.Prefix):
				parts = append(parts, entry.Prefix)
			case contains(entry.Prefix, offered):
				parts = append(parts, offered)
			}
		}
		parts = outermost(parts)
		if len(parts) == 0 {
			refused = append(refused, Refusal{Prefix: entry.Prefix, Reason: ReasonNotAdvertised})
			continue
		}
		for _, part := range parts {
			admitted = append(admitted, ServedEntry{SiteRef: entry.SiteRef, Prefix: part, Masquerade: entry.Masquerade})
		}
	}
	slices.SortFunc(admitted, func(first, second ServedEntry) int { return comparePrefixes(first.Prefix, second.Prefix) })
	// Served Sites never overlap (Core and the map check it), so neither do
	// their parts; an overlap left means a malformed request: keep the first.
	kept := admitted[:0]
	for _, entry := range admitted {
		if len(kept) > 0 && kept[len(kept)-1].Prefix.Overlaps(entry.Prefix) {
			continue
		}
		kept = append(kept, entry)
	}
	admitted = kept
	if len(admitted) > MaximumRoutes {
		for _, entry := range admitted {
			refused = append(refused, Refusal{Prefix: entry.Prefix, Reason: ReasonTooMany})
		}
		admitted = nil
	}
	return admitted, refused
}

// contains reports whether outer contains or equals inner.
func contains(outer, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

// outermost keeps the prefixes no other one contains, each once.
func outermost(prefixes []netip.Prefix) []netip.Prefix {
	slices.SortFunc(prefixes, comparePrefixes)
	prefixes = slices.Compact(prefixes)
	kept := prefixes[:0]
	for _, prefix := range prefixes {
		if len(kept) == 0 || !contains(kept[len(kept)-1], prefix) {
			kept = append(kept, prefix)
		}
	}
	return kept
}
