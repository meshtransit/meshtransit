package networkmap

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"unicode/utf8"
)

// maxServedProbes bounds the probes of one served Site (mtcp-v1 §14).
const maxServedProbes = 4

// ServedSite is one Site the node forwards to as a router (mtcp-v1 §7.6).
type ServedSite struct {
	Ref      string
	Prefixes []netip.Prefix
	// Masquerade translates mesh sources to the router's own address on the
	// way into the Site.
	Masquerade bool
	Probes     []RouteProbe
}

// RouteProbe is an address inside a served Site the router checks.
type RouteProbe struct {
	Address netip.Addr
	// TCP probes Port; otherwise the probe is an ICMP echo.
	TCP  bool
	Port uint16
}

// validateServed checks served as mtcp-v1 §7.6 requires: Sites sorted by
// reference and listed once; canonical, sorted prefixes within the bounds
// that overlap nowhere, within a Site or across Sites; at most 4 probes per
// Site, each inside its Site with a port only for TCP.
func validateServed(served []ServedSite) error {
	if len(served) > maxRouteSites {
		return fmt.Errorf("more than %d served Sites", maxRouteSites)
	}
	var all []netip.Prefix
	for index, site := range served {
		if site.Ref == "" || len(site.Ref) > maxRouteSiteReferences || !utf8.ValidString(site.Ref) ||
			(index > 0 && served[index-1].Ref >= site.Ref) {
			return errors.New("served site references must be valid, sorted and listed once")
		}
		if len(site.Prefixes) == 0 || len(site.Prefixes) > maxRouteSitePrefixes {
			return fmt.Errorf("served site %q has no or too many prefixes", site.Ref)
		}
		for position, prefix := range site.Prefixes {
			if !canonicalRoutePrefix(prefix) ||
				(position > 0 && compareRoutePrefixes(site.Prefixes[position-1], prefix) >= 0) {
				return fmt.Errorf("served site %q prefixes must be canonical, sorted and listed once", site.Ref)
			}
		}
		all = append(all, site.Prefixes...)
		if len(all) > maxRoutePrefixes {
			return errors.New("served routes exceed the map bounds")
		}
		if len(site.Probes) > maxServedProbes {
			return fmt.Errorf("served site %q has more than %d probes", site.Ref, maxServedProbes)
		}
		for _, probe := range site.Probes {
			inside := slices.ContainsFunc(site.Prefixes, func(prefix netip.Prefix) bool { return prefix.Contains(probe.Address) })
			if !probe.Address.IsValid() || probe.Address.Zone() != "" || !inside || probe.TCP != (probe.Port != 0) {
				return fmt.Errorf("served site %q has an invalid probe", site.Ref)
			}
		}
	}
	// Canonical prefixes overlap only by containment: sorted, a prefix that
	// overlaps any earlier one overlaps the one just before it.
	slices.SortFunc(all, compareRoutePrefixes)
	for index := 1; index < len(all); index++ {
		if all[index-1].Overlaps(all[index]) {
			return errors.New("served prefixes overlap")
		}
	}
	return nil
}

func cloneServed(served []ServedSite) []ServedSite {
	if served == nil {
		return nil
	}
	cloned := make([]ServedSite, len(served))
	for index, site := range served {
		cloned[index] = site
		cloned[index].Prefixes = slices.Clone(site.Prefixes)
		cloned[index].Probes = slices.Clone(site.Probes)
	}
	return cloned
}
