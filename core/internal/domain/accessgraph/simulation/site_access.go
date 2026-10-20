package simulation

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"

	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/site"
)

// SiteAccess is one Device's access to part of a Site through one rule:
// the prefixes of the Site the rule grants, for its traffic. Maps send the
// Device a route to the Site while some rule grants it (mtcp-v1 §7.6).
type SiteAccess struct {
	ruleID   policy.RuleID
	source   node.ID
	site     site.ID
	prefixes []netip.Prefix
	protocol policy.Protocol
	ports    []policy.PortRange
}

// RuleID returns the rule that grants the access.
func (access SiteAccess) RuleID() policy.RuleID { return access.ruleID }

// SourceNodeID returns the Device the rule lets reach the Site.
func (access SiteAccess) SourceNodeID() node.ID { return access.source }

// SiteID returns the Site.
func (access SiteAccess) SiteID() site.ID { return access.site }

// Prefixes returns the part of the Site the rule grants; empty for all of
// it.
func (access SiteAccess) Prefixes() []netip.Prefix { return slices.Clone(access.prefixes) }

// Protocol returns the rule's protocol.
func (access SiteAccess) Protocol() policy.Protocol { return access.protocol }

// DestinationPortRanges returns the rule's ports; empty for ICMP.
func (access SiteAccess) DestinationPortRanges() []policy.PortRange { return slices.Clone(access.ports) }

func (access SiteAccess) isValid() bool {
	return access.ruleID.IsValid() && access.source.IsValid() && access.site.IsValid() && access.protocol.IsValid()
}

// siteAccess resolves the candidate's rules to Sites into one access per
// source Device, as maps resolve them.
func siteAccess(candidate publication.Candidate, members map[publication.RuleSide][]node.ID) ([]SiteAccess, error) {
	var accesses []SiteAccess
	for _, rule := range candidate.RouteRules() {
		sources := members[rule.Source()]
		if rule.Source().Kind() == publication.SideDevice {
			sources = []node.ID{node.ID(rule.Source().ID())}
		}
		if len(accesses)+len(sources) > MaximumResolvedRelationships {
			return nil, ErrTooLarge
		}
		for _, source := range sources {
			accesses = append(accesses, SiteAccess{
				ruleID: rule.RuleID(), source: source, site: rule.SiteID(), prefixes: rule.Prefixes(),
				protocol: rule.Protocol(), ports: rule.DestinationPortRanges(),
			})
		}
	}
	slices.SortFunc(accesses, compareSiteAccess)
	return slices.CompactFunc(accesses, func(first, second SiteAccess) bool { return compareSiteAccess(first, second) == 0 }), nil
}

func compareSiteAccess(first, second SiteAccess) int {
	return cmp.Or(
		strings.Compare(first.source.String(), second.source.String()),
		strings.Compare(first.site.String(), second.site.String()),
		strings.Compare(first.ruleID.String(), second.ruleID.String()),
		slices.CompareFunc(first.prefixes, second.prefixes, func(left, right netip.Prefix) int {
			return cmp.Or(left.Addr().Compare(right.Addr()), cmp.Compare(left.Bits(), right.Bits()))
		}),
		cmp.Compare(first.protocol, second.protocol),
		slices.CompareFunc(first.ports, second.ports, func(left, right policy.PortRange) int {
			return cmp.Or(cmp.Compare(left.First(), right.First()), cmp.Compare(left.Last(), right.Last()))
		}),
	)
}

func validSiteAccess(values []SiteAccess) bool {
	for index, value := range values {
		if !value.isValid() || (index > 0 && compareSiteAccess(values[index-1], value) >= 0) {
			return false
		}
	}
	return true
}

func cloneSiteAccess(values []SiteAccess) []SiteAccess {
	cloned := make([]SiteAccess, len(values))
	for index, value := range values {
		value.prefixes = slices.Clone(value.prefixes)
		value.ports = slices.Clone(value.ports)
		cloned[index] = value
	}
	return cloned
}
