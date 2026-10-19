package publication

import (
	"cmp"
	"errors"
	"net/netip"
	"slices"
	"strings"

	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/devicetag"
	"meshtransit.net/core/internal/domain/identitygroup"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/site"
)

// MaximumGrantedRoutePrefixes bounds the prefixes all route rules of one
// release grant, so overlap checks and stored releases stay bounded.
const MaximumGrantedRoutePrefixes = 16384

var (
	// ErrInvalidRouteRule reports a route rule without one source, a Site and
	// canonical granted prefixes.
	ErrInvalidRouteRule = errors.New("policy publication: invalid route rule")
	// ErrRouteOverlap reports two rules that grant overlapping prefixes of two
	// different Sites: a Device could receive both and could not tell which
	// router a packet is for.
	ErrRouteOverlap = errors.New("policy publication: route rules of different Sites overlap")
	// ErrRoutePrefixLimit reports route rules that grant more than
	// MaximumGrantedRoutePrefixes prefixes in all.
	ErrRoutePrefixLimit = errors.New("policy publication: route rules grant too many prefixes")
)

// RouteRuleParams describes one Access Rule whose destination is a Site.
// Exactly one source is set. Prefixes are the part of the Site the rule
// grants, already intersected with the Site's prefixes at compilation.
type RouteRuleParams struct {
	RuleID                policy.RuleID
	SourceNodeID          node.ID
	SourceGroupID         devicegroup.ID
	SourceIdentityGroupID identitygroup.ID
	SourceTagID           devicetag.ID
	SiteID                site.ID
	Prefixes              []netip.Prefix
	Protocol              policy.Protocol
	DestinationPortRanges []policy.PortRange
}

// RouteRule is a release fact that names a source selector and a Site with
// the prefixes it grants. Maps resolve the source from membership current at
// each Network revision and intersect the prefixes with the Site's current
// ones, so a later Site change can narrow what the rule grants, never widen it.
type RouteRule struct {
	ruleID                policy.RuleID
	source                RuleSide
	siteID                site.ID
	prefixes              []netip.Prefix
	protocol              policy.Protocol
	destinationPortRanges []policy.PortRange
}

// NewRouteRule validates one route rule and canonicalizes its prefixes and
// ports.
func NewRouteRule(params RouteRuleParams) (RouteRule, error) {
	ports, valid := policy.CanonicalTraffic(params.Protocol, params.DestinationPortRanges)
	rule := RouteRule{
		ruleID: params.RuleID,
		source: oneSide(
			RuleSide{SideDevice, publicid.ID(params.SourceNodeID)},
			RuleSide{SideDeviceGroup, publicid.ID(params.SourceGroupID)},
			RuleSide{SideIdentityGroup, publicid.ID(params.SourceIdentityGroupID)},
			RuleSide{SideDeviceTag, publicid.ID(params.SourceTagID)},
		),
		siteID:   params.SiteID,
		prefixes: canonicalPrefixes(params.Prefixes),
		protocol: params.Protocol, destinationPortRanges: ports,
	}
	if !valid || !rule.IsValid() {
		return RouteRule{}, ErrInvalidRouteRule
	}
	return rule, nil
}

// canonicalPrefixes sorts IPv4 before IPv6, then by address and length, and
// drops duplicates.
func canonicalPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	sorted := slices.Clone(prefixes)
	slices.SortFunc(sorted, comparePrefixes)
	return slices.Compact(sorted)
}

func comparePrefixes(first, second netip.Prefix) int {
	return cmp.Or(first.Addr().Compare(second.Addr()), cmp.Compare(first.Bits(), second.Bits()))
}

// RuleID returns the Access Rule identity.
func (rule RouteRule) RuleID() policy.RuleID { return rule.ruleID }

// Source returns the source side.
func (rule RouteRule) Source() RuleSide { return rule.source }

// SiteID returns the destination Site.
func (rule RouteRule) SiteID() site.ID { return rule.siteID }

// Prefixes returns the caller-owned granted prefixes, canonical and sorted.
func (rule RouteRule) Prefixes() []netip.Prefix { return slices.Clone(rule.prefixes) }

// Protocol returns the packet protocol.
func (rule RouteRule) Protocol() policy.Protocol { return rule.protocol }

// DestinationPortRanges returns caller-owned canonical port ranges.
func (rule RouteRule) DestinationPortRanges() []policy.PortRange {
	return slices.Clone(rule.destinationPortRanges)
}

// IsValid reports one source, a Site, 1 to MaximumPrefixesPerSite canonical
// prefixes that do not overlap each other, and canonical traffic.
func (rule RouteRule) IsValid() bool {
	if !rule.ruleID.IsValid() || !rule.source.IsValid() || !rule.siteID.IsValid() ||
		len(rule.prefixes) == 0 || len(rule.prefixes) > site.MaximumPrefixesPerSite ||
		!slices.Equal(rule.prefixes, canonicalPrefixes(rule.prefixes)) {
		return false
	}
	for index, prefix := range rule.prefixes {
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() ||
			(index > 0 && rule.prefixes[index-1].Overlaps(prefix)) {
			return false
		}
	}
	ports, valid := policy.CanonicalTraffic(rule.protocol, rule.destinationPortRanges)
	return valid && slices.Equal(ports, rule.destinationPortRanges)
}

// CheckRouteOverlap refuses rules of different Sites whose prefixes overlap,
// whatever their sources: memberships change without a new release, so any
// two such rules could reach the same Device. Maps check again per Device.
//
// Two prefixes are either disjoint or one contains the other. Sorted by
// address and then length, each prefix follows the prefixes that contain
// it, so a stack of open containers finds every overlap in O(n log n) for
// n prefixes in all. Checking the innermost container is enough: an outer
// one of a third Site would already have overlapped the inner one.
func CheckRouteOverlap(rules []RouteRule) error {
	if GrantedRoutePrefixes(rules) > MaximumGrantedRoutePrefixes {
		return ErrRoutePrefixLimit
	}
	type entry struct {
		prefix netip.Prefix
		site   site.ID
	}
	entries := make([]entry, 0, len(rules))
	for _, rule := range rules {
		for _, prefix := range rule.prefixes {
			entries = append(entries, entry{prefix, rule.siteID})
		}
	}
	slices.SortFunc(entries, func(first, second entry) int { return comparePrefixes(first.prefix, second.prefix) })
	var open []entry
	for _, current := range entries {
		for len(open) > 0 && !containsPrefix(open[len(open)-1].prefix, current.prefix) {
			open = open[:len(open)-1]
		}
		if len(open) > 0 && open[len(open)-1].site != current.site {
			return ErrRouteOverlap
		}
		open = append(open, current)
	}
	return nil
}

// GrantedRoutePrefixes counts the prefixes the rules grant in all.
func GrantedRoutePrefixes(rules []RouteRule) int {
	granted := 0
	for _, rule := range rules {
		granted += len(rule.prefixes)
	}
	return granted
}

func containsPrefix(outer, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

func compareRouteRules(first, second RouteRule) int {
	return strings.Compare(first.ruleID.String(), second.ruleID.String())
}

func cloneRouteRules(rules []RouteRule) []RouteRule {
	cloned := make([]RouteRule, len(rules))
	for index, rule := range rules {
		cloned[index] = rule
		cloned[index].prefixes = slices.Clone(rule.prefixes)
		cloned[index].destinationPortRanges = slices.Clone(rule.destinationPortRanges)
	}
	return cloned
}
