package mapsession

import (
	"net/netip"
	"slices"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/node"
)

// Bounds of a Network's DNS names (DNS design D2 §3.4).
const (
	MaximumDNSNames         = 10_000
	MaximumDNSNameAddresses = 8
	maximumDNSCNAMEChain    = 8
	maximumDNSNameBytes     = 253
)

// DNSOtherNames is what a zone answers for the names it does not hold.
type DNSOtherNames uint8

const (
	// DNSOtherUnknown is the invalid zero value.
	DNSOtherUnknown DNSOtherNames = iota
	// DNSOtherForward asks the zone's resolvers (D1).
	DNSOtherForward
	// DNSOtherNXDomain answers that they do not exist, on the Device.
	DNSOtherNXDomain
	// DNSOtherHost leaves them to the host's own DNS.
	DNSOtherHost
)

// DNSName is one name an administrator set in a zone: one Device of the
// Network (its internal reference, 0 once it is gone), fixed addresses, or
// a CNAME; exactly one is set.
type DNSName struct {
	Zone      int64
	FQDN      string
	Device    int64
	NodeID    node.ID
	Addresses []netip.Addr
	CNAME     string
}

// DNSNameRoute is one name a map may carry: a Device target by NodeID (its
// addresses come from the map's peer, or self), fixed addresses, or a CNAME.
type DNSNameRoute struct {
	FQDN      string
	NodeID    node.ID
	Addresses []netip.Addr
	CNAME     string
}

func equalDNSNameRoute(first, second DNSNameRoute) bool {
	return first.FQDN == second.FQDN && first.NodeID == second.NodeID && first.CNAME == second.CNAME &&
		slices.Equal(first.Addresses, second.Addresses)
}

// DNSNames returns the names the Device may see, sorted by name.
func (view RouteView) DNSNames() []DNSNameRoute {
	cloned := make([]DNSNameRoute, len(view.dnsNames))
	for index, position := range view.dnsNames {
		name := view.nameTable[position]
		name.Addresses = slices.Clone(name.Addresses)
		cloned[index] = name
	}
	return cloned
}

// eachDNSName visits the names the Device may see in order, without
// copying: the table is shared and never changed.
func (view RouteView) eachDNSName(visit func(DNSNameRoute)) {
	for _, position := range view.dnsNames {
		visit(view.nameTable[position])
	}
}

func (view RouteView) equalDNSNames(other RouteView) bool {
	if len(view.dnsNames) != len(other.dnsNames) {
		return false
	}
	for index, position := range view.dnsNames {
		if !equalDNSNameRoute(view.nameTable[position], other.nameTable[other.dnsNames[index]]) {
			return false
		}
	}
	return true
}

// NameTargets returns the Devices the map's names point at, sorted: a
// limited map keeps them after shares, before other peers.
func (view RouteView) NameTargets() []node.ID { return slices.Clone(view.nameTargets) }

// indexDNSNames validates and indexes the Network's names: each in an
// active zone that is not the root and covers it, sorted by name, once
// each; and the rules by source, to find the destinations a Device may
// reach. Names come after indexDNSZones.
func (index *routeIndex) indexDNSNames(params NetworkPolicyParams, keysOf func(int64) []selectorKey) bool {
	if len(params.DNSNames) > MaximumDNSNames {
		return false
	}
	zoneOf := make(map[int64]int, len(index.zoneList))
	for position, zone := range index.zoneList {
		zoneOf[zone.Zone] = position
	}
	index.nameList = cloneDNSNames(params.DNSNames)
	slices.SortFunc(index.nameList, func(first, second DNSName) int { return strings.Compare(first.FQDN, second.FQDN) })
	index.nameZone = make([]int, len(index.nameList))
	index.nameRoutes = make([]DNSNameRoute, len(index.nameList))
	index.nameKeys = make([][]selectorKey, len(index.nameList))
	index.nameByFQDN = make(map[string]int, len(index.nameList))
	for position, name := range index.nameList {
		zone, known := zoneOf[name.Zone]
		if !known || !validDNSName(name, index.zoneList[zone].Domain) {
			return false
		}
		if _, duplicate := index.nameByFQDN[name.FQDN]; duplicate {
			return false
		}
		index.nameZone[position] = zone
		index.nameByFQDN[name.FQDN] = position
		index.nameRoutes[position] = DNSNameRoute{FQDN: name.FQDN, NodeID: name.NodeID, Addresses: name.Addresses,
			CNAME: name.CNAME}
		if name.Device > 0 {
			index.nameKeys[position] = append([]selectorKey{{kind: SelectorDevice, id: name.Device}},
				keysOf(name.Device)...)
		}
	}
	if len(index.nameList) == 0 {
		return true
	}
	index.rulesBySource = make(map[selectorKey][]int)
	for position, rule := range params.Rules {
		source := selectorKey{kind: rule.SourceKind, id: rule.SourceRef}
		index.rulesBySource[source] = append(index.rulesBySource[source], position)
	}
	return true
}

// validDNSName checks one name as read: a name in its zone's domain (the
// root holds none), and exactly one target, a CNAME to another name.
func validDNSName(name DNSName, domain string) bool {
	if name.Zone <= 0 || name.FQDN == "" || len(name.FQDN) > maximumDNSNameBytes || domain == "." ||
		(name.FQDN != domain && !strings.HasSuffix(name.FQDN, "."+domain)) {
		return false
	}
	device := name.NodeID.IsValid()
	switch {
	case name.CNAME != "":
		return !device && name.Device == 0 && len(name.Addresses) == 0 && name.CNAME != name.FQDN &&
			len(name.CNAME) <= maximumDNSNameBytes
	case device:
		return name.Device >= 0 && len(name.Addresses) == 0
	default:
		return name.Device == 0 && len(name.Addresses) > 0 && len(name.Addresses) <= MaximumDNSNameAddresses &&
			!slices.ContainsFunc(name.Addresses, func(address netip.Addr) bool { return !address.IsValid() })
	}
}

// reaches returns the selectors a rule from self may reach at now: the
// destination of every rule whose source selects self.
func (inner *networkPolicy) reaches(self int64, now time.Time) map[selectorKey]struct{} {
	index := inner.routes
	destinations := make(map[selectorKey]struct{})
	add := func(source selectorKey) {
		for _, position := range index.rulesBySource[source] {
			rule := inner.rules[position]
			destinations[selectorKey{kind: rule.DestinationKind, id: rule.DestinationRef}] = struct{}{}
		}
	}
	add(selectorKey{kind: SelectorDevice, id: self})
	for key, validUntil := range inner.memberOf[self] {
		if validUntil.IsZero() || now.Before(validUntil) {
			add(key)
		}
	}
	return destinations
}

// reachable reports whether target is self, or a live Device that one of
// destinations selects at now; keys are the target's selectors, its own
// first.
func (inner *networkPolicy) reachable(self, target int64, keys []selectorKey, destinations map[selectorKey]struct{},
	now time.Time) bool {
	if target == self {
		return true
	}
	if target <= 0 || !inner.live(target, now) {
		return false
	}
	for _, key := range keys {
		if _, found := destinations[key]; found && inner.selects(key.kind, key.id, target, now) {
			return true
		}
	}
	return false
}

// consumerDNSNames adds the names self may see (DNS design D2 §4.2): those of
// the zones sent to it; a name pointing at a Device only while a rule from
// self reaches that live Device (one the other way is not enough); a CNAME
// unless its chain through the Network's names ends at a Device name self
// may not see. The Device targets are kept for the peer limit.
func (inner *networkPolicy) consumerDNSNames(view *RouteView, self int64, now time.Time) {
	index := inner.routes
	if len(index.nameList) == 0 {
		return
	}
	received := make([]bool, len(index.zoneList))
	for position, zone := range index.zoneList {
		received[position] = zone.Domain != "." && inner.receives(zone, self, now)
	}
	destinations := inner.reaches(self, now)
	view.nameTable = index.nameRoutes
	visible := make([]int32, 0, len(index.nameList))
	// hidden reports a name self may not see, CNAMEs not followed.
	hidden := func(position int) bool {
		name := index.nameList[position]
		if !received[index.nameZone[position]] {
			return true
		}
		return name.NodeID.IsValid() && !inner.reachable(self, name.Device, index.nameKeys[position], destinations, now)
	}
	for position, name := range index.nameList {
		if hidden(position) {
			continue
		}
		if name.CNAME != "" && !inner.chainVisible(name, hidden) {
			continue
		}
		visible = append(visible, int32(position))
		if name.NodeID.IsValid() && name.Device != self {
			view.nameTargets = append(view.nameTargets, name.NodeID)
		}
	}
	// Every stream keeps its map: hold exactly the names it sees.
	if len(visible) > 0 {
		view.dnsNames = slices.Clone(visible)
	}
}

// chainVisible follows a CNAME through the Network's own names: it hides
// the name when a step is a Device name self may not see. A chain that
// leaves the Network's names, or runs past the bound, is the client's to
// resolve.
func (inner *networkPolicy) chainVisible(name DNSName, hidden func(int) bool) bool {
	index := inner.routes
	target := name.CNAME
	for range maximumDNSCNAMEChain {
		position, found := index.nameByFQDN[target]
		if !found {
			return true
		}
		next := index.nameList[position]
		if next.NodeID.IsValid() && hidden(position) {
			return false
		}
		if next.CNAME == "" {
			return true
		}
		target = next.CNAME
	}
	return true
}

func (index *routeIndex) equalDNSNames(other *routeIndex) bool {
	return slices.EqualFunc(index.nameList, other.nameList, func(first, second DNSName) bool {
		return first.Zone == second.Zone && first.FQDN == second.FQDN && first.Device == second.Device &&
			first.NodeID == second.NodeID && first.CNAME == second.CNAME &&
			slices.Equal(first.Addresses, second.Addresses)
	})
}

func cloneDNSNames(names []DNSName) []DNSName {
	cloned := make([]DNSName, len(names))
	for index, name := range names {
		name.Addresses = slices.Clone(name.Addresses)
		cloned[index] = name
	}
	return cloned
}
