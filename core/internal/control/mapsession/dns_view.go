package mapsession

import (
	"errors"
	"net/netip"
	"slices"
	"strings"

	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/node"
)

// MaximumDNSRecords bounds the address records of one map (mtcp-v1 §7.3).
const MaximumDNSRecords = 50_000

// ErrDNSView reports a snapshot whose names cannot be computed at all.
var ErrDNSView = errors.New("map session: invalid DNS view")

// DNSRecord is one name and its addresses, A and AAAA alike.
type DNSRecord struct {
	Name      string
	Addresses []netip.Addr
}

// DNSView is what a map publishes about names under one deployment suffix
// (mtcp-v1 §7.3). Names carry no trailing root dot.
//
// Self and the peers of its own Network are <label>.<zone>, the zone being
// <workspace code>.<network code>.<suffix>; each has an address record. A
// peer of another Network is known only by the name this map imports it
// under (its share name, under shared.<suffix>), or by a placeholder that
// never resolves when the map only exports to it: its hostname and label are
// never published. The suffix is one locally authoritative route and the
// zone the search domain.
//
// Names never fail a map: a Device of the Network without a label gets no
// name or record (Unnamed counts them), and a record whose name another
// record already took, or that would pass MaximumDNSRecords addresses, is
// left out (Dropped counts them). Records are kept in a fixed order: self,
// the peers in Device order, then shares in stored-name order.
type DNSView struct {
	selfName     string
	peerNames    map[node.ID]string
	records      []DNSRecord
	localSuffix  string
	searchDomain string
	// Forward zones (DNS design D1) and the search domains after the
	// Network's zone.
	zones         []DNSForwardZone
	searchDomains []string
	unnamed       int
	dropped       int
}

// DNSForwardZone is one zone the node asks its resolvers for, each a peer's
// mesh address or an Internet address with its port. No resolver: the zone
// is unavailable and the node applies its failure mode.
type DNSForwardZone struct {
	Domain    string
	FailOpen  bool
	Resolvers []DNSResolver
}

// DNSResolver is one address and port a zone's questions go to.
type DNSResolver struct {
	Address netip.Addr
	Port    uint16
}

// placeholderZone never resolves (RFC 2606); it names the peers a map has
// no name for.
const placeholderZone = "invalid"

// DNSView computes the names this map publishes. A share name that falls in
// the Network's own zone (a legacy consumer-typed name) is left out so it
// can never shadow a Device. It fails only for an invalid snapshot or share
// evidence.
func (snapshot Snapshot) DNSView(suffix dnsname.Suffix) (DNSView, error) {
	if !snapshot.valid {
		return DNSView{}, ErrDNSView
	}
	view := DNSView{peerNames: make(map[node.ID]string, len(snapshot.authorized))}
	zone, named := snapshot.zone(suffix)
	if suffix.IsValid() {
		view.localSuffix = suffix.String()
	}
	if named {
		view.searchDomain = zone.String()
	}
	shared, err := snapshot.SharedDNSRecords()
	if err != nil {
		return DNSView{}, errors.Join(ErrDNSView, err)
	}
	candidates := make([]DNSRecord, 0, len(snapshot.authorized)+len(shared)+1)
	view.selfName = snapshot.hostname.String()
	if name, ok := zone.DeviceName(snapshot.dnsLabel); named && ok {
		view.selfName = name
		candidates = append(candidates, recordOf(name, snapshot.addresses))
	} else if named {
		view.unnamed++
	}
	for _, peer := range snapshot.authorized {
		name, record, unnamed := snapshot.peerName(peer, zone, named, suffix)
		view.peerNames[peer.nodeID] = name
		if record {
			candidates = append(candidates, recordOf(name, peer.addresses))
		}
		if unnamed {
			view.unnamed++
		}
	}
	for _, record := range shared {
		name := suffix.SharedName(record.Name)
		if named && zone.Contains(name) {
			view.dropped++
			continue
		}
		candidates = append(candidates, DNSRecord{Name: name, Addresses: slices.Clone(record.Addresses)})
	}
	view.keep(candidates)
	slices.SortFunc(view.records, func(left, right DNSRecord) int { return strings.Compare(left.Name, right.Name) })
	view.forwardZones(snapshot)
	return view, nil
}

// forwardZones adds the zones of the map's routes. A resolver Device is
// asked at the first IPv4 address of its peer: one the peer limit left out
// of the map is not asked. Search domains follow the Network's zone by
// position, then domain, up to MaximumDNSSearchDomains in all.
func (view *DNSView) forwardZones(snapshot Snapshot) {
	routes := snapshot.routes.dnsZones
	for _, route := range routes {
		zone := DNSForwardZone{Domain: route.Domain, FailOpen: route.FailOpen}
		for _, resolver := range route.Resolvers {
			if resolver.Address.IsValid() {
				zone.Resolvers = append(zone.Resolvers, DNSResolver{Address: resolver.Address, Port: resolver.Port})
				continue
			}
			peer, found := snapshot.authorizedPeer(resolver.NodeID)
			if !found {
				continue
			}
			if index := slices.IndexFunc(peer.addresses, func(prefix netip.Prefix) bool {
				return prefix.Addr().Unmap().Is4()
			}); index >= 0 {
				zone.Resolvers = append(zone.Resolvers, DNSResolver{Address: peer.addresses[index].Addr().Unmap(),
					Port: resolver.Port})
			}
		}
		view.zones = append(view.zones, zone)
	}
	search := slices.DeleteFunc(slices.Clone(routes), func(route DNSZoneRoute) bool { return route.SearchPosition == 0 })
	slices.SortFunc(search, compareSearchZones)
	room := MaximumDNSSearchDomains
	if view.searchDomain != "" {
		room--
	}
	for _, route := range search[:min(len(search), room)] {
		view.searchDomains = append(view.searchDomains, route.Domain)
	}
}

// keep adds candidates in order, leaving out a name already taken and any
// record past MaximumDNSRecords addresses.
func (view *DNSView) keep(candidates []DNSRecord) {
	taken := make(map[string]struct{}, len(candidates))
	total := 0
	for _, record := range candidates {
		if _, duplicate := taken[record.Name]; duplicate || total+len(record.Addresses) > MaximumDNSRecords {
			view.dropped++
			continue
		}
		taken[record.Name] = struct{}{}
		total += len(record.Addresses)
		view.records = append(view.records, record)
	}
}

// zone returns the Network's zone when the store gave its display codes.
func (snapshot Snapshot) zone(suffix dnsname.Suffix) (dnsname.Zone, bool) {
	workspaceCode, networkCode, ok := snapshot.DisplayCodes()
	if !ok {
		return dnsname.Zone{}, false
	}
	zone, err := dnsname.NewZone(workspaceCode, networkCode, suffix)
	return zone, err == nil
}

// peerName names one authorized peer; record reports whether the name gets
// an address record of the peer's own addresses, unnamed that a peer of the
// Network has no label to be named by.
func (snapshot Snapshot) peerName(peer PeerCandidate, zone dnsname.Zone, named bool,
	suffix dnsname.Suffix) (name string, record, unnamed bool) {
	if peer.scope != snapshot.scope {
		if imported, ok := snapshot.ImportedPeerName(peer.nodeID); ok {
			return suffix.SharedName(imported), false, false
		}
		return "device-" + strings.ReplaceAll(peer.nodeID.String(), "-", "") + "." + placeholderZone, false, false
	}
	if name, ok := zone.DeviceName(peer.dnsLabel); named && ok {
		return name, true, false
	}
	return peer.hostname.String(), false, named
}

func recordOf(name string, prefixes []netip.Prefix) DNSRecord {
	addresses := make([]netip.Addr, 0, len(prefixes))
	for _, prefix := range prefixes {
		addresses = append(addresses, prefix.Addr().Unmap())
	}
	return DNSRecord{Name: name, Addresses: addresses}
}

// SelfName returns the name of the map's own Device.
func (view DNSView) SelfName() string { return view.selfName }

// PeerName returns the name of an authorized peer; found is false for a
// Device that is not one.
func (view DNSView) PeerName(peer node.ID) (string, bool) {
	name, found := view.peerNames[peer]
	return name, found
}

// Records returns caller-owned address records sorted by name.
func (view DNSView) Records() []DNSRecord {
	records := make([]DNSRecord, len(view.records))
	for index, record := range view.records {
		records[index] = DNSRecord{Name: record.Name, Addresses: slices.Clone(record.Addresses)}
	}
	return records
}

// LocalSuffix returns the suffix the node answers itself ("" without one).
func (view DNSView) LocalSuffix() string { return view.localSuffix }

// SearchDomain returns the Network's zone ("" when the map names no Device).
func (view DNSView) SearchDomain() string { return view.searchDomain }

// SearchDomains returns every search domain in order: the Network's zone,
// then the forward zones that are search domains.
func (view DNSView) SearchDomains() []string {
	if view.searchDomain == "" {
		return slices.Clone(view.searchDomains)
	}
	return append([]string{view.searchDomain}, view.searchDomains...)
}

// Zones returns the forward zones sorted by domain.
func (view DNSView) Zones() []DNSForwardZone {
	zones := make([]DNSForwardZone, len(view.zones))
	for index, zone := range view.zones {
		zone.Resolvers = slices.Clone(zone.Resolvers)
		zones[index] = zone
	}
	return zones
}

// Unnamed returns how many Devices of the Network the map lists without a
// name because they hold no DNS label.
func (view DNSView) Unnamed() int { return view.unnamed }

// Dropped returns how many records were left out: a name another record
// took, a share name in the Network's zone, or past MaximumDNSRecords.
func (view DNSView) Dropped() int { return view.dropped }
