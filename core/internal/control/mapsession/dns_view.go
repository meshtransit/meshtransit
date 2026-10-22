package mapsession

import (
	"errors"
	"net/netip"
	"slices"
	"strings"

	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/sharing"
)

// MaximumDNSRecords bounds the address records of one map (mtcp-v1 §7.3),
// CNAME records included.
const MaximumDNSRecords = 50_000

// MaximumDNSNameBytes bounds what the names an administrator set add to one
// map's DNS, encoded (DNS design D2 §3.4): every map of the Network carries
// them again on each DNS change.
const MaximumDNSNameBytes = 1 << 20

// dnsRecordOverhead approximates the encoding of one record besides its name
// and value: field tags, lengths and its type.
const dnsRecordOverhead = 8

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
	// CNAME records of the names an administrator set (DNS design D2).
	aliases []DNSAlias
	unnamed int
	dropped int
	// overBudget counts zones, search domains and names left out by the
	// route budget of one map (DNS design D3 §4.3).
	overBudget int
}

// DNSAlias is one CNAME record: Name answers with Target.
type DNSAlias struct {
	Name   string
	Target string
}

// DNSForwardZone is one zone the node asks its resolvers for, each a peer's
// mesh address or an Internet address with its port. No resolver: the zone
// is unavailable and the node applies its failure mode.
type DNSForwardZone struct {
	Domain     string
	OtherNames DNSOtherNames
	FailOpen   bool
	Resolvers  []DNSResolver
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
	return snapshot.dnsView(suffix, true)
}

// DNSPeerNames is DNSView for naming peers only (a connectivity delta): it
// leaves out the names an administrator set and the zones, which only the
// DNS configuration carries.
func (snapshot Snapshot) DNSPeerNames(suffix dnsname.Suffix) (DNSView, error) {
	return snapshot.dnsView(suffix, false)
}

func (snapshot Snapshot) dnsView(suffix dnsname.Suffix, full bool) (DNSView, error) {
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
	taken, total := view.keep(candidates)
	if full {
		view.forwardZones(snapshot)
		config, left := view.routeBudget()
		view.keepAdminNames(config, left, view.adminNames(snapshot, taken, total))
	}
	slices.SortFunc(view.records, func(left, right DNSRecord) int { return strings.Compare(left.Name, right.Name) })
	return view, nil
}

// forwardZones adds the zones of the map's routes. A resolver Device is
// asked at the first IPv4 address of its peer: one the peer limit left out
// of the map is not asked. Search domains follow the Network's zone by
// position, then domain, up to MaximumDNSSearchDomains in all.
func (view *DNSView) forwardZones(snapshot Snapshot) {
	routes := snapshot.routes.dnsZones
	for _, route := range routes {
		zone := DNSForwardZone{Domain: route.Domain, OtherNames: route.OtherNames, FailOpen: route.FailOpen}
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
// record past MaximumDNSRecords addresses. It returns the names taken and
// the records kept.
func (view *DNSView) keep(candidates []DNSRecord) (map[string]struct{}, int) {
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
	return taken, total
}

// adminNames adds the names an administrator set that the map's routes let
// the Device see (DNS design D2 §3.4, §4.2), in name order after the names
// MeshTransit gives: a name another record took is left out, and so is a
// whole name past MaximumDNSRecords records or MaximumDNSNameBytes, or past
// the route budget. A name that points at a Device answers that Device's
// addresses while the map holds it (or it is the Device itself); one the
// peer limit left out is left out too. A name that points at a share
// answers the share's alias while the map projects the share (DNS design D3
// §4.1); else it is left out, and so is a CNAME whose chain reaches it.
func (view *DNSView) adminNames(snapshot Snapshot, taken map[string]struct{}, total int) []adminName {
	used := 0
	var names []adminName
	shares := snapshot.shareAnswers()
	unshared, cnames := snapshot.unsharedNames(shares)
	snapshot.routes.eachDNSName(func(name DNSNameRoute) {
		if _, hidden := unshared[name.FQDN]; hidden {
			return
		}
		if name.CNAME != "" && reachesUnshared(name, unshared, cnames) {
			return
		}
		if _, duplicate := taken[name.FQDN]; duplicate {
			view.dropped++
			return
		}
		if name.CNAME != "" {
			size := len(name.FQDN) + len(name.CNAME) + dnsRecordOverhead
			if total+1 > MaximumDNSRecords || used+size > MaximumDNSNameBytes {
				view.dropped++
				return
			}
			taken[name.FQDN] = struct{}{}
			total, used = total+1, used+size
			names = append(names, adminName{alias: &DNSAlias{Name: name.FQDN, Target: name.CNAME}})
			return
		}
		addresses := slices.Clone(name.Addresses)
		if name.Share.IsValid() {
			addresses = slices.Clone(shares[name.Share])
		} else if name.NodeID.IsValid() {
			if name.NodeID == snapshot.nodeID {
				addresses = recordOf(name.FQDN, snapshot.addresses).Addresses
			} else if peer, found := snapshot.authorizedPeer(name.NodeID); found {
				addresses = recordOf(name.FQDN, peer.addresses).Addresses
			} else {
				view.dropped++
				return
			}
		}
		size := 0
		for _, address := range addresses {
			size += len(name.FQDN) + len(address.AsSlice()) + dnsRecordOverhead
		}
		if len(addresses) == 0 || total+len(addresses) > MaximumDNSRecords || used+size > MaximumDNSNameBytes {
			view.dropped++
			return
		}
		taken[name.FQDN] = struct{}{}
		total, used = total+len(addresses), used+size
		names = append(names, adminName{record: DNSRecord{Name: name.FQDN, Addresses: addresses}})
	})
	return names
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

// Aliases returns the CNAME records sorted by name.
func (view DNSView) Aliases() []DNSAlias { return slices.Clone(view.aliases) }

// Zones returns the zones sorted by domain.
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

// OverBudget returns how many zones, search domains and names the route
// budget of one map left out.
func (view DNSView) OverBudget() int { return view.overBudget }

// unsharedNames returns the share names the map's routes let the Device
// see whose share the map does not project (no rule to it, an ended
// contract, or the peer limit) and, when there is one, the CNAMEs the
// Device sees, to follow chains to them. shares are the map's
// shareAnswers.
func (snapshot Snapshot) unsharedNames(shares map[sharing.ImportedResourceID][]netip.Addr) (map[string]struct{},
	map[string]string) {
	var unshared map[string]struct{}
	snapshot.routes.eachDNSName(func(name DNSNameRoute) {
		if !name.Share.IsValid() {
			return
		}
		if _, projected := shares[name.Share]; projected {
			return
		}
		if unshared == nil {
			unshared = make(map[string]struct{})
		}
		unshared[name.FQDN] = struct{}{}
	})
	if len(unshared) == 0 {
		return nil, nil
	}
	cnames := make(map[string]string)
	snapshot.routes.eachDNSName(func(name DNSNameRoute) {
		if name.CNAME != "" {
			cnames[name.FQDN] = name.CNAME
		}
	})
	return unshared, cnames
}

// reachesUnshared reports whether a CNAME's chain through the names the
// Device sees reaches a share name the map does not project: the CNAME
// stays hidden like the name (DNS design D3 §4.1). The routes already hid
// the chains through names the Device does not see.
func reachesUnshared(name DNSNameRoute, unshared map[string]struct{}, cnames map[string]string) bool {
	if len(unshared) == 0 {
		return false
	}
	target := name.CNAME
	for range maximumDNSCNAMEChain {
		if _, hidden := unshared[target]; hidden {
			return true
		}
		next, found := cnames[target]
		if !found {
			return false
		}
		target = next
	}
	return false
}
