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

// ErrDNSView reports a map whose names cannot be published safely.
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
type DNSView struct {
	selfName     string
	peerNames    map[node.ID]string
	records      []DNSRecord
	localSuffix  string
	searchDomain string
}

// placeholderZone never resolves (RFC 2606); it names the peers a map has
// no name for.
const placeholderZone = "invalid"

// DNSView computes the names this map publishes. A share name that falls in
// the Network's own zone (a legacy consumer-typed name) is left out so it
// can never shadow a Device.
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
	view.selfName = snapshot.hostname.String()
	if name, ok := zone.DeviceName(snapshot.dnsLabel); named && ok {
		view.selfName = name
		view.records = append(view.records, recordOf(name, snapshot.addresses))
	}
	for _, peer := range snapshot.authorized {
		name, record := snapshot.peerName(peer, zone, named, suffix)
		view.peerNames[peer.nodeID] = name
		if record {
			view.records = append(view.records, recordOf(name, peer.addresses))
		}
	}
	shared, err := snapshot.SharedDNSRecords()
	if err != nil {
		return DNSView{}, errors.Join(ErrDNSView, err)
	}
	for _, record := range shared {
		name := suffix.SharedName(record.Name)
		if named && zone.Contains(name) {
			continue
		}
		view.records = append(view.records, DNSRecord{Name: name, Addresses: slices.Clone(record.Addresses)})
	}
	slices.SortFunc(view.records, func(left, right DNSRecord) int { return strings.Compare(left.Name, right.Name) })
	total := 0
	for index, record := range view.records {
		if index > 0 && view.records[index-1].Name == record.Name {
			return DNSView{}, ErrDNSView
		}
		total += len(record.Addresses)
	}
	if total > MaximumDNSRecords {
		return DNSView{}, ErrDNSView
	}
	return view, nil
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
// an address record of the peer's own addresses.
func (snapshot Snapshot) peerName(peer PeerCandidate, zone dnsname.Zone, named bool,
	suffix dnsname.Suffix) (string, bool) {
	if peer.scope != snapshot.scope {
		if imported, ok := snapshot.ImportedPeerName(peer.nodeID); ok {
			return suffix.SharedName(imported), false
		}
		return "device-" + strings.ReplaceAll(peer.nodeID.String(), "-", "") + "." + placeholderZone, false
	}
	if name, ok := zone.DeviceName(peer.dnsLabel); named && ok {
		return name, true
	}
	return peer.hostname.String(), false
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
