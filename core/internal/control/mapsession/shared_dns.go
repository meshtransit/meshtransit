package mapsession

import (
	"net/netip"
	"slices"
	"strings"

	"meshtransit.net/core/internal/domain/node"
)

// SharedDNSRecord maps one consumer-local imported Resource name to the
// addresses this map routes to its provider Device. A name is discovery
// metadata only; packet authority remains the projection's exact grant.
type SharedDNSRecord struct {
	Name      string
	Addresses []netip.Addr
}

// SharedDNSRecords returns caller-owned records for every share this map
// imports, sorted by name. Only the consumer side receives names. Alias shares
// resolve to the Resource Alias; legacy direct shares to the provider's
// canonical address. A duplicate or invalid name fails the whole map closed.
func (snapshot Snapshot) SharedDNSRecords() ([]SharedDNSRecord, error) {
	records := make([]SharedDNSRecord, 0, len(snapshot.directDeviceProjections))
	for _, projection := range snapshot.directDeviceProjections {
		if snapshot.Scope() != projection.authority.Contract.ConsumerScope() {
			continue
		}
		name := projection.authority.Endpoint.AccessName()
		if !name.IsValid() {
			return nil, ErrInvalidDirectDeviceProjection
		}
		prefixes := projection.peer.Addresses()
		if projection.aliases.IsValid() {
			prefixes = projection.aliases.RemoteAddresses()
		}
		addresses := make([]netip.Addr, 0, len(prefixes))
		for _, prefix := range prefixes {
			addresses = append(addresses, prefix.Addr())
		}
		records = append(records, SharedDNSRecord{Name: name.String(), Addresses: addresses})
	}
	slices.SortFunc(records, func(left, right SharedDNSRecord) int { return strings.Compare(left.Name, right.Name) })
	for index := 1; index < len(records); index++ {
		if records[index].Name == records[index-1].Name {
			return nil, ErrInvalidDirectDeviceProjection
		}
	}
	return records, nil
}

// ImportedPeerName returns the consumer-local name under which this map
// imports peer (the smallest, when several shares import it), and whether
// it imports it at all. A provider-side map, which only exports to the
// peer, has no name for it.
func (snapshot Snapshot) ImportedPeerName(peer node.ID) (string, bool) {
	name := ""
	for _, projection := range snapshot.directDeviceProjections {
		if snapshot.Scope() != projection.authority.Contract.ConsumerScope() || projection.peer.NodeID() != peer {
			continue
		}
		access := projection.authority.Endpoint.AccessName()
		if access.IsValid() && (name == "" || access.String() < name) {
			name = access.String()
		}
	}
	return name, name != ""
}
