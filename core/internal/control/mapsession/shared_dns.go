package mapsession

import (
	"net/netip"
	"slices"
	"strings"

	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/sharing"
)

// SharedDNSRecord maps one consumer-local imported Resource name to the
// addresses this map routes to its provider Device. A name is discovery
// metadata only; packet authority remains the projection's exact grant.
type SharedDNSRecord struct {
	Name      string
	Addresses []netip.Addr
}

// SharedDNSRecords returns caller-owned records for every share this map
// imports, sorted by name, one per share: a share the map imports through
// several rules has one projection per rule, all of one contract and one
// name. Only the consumer side receives names. Alias shares resolve to the
// Resource Alias; legacy direct shares to the provider's canonical address.
// An invalid name fails the whole map closed; two shares under one name are
// both kept here, and the DNS view keeps the first (TD-CORE-80).
func (snapshot Snapshot) SharedDNSRecords() ([]SharedDNSRecord, error) {
	records := make([]SharedDNSRecord, 0, len(snapshot.directDeviceProjections))
	named := make(map[sharing.ContractID]struct{}, len(snapshot.directDeviceProjections))
	for _, projection := range snapshot.directDeviceProjections {
		if snapshot.Scope() != projection.authority.Contract.ConsumerScope() {
			continue
		}
		if _, done := named[projection.ContractID()]; done {
			continue
		}
		named[projection.ContractID()] = struct{}{}
		name := projection.authority.Endpoint.AccessName()
		if !name.IsValid() {
			return nil, ErrInvalidDirectDeviceProjection
		}
		records = append(records, SharedDNSRecord{Name: name.String(), Addresses: projection.answers()})
	}
	slices.SortStableFunc(records, func(left, right SharedDNSRecord) int { return strings.Compare(left.Name, right.Name) })
	return records, nil
}

// answers returns the addresses a name of the projected share answers: the
// Resource Alias, or a legacy direct share's provider address.
func (projection DirectDeviceProjection) answers() []netip.Addr {
	prefixes := projection.peer.Addresses()
	if projection.aliases.IsValid() {
		prefixes = projection.aliases.RemoteAddresses()
	}
	addresses := make([]netip.Addr, 0, len(prefixes))
	for _, prefix := range prefixes {
		addresses = append(addresses, prefix.Addr().Unmap())
	}
	return addresses
}

// shareAnswers returns the addresses a service name of each share this map
// imports answers (DNS design D3 §4.1): the consumer side holds a projection
// of it, one per rule, all of one contract and one alias. A share the map
// does not import is absent.
func (snapshot Snapshot) shareAnswers() map[sharing.ImportedResourceID][]netip.Addr {
	var shares map[sharing.ImportedResourceID][]netip.Addr
	for _, projection := range snapshot.directDeviceProjections {
		if snapshot.Scope() != projection.authority.Contract.ConsumerScope() {
			continue
		}
		share := projection.authority.Contract.ImportedResourceID()
		if _, done := shares[share]; done {
			continue
		}
		if shares == nil {
			shares = make(map[sharing.ImportedResourceID][]netip.Addr)
		}
		shares[share] = projection.answers()
	}
	return shares
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
