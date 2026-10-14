package mtcp

import (
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	mtcpv1 "meshtransit.net/api/mtcp/v1"
	"meshtransit.net/core/internal/control/mapsession"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	sharedmtcp "meshtransit.net/shared/mtcp"
	"meshtransit.net/shared/mtrp"
)

// ErrMapEncoding reports a snapshot that cannot be encoded.
var ErrMapEncoding = errors.New("mtcp: map encoding")

// Map settings sent to every node (mtcp-v1 §7.3, §8).
const (
	endpointReportSeconds = 20
	pathStatsSeconds      = 60
)

// grantParts is a relay grant split into the MTCP messages that carry it.
type grantParts struct {
	relayMap    []byte
	signingKeys []*mtcpv1.KeyUpdate_SigningKey
	ticket      *mtcpv1.RelayTicket
}

func splitGrant(grant mapsession.RelayGrant) (grantParts, error) {
	if !grant.IsValid() {
		return grantParts{}, nil
	}
	parsed, err := mtrp.ParseInterchangeGrant(grant.Payload())
	if err != nil {
		return grantParts{}, errors.Join(ErrMapEncoding, err)
	}
	parts := grantParts{relayMap: parsed.RelayMap,
		ticket: &mtcpv1.RelayTicket{Ticket: parsed.Ticket, NotAfterMs: parsed.TicketNotAfter.UnixMilli(),
			Zones: parsed.TicketZones, FallbackTicket: parsed.FallbackTicket}}
	for _, trusted := range parsed.SigningKeys {
		id := trusted.Key.ID()
		parts.signingKeys = append(parts.signingKeys, &mtcpv1.KeyUpdate_SigningKey{
			KeyId: id[:], Key: trusted.Key[:], NotAfterMs: trusted.NotAfter.UnixMilli(),
		})
	}
	return parts, nil
}

// encodeSnapshot builds a complete MapSnapshot for view.
// encodeSnapshot encodes a full map; denied are the operator's ranges never
// sent as endpoints.
func encodeSnapshot(snapshot mapsession.Snapshot, view *mtcpv1.View, aliases bool,
	denied []netip.Prefix) (*mtcpv1.MapSnapshot, error) {
	if !snapshot.IsValid() {
		return nil, ErrMapEncoding
	}
	endpoints := newEndpointFilter(snapshot.RelayDirectory(), denied)
	self, err := encodeSelf(snapshot, endpoints)
	if err != nil {
		return nil, err
	}
	peers, err := encodePeers(snapshot, snapshot.AuthorizedPeers(), aliases, endpoints)
	if err != nil {
		return nil, err
	}
	filter, err := encodePacketFilter(snapshot)
	if err != nil {
		return nil, err
	}
	dns, err := encodeDNS(snapshot)
	if err != nil {
		return nil, err
	}
	grant, err := splitGrant(snapshot.RelayGrant())
	if err != nil {
		return nil, err
	}
	return &mtcpv1.MapSnapshot{
		View: view, NetworkRevisions: networkRevisions(snapshot), Self: self, Peers: peers,
		PacketFilter: filter, Dns: dns, RelayMap: grant.relayMap, Settings: settings(),
	}, nil
}

func settings() *mtcpv1.Settings {
	return &mtcpv1.Settings{EndpointReportS: endpointReportSeconds, PathStatsS: pathStatsSeconds}
}

func networkRevisions(snapshot mapsession.Snapshot) []*mtcpv1.NetworkRevision {
	return []*mtcpv1.NetworkRevision{{
		NetworkId: snapshot.Scope().NetworkID().String(),
		Revision:  uint64(snapshot.NetworkRevision()), //nolint:gosec // revisions are positive
	}}
}

func encodeSelf(snapshot mapsession.Snapshot, endpoints endpointFilter) (*mtcpv1.Device, error) {
	key := snapshot.NodeKey().Bytes()
	device := &mtcpv1.Device{
		DeviceId: snapshot.NodeID().String(), Name: snapshot.Hostname().String() + ".",
		DisplayName: snapshot.Hostname().String(), NodeKey: key[:],
		KeyExpiryMs: snapshot.KeyExpiry().UnixMilli(),
	}
	encodeAddresses(device, snapshot.Addresses())
	if connectivity, found := snapshot.ConnectivityFor(snapshot.NodeID()); found {
		if err := encodeConnectivity(device, connectivity, true, endpoints, snapshot.Addresses()); err != nil {
			return nil, err
		}
	}
	return device, nil
}

// encodePeers encodes candidates sorted by device ID.
func encodePeers(snapshot mapsession.Snapshot, candidates []mapsession.PeerCandidate,
	aliases bool, endpoints endpointFilter) ([]*mtcpv1.Device, error) {
	peers := make([]*mtcpv1.Device, 0, len(candidates))
	for _, candidate := range candidates {
		peer, err := encodePeer(snapshot, candidate, aliases, endpoints)
		if err != nil {
			return nil, err
		}
		peers = append(peers, peer)
	}
	slices.SortFunc(peers, func(a, b *mtcpv1.Device) int { return strings.Compare(a.GetDeviceId(), b.GetDeviceId()) })
	return peers, nil
}

func encodePeer(snapshot mapsession.Snapshot, candidate mapsession.PeerCandidate,
	aliases bool, endpoints endpointFilter) (*mtcpv1.Device, error) {
	key := candidate.NodeKey().Bytes()
	device := &mtcpv1.Device{
		DeviceId: candidate.NodeID().String(), Name: candidate.Hostname().String() + ".",
		NodeKey: key[:], KeyExpiryMs: candidate.KeyExpiry().UnixMilli(),
	}
	// A peer of another Workspace carries no display name (mtcp-v1 §7.3).
	if candidate.Scope().WorkspaceID() == snapshot.Scope().WorkspaceID() {
		device.DisplayName = candidate.Hostname().String()
	}
	encodeAddresses(device, candidate.Addresses())
	if connectivity, found := snapshot.ConnectivityFor(candidate.NodeID()); found {
		if err := encodeConnectivity(device, connectivity, false, endpoints, candidate.Addresses()); err != nil {
			return nil, err
		}
	}
	if grant, found := snapshot.DeviceAliasFor(candidate.NodeID()); found {
		if !aliases {
			return nil, ErrMapEncoding // such peers are never selected without device-alias.v1
		}
		alias, err := encodeAlias(grant)
		if err != nil {
			return nil, err
		}
		device.Alias = alias
	}
	return device, nil
}

func encodeAddresses(device *mtcpv1.Device, addresses []netip.Prefix) {
	for _, prefix := range addresses {
		address := prefix.Addr().Unmap()
		device.Addresses = append(device.Addresses, address.AsSlice())
		device.AllowedPrefixes = append(device.AllowedPrefixes,
			sharedmtcp.AppendPrefix(netip.PrefixFrom(address, address.BitLen())))
	}
}

// encodeConnectivity encodes the endpoints endpoints allows for a Device
// whose overlay addresses are overlay.
func encodeConnectivity(device *mtcpv1.Device, connectivity mapsession.Connectivity, self bool,
	endpoints endpointFilter, overlay []netip.Prefix) error {
	if !connectivity.IsValid() {
		return ErrMapEncoding
	}
	if set, present := connectivity.EndpointSet(); present {
		disco := set.DiscoveryKey().Bytes()
		device.DiscoKey = disco[:]
		for _, endpoint := range set.Endpoints() {
			kind, ok := endpointKind(endpoint.Source())
			address := endpoint.Address()
			if !ok || !endpoints.allows(address.Addr(), overlay) {
				continue
			}
			device.Endpoints = append(device.Endpoints, &mtcpv1.Endpoint{
				Ip: address.Addr().Unmap().AsSlice(), Port: uint32(address.Port()), Kind: kind,
			})
		}
	}
	if relay, present := connectivity.PreferredRelay(); present && relay > 0 {
		device.HomeRelay = uint32(relay) //nolint:gosec // region IDs are bounded
	}
	if !self {
		online := connectivity.Online()
		device.Online = &online
	}
	return nil
}

func endpointKind(source node.EndpointSource) (mtcpv1.Endpoint_Kind, bool) {
	switch source {
	case node.EndpointSourceLocal:
		return mtcpv1.Endpoint_HOST, true
	case node.EndpointSourceSTUN, node.EndpointSourceSTUNLocalPort:
		return mtcpv1.Endpoint_SERVER_REFLEXIVE, true
	case node.EndpointSourcePortMapped:
		return mtcpv1.Endpoint_PORT_MAPPED, true
	case node.EndpointSourceConfigured:
		return mtcpv1.Endpoint_STATIC, true
	default:
		return mtcpv1.Endpoint_KIND_UNSPECIFIED, false
	}
}

func encodeAlias(grant mapsession.DeviceAliasGrant) (*mtcpv1.AliasGrant, error) {
	role := mtcpv1.AliasGrant_PROVIDER
	if grant.IsConsumer {
		role = mtcpv1.AliasGrant_CONSUMER
	}
	alias := &mtcpv1.AliasGrant{
		ContractId: grant.ContractID.String(), EndpointId: grant.EndpointID.String(),
		Generation: uint64(grant.Generation), GrantRevision: grant.GrantRevision, //nolint:gosec // positive
		RecoveryEpoch: uint64(grant.RecoveryEpoch), Role: role, ExpiresMs: grant.ExpiresAt.UnixMilli(), //nolint:gosec // positive
	}
	for _, constraint := range grant.Traffic.Constraints() {
		switch constraint.Protocol() {
		case policy.ProtocolTCP, policy.ProtocolUDP:
			protocol := uint32(6)
			if constraint.Protocol() == policy.ProtocolUDP {
				protocol = 17
			}
			for _, ports := range constraint.DestinationPortRanges() {
				alias.Services = append(alias.Services, &mtcpv1.AliasService{
					Protocol: protocol, PortFrom: uint32(ports.First()), PortTo: uint32(ports.Last()),
				})
			}
		case policy.ProtocolICMP:
			for _, prefix := range grant.LocalAddresses {
				protocol := uint32(58)
				if prefix.Addr().Is4() {
					protocol = 1
				}
				alias.Services = append(alias.Services, &mtcpv1.AliasService{Protocol: protocol})
			}
		default:
			return nil, ErrMapEncoding
		}
	}
	if len(alias.Services) == 0 || len(alias.Services) > 64 {
		return nil, ErrMapEncoding
	}
	slices.SortFunc(alias.Services, func(a, b *mtcpv1.AliasService) int {
		if a.GetProtocol() != b.GetProtocol() {
			return int(a.GetProtocol()) - int(b.GetProtocol())
		}
		return int(a.GetPortFrom()) - int(b.GetPortFrom())
	})
	for _, prefix := range grant.LocalAddresses {
		if address := prefix.Addr(); address.Is4() {
			alias.MasqueradeV4 = address.AsSlice()
		} else {
			alias.MasqueradeV6 = address.AsSlice()
		}
	}
	return alias, nil
}

// ErrFilterDigest reports a packet filter the policy digest cannot cover.
var ErrFilterDigest = errors.New("mtcp: packet filter digest")

// PacketFilterDigest returns the policy digest v1 of the packet filter a
// map for snapshot carries, as meshd computes it from the filter it
// installs (docs/protocol/policy-digest-v1.md). Core compares it with the
// node's enforcement reports.
func PacketFilterDigest(snapshot mapsession.Snapshot) (mapsession.FilterDigest, error) {
	if !snapshot.IsValid() {
		return mapsession.FilterDigest{}, ErrFilterDigest
	}
	filter, err := encodePacketFilter(snapshot)
	if err != nil {
		return mapsession.FilterDigest{}, errors.Join(ErrFilterDigest, err)
	}
	digest, grants, err := sharedmtcp.FilterDigest(filter)
	if err != nil {
		return mapsession.FilterDigest{}, errors.Join(ErrFilterDigest, err)
	}
	return mapsession.NewFilterDigest(digest, grants)
}

// encodePacketFilter builds this node's inbound filter. Rules opening the
// same traffic to this node are merged and their sources split at the
// per-rule limit.
func encodePacketFilter(snapshot mapsession.Snapshot) (*mtcpv1.PacketFilter, error) {
	candidates := make(map[node.ID]mapsession.PeerCandidate)
	for _, candidate := range snapshot.AuthorizedPeers() {
		candidates[candidate.NodeID()] = candidate
	}
	type merged struct {
		destinations []*mtcpv1.Destination
		protocols    []uint32
		sources      []netip.Prefix
		seen         map[netip.Addr]struct{}
	}
	var order []string
	groups := make(map[string]*merged)
	for _, rule := range snapshot.InboundPacketRules() {
		if rule.DestinationNodeID() != snapshot.NodeID() {
			continue
		}
		candidate, ok := candidates[rule.SourceNodeID()]
		if !ok {
			continue // a rule may outlive its source Device; peers are authoritative
		}
		destinations, protocols, err := encodeDestinations(snapshot.Addresses(), rule)
		if err != nil {
			return nil, err
		}
		groupKey := trafficKey(destinations, protocols)
		group, exists := groups[groupKey]
		if !exists {
			group = &merged{destinations: destinations, protocols: protocols, seen: make(map[netip.Addr]struct{})}
			groups[groupKey] = group
			order = append(order, groupKey)
		}
		for _, source := range candidate.Addresses() {
			address := source.Addr().Unmap()
			if _, duplicate := group.seen[address]; duplicate {
				continue
			}
			group.seen[address] = struct{}{}
			group.sources = append(group.sources, netip.PrefixFrom(address, address.BitLen()))
		}
	}
	filter := &mtcpv1.PacketFilter{}
	for _, groupKey := range order {
		group := groups[groupKey]
		for start := 0; start < len(group.sources); start += sharedmtcp.MaxFilterRuleSources {
			rule := &mtcpv1.FilterRule{Destinations: group.destinations, Protocols: group.protocols}
			for _, source := range group.sources[start:min(start+sharedmtcp.MaxFilterRuleSources, len(group.sources))] {
				rule.Sources = append(rule.Sources, sharedmtcp.AppendPrefix(source))
			}
			filter.Rules = append(filter.Rules, rule)
		}
	}
	if len(filter.Rules) > sharedmtcp.MaxFilterRules {
		return nil, ErrMapEncoding
	}
	return filter, nil
}

func encodeDestinations(addresses []netip.Prefix, rule mapsession.InboundPacketRule) ([]*mtcpv1.Destination,
	[]uint32, error) {
	var protocols []uint32
	var ports []*mtcpv1.PortRange
	switch rule.Protocol() {
	case policy.ProtocolTCP:
		protocols = []uint32{6}
	case policy.ProtocolUDP:
		protocols = []uint32{17}
	case policy.ProtocolICMP:
		for _, address := range addresses {
			if address.Addr().Is4() && !slices.Contains(protocols, 1) {
				protocols = append(protocols, 1)
			}
			if address.Addr().Is6() && !slices.Contains(protocols, 58) {
				protocols = append(protocols, 58)
			}
		}
	default:
		return nil, nil, ErrMapEncoding
	}
	if rule.Protocol() != policy.ProtocolICMP {
		for _, portRange := range rule.DestinationPortRanges() {
			ports = append(ports, &mtcpv1.PortRange{First: uint32(portRange.First()), Last: uint32(portRange.Last())})
		}
		if len(ports) == 0 {
			return nil, nil, ErrMapEncoding
		}
	}
	destinations := make([]*mtcpv1.Destination, 0, len(addresses))
	for _, address := range addresses {
		host := address.Addr().Unmap()
		destinations = append(destinations, &mtcpv1.Destination{
			Prefix: sharedmtcp.AppendPrefix(netip.PrefixFrom(host, host.BitLen())), Ports: ports,
		})
	}
	if len(destinations) == 0 || len(protocols) == 0 {
		return nil, nil, ErrMapEncoding
	}
	return destinations, protocols, nil
}

func trafficKey(destinations []*mtcpv1.Destination, protocols []uint32) string {
	var builder strings.Builder
	for _, protocol := range protocols {
		builder.WriteString(strconv.FormatUint(uint64(protocol), 10))
		builder.WriteByte(',')
	}
	builder.WriteByte('|')
	for _, destination := range destinations {
		prefix, _ := sharedmtcp.ParsePrefix(destination.GetPrefix())
		builder.WriteString(prefix.String())
		for _, ports := range destination.GetPorts() {
			builder.WriteByte(':')
			builder.WriteString(strconv.FormatUint(uint64(ports.GetFirst()), 10))
			builder.WriteByte('-')
			builder.WriteString(strconv.FormatUint(uint64(ports.GetLast()), 10))
		}
		builder.WriteByte(';')
	}
	return builder.String()
}

// encodeDNS publishes the exact imported share names as A/AAAA records.
// It is never nil: within a stream an absent DNS means "unchanged".
func encodeDNS(snapshot mapsession.Snapshot) (*mtcpv1.DnsConfig, error) {
	records, err := snapshot.SharedDNSRecords()
	if err != nil {
		return nil, errors.Join(ErrMapEncoding, err)
	}
	config := &mtcpv1.DnsConfig{}
	for _, record := range records {
		for _, address := range record.Addresses {
			recordType := mtcpv1.DnsRecord_AAAA
			if address.Is4() {
				recordType = mtcpv1.DnsRecord_A
			}
			config.Records = append(config.Records, &mtcpv1.DnsRecord{
				Name: record.Name, Type: recordType, Value: address.Unmap().AsSlice(),
			})
		}
	}
	return config, nil
}
