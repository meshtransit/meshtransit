// Package mapsession opens authenticated client sessions from immutable,
// authoritative Network snapshots.
package mapsession

import (
	"errors"

	"meshtransit.net/core/internal/domain/node"
)

// ErrInvalidRequest reports an incomplete or unsupported map-session request.
var ErrInvalidRequest = errors.New("map session: invalid request")

// Request is the protocol-independent identity and connectivity input needed
// to open one map session.
type Request struct {
	nodeKey            node.Key
	deviceAliasVersion uint8
	relayZones         bool
	largeMap           bool
	routes             bool
	router             bool
	exits              bool
	exitRouter         bool
	dnsForward         bool
	dnsRecords         bool
	dnsRoot            bool
	kubernetes         bool
	endpointSet        node.EndpointSet
	hasEndpointSet     bool
	preferredRelay     int
	hasPreferredRelay  bool
}

// WithPreferredRelay returns a validated request carrying the complete client
// home-relay observation. Region zero is an explicit managed withdrawal.
func (request Request) WithPreferredRelay(regionID int) (Request, error) {
	request.preferredRelay = regionID
	request.hasPreferredRelay = true
	if !request.IsValid() {
		return Request{}, ErrInvalidRequest
	}
	return request, nil
}

// NewRequest validates an untrusted Node key.
func NewRequest(nodeKey node.Key) (Request, error) {
	request := Request{nodeKey: nodeKey}
	if !request.IsValid() {
		return Request{}, ErrInvalidRequest
	}
	return request, nil
}

// NodeKey returns the Node key claimed by this request.
func (request Request) NodeKey() node.Key { return request.nodeKey }

// WithEndpointSet returns a validated request carrying one transient client
// connectivity report. The original request remains unchanged.
func (request Request) WithEndpointSet(set node.EndpointSet) (Request, error) {
	request.endpointSet = set
	request.hasEndpointSet = true
	if !request.IsValid() {
		return Request{}, ErrInvalidRequest
	}
	return request, nil
}

// EndpointSet returns the client connectivity report when this request is an
// endpoint update. The returned set is immutable and protocol independent.
func (request Request) EndpointSet() (node.EndpointSet, bool) {
	return request.endpointSet, request.hasEndpointSet
}

// PreferredRelay returns the reported home relay when present. A present zero
// is an explicit withdrawal, not an omitted observation.
func (request Request) PreferredRelay() (int, bool) {
	return request.preferredRelay, request.hasPreferredRelay
}

// IsValid reports whether the request is safe to authorize.
func (request Request) IsValid() bool {
	if request.deviceAliasVersion > 1 || !request.nodeKey.IsValid() ||
		request.preferredRelay < 0 || request.preferredRelay > node.MaximumRelayRegionID ||
		(!request.hasPreferredRelay && request.preferredRelay != 0) ||
		request.hasPreferredRelay && !request.hasEndpointSet {
		return false
	}
	return !request.hasEndpointSet || request.endpointSet.IsValid()
}

// WithDeviceAliasVersion records an untrusted compatibility declaration.
// Only versions zero (unsupported) and one have an owned contract; neither
// grants access or substitutes for the authenticated bilateral reader.
func (request Request) WithDeviceAliasVersion(version uint8) (Request, error) {
	if version > 1 {
		return Request{}, ErrInvalidRequest
	}
	request.deviceAliasVersion = version
	if !request.IsValid() {
		return Request{}, ErrInvalidRequest
	}
	return request, nil
}

// DeviceAliasVersion returns the declared compatibility contract, or zero.
func (request Request) DeviceAliasVersion() uint8 { return request.deviceAliasVersion }

// WithLargeMap records the client's declaration (MTCP map.large1) that it
// applies maps of up to MaximumPeerCandidates peers. Without it a map carries
// at most LegacyPeerLimit peers; the declaration only raises that bound and
// grants no access.
func (request Request) WithLargeMap() Request {
	request.largeMap = true
	return request
}

// LargeMap reports whether the client declared large maps.
func (request Request) LargeMap() bool { return request.largeMap }

// WithKubernetes records that the node is a Kubernetes gateway that applies
// its peers' Kubernetes access (MTCP gateway.kube.v1, §7.8); the protocol
// adapter sets it only for a gateway's session.
func (request Request) WithKubernetes() Request {
	request.kubernetes = true
	return request
}

// Kubernetes reports whether the session takes its peers' Kubernetes access.
func (request Request) Kubernetes() bool { return request.kubernetes }

// WithRelayZones records that the client and Core negotiated relay.zones2:
// the client hands relays MTT2 tickets and their zone lists, so its relay
// grant may name every share instead of the oldest 31.
func (request Request) WithRelayZones() Request {
	request.relayZones = true
	return request
}

// RelayZones reports whether the session negotiated relay.zones2.
func (request Request) RelayZones() bool { return request.relayZones }

// WithRoutes records that the client takes subnet routes (MTCP
// routes.subnet.v1). Routes reach only clients that also declared large
// maps.
func (request Request) WithRoutes() Request {
	request.routes = true
	return request
}

// Routes reports whether the client takes subnet routes on a large map.
func (request Request) Routes() bool { return request.routes && request.largeMap }

// WithRouter records that the client can route into Sites (MTCP
// router.subnet.v1). It serves only on a large map: its consumers are cut
// at the large map's peer limit.
func (request Request) WithRouter() Request {
	request.router = true
	return request
}

// Router reports whether the client can route into Sites on a large map.
func (request Request) Router() bool { return request.router && request.largeMap }

// WithExits records that the client may send its Internet traffic through
// Exit Pools (MTCP routes.exit.v1). Pools reach only clients that also
// declared large maps.
func (request Request) WithExits() Request {
	request.exits = true
	return request
}

// Exits reports whether the client takes Exit Pools on a large map.
func (request Request) Exits() bool { return request.exits && request.largeMap }

// WithExitRouter records that the client can be an exit node (MTCP
// router.exit.v1). It serves only on a large map, as a router does.
func (request Request) WithExitRouter() Request {
	request.exitRouter = true
	return request
}

// ExitRouter reports whether the client can be an exit node on a large map.
func (request Request) ExitRouter() bool { return request.exitRouter && request.largeMap }

// WithDNSForward records that the client applies forward DNS zones (MTCP
// dns.forward1 with dns.split): routes with resolvers and ports, routes no
// resolver can serve, and their failure modes. Zones reach only clients
// that also declared large maps: their resolver Devices are needed peers.
func (request Request) WithDNSForward() Request {
	request.dnsForward = true
	return request
}

// DNSForward reports whether the client applies forward DNS zones on a
// large map.
func (request Request) DNSForward() bool { return request.dnsForward && request.largeMap }

// WithDNSRecords records that the client applies DNS names and every zone
// kind (MTCP dns.records1, DNS design D2 §4.1): CNAME records, zones that
// answer their other names NXDOMAIN or leave them to the host, and names
// under a zone's route without a route of their own.
func (request Request) WithDNSRecords() Request {
	request.dnsRecords = true
	return request
}

// DNSRecords reports whether the client applies DNS names: only with
// forward zones on a large map.
func (request Request) DNSRecords() bool { return request.dnsRecords && request.DNSForward() }

// WithDNSRoot records that the client applies the root zone, every name no
// other zone holds (MTCP dns.root1, DNS design D1b §3.2), and reports what
// DNS it applied.
func (request Request) WithDNSRoot() Request {
	request.dnsRoot = true
	return request
}

// DNSRoot reports whether the client applies the root zone: only with
// forward zones on a large map.
func (request Request) DNSRoot() bool { return request.dnsRoot && request.DNSForward() }
