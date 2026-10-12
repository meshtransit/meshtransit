package mapsession

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"time"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/sharing"
)

// MaximumRelayGrantContracts bounds the Trust Contract zones of one relay
// grant for a client without relay.zones2: an MTT1 ticket carries at most 32
// zones, one of them the Network.
const MaximumRelayGrantContracts = 31

// MaximumRelayZoneContracts bounds them for a client that declared
// relay.zones2 (MTT2 tickets): every share a map can carry.
const MaximumRelayZoneContracts = MaximumDirectDeviceProjections

// relayGrantRenewBefore is how long before expiry a grant is renewed. It
// leaves the node time to hand the relay a fresh ticket (mtcp-v1 §9 asks
// for at least two minutes).
const relayGrantRenewBefore = 5 * time.Minute

// ErrInvalidRelayGrant reports a malformed relay grant or request.
var ErrInvalidRelayGrant = errors.New("map session: invalid relay grant")

// RelayGrantRequest is what a node's Interchange access depends on. A new
// grant is needed when any of it changes.
type RelayGrantRequest struct {
	NodeKey        node.Key
	DiscoveryKey   node.DiscoveryKey
	Network        network.ID
	TrustContracts []sharing.ContractID // sorted, unique, at most the session's relay contract limit
	// NotAfter bounds the grant: the node's authority deadline.
	NotAfter time.Time
}

func (request RelayGrantRequest) equal(other RelayGrantRequest) bool {
	return request.NodeKey == other.NodeKey && request.DiscoveryKey == other.DiscoveryKey &&
		request.Network == other.Network && slices.Equal(request.TrustContracts, other.TrustContracts) &&
		request.NotAfter.Equal(other.NotAfter)
}

// RelayGrant is a node's Interchange access as produced by the relay
// authority: an opaque encoded payload, delivered to the node unchanged, and
// when it must be renewed.
type RelayGrant struct {
	payload []byte
	request RelayGrantRequest
	renewAt time.Time
	// mapKey identifies the relay map inside the grant, for relay access
	// that can tell when a Network's map changed (RelayMapFreshness).
	mapKey string
}

// RelayMapFreshness is implemented by relay access whose relay maps differ
// per Network (Private Interchange): a grant built on an older map is
// replaced at the next snapshot.
type RelayMapFreshness interface {
	RelayMapCurrent(network.ID, string) bool
}

// NewRelayGrantForMap is NewRelayGrant for a grant whose relay map has
// content key mapKey.
func NewRelayGrantForMap(request RelayGrantRequest, payload []byte, notAfter time.Time,
	mapKey string) (RelayGrant, error) {
	grant, err := NewRelayGrant(request, payload, notAfter)
	grant.mapKey = mapKey
	return grant, err
}

// NewRelayGrant wraps an encoded grant valid until notAfter.
func NewRelayGrant(request RelayGrantRequest, payload []byte, notAfter time.Time) (RelayGrant, error) {
	if len(payload) == 0 || notAfter.IsZero() {
		return RelayGrant{}, ErrInvalidRelayGrant
	}
	return RelayGrant{
		payload: bytes.Clone(payload),
		request: request,
		renewAt: notAfter.Add(-relayGrantRenewBefore),
	}, nil
}

// Payload returns a caller-owned copy of the encoded grant.
func (grant RelayGrant) Payload() []byte { return bytes.Clone(grant.payload) }

// IsValid reports whether the grant carries a payload.
func (grant RelayGrant) IsValid() bool { return len(grant.payload) != 0 }

// RenewAt is when the grant should be replaced.
func (grant RelayGrant) RenewAt() time.Time { return grant.renewAt }

// RelayAccess issues relay grants. Implementations sign tickets; the map
// session only decides when one is needed.
type RelayAccess interface {
	GrantRelayAccess(context.Context, RelayGrantRequest) (RelayGrant, error)
}

// RelayGrant returns the node's current relay grant, if any.
func (snapshot Snapshot) RelayGrant() RelayGrant { return snapshot.relayGrant }

// WithRelayGrant returns a copy carrying grant.
func (snapshot Snapshot) WithRelayGrant(grant RelayGrant) Snapshot {
	snapshot.relayGrant = grant
	return snapshot
}

// RelayGrantRequest derives what the node's grant must cover. It reports
// false while the node's disco key is unknown: a ticket binds it.
func (snapshot Snapshot) RelayGrantRequest() (RelayGrantRequest, bool) {
	if !snapshot.IsValid() {
		return RelayGrantRequest{}, false
	}
	self, found := snapshot.ConnectivityFor(snapshot.NodeID())
	if !found {
		return RelayGrantRequest{}, false
	}
	endpoints, present := self.EndpointSet()
	if !present || endpoints.DiscoveryKey() == (node.DiscoveryKey{}) {
		return RelayGrantRequest{}, false
	}
	contracts := make([]sharing.ContractID, 0, len(snapshot.directDeviceProjections))
	for _, projection := range snapshot.directDeviceProjections {
		contracts = append(contracts, projection.ContractID())
	}
	slices.SortFunc(contracts, func(a, b sharing.ContractID) int {
		left, right := a.Bytes(), b.Bytes()
		return bytes.Compare(left[:], right[:])
	})
	contracts = slices.Compact(contracts)
	if limit := snapshot.relayContractLimit(); len(contracts) > limit {
		// UUIDv7 order keeps the oldest contracts; a client without
		// relay.zones2 reaches newer ones only directly.
		contracts = contracts[:limit]
	}
	return RelayGrantRequest{
		NodeKey:        snapshot.NodeKey(),
		DiscoveryKey:   endpoints.DiscoveryKey(),
		Network:        snapshot.Scope().NetworkID(),
		TrustContracts: contracts,
		NotAfter:       snapshot.KeyExpiry(),
	}, true
}

// relayContractLimit is the session's bound on Trust Contract zones.
func (snapshot Snapshot) relayContractLimit() int {
	if snapshot.relayZones {
		return MaximumRelayZoneContracts
	}
	return MaximumRelayGrantContracts
}

// relayGrantCurrent reports whether grant still covers request at now.
func relayGrantCurrent(grant RelayGrant, request RelayGrantRequest, now time.Time) bool {
	return grant.IsValid() && grant.request.equal(request) && now.Before(grant.renewAt)
}

// WithRelayAccess returns a copy of the service that grants each node
// Interchange access through access.
func (service *StreamService) WithRelayAccess(access RelayAccess) (*StreamService, error) {
	if service == nil || isNilDependency(access) {
		return nil, ErrInvalidStreamService
	}
	options := service.options
	options.RelayAccess = access
	granted, err := NewStreamService(service.snapshots, service.presence, service.revisions,
		service.connectivity, options)
	if err != nil {
		return nil, err
	}
	granted.delivery = service.delivery
	granted.enforcement = service.enforcement
	return granted, nil
}
