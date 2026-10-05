package mapsession

import (
	"net/netip"
	"slices"
	"time"

	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/sharing"
)

// DeviceAliasParams binds durable reservations to one exact peer pair. The
// reader must verify lease/session/key epochs before constructing this evidence.
type DeviceAliasParams struct {
	ContractID            sharing.ContractID
	EndpointID            sharing.PrivateEndpointID
	Generation            int64
	RecoveryEpoch         int64
	SelfKey               node.Key
	PeerKey               node.Key
	SelfSessionGeneration int64
	PeerSessionGeneration int64
	LocalAddresses        []netip.Prefix
	RemoteAddresses       []netip.Prefix
	ExpiresAt             time.Time
}

// DeviceAlias is immutable address ownership, never packet permission by itself.
// Permission comes only from each freshly evaluated bilateral projection.
type DeviceAlias struct{ params DeviceAliasParams }

// NewDeviceAlias validates and copies an exact-family reservation pair.
func NewDeviceAlias(params DeviceAliasParams) (DeviceAlias, error) {
	params.LocalAddresses = slices.Clone(params.LocalAddresses)
	params.RemoteAddresses = slices.Clone(params.RemoteAddresses)
	params.ExpiresAt = params.ExpiresAt.UTC()
	value := DeviceAlias{params: params}
	if !value.IsValid() {
		return DeviceAlias{}, ErrInvalidDirectDeviceProjection
	}
	return value, nil
}

// IsValid reports complete identity, family and finite deadline ownership.
func (value DeviceAlias) IsValid() bool {
	p := value.params
	if !p.ContractID.IsValid() || !p.EndpointID.IsValid() || p.Generation <= 0 || p.RecoveryEpoch <= 0 ||
		!p.SelfKey.IsValid() || !p.PeerKey.IsValid() || p.SelfKey == p.PeerKey ||
		p.SelfSessionGeneration <= 0 || p.PeerSessionGeneration <= 0 || p.ExpiresAt.IsZero() ||
		p.ExpiresAt.Year() < 1 || p.ExpiresAt.Year() > 9999 ||
		!validAliasAddresses(p.LocalAddresses) || !validAliasAddresses(p.RemoteAddresses) ||
		len(p.LocalAddresses) != len(p.RemoteAddresses) {
		return false
	}
	for i, local := range p.LocalAddresses {
		remote := p.RemoteAddresses[i]
		if local.Addr().BitLen() != remote.Addr().BitLen() || local == remote {
			return false
		}
	}
	return true
}

// LocalAddresses returns caller-owned host routes for the self alias per family.
func (value DeviceAlias) LocalAddresses() []netip.Prefix {
	return slices.Clone(value.params.LocalAddresses)
}

// RemoteAddresses returns caller-owned host routes owned by the exact peer key.
func (value DeviceAlias) RemoteAddresses() []netip.Prefix {
	return slices.Clone(value.params.RemoteAddresses)
}

func validAliasAddresses(values []netip.Prefix) bool {
	if !validSnapshotAddresses(values) {
		return false
	}
	for i, value := range values {
		a := value.Addr()
		if !a.IsGlobalUnicast() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.Is4In6() || a.Zone() != "" ||
			i > 0 && values[i-1].Addr().BitLen() >= a.BitLen() {
			return false
		}
	}
	return true
}

func (value DeviceAlias) matches(projection DirectDeviceProjection) bool {
	p, self, peer, authority := value.params, projection.self, projection.peer, projection.authority
	if !value.IsValid() || !authority.Contract.ScopeRelation().IsValid() ||
		authority.Endpoint.Mode() != sharing.EndpointModeFederationAlias ||
		p.ContractID != authority.Contract.ID() || p.EndpointID != authority.Endpoint.ID() ||
		p.Generation != authority.Endpoint.Generation() || p.RecoveryEpoch != authority.RecoveryEpoch ||
		p.SelfKey != self.NodeKey() || p.PeerKey != peer.NodeKey() ||
		p.SelfSessionGeneration != self.SessionGeneration() || p.PeerSessionGeneration != peer.SessionGeneration() ||
		!slices.Equal(p.RemoteAddresses, peer.Addresses()) ||
		!authority.EvaluatedAt.Before(p.ExpiresAt) ||
		p.ExpiresAt.After(earliestDeadline(self.KeyExpiry(), peer.KeyExpiry(), authority.Endpoint.ExpiresAt())) {
		return false
	}
	resources := p.RemoteAddresses
	if self.Scope() == authority.Contract.ProviderScope() {
		resources = p.LocalAddresses
	}
	found := false
	for i, local := range p.LocalAddresses {
		hasCanonical := false
		for _, canonical := range self.Addresses() {
			if canonical.Addr().BitLen() == local.Addr().BitLen() {
				hasCanonical = true
			}
			if canonical == local || canonical == p.RemoteAddresses[i] {
				return false
			}
		}
		if !hasCanonical {
			return false
		}
		if resources[i].Addr() == authority.Endpoint.ResourceAlias() {
			found = true
		}
	}
	return found
}

func equalDeviceAliases(first, second DeviceAlias) bool {
	a, b := first.params, second.params
	return a.ContractID == b.ContractID && a.EndpointID == b.EndpointID && a.Generation == b.Generation &&
		a.RecoveryEpoch == b.RecoveryEpoch && a.SelfKey == b.SelfKey && a.PeerKey == b.PeerKey &&
		a.SelfSessionGeneration == b.SelfSessionGeneration && a.PeerSessionGeneration == b.PeerSessionGeneration &&
		a.ExpiresAt.Equal(b.ExpiresAt) && slices.Equal(a.LocalAddresses, b.LocalAddresses) && slices.Equal(a.RemoteAddresses, b.RemoteAddresses)
}

// DeviceAliasGrant contains freshly evaluated packet authority for one peer.
// Multiple current rules for the same endpoint are canonicalized together.
type DeviceAliasGrant struct {
	ContractID      sharing.ContractID
	EndpointID      sharing.PrivateEndpointID
	Generation      int64
	GrantRevision   uint64
	RecoveryEpoch   int64
	SelfKey         node.Key
	PeerKey         node.Key
	IsConsumer      bool
	LocalAddresses  []netip.Prefix
	RemoteAddresses []netip.Prefix
	ExpiresAt       time.Time
	Traffic         sharing.TrafficSet
}

// DeviceAliasFor returns the exact alias grant, if this map authorizes the peer.
func (snapshot Snapshot) DeviceAliasFor(peerID node.ID) (DeviceAliasGrant, bool) {
	var result DeviceAliasGrant
	constraints := make([]sharing.TrafficConstraint, 0, 3)
	for _, projection := range snapshot.directDeviceProjections {
		if projection.Peer().NodeID() != peerID || !projection.aliases.IsValid() {
			continue
		}
		p := projection.aliases.params
		providerRevision, consumerRevision := projection.providerNetworkRevision, projection.consumerNetworkRevision
		if providerRevision <= 0 || consumerRevision <= 0 {
			return DeviceAliasGrant{}, false
		}
		revision := uint64(providerRevision) + uint64(consumerRevision)
		if result.GrantRevision == 0 {
			result = DeviceAliasGrant{ContractID: p.ContractID, EndpointID: p.EndpointID, Generation: p.Generation,
				GrantRevision: revision, RecoveryEpoch: p.RecoveryEpoch, SelfKey: p.SelfKey, PeerKey: p.PeerKey,
				IsConsumer:     snapshot.Scope() == projection.authority.Contract.ConsumerScope(),
				LocalAddresses: projection.aliases.LocalAddresses(), RemoteAddresses: projection.aliases.RemoteAddresses(), ExpiresAt: projection.ExpiresAt()}
		}
		constraints = append(constraints, projection.Traffic().Constraints()...)
		result.ExpiresAt = earliestDeadline(result.ExpiresAt, projection.ExpiresAt())
	}
	if result.GrantRevision == 0 {
		return DeviceAliasGrant{}, false
	}
	traffic, err := sharing.NewTrafficSet(constraints)
	if err != nil {
		return DeviceAliasGrant{}, false
	}
	result.Traffic = traffic
	return result, true
}

func aliasGrantChanged(current, next Snapshot, peerID node.ID) bool {
	a, before := current.DeviceAliasFor(peerID)
	b, after := next.DeviceAliasFor(peerID)
	return before != after || before && (a.GrantRevision != b.GrantRevision || a.EndpointID != b.EndpointID ||
		a.Generation != b.Generation || a.RecoveryEpoch != b.RecoveryEpoch || a.IsConsumer != b.IsConsumer ||
		a.SelfKey != b.SelfKey || a.PeerKey != b.PeerKey || !a.ExpiresAt.Equal(b.ExpiresAt) ||
		!slices.Equal(a.LocalAddresses, b.LocalAddresses) || !slices.Equal(a.RemoteAddresses, b.RemoteAddresses) || a.Traffic.Hash() != b.Traffic.Hash())
}

func (value DeviceAlias) isAbsent() bool {
	p := value.params
	return p.ContractID == (sharing.ContractID{}) && p.EndpointID == (sharing.PrivateEndpointID{}) && p.Generation == 0 &&
		p.RecoveryEpoch == 0 && p.SelfKey == (node.Key{}) && p.PeerKey == (node.Key{}) && p.SelfSessionGeneration == 0 &&
		p.PeerSessionGeneration == 0 && len(p.LocalAddresses) == 0 && len(p.RemoteAddresses) == 0 && p.ExpiresAt.IsZero()
}

func validAliasGrantBounds(params SnapshotParams) bool {
	constraints := make(map[node.ID][]sharing.TrafficConstraint)
	authorized := make(map[node.ID]struct{})
	for _, peer := range params.PeerCandidates {
		if params.PacketPolicy.AllowsPeer(params.NodeID, peer.NodeID()) {
			authorized[peer.NodeID()] = struct{}{}
		}
	}
	for _, projection := range params.DirectDeviceProjections {
		authorized[projection.Peer().NodeID()] = struct{}{}
		if projection.aliases.IsValid() {
			constraints[projection.Peer().NodeID()] = append(constraints[projection.Peer().NodeID()], projection.Traffic().Constraints()...)
		}
	}
	if len(constraints) == 0 {
		return true
	}
	if len(authorized) > MaximumDirectDeviceProjections {
		return false
	}
	for peer, values := range constraints {
		traffic, err := sharing.NewTrafficSet(values)
		if err != nil {
			return false
		}
		services := 0
		for _, constraint := range traffic.Constraints() {
			if constraint.Protocol() == policy.ProtocolICMP {
				for _, projection := range params.DirectDeviceProjections {
					if projection.Peer().NodeID() == peer {
						services += len(projection.aliases.LocalAddresses())
						break
					}
				}
			} else {
				services += len(constraint.DestinationPortRanges())
			}
		}
		if services > sharing.MaximumTrafficConstraints {
			return false
		}
	}
	return true
}
