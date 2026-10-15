package mapsession

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/core/internal/domain/resource"
	"meshtransit.net/core/internal/domain/resource/catalog"
	"meshtransit.net/core/internal/domain/sharing"
)

// MaximumDirectDeviceProjections bounds the explicit cross-Network grants a
// store puts in one snapshot: Core's largest map. A session sends at most its
// peer limit of them (oldest contracts first) and reports the rest omitted.
const MaximumDirectDeviceProjections = MaximumPeerCandidates

// ErrInvalidDirectDeviceProjection reports incomplete or unsafe bilateral evidence.
var ErrInvalidDirectDeviceProjection = errors.New("map session: invalid direct Device projection")

// DirectDeviceProjectionParams contains freshly resolved authority from one
// consistent snapshot. Peer inventory and a stored contract are insufficient.
type DirectDeviceProjectionParams struct {
	Self                    Snapshot
	Peer                    PeerCandidate
	ProviderTarget          catalog.Resource
	ProviderExport          sharing.Export
	Authority               sharing.EffectiveAccessParams
	ConsumerRule            publication.ImportedResourceDestination
	ProviderNetworkRevision int64
	ConsumerNetworkRevision int64
	ConsumerPolicyRevision  int64
	Aliases                 DeviceAlias
}

// DirectDeviceProjection is a directional two-client exception to ordinary
// Network isolation. It retains the peer's real scope and grants no membership.
type DirectDeviceProjection struct {
	self                    Snapshot
	peer                    PeerCandidate
	target                  catalog.Resource
	export                  sharing.Export
	authority               sharing.EffectiveAccessParams
	consumerRule            publication.ImportedResourceDestination
	providerNetworkRevision int64
	consumerNetworkRevision int64
	consumerPolicyRevision  int64
	traffic                 sharing.TrafficSet
	expiresAt               time.Time
	aliases                 DeviceAlias
}

// NewDirectDeviceProjection validates a ready direct endpoint and narrows one
// current consumer rule through every independent authority input.
func NewDirectDeviceProjection(params DirectDeviceProjectionParams) (DirectDeviceProjection, error) {
	if !params.Self.IsValid() || len(params.Self.directDeviceProjections) != 0 {
		return DirectDeviceProjection{}, ErrInvalidDirectDeviceProjection
	}
	// Retain only local authority, avoiding a copy of inventory per grant.
	empty, err := newNetworkInventory(params.Self.scope, nil)
	if err != nil {
		return DirectDeviceProjection{}, ErrInvalidDirectDeviceProjection
	}
	params.Self.candidates = snapshotCandidates{inventory: empty, self: -1}
	params.Self.authorized = []PeerCandidate{}
	params.Self.connectivity = nil
	projection := DirectDeviceProjection{
		self: params.Self, peer: params.Peer, target: params.ProviderTarget, export: params.ProviderExport,
		authority: params.Authority, consumerRule: params.ConsumerRule,
		providerNetworkRevision: params.ProviderNetworkRevision,
		consumerNetworkRevision: params.ConsumerNetworkRevision,
		consumerPolicyRevision:  params.ConsumerPolicyRevision,
		aliases:                 params.Aliases,
	}
	if !validDirectDeviceEvidence(projection) {
		return DirectDeviceProjection{}, ErrInvalidDirectDeviceProjection
	}
	decision := sharing.EvaluateEffectiveAccess(params.Authority)
	if !decision.IsAllowed() {
		return DirectDeviceProjection{}, ErrInvalidDirectDeviceProjection
	}
	projection.traffic = decision.Traffic()
	projection.expiresAt = earliestDeadline(
		params.Self.KeyExpiry(), params.Peer.KeyExpiry(),
		params.Authority.Contract.ExpiresAt(), params.Authority.Endpoint.ExpiresAt(),
	)
	if projection.aliases.IsValid() {
		projection.expiresAt = earliestDeadline(projection.expiresAt, projection.aliases.params.ExpiresAt)
	}
	return projection, nil
}

// Peer returns only the exact remote Device required by this directional grant.
func (projection DirectDeviceProjection) Peer() PeerCandidate { return projection.peer }

// ExpiresAt returns the earliest exclusive Device, contract or endpoint deadline.
func (projection DirectDeviceProjection) ExpiresAt() time.Time { return projection.expiresAt }

// ContractID returns the bilateral authority identity for this projection.
func (projection DirectDeviceProjection) ContractID() sharing.ContractID {
	return projection.authority.Contract.ID()
}

// ProviderScope returns the Network of the shared Device.
func (projection DirectDeviceProjection) ProviderScope() network.Scope {
	return projection.authority.Contract.ProviderScope()
}

// ConsumerScope returns the Network whose Devices reach the shared Device.
func (projection DirectDeviceProjection) ConsumerScope() network.Scope {
	return projection.authority.Contract.ConsumerScope()
}

// ConsumerRuleID returns the immutable consumer Access Rule identity.
func (projection DirectDeviceProjection) ConsumerRuleID() policy.RuleID {
	return projection.consumerRule.RuleID()
}

// Traffic returns a caller-owned exact authority intersection.
func (projection DirectDeviceProjection) Traffic() sharing.TrafficSet {
	value, _ := sharing.NewTrafficSet(projection.traffic.Constraints())
	return value
}

// IsValid reports whether all bilateral evidence still agrees at its recorded
// evaluation instant. Callers must reload authority before publishing a new map.
func (projection DirectDeviceProjection) IsValid() bool {
	if !validDirectDeviceEvidence(projection) || !projection.traffic.IsValid() {
		return false
	}
	decision := sharing.EvaluateEffectiveAccess(projection.authority)
	deadline := earliestDeadline(
		projection.self.KeyExpiry(), projection.peer.KeyExpiry(),
		projection.authority.Contract.ExpiresAt(), projection.authority.Endpoint.ExpiresAt(),
	)
	if projection.aliases.IsValid() {
		deadline = earliestDeadline(deadline, projection.aliases.params.ExpiresAt)
	}
	return decision.IsAllowed() && decision.Traffic().Hash() == projection.traffic.Hash() && projection.expiresAt.Equal(deadline)
}

func validDirectDeviceEvidence(projection DirectDeviceProjection) bool {
	self, peer, target, authority := projection.self, projection.peer, projection.target, projection.authority
	contract := authority.Contract
	if !self.IsValid() || len(self.directDeviceProjections) != 0 || !peer.IsValid() ||
		!target.IsValid() || target.State() != resource.StateActive || !contract.IsValid() ||
		!projection.export.IsUsableAt(authority.EvaluatedAt) ||
		projection.export.ID() != contract.ExportID() || projection.export.Resource() != contract.Resource() ||
		projection.export.ProviderScope() != contract.ProviderScope() || projection.export.ConsumerScope() != contract.ConsumerScope() ||
		projection.export.ProviderAuthorityGeneration() != authority.ProviderAuthorityGeneration ||
		projection.export.Version() != projection.consumerRule.Resolution().ExportVersion() ||
		!contract.MaximumTraffic().IsSubsetOf(projection.export.MaximumTraffic()) ||
		contract.ExpiresAt().After(projection.export.ExpiresAt()) ||
		!validDeviceProjectionMode(projection) ||
		!projection.consumerRule.IsValid() || !directConsumerRuleMatches(projection) ||
		projection.consumerRule.SourceNodeID() == target.DeviceID() ||
		projection.providerNetworkRevision < target.ActivatedNetworkRevision() || projection.consumerNetworkRevision <= 0 ||
		projection.consumerPolicyRevision <= 0 || len(authority.ConsumerRule.Constraints()) != 1 ||
		self.RecoveryEpoch() != authority.RecoveryEpoch ||
		!authority.EvaluatedAt.Before(self.KeyExpiry()) ||
		!authority.EvaluatedAt.Before(peer.KeyExpiry()) ||
		authority.EvaluatedAt.Before(self.CreatedAt()) || authority.EvaluatedAt.Before(peer.CreatedAt()) {
		return false
	}
	binding := contract.Resource()
	if target.Scope() != contract.ProviderScope() || target.ID() != binding.ResourceID() ||
		target.Version() != binding.ResourceVersion() ||
		target.TargetGeneration() != binding.TargetGeneration() ||
		target.SemanticHash() != binding.SemanticHash() ||
		authority.ResourceVersion != target.Version() ||
		authority.TargetGeneration != target.TargetGeneration() ||
		authority.ResourceSemanticHash != target.SemanticHash() {
		return false
	}
	providerAddresses := peer.Addresses()
	switch self.Scope() {
	case contract.ConsumerScope():
		if self.NodeID() != projection.consumerRule.SourceNodeID() || peer.NodeID() != target.DeviceID() ||
			peer.Scope() != contract.ProviderScope() ||
			self.NetworkRevision() != projection.consumerNetworkRevision ||
			self.PacketPolicy().Revision() != projection.consumerPolicyRevision {
			return false
		}
	case contract.ProviderScope():
		if self.NodeID() != target.DeviceID() || peer.NodeID() != projection.consumerRule.SourceNodeID() ||
			peer.Scope() != contract.ConsumerScope() ||
			self.NetworkRevision() != projection.providerNetworkRevision {
			return false
		}
		providerAddresses = self.Addresses()
	default:
		return false
	}
	if projection.aliases.IsValid() {
		return projection.aliases.matches(projection)
	}
	for _, local := range self.Addresses() {
		for _, remote := range peer.Addresses() {
			if local.Addr() == remote.Addr() {
				return false
			}
		}
	}
	for _, address := range providerAddresses {
		if address.Addr() == authority.Endpoint.ResourceAlias() {
			return true
		}
	}
	return false
}

func (projection DirectDeviceProjection) matchesSelf(params SnapshotParams) bool {
	self := projection.self
	return projection.IsValid() && params.Scope == self.Scope() && params.NodeID == self.NodeID() &&
		params.NetworkRevision == self.NetworkRevision() && params.RecoveryEpoch == self.RecoveryEpoch() &&
		params.SessionGeneration == self.SessionGeneration() &&
		params.NumericNodeID == self.NumericNodeID() && params.NumericOwnerID == self.NumericOwnerID() &&
		params.Hostname == self.Hostname() && params.CreatedAt.Equal(self.CreatedAt()) &&
		params.NodeKey == self.NodeKey() &&
		params.MachineKey == self.MachineKey() && params.KeyExpiry.Equal(self.KeyExpiry()) &&
		slices.Equal(params.Addresses, self.Addresses()) &&
		params.PacketPolicy.Equal(self.PacketPolicy())
}

func (projection DirectDeviceProjection) inboundRule() (InboundPacketRule, bool) {
	if projection.self.Scope() != projection.authority.Contract.ProviderScope() {
		return InboundPacketRule{}, false
	}
	constraint := projection.traffic.Constraints()[0]
	return InboundPacketRule{
		sourceNodeID: projection.consumerRule.SourceNodeID(), destinationNodeID: projection.target.DeviceID(),
		protocol: constraint.Protocol(), destinationPortRanges: constraint.DestinationPortRanges(),
	}, true
}

func earliestDeadline(values ...time.Time) time.Time {
	result := values[0]
	for _, value := range values[1:] {
		if value.Before(result) {
			result = value
		}
	}
	return result
}

func compareDirectDeviceProjections(first, second DirectDeviceProjection) int {
	if result := strings.Compare(first.ContractID().String(), second.ContractID().String()); result != 0 {
		return result
	}
	return strings.Compare(first.ConsumerRuleID().String(), second.ConsumerRuleID().String())
}

func equalDirectDeviceProjections(first, second []DirectDeviceProjection) bool {
	return slices.EqualFunc(first, second, func(left, right DirectDeviceProjection) bool {
		return left.ContractID() == right.ContractID() && left.ConsumerRuleID() == right.ConsumerRuleID() &&
			left.authority.Contract.Version() == right.authority.Contract.Version() &&
			left.export.Version() == right.export.Version() &&
			left.authority.Endpoint.ID() == right.authority.Endpoint.ID() &&
			left.authority.Endpoint.Generation() == right.authority.Endpoint.Generation() &&
			left.providerNetworkRevision == right.providerNetworkRevision &&
			left.consumerNetworkRevision == right.consumerNetworkRevision &&
			left.consumerPolicyRevision == right.consumerPolicyRevision &&
			left.traffic.Hash() == right.traffic.Hash() && left.expiresAt.Equal(right.expiresAt) &&
			equalPeerCandidate(left.peer, right.peer) && equalDeviceAliases(left.aliases, right.aliases)
	})
}

func validDirectDeviceProjections(params SnapshotParams, candidates snapshotCandidates) bool {
	if len(params.DirectDeviceProjections) == 0 {
		return true
	}
	// Peers, packet rules and projections are each bounded on their own; what
	// one session sends is bounded by its peer limit (withSessionLimit).
	if !validAliasGrantBounds(params) || len(params.DirectDeviceProjections) > MaximumDirectDeviceProjections {
		return false
	}
	ruleIDs := make(map[policy.RuleID]struct{}, len(params.DirectDeviceProjections))
	for _, rule := range params.PacketPolicy.Rules() {
		ruleIDs[rule.ID()] = struct{}{}
	}
	bindings := make(map[node.ID]DeviceAlias, len(params.DirectDeviceProjections))
	localAliases := make(map[netip.Addr]DirectDeviceProjection, 2*len(params.DirectDeviceProjections))
	seen := make(map[node.ID]PeerCandidate, candidates.len()+len(params.DirectDeviceProjections))
	numericIDs := map[int64]struct{}{params.NumericNodeID: {}}
	machineKeys := map[node.MachineKey]struct{}{params.MachineKey: {}}
	nodeKeys := map[node.Key]struct{}{params.NodeKey: {}}
	addresses := make(map[netip.Addr]struct{}, 2*(candidates.len()+len(params.DirectDeviceProjections)+1))
	for _, address := range params.Addresses {
		addresses[address.Addr()] = struct{}{}
	}
	add := func(peer PeerCandidate) {
		seen[peer.NodeID()] = peer
		numericIDs[peer.NumericNodeID()] = struct{}{}
		machineKeys[peer.MachineKey()] = struct{}{}
		nodeKeys[peer.NodeKey()] = struct{}{}
		for _, address := range peer.Addresses() {
			addresses[address.Addr()] = struct{}{}
		}
	}
	candidates.each(func(peer PeerCandidate) bool {
		add(peer)
		return true
	})
	for index, projection := range params.DirectDeviceProjections {
		if !projection.matchesSelf(params) || index > 0 &&
			compareDirectDeviceProjections(params.DirectDeviceProjections[index-1], projection) >= 0 {
			return false
		}
		if _, collision := ruleIDs[projection.ConsumerRuleID()]; collision {
			return false
		}
		ruleIDs[projection.ConsumerRuleID()] = struct{}{}
		peer := projection.Peer()
		if projection.aliases.IsValid() {
			if previous, exists := bindings[peer.NodeID()]; exists && !equalDeviceAliases(previous, projection.aliases) {
				return false
			}
			bindings[peer.NodeID()] = projection.aliases
			for _, address := range projection.aliases.LocalAddresses() {
				if _, collision := addresses[address.Addr()]; collision {
					return false
				}
				if previous, exists := localAliases[address.Addr()]; exists &&
					(previous.Peer().NodeID() != peer.NodeID() && (params.Scope != projection.authority.Contract.ProviderScope() ||
						previous.ContractID() != projection.ContractID() || previous.authority.Endpoint.ID() != projection.authority.Endpoint.ID() ||
						previous.aliases.params.Generation != projection.aliases.params.Generation)) {
					return false
				}
				localAliases[address.Addr()] = projection
			}
			for _, address := range peer.Addresses() {
				if _, collision := localAliases[address.Addr()]; collision {
					return false
				}
			}
		}
		if peer.NodeID() == params.NodeID || peer.NumericNodeID() == params.NumericNodeID ||
			peer.MachineKey() == params.MachineKey || peer.NodeKey() == params.NodeKey {
			return false
		}
		if previous, exists := seen[peer.NodeID()]; exists {
			if !equalPeerCandidate(previous, peer) {
				return false
			}
			continue
		}
		if _, collision := numericIDs[peer.NumericNodeID()]; collision {
			return false
		}
		if _, collision := machineKeys[peer.MachineKey()]; collision {
			return false
		}
		if _, collision := nodeKeys[peer.NodeKey()]; collision {
			return false
		}
		for _, address := range peer.Addresses() {
			if _, collision := addresses[address.Addr()]; collision {
				return false
			}
		}
		add(peer)
	}
	return true
}

// WithDirectDeviceProjections attaches explicit grants to an unchanged local
// map. Ordinary Network candidates and packet policy retain their exact scope.
func (snapshot Snapshot) WithDirectDeviceProjections(values []DirectDeviceProjection) (Snapshot, error) {
	params := snapshot.params()
	params.DirectDeviceProjections = slices.Clone(values)
	return NewSnapshot(params)
}

// WithOmittedShares returns a copy that reports at least omitted more shares
// than it carries, which a store left out to stay within its bounds.
func (snapshot Snapshot) WithOmittedShares(omitted int) (Snapshot, error) {
	if omitted < 0 {
		return Snapshot{}, ErrInvalidSnapshot
	}
	params := snapshot.params()
	params.OmittedShares = snapshot.omittedShares + omitted
	return NewSnapshot(params)
}

// CompareDirectDeviceProjections orders projections as a snapshot keeps
// them: oldest contract (a UUIDv7) first.
func CompareDirectDeviceProjections(first, second DirectDeviceProjection) int {
	return compareDirectDeviceProjections(first, second)
}

// InboundPacketRules returns local inbound rules and separately validated
// consumer-to-provider sharing rules. Consumer maps gain no reverse allow rule.
func (snapshot Snapshot) InboundPacketRules() []InboundPacketRule {
	if !snapshot.IsValid() {
		return []InboundPacketRule{}
	}
	rules := make([]InboundPacketRule, 0, len(snapshot.packetPolicy.Rules())+len(snapshot.directDeviceProjections))
	for _, rule := range snapshot.packetPolicy.Rules() {
		if rule.DestinationNodeID() == snapshot.nodeID {
			rules = append(rules, InboundPacketRule{
				sourceNodeID: rule.SourceNodeID(), destinationNodeID: rule.DestinationNodeID(),
				protocol: rule.Protocol(), destinationPortRanges: rule.DestinationPortRanges(),
			})
		}
	}
	for _, projection := range snapshot.directDeviceProjections {
		if rule, ok := projection.inboundRule(); ok {
			rules = append(rules, rule)
		}
	}
	return rules
}

// DirectDeviceProjectionCount returns how many shares the snapshot carries.
func (snapshot Snapshot) DirectDeviceProjectionCount() int {
	return len(snapshot.directDeviceProjections)
}

// HasDirectProjections reports whether the snapshot carries any direct
// sharing projection or sharing dependency.
func (snapshot Snapshot) HasDirectProjections() bool {
	return len(snapshot.directDeviceProjections) != 0 || len(snapshot.sharingDependencies) != 0
}

// ProjectionExpiry returns the earliest deadline requiring authoritative map
// reconstruction, independently of the authenticated self Device deadline.
func (snapshot Snapshot) ProjectionExpiry() time.Time {
	result := snapshot.keyExpiry
	for _, projection := range snapshot.directDeviceProjections {
		if projection.expiresAt.Before(result) {
			result = projection.expiresAt
		}
	}
	return result
}

// SharingScopes returns only distinct remote Network scopes used by current
// explicit grants and accepted-contract dependencies. Subscription hints never
// authorize peers, packets or cross-Network reads.
func (snapshot Snapshot) SharingScopes() []network.Scope {
	seen := make(map[network.Scope]struct{}, len(snapshot.directDeviceProjections)+len(snapshot.sharingDependencies))
	for _, scope := range snapshot.sharingDependencies {
		seen[scope] = struct{}{}
	}
	for _, projection := range snapshot.directDeviceProjections {
		seen[projection.Peer().Scope()] = struct{}{}
	}
	result := make([]network.Scope, 0, len(seen))
	for scope := range seen {
		result = append(result, scope)
	}
	slices.SortFunc(result, compareSharingScopes)
	return result
}

// InboundPacketRule is one validated local inbound tuple. It carries no
// administrative scope or reusable product Access Rule authority.
type InboundPacketRule struct {
	sourceNodeID          node.ID
	destinationNodeID     node.ID
	protocol              policy.Protocol
	destinationPortRanges []policy.PortRange
}

// SourceNodeID returns the exact authenticated source peer.
func (rule InboundPacketRule) SourceNodeID() node.ID { return rule.sourceNodeID }

// DestinationNodeID returns the exact self Device target.
func (rule InboundPacketRule) DestinationNodeID() node.ID { return rule.destinationNodeID }

// Protocol returns the allowed packet protocol.
func (rule InboundPacketRule) Protocol() policy.Protocol { return rule.protocol }

// DestinationPortRanges returns caller-owned destination intervals.
func (rule InboundPacketRule) DestinationPortRanges() []policy.PortRange {
	return slices.Clone(rule.destinationPortRanges)
}

func directConsumerRuleMatches(projection DirectDeviceProjection) bool {
	resolution := projection.consumerRule.Resolution()
	current, published := projection.authority.Contract, resolution.Contract()
	if current.ID() != published.ID() || current.Version() != published.Version() ||
		current.ProviderScope() != published.ProviderScope() || current.ConsumerScope() != published.ConsumerScope() ||
		current.Resource() != published.Resource() || current.ImportedResourceID() != resolution.ImportedResourceID() ||
		projection.authority.ImportedResourceVersion != resolution.ImportedResourceVersion() ||
		current.ExportID() != published.ExportID() || current.OfferID() != published.OfferID() ||
		current.RecoveryEpoch() != published.RecoveryEpoch() ||
		current.ProviderAuthorityGeneration() != published.ProviderAuthorityGeneration() ||
		current.ConsumerAuthorityGeneration() != published.ConsumerAuthorityGeneration() ||
		current.MaximumTraffic().Hash() != published.MaximumTraffic().Hash() ||
		!current.ExpiresAt().Equal(published.ExpiresAt()) {
		return false
	}
	constraint, err := sharing.NewTrafficConstraint(sharing.TrafficConstraintParams{
		Protocol: projection.consumerRule.Protocol(), DestinationPortRanges: projection.consumerRule.DestinationPortRanges(),
	})
	if err != nil {
		return false
	}
	traffic, err := sharing.NewTrafficSet([]sharing.TrafficConstraint{constraint})
	return err == nil && traffic.Hash() == projection.authority.ConsumerRule.Hash()
}

// validDeviceProjectionMode admits the alias path for every Network pair. The
// canonical-address direct path remains only for existing same-Workspace
// readiness until it is withdrawn; it is never valid across Workspaces.
func validDeviceProjectionMode(projection DirectDeviceProjection) bool {
	relation := projection.authority.Contract.ScopeRelation()
	if projection.authority.Endpoint.Mode() == sharing.EndpointModeFederationAlias {
		return relation.IsValid() && projection.aliases.IsValid()
	}
	return projection.aliases.isAbsent() &&
		relation == sharing.ScopeRelationWithinWorkspace && projection.authority.Endpoint.Mode() == sharing.EndpointModeDirect
}
