package sharing

import (
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/resource"
)

var (
	// ErrInvalidExport reports incomplete or inconsistent provider authority.
	ErrInvalidExport = errors.New("sharing: invalid export")
	// ErrInvalidOffer reports incomplete or inconsistent bilateral offer state.
	ErrInvalidOffer = errors.New("sharing: invalid offer")
	// ErrInvalidContract reports incomplete or inconsistent accepted authority.
	ErrInvalidContract = errors.New("sharing: invalid contract")
	// ErrInvalidTransition reports a non-monotonic or expired lifecycle action.
	ErrInvalidTransition = errors.New("sharing: invalid transition")
)

// ExportState is the provider-controlled Resource Export lifecycle.
type ExportState uint8

const (
	// ExportStateUnknown is the unusable zero value.
	ExportStateUnknown ExportState = iota
	// ExportStateActive permits bounded offers and accepted contracts.
	ExportStateActive
	// ExportStateRevoked permanently removes provider authority.
	ExportStateRevoked
)

// OfferState is the single-decision Share Offer lifecycle.
type OfferState uint8

const (
	// OfferStateUnknown is the unusable zero value.
	OfferStateUnknown OfferState = iota
	// OfferStateOffered awaits one consumer decision.
	OfferStateOffered
	// OfferStateAccepted records the terminal successful decision.
	OfferStateAccepted
	// OfferStateRejected records the terminal consumer rejection.
	OfferStateRejected
	// OfferStateExpired records that the exclusive deadline elapsed.
	OfferStateExpired
	// OfferStateRevoked records provider withdrawal before acceptance.
	OfferStateRevoked
)

// ContractState is the accepted Trust Contract lifecycle.
type ContractState uint8

const (
	// ContractStateUnknown is the unusable zero value.
	ContractStateUnknown ContractState = iota
	// ContractStateActivating retains accepted authority while no safe path exists.
	ContractStateActivating
	// ContractStateActive permits evaluation when every current input agrees.
	ContractStateActive
	// ContractStateRevoked permanently removes authority at either side.
	ContractStateRevoked
	// ContractStateExpired records validity-window exhaustion.
	ContractStateExpired
	// ContractStateInvalidated records stale Resource, generation, or recovery authority.
	ContractStateInvalidated
)

// ResourceBinding pins provider identity and target authority for one share.
type ResourceBinding struct {
	scope            network.Scope
	resourceID       resource.ID
	resourceVersion  int64
	targetGeneration int64
	semanticHash     resource.SemanticHash
}

// NewResourceBinding constructs exact provider Resource authority.
func NewResourceBinding(
	scope network.Scope,
	resourceID resource.ID,
	resourceVersion int64,
	targetGeneration int64,
	semanticHash resource.SemanticHash,
) (ResourceBinding, error) {
	binding := ResourceBinding{
		scope: scope, resourceID: resourceID, resourceVersion: resourceVersion,
		targetGeneration: targetGeneration, semanticHash: semanticHash,
	}
	if !binding.IsValid() {
		return ResourceBinding{}, ErrInvalidExport
	}
	return binding, nil
}

// Scope returns the exact provider Workspace and Network.
func (binding ResourceBinding) Scope() network.Scope { return binding.scope }

// ResourceID returns the stable provider Resource identity.
func (binding ResourceBinding) ResourceID() resource.ID { return binding.resourceID }

// ResourceVersion returns the pinned authority version.
func (binding ResourceBinding) ResourceVersion() int64 { return binding.resourceVersion }

// TargetGeneration returns the pinned target generation.
func (binding ResourceBinding) TargetGeneration() int64 { return binding.targetGeneration }

// SemanticHash returns the pinned provider Resource semantics.
func (binding ResourceBinding) SemanticHash() resource.SemanticHash { return binding.semanticHash }

// IsValid reports whether every provider authority component is present.
func (binding ResourceBinding) IsValid() bool {
	return binding.scope.IsValid() && binding.resourceID.IsValid() &&
		binding.resourceVersion > 0 && binding.targetGeneration > 0 && binding.semanticHash.IsValid()
}

// ExportParams contains one durable provider maximum.
type ExportParams struct {
	ID                          ExportID
	ProviderScope               network.Scope
	ConsumerScope               network.Scope
	Resource                    ResourceBinding
	MaximumTraffic              TrafficSet
	ProviderAuthorityGeneration int64
	ExpiresAt                   time.Time
	State                       ExportState
	Version                     int64
}

// Export is provider-owned maximum authority for one exact consumer scope.
type Export struct{ params ExportParams }

// NewExport validates one durable Resource Export snapshot.
func NewExport(params ExportParams) (Export, error) {
	params.ExpiresAt = params.ExpiresAt.UTC()
	export := Export{params: params}
	if !export.IsValid() {
		return Export{}, ErrInvalidExport
	}
	return export, nil
}

// ID returns the stable Resource Export identity.
func (export Export) ID() ExportID { return export.params.ID }

// ProviderScope returns the exporting Resource's exact scope.
func (export Export) ProviderScope() network.Scope { return export.params.ProviderScope }

// ConsumerScope returns the only scope permitted to accept the export.
func (export Export) ConsumerScope() network.Scope { return export.params.ConsumerScope }

// ScopeRelation returns the derived Workspace trust boundary.
func (export Export) ScopeRelation() ScopeRelation {
	return ClassifyScopeRelation(export.params.ProviderScope, export.params.ConsumerScope)
}

// Resource returns pinned provider Resource authority.
func (export Export) Resource() ResourceBinding { return export.params.Resource }

// MaximumTraffic returns an independently owned provider ceiling.
func (export Export) MaximumTraffic() TrafficSet {
	set, _ := NewTrafficSet(export.params.MaximumTraffic.Constraints())
	return set
}

// ProviderAuthorityGeneration returns the provider-side CAS generation.
func (export Export) ProviderAuthorityGeneration() int64 {
	return export.params.ProviderAuthorityGeneration
}

// ExpiresAt returns the exclusive provider validity ceiling.
func (export Export) ExpiresAt() time.Time { return export.params.ExpiresAt }

// State returns the provider lifecycle state.
func (export Export) State() ExportState { return export.params.State }

// Version returns the optimistic authority version.
func (export Export) Version() int64 { return export.params.Version }

// IsValid reports whether identity, scope, Resource, ceiling, and state agree.
func (export Export) IsValid() bool {
	params := export.params
	return params.ID.IsValid() && params.ProviderScope.IsValid() && params.ConsumerScope.IsValid() &&
		params.ProviderScope != params.ConsumerScope && params.Resource.IsValid() &&
		params.Resource.Scope() == params.ProviderScope && params.MaximumTraffic.IsValid() &&
		params.ProviderAuthorityGeneration > 0 && !params.ExpiresAt.IsZero() &&
		(params.State == ExportStateActive || params.State == ExportStateRevoked) && params.Version > 0
}

// IsUsableAt reports whether provider authority is active before its exclusive deadline.
func (export Export) IsUsableAt(evaluatedAt time.Time) bool {
	return export.IsValid() && export.params.State == ExportStateActive &&
		!evaluatedAt.IsZero() && evaluatedAt.Before(export.params.ExpiresAt)
}

// OfferParams contains one targeted bilateral decision request.
type OfferParams struct {
	ID                 OfferID
	ExportID           ExportID
	ProviderScope      network.Scope
	ConsumerScope      network.Scope
	MaximumTraffic     TrafficSet
	NonceDigest        [32]byte
	ExpiresAt          time.Time
	State              OfferState
	Version            int64
	DecidedAt          time.Time
	AcceptedContractID ContractID
}

// Offer is a targeted, expiry-bounded, single-decision share invitation.
type Offer struct{ params OfferParams }

// NewOffer validates one durable Share Offer snapshot.
func NewOffer(params OfferParams) (Offer, error) {
	params.ExpiresAt = params.ExpiresAt.UTC()
	params.DecidedAt = params.DecidedAt.UTC()
	offer := Offer{params: params}
	if !offer.IsValid() {
		return Offer{}, ErrInvalidOffer
	}
	return offer, nil
}

// ID returns the stable Share Offer identity.
func (offer Offer) ID() OfferID { return offer.params.ID }

// ExportID returns the provider authority referenced by this offer.
func (offer Offer) ExportID() ExportID { return offer.params.ExportID }

// ProviderScope returns the exact provider scope.
func (offer Offer) ProviderScope() network.Scope { return offer.params.ProviderScope }

// ConsumerScope returns the exact intended consumer scope.
func (offer Offer) ConsumerScope() network.Scope { return offer.params.ConsumerScope }

// ScopeRelation returns the derived Workspace trust boundary.
func (offer Offer) ScopeRelation() ScopeRelation {
	return ClassifyScopeRelation(offer.params.ProviderScope, offer.params.ConsumerScope)
}

// MaximumTraffic returns the provider ceiling bound into the offer.
func (offer Offer) MaximumTraffic() TrafficSet {
	set, _ := NewTrafficSet(offer.params.MaximumTraffic.Constraints())
	return set
}

// NonceDigest returns the non-secret digest used to bind consumer possession.
func (offer Offer) NonceDigest() [32]byte { return offer.params.NonceDigest }

// ExpiresAt returns the exclusive decision deadline.
func (offer Offer) ExpiresAt() time.Time { return offer.params.ExpiresAt }

// State returns the current or terminal decision state.
func (offer Offer) State() OfferState { return offer.params.State }

// Version returns the optimistic authority version.
func (offer Offer) Version() int64 { return offer.params.Version }

// DecidedAt returns the terminal decision time or zero while offered.
func (offer Offer) DecidedAt() time.Time { return offer.params.DecidedAt }

// AcceptedContractID returns the accepted contract identity, when applicable.
func (offer Offer) AcceptedContractID() ContractID { return offer.params.AcceptedContractID }

// IsValid reports whether state and terminal evidence agree.
func (offer Offer) IsValid() bool {
	params := offer.params
	if !params.ID.IsValid() || !params.ExportID.IsValid() || !params.ProviderScope.IsValid() ||
		!params.ConsumerScope.IsValid() || params.ProviderScope == params.ConsumerScope ||
		!params.MaximumTraffic.IsValid() || params.NonceDigest == ([32]byte{}) ||
		params.ExpiresAt.IsZero() || params.Version <= 0 {
		return false
	}
	if params.State == OfferStateOffered {
		return params.DecidedAt.IsZero() && !params.AcceptedContractID.IsValid()
	}
	if params.State != OfferStateAccepted && params.State != OfferStateRejected &&
		params.State != OfferStateExpired && params.State != OfferStateRevoked {
		return false
	}
	if params.DecidedAt.IsZero() || params.DecidedAt.Before(params.ExpiresAt) &&
		params.State == OfferStateExpired {
		return false
	}
	return (params.State == OfferStateAccepted) == params.AcceptedContractID.IsValid()
}

// CanDecideAt reports whether one fresh consumer decision is still admissible.
func (offer Offer) CanDecideAt(evaluatedAt time.Time) bool {
	return offer.IsValid() && offer.params.State == OfferStateOffered &&
		!evaluatedAt.IsZero() && evaluatedAt.Before(offer.params.ExpiresAt)
}

// ContractParams contains one accepted bilateral authority snapshot.
type ContractParams struct {
	ID                          ContractID
	ImportedResourceID          ImportedResourceID
	OfferID                     OfferID
	ExportID                    ExportID
	ProviderScope               network.Scope
	ConsumerScope               network.Scope
	Resource                    ResourceBinding
	MaximumTraffic              TrafficSet
	ProviderAuthorityGeneration int64
	ConsumerAuthorityGeneration int64
	RecoveryEpoch               int64
	ExpiresAt                   time.Time
	State                       ContractState
	Version                     int64
	EndedAt                     time.Time
}

// Contract is an accepted two-authority Trust Contract.
type Contract struct{ params ContractParams }

// NewContract validates one durable Trust Contract snapshot.
func NewContract(params ContractParams) (Contract, error) {
	params.ExpiresAt = params.ExpiresAt.UTC()
	params.EndedAt = params.EndedAt.UTC()
	contract := Contract{params: params}
	if !contract.IsValid() {
		return Contract{}, ErrInvalidContract
	}
	return contract, nil
}

// ID returns the stable Trust Contract identity.
func (contract Contract) ID() ContractID { return contract.params.ID }

// ImportedResourceID returns the consumer-local policy identity.
func (contract Contract) ImportedResourceID() ImportedResourceID {
	return contract.params.ImportedResourceID
}

// OfferID returns the accepted offer identity.
func (contract Contract) OfferID() OfferID { return contract.params.OfferID }

// ExportID returns the provider maximum identity.
func (contract Contract) ExportID() ExportID { return contract.params.ExportID }

// ProviderScope returns the exact provider scope.
func (contract Contract) ProviderScope() network.Scope { return contract.params.ProviderScope }

// ConsumerScope returns the exact consumer scope.
func (contract Contract) ConsumerScope() network.Scope { return contract.params.ConsumerScope }

// ScopeRelation returns the derived Workspace trust boundary.
func (contract Contract) ScopeRelation() ScopeRelation {
	return ClassifyScopeRelation(contract.params.ProviderScope, contract.params.ConsumerScope)
}

// Resource returns pinned provider Resource authority.
func (contract Contract) Resource() ResourceBinding { return contract.params.Resource }

// MaximumTraffic returns the accepted provider ceiling.
func (contract Contract) MaximumTraffic() TrafficSet {
	set, _ := NewTrafficSet(contract.params.MaximumTraffic.Constraints())
	return set
}

// ProviderAuthorityGeneration returns the accepted provider generation.
func (contract Contract) ProviderAuthorityGeneration() int64 {
	return contract.params.ProviderAuthorityGeneration
}

// ConsumerAuthorityGeneration returns the accepted consumer generation.
func (contract Contract) ConsumerAuthorityGeneration() int64 {
	return contract.params.ConsumerAuthorityGeneration
}

// RecoveryEpoch returns the Deployment recovery epoch bound at acceptance.
func (contract Contract) RecoveryEpoch() int64 { return contract.params.RecoveryEpoch }

// ExpiresAt returns the exclusive contract deadline.
func (contract Contract) ExpiresAt() time.Time { return contract.params.ExpiresAt }

// State returns the Trust Contract lifecycle state.
func (contract Contract) State() ContractState { return contract.params.State }

// Version returns the optimistic authority version.
func (contract Contract) Version() int64 { return contract.params.Version }

// EndedAt returns the terminal transition time or zero while active.
func (contract Contract) EndedAt() time.Time { return contract.params.EndedAt }

// IsValid reports whether both exact scopes and lifecycle evidence agree.
func (contract Contract) IsValid() bool {
	params := contract.params
	if !params.ID.IsValid() || !params.ImportedResourceID.IsValid() || !params.OfferID.IsValid() ||
		!params.ExportID.IsValid() || !params.ProviderScope.IsValid() || !params.ConsumerScope.IsValid() ||
		params.ProviderScope == params.ConsumerScope || !params.Resource.IsValid() ||
		params.Resource.Scope() != params.ProviderScope || !params.MaximumTraffic.IsValid() ||
		params.ProviderAuthorityGeneration <= 0 || params.ConsumerAuthorityGeneration <= 0 ||
		params.RecoveryEpoch <= 0 || params.ExpiresAt.IsZero() || params.Version <= 0 {
		return false
	}
	if params.State == ContractStateActivating || params.State == ContractStateActive {
		return params.EndedAt.IsZero()
	}
	if params.State != ContractStateRevoked && params.State != ContractStateExpired &&
		params.State != ContractStateInvalidated {
		return false
	}
	if params.EndedAt.IsZero() {
		return false
	}
	return params.State != ContractStateExpired || !params.EndedAt.Before(params.ExpiresAt)
}

// IsUsableAt checks lifecycle, time, recovery epoch, both generations, and Resource authority.
func (contract Contract) IsUsableAt(
	evaluatedAt time.Time,
	recoveryEpoch int64,
	providerAuthorityGeneration int64,
	consumerAuthorityGeneration int64,
	resourceVersion int64,
	targetGeneration int64,
	semanticHash resource.SemanticHash,
) bool {
	return contract.IsValid() && contract.params.State == ContractStateActive &&
		!evaluatedAt.IsZero() && evaluatedAt.Before(contract.params.ExpiresAt) &&
		recoveryEpoch == contract.params.RecoveryEpoch &&
		providerAuthorityGeneration == contract.params.ProviderAuthorityGeneration &&
		consumerAuthorityGeneration == contract.params.ConsumerAuthorityGeneration &&
		resourceVersion == contract.params.Resource.ResourceVersion() &&
		targetGeneration == contract.params.Resource.TargetGeneration() &&
		semanticHash == contract.params.Resource.SemanticHash()
}
