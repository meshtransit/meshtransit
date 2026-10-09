package sharing

import (
	"errors"
	"net/netip"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/network"
)

var (
	// ErrInvalidPrivateEndpoint reports incomplete or inconsistent endpoint authority.
	ErrInvalidPrivateEndpoint = errors.New("sharing: invalid private endpoint")
)

// EndpointMode describes how the consumer-visible destination reaches the provider Resource.
type EndpointMode uint8

const (
	// EndpointModeUnknown is the unusable zero value.
	EndpointModeUnknown EndpointMode = iota
	// EndpointModeDirect projects an unambiguous same-Workspace Resource address.
	EndpointModeDirect
	// EndpointModeFederationAlias uses an address from the Federation Alias Realm.
	EndpointModeFederationAlias
)

// IsValid reports whether the endpoint mode has explicit routing semantics.
func (mode EndpointMode) IsValid() bool {
	return mode == EndpointModeDirect || mode == EndpointModeFederationAlias
}

// EndpointState is the monotonic Private Endpoint lifecycle.
type EndpointState uint8

const (
	// EndpointStateUnknown is the unusable zero value.
	EndpointStateUnknown EndpointState = iota
	// EndpointStateProvisioning retains authority while no consumable path exists.
	EndpointStateProvisioning
	// EndpointStateReady permits evaluation against the generation-bound grant.
	EndpointStateReady
	// EndpointStateRevoked records explicit authority withdrawal.
	EndpointStateRevoked
	// EndpointStateExpired records validity-window exhaustion.
	EndpointStateExpired
	// EndpointStateInvalidated records stale contract, Resource, alias, or recovery authority.
	EndpointStateInvalidated
)

// PrivateEndpointParams contains one contract-bound consumer destination generation.
type PrivateEndpointParams struct {
	ID                      PrivateEndpointID
	Contract                Contract
	AccessName              AccessName
	Mode                    EndpointMode
	ResourceAlias           netip.Addr
	Generation              int64
	ImportedResourceVersion int64
	Grant                   TrafficSet
	ExpiresAt               time.Time
	State                   EndpointState
	EndedAt                 time.Time
}

// PrivateEndpoint binds a DNS name and consumer-visible destination to one
// exact Trust Contract generation. Knowing either value grants no authority.
type PrivateEndpoint struct {
	id                      PrivateEndpointID
	contractID              ContractID
	contractVersion         int64
	importedResourceID      ImportedResourceID
	importedResourceVersion int64
	providerScope           network.Scope
	consumerScope           network.Scope
	recoveryEpoch           int64
	accessName              AccessName
	mode                    EndpointMode
	resourceAlias           netip.Addr
	generation              int64
	grant                   TrafficSet
	expiresAt               time.Time
	state                   EndpointState
	endedAt                 time.Time
}

// NewPrivateEndpoint constructs one endpoint from a validated contract snapshot.
func NewPrivateEndpoint(params PrivateEndpointParams) (PrivateEndpoint, error) {
	params.ExpiresAt = params.ExpiresAt.UTC()
	params.EndedAt = params.EndedAt.UTC()
	endpoint := PrivateEndpoint{
		id: params.ID, contractID: params.Contract.ID(), contractVersion: params.Contract.Version(),
		importedResourceID:      params.Contract.ImportedResourceID(),
		importedResourceVersion: params.ImportedResourceVersion,
		providerScope:           params.Contract.ProviderScope(), consumerScope: params.Contract.ConsumerScope(),
		recoveryEpoch: params.Contract.RecoveryEpoch(), accessName: params.AccessName,
		mode: params.Mode, resourceAlias: params.ResourceAlias, generation: params.Generation,
		grant: params.Grant, expiresAt: params.ExpiresAt, state: params.State, endedAt: params.EndedAt,
	}
	if !params.Contract.IsValid() || !endpoint.IsValid() ||
		endpoint.expiresAt.After(params.Contract.ExpiresAt()) ||
		endpoint.state == EndpointStateReady && params.Contract.State() != ContractStateActive {
		return PrivateEndpoint{}, ErrInvalidPrivateEndpoint
	}
	return endpoint, nil
}

// ID returns the endpoint generation identity.
func (endpoint PrivateEndpoint) ID() PrivateEndpointID { return endpoint.id }

// ContractID returns the exact bilateral authority identity.
func (endpoint PrivateEndpoint) ContractID() ContractID { return endpoint.contractID }

// ContractVersion returns the Trust Contract version pinned by this endpoint.
func (endpoint PrivateEndpoint) ContractVersion() int64 { return endpoint.contractVersion }

// ImportedResourceID returns the consumer-local policy identity.
func (endpoint PrivateEndpoint) ImportedResourceID() ImportedResourceID {
	return endpoint.importedResourceID
}

// ImportedResourceVersion returns the consumer projection version pinned at publication.
func (endpoint PrivateEndpoint) ImportedResourceVersion() int64 {
	return endpoint.importedResourceVersion
}

// ProviderScope returns the exact source authority scope.
func (endpoint PrivateEndpoint) ProviderScope() network.Scope { return endpoint.providerScope }

// ConsumerScope returns the exact destination authority scope.
func (endpoint PrivateEndpoint) ConsumerScope() network.Scope { return endpoint.consumerScope }

// ScopeRelation returns the derived Workspace trust boundary.
func (endpoint PrivateEndpoint) ScopeRelation() ScopeRelation {
	return ClassifyScopeRelation(endpoint.providerScope, endpoint.consumerScope)
}

// RecoveryEpoch returns the Deployment recovery epoch pinned by this endpoint.
func (endpoint PrivateEndpoint) RecoveryEpoch() int64 { return endpoint.recoveryEpoch }

// AccessName returns the consumer-local DNS discovery name.
func (endpoint PrivateEndpoint) AccessName() AccessName { return endpoint.accessName }

// Mode returns the explicit direct or federation-alias routing mode.
func (endpoint PrivateEndpoint) Mode() EndpointMode { return endpoint.mode }

// ResourceAlias returns the sole consumer-visible destination address.
func (endpoint PrivateEndpoint) ResourceAlias() netip.Addr { return endpoint.resourceAlias }

// Generation returns the monotonic endpoint grant generation.
func (endpoint PrivateEndpoint) Generation() int64 { return endpoint.generation }

// Grant returns a caller-owned copy of endpoint-local traffic authority.
func (endpoint PrivateEndpoint) Grant() TrafficSet {
	grant, _ := NewTrafficSet(endpoint.grant.Constraints())
	return grant
}

// ExpiresAt returns the exclusive endpoint deadline.
func (endpoint PrivateEndpoint) ExpiresAt() time.Time { return endpoint.expiresAt }

// State returns the endpoint lifecycle state.
func (endpoint PrivateEndpoint) State() EndpointState { return endpoint.state }

// EndedAt returns the terminal transition time or zero while non-terminal.
func (endpoint PrivateEndpoint) EndedAt() time.Time { return endpoint.endedAt }

// IsValid reports whether identity, scope, alias, generation, and lifecycle agree.
func (endpoint PrivateEndpoint) IsValid() bool {
	if !endpoint.id.IsValid() || !endpoint.contractID.IsValid() ||
		!endpoint.importedResourceID.IsValid() || endpoint.contractVersion <= 0 ||
		endpoint.importedResourceVersion <= 0 || !endpoint.providerScope.IsValid() ||
		!endpoint.consumerScope.IsValid() || endpoint.providerScope == endpoint.consumerScope ||
		endpoint.recoveryEpoch <= 0 || !endpoint.accessName.IsValid() || !endpoint.mode.IsValid() ||
		!validResourceAlias(endpoint.resourceAlias) || endpoint.generation <= 0 ||
		!endpoint.grant.IsValid() || endpoint.expiresAt.IsZero() {
		return false
	}
	if endpoint.ScopeRelation() == ScopeRelationCrossWorkspace &&
		endpoint.mode != EndpointModeFederationAlias {
		return false
	}
	if endpoint.state == EndpointStateProvisioning || endpoint.state == EndpointStateReady {
		return endpoint.endedAt.IsZero()
	}
	if endpoint.state != EndpointStateRevoked && endpoint.state != EndpointStateExpired &&
		endpoint.state != EndpointStateInvalidated || endpoint.endedAt.IsZero() {
		return false
	}
	return endpoint.state != EndpointStateExpired || !endpoint.endedAt.Before(endpoint.expiresAt)
}

// IsUsableAt verifies that current contract and Imported Resource authority
// still match the ready endpoint generation at the exclusive evaluation time.
func (endpoint PrivateEndpoint) IsUsableAt(
	contract Contract,
	importedResourceVersion int64,
	evaluatedAt time.Time,
) bool {
	return endpoint.IsValid() && contract.IsValid() && endpoint.state == EndpointStateReady &&
		!evaluatedAt.IsZero() && evaluatedAt.Before(endpoint.expiresAt) &&
		contract.State() == ContractStateActive && evaluatedAt.Before(contract.ExpiresAt()) &&
		endpoint.contractID == contract.ID() && endpoint.contractVersion == contract.Version() &&
		endpoint.importedResourceID == contract.ImportedResourceID() &&
		endpoint.importedResourceVersion == importedResourceVersion &&
		endpoint.providerScope == contract.ProviderScope() &&
		endpoint.consumerScope == contract.ConsumerScope() &&
		endpoint.recoveryEpoch == contract.RecoveryEpoch()
}

func validResourceAlias(alias netip.Addr) bool {
	return alias.IsValid() && alias.IsGlobalUnicast() && !alias.IsUnspecified()
}
