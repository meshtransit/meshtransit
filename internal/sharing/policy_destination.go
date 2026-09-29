package sharing

import (
	"time"

	"github.com/meshtransit/meshtransit/internal/network"
)

// PolicyDestinationParams contains one active Imported Resource resolution.
type PolicyDestinationParams struct {
	ImportedResourceID        ImportedResourceID
	ImportedResourceVersion   int64
	Contract                  Contract
	ExportVersion             int64
	ProviderInventoryRevision int64
	ProviderSharingRevision   int64
	ConsumerSharingRevision   int64
	EvaluatedAt               time.Time
}

// PolicyDestination is the complete bilateral authority snapshot consumed by
// the policy compiler. It is provenance only; endpoint authority is evaluated
// independently before any packet path can become effective.
type PolicyDestination struct {
	importedResourceID        ImportedResourceID
	importedResourceVersion   int64
	contract                  Contract
	exportVersion             int64
	providerInventoryRevision int64
	providerSharingRevision   int64
	consumerSharingRevision   int64
	evaluatedAt               time.Time
}

// NewPolicyDestination validates one current, active Imported Resource resolution.
func NewPolicyDestination(params PolicyDestinationParams) (PolicyDestination, error) {
	destination := PolicyDestination{
		importedResourceID:        params.ImportedResourceID,
		importedResourceVersion:   params.ImportedResourceVersion,
		contract:                  params.Contract,
		exportVersion:             params.ExportVersion,
		providerInventoryRevision: params.ProviderInventoryRevision,
		providerSharingRevision:   params.ProviderSharingRevision,
		consumerSharingRevision:   params.ConsumerSharingRevision,
		evaluatedAt:               params.EvaluatedAt.UTC(),
	}
	if !destination.IsValid() {
		return PolicyDestination{}, ErrInvalidContract
	}
	return destination, nil
}

// ImportedResourceID returns the consumer-local selector identity.
func (destination PolicyDestination) ImportedResourceID() ImportedResourceID {
	return destination.importedResourceID
}

// ImportedResourceVersion returns the active local projection version.
func (destination PolicyDestination) ImportedResourceVersion() int64 {
	return destination.importedResourceVersion
}

// Contract returns the immutable active bilateral authority snapshot.
func (destination PolicyDestination) Contract() Contract { return destination.contract }

// ExportVersion returns the current provider export authority version.
func (destination PolicyDestination) ExportVersion() int64 { return destination.exportVersion }

// ProviderScope returns the Resource's exact provider Network.
func (destination PolicyDestination) ProviderScope() network.Scope {
	return destination.contract.ProviderScope()
}

// ConsumerScope returns the Imported Resource's exact local Network.
func (destination PolicyDestination) ConsumerScope() network.Scope {
	return destination.contract.ConsumerScope()
}

// ProviderInventoryRevision returns the current provider Resource revision.
func (destination PolicyDestination) ProviderInventoryRevision() int64 {
	return destination.providerInventoryRevision
}

// ProviderSharingRevision returns the provider sharing revision observed by resolution.
func (destination PolicyDestination) ProviderSharingRevision() int64 {
	return destination.providerSharingRevision
}

// ConsumerSharingRevision returns the consumer sharing revision observed by resolution.
func (destination PolicyDestination) ConsumerSharingRevision() int64 {
	return destination.consumerSharingRevision
}

// EvaluatedAt returns the authority evaluation instant.
func (destination PolicyDestination) EvaluatedAt() time.Time { return destination.evaluatedAt }

// IsValid reports whether this snapshot is active, exact-scoped, and internally coherent.
func (destination PolicyDestination) IsValid() bool {
	contract := destination.contract
	return destination.importedResourceID.IsValid() && destination.importedResourceVersion > 0 &&
		contract.IsValid() && contract.ImportedResourceID() == destination.importedResourceID &&
		contract.State() == ContractStateActive && destination.exportVersion > 0 &&
		destination.providerInventoryRevision > 0 &&
		destination.providerSharingRevision > 0 && destination.consumerSharingRevision > 0 &&
		!destination.evaluatedAt.IsZero() && destination.evaluatedAt.Before(contract.ExpiresAt())
}
