package publication

import (
	"errors"
	"slices"
	"strings"

	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/resource"
)

var (
	// ErrInvalidResourceDestination reports incomplete or inconsistent Resource provenance.
	ErrInvalidResourceDestination = errors.New("policy publication: invalid resource destination")
)

// ResourceDestinationParams binds one compiled edge to exact Resource authority.
type ResourceDestinationParams struct {
	RuleID               policy.RuleID
	Scope                network.Scope
	ResourceID           resource.ID
	ResourceVersion      int64
	TargetGeneration     int64
	InventoryRevision    int64
	DestinationNodeID    node.ID
	ResourceSemanticHash resource.SemanticHash
}

// ResourceDestination records the exact Resource facts used to resolve one
// destination Device. Activation revalidates these facts under the Network lock.
type ResourceDestination struct {
	ruleID               policy.RuleID
	reference            resource.Reference
	inventoryRevision    int64
	destinationNodeID    node.ID
	resourceSemanticHash resource.SemanticHash
}

// NewResourceDestination validates one version- and generation-pinned resolution.
func NewResourceDestination(params ResourceDestinationParams) (ResourceDestination, error) {
	reference, err := resource.NewReference(
		params.Scope,
		params.ResourceID,
		params.ResourceVersion,
		params.TargetGeneration,
	)
	if err != nil {
		return ResourceDestination{}, ErrInvalidResourceDestination
	}
	destination := ResourceDestination{
		ruleID:               params.RuleID,
		reference:            reference,
		inventoryRevision:    params.InventoryRevision,
		destinationNodeID:    params.DestinationNodeID,
		resourceSemanticHash: params.ResourceSemanticHash,
	}
	if !destination.IsValid() {
		return ResourceDestination{}, ErrInvalidResourceDestination
	}
	return destination, nil
}

// RuleID returns the stable Access Rule identity that selected the Resource.
func (destination ResourceDestination) RuleID() policy.RuleID { return destination.ruleID }

// Reference returns the exact Resource identity, version, and target generation.
func (destination ResourceDestination) Reference() resource.Reference { return destination.reference }

// InventoryRevision returns the Resource collection revision observed by compilation.
func (destination ResourceDestination) InventoryRevision() int64 {
	return destination.inventoryRevision
}

// DestinationNodeID returns the Device resolved from the active Resource target.
func (destination ResourceDestination) DestinationNodeID() node.ID {
	return destination.destinationNodeID
}

// ResourceSemanticHash returns the exact Resource semantics used by compilation.
func (destination ResourceDestination) ResourceSemanticHash() resource.SemanticHash {
	return destination.resourceSemanticHash
}

// IsValid reports whether all exact-scope provenance facts are usable.
func (destination ResourceDestination) IsValid() bool {
	return destination.ruleID.IsValid() && destination.reference.IsValid() &&
		destination.inventoryRevision > 0 && destination.destinationNodeID.IsValid() &&
		destination.resourceSemanticHash.IsValid()
}

func cloneResourceDestinations(destinations []ResourceDestination) []ResourceDestination {
	return slices.Clone(destinations)
}

func compareResourceDestinations(first, second ResourceDestination) int {
	if comparison := strings.Compare(first.ruleID.String(), second.ruleID.String()); comparison != 0 {
		return comparison
	}
	if comparison := strings.Compare(
		first.reference.ResourceID().String(),
		second.reference.ResourceID().String(),
	); comparison != 0 {
		return comparison
	}
	return strings.Compare(first.destinationNodeID.String(), second.destinationNodeID.String())
}
