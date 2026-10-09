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
	// ErrInvalidResourceGroupDestination reports incomplete or inconsistent group provenance.
	ErrInvalidResourceGroupDestination = errors.New("policy publication: invalid resource group destination")
)

// ResourceGroupMemberDestinationParams binds one expanded member to exact Resource authority.
type ResourceGroupMemberDestinationParams struct {
	Scope                network.Scope
	ResourceID           resource.ID
	ResourceVersion      int64
	TargetGeneration     int64
	InventoryRevision    int64
	DestinationNodeID    node.ID
	ResourceSemanticHash resource.SemanticHash
}

// ResourceGroupMemberDestination records the exact Resource facts used for one
// expanded Resource Group edge.
type ResourceGroupMemberDestination struct {
	reference            resource.Reference
	inventoryRevision    int64
	destinationNodeID    node.ID
	resourceSemanticHash resource.SemanticHash
}

// NewResourceGroupMemberDestination validates one expanded member resolution.
func NewResourceGroupMemberDestination(
	params ResourceGroupMemberDestinationParams,
) (ResourceGroupMemberDestination, error) {
	reference, err := resource.NewReference(
		params.Scope,
		params.ResourceID,
		params.ResourceVersion,
		params.TargetGeneration,
	)
	if err != nil {
		return ResourceGroupMemberDestination{}, ErrInvalidResourceGroupDestination
	}
	member := ResourceGroupMemberDestination{
		reference:            reference,
		inventoryRevision:    params.InventoryRevision,
		destinationNodeID:    params.DestinationNodeID,
		resourceSemanticHash: params.ResourceSemanticHash,
	}
	if !member.IsValid() {
		return ResourceGroupMemberDestination{}, ErrInvalidResourceGroupDestination
	}
	return member, nil
}

// Reference returns the exact Resource identity, version, and target generation.
func (member ResourceGroupMemberDestination) Reference() resource.Reference {
	return member.reference
}

// InventoryRevision returns the Resource collection revision observed by compilation.
func (member ResourceGroupMemberDestination) InventoryRevision() int64 {
	return member.inventoryRevision
}

// DestinationNodeID returns the Device resolved from the active Resource target.
func (member ResourceGroupMemberDestination) DestinationNodeID() node.ID {
	return member.destinationNodeID
}

// ResourceSemanticHash returns the exact Resource semantics used by compilation.
func (member ResourceGroupMemberDestination) ResourceSemanticHash() resource.SemanticHash {
	return member.resourceSemanticHash
}

// IsValid reports whether all exact-scope member facts are usable.
func (member ResourceGroupMemberDestination) IsValid() bool {
	return member.reference.IsValid() && member.inventoryRevision > 0 &&
		member.destinationNodeID.IsValid() && member.resourceSemanticHash.IsValid()
}

// ResourceGroupDestinationParams binds one Access Rule to an immutable group definition.
type ResourceGroupDestinationParams struct {
	RuleID            policy.RuleID
	Scope             network.Scope
	ResourceGroupID   resource.GroupID
	GroupVersion      int64
	DefinitionVersion int64
	GroupRevision     int64
	GroupSemanticHash resource.SemanticHash
	Members           []ResourceGroupMemberDestination
}

// ResourceGroupDestination records exact group and expanded member authority.
// Activation revalidates the complete definition under the Network lock.
type ResourceGroupDestination struct {
	ruleID            policy.RuleID
	scope             network.Scope
	resourceGroupID   resource.GroupID
	groupVersion      int64
	definitionVersion int64
	groupRevision     int64
	groupSemanticHash resource.SemanticHash
	members           []ResourceGroupMemberDestination
}

// NewResourceGroupDestination validates and canonicalizes one group expansion.
func NewResourceGroupDestination(
	params ResourceGroupDestinationParams,
) (ResourceGroupDestination, error) {
	members := slices.Clone(params.Members)
	slices.SortFunc(members, compareResourceGroupMembers)
	destination := ResourceGroupDestination{
		ruleID: params.RuleID, scope: params.Scope, resourceGroupID: params.ResourceGroupID,
		groupVersion: params.GroupVersion, definitionVersion: params.DefinitionVersion,
		groupRevision: params.GroupRevision, groupSemanticHash: params.GroupSemanticHash,
		members: members,
	}
	if !destination.IsValid() {
		return ResourceGroupDestination{}, ErrInvalidResourceGroupDestination
	}
	return destination, nil
}

// RuleID returns the stable Access Rule identity selecting the group.
func (destination ResourceGroupDestination) RuleID() policy.RuleID { return destination.ruleID }

// Scope returns the exact Workspace-qualified Network scope.
func (destination ResourceGroupDestination) Scope() network.Scope { return destination.scope }

// ResourceGroupID returns the stable Resource Group identity.
func (destination ResourceGroupDestination) ResourceGroupID() resource.GroupID {
	return destination.resourceGroupID
}

// GroupVersion returns the current Resource Group authority version.
func (destination ResourceGroupDestination) GroupVersion() int64 {
	return destination.groupVersion
}

// DefinitionVersion returns the active immutable group definition version.
func (destination ResourceGroupDestination) DefinitionVersion() int64 {
	return destination.definitionVersion
}

// GroupRevision returns the Resource Group collection revision observed by compilation.
func (destination ResourceGroupDestination) GroupRevision() int64 {
	return destination.groupRevision
}

// GroupSemanticHash returns the exact group definition digest.
func (destination ResourceGroupDestination) GroupSemanticHash() resource.SemanticHash {
	return destination.groupSemanticHash
}

// Members returns a caller-owned canonical expansion snapshot.
func (destination ResourceGroupDestination) Members() []ResourceGroupMemberDestination {
	return slices.Clone(destination.members)
}

// IsValid reports whether group and member provenance is complete and canonical.
func (destination ResourceGroupDestination) IsValid() bool {
	if !destination.ruleID.IsValid() || !destination.scope.IsValid() ||
		!destination.resourceGroupID.IsValid() || destination.groupVersion <= 0 ||
		destination.definitionVersion <= 0 || destination.groupRevision <= 0 ||
		!destination.groupSemanticHash.IsValid() || len(destination.members) == 0 ||
		len(destination.members) > resource.MaximumGroupMembers {
		return false
	}
	for index, member := range destination.members {
		if !member.IsValid() || member.reference.Scope() != destination.scope ||
			(index > 0 && compareResourceGroupMembers(destination.members[index-1], member) >= 0) {
			return false
		}
	}
	return true
}

func cloneResourceGroupDestinations(
	destinations []ResourceGroupDestination,
) []ResourceGroupDestination {
	cloned := make([]ResourceGroupDestination, len(destinations))
	for index, destination := range destinations {
		cloned[index] = destination
		cloned[index].members = slices.Clone(destination.members)
	}
	return cloned
}

func compareResourceGroupDestinations(first, second ResourceGroupDestination) int {
	if comparison := strings.Compare(first.ruleID.String(), second.ruleID.String()); comparison != 0 {
		return comparison
	}
	return strings.Compare(first.resourceGroupID.String(), second.resourceGroupID.String())
}

func compareResourceGroupMembers(
	first,
	second ResourceGroupMemberDestination,
) int {
	if comparison := strings.Compare(
		first.reference.ResourceID().String(),
		second.reference.ResourceID().String(),
	); comparison != 0 {
		return comparison
	}
	return strings.Compare(first.destinationNodeID.String(), second.destinationNodeID.String())
}
