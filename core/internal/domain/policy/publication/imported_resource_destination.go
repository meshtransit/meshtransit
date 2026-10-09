package publication

import (
	"errors"
	"slices"
	"strings"

	"github.com/meshtransit/meshtransit/core/internal/domain/node"
	"github.com/meshtransit/meshtransit/core/internal/domain/policy"
	"github.com/meshtransit/meshtransit/core/internal/domain/sharing"
)

// ErrInvalidImportedResourceDestination reports incomplete bilateral provenance.
var ErrInvalidImportedResourceDestination = errors.New(
	"policy publication: invalid Imported Resource destination",
)

// ImportedResourceDestinationParams binds one authoring rule to exact bilateral authority.
type ImportedResourceDestinationParams struct {
	RuleID                policy.RuleID
	SourceNodeID          node.ID
	Resolution            sharing.PolicyDestination
	Protocol              policy.Protocol
	DestinationPortRanges []policy.PortRange
}

// ImportedResourceDestination retains an Imported Resource selector as
// immutable publication provenance. It is deliberately not a packet edge:
// trusted endpoint authority remains an independent fail-closed prerequisite.
type ImportedResourceDestination struct {
	ruleID                policy.RuleID
	sourceNodeID          node.ID
	resolution            sharing.PolicyDestination
	protocol              policy.Protocol
	destinationPortRanges []policy.PortRange
}

// NewImportedResourceDestination validates one active, traffic-bounded selector.
func NewImportedResourceDestination(
	params ImportedResourceDestinationParams,
) (ImportedResourceDestination, error) {
	destination := ImportedResourceDestination{
		ruleID:                params.RuleID,
		sourceNodeID:          params.SourceNodeID,
		resolution:            params.Resolution,
		protocol:              params.Protocol,
		destinationPortRanges: slices.Clone(params.DestinationPortRanges),
	}
	if !destination.IsValid() {
		return ImportedResourceDestination{}, ErrInvalidImportedResourceDestination
	}
	return destination, nil
}

// RuleID returns the stable authoring Access Rule identity.
func (destination ImportedResourceDestination) RuleID() policy.RuleID { return destination.ruleID }

// SourceNodeID returns the consumer Device selecting the Imported Resource.
func (destination ImportedResourceDestination) SourceNodeID() node.ID {
	return destination.sourceNodeID
}

// Resolution returns the exact bilateral authority snapshot.
func (destination ImportedResourceDestination) Resolution() sharing.PolicyDestination {
	return destination.resolution
}

// Protocol returns the narrowed transport protocol.
func (destination ImportedResourceDestination) Protocol() policy.Protocol {
	return destination.protocol
}

// DestinationPortRanges returns caller-owned narrowed intervals.
func (destination ImportedResourceDestination) DestinationPortRanges() []policy.PortRange {
	return slices.Clone(destination.destinationPortRanges)
}

// IsValid reports whether provenance and traffic shape are canonical.
func (destination ImportedResourceDestination) IsValid() bool {
	if !destination.ruleID.IsValid() || !destination.sourceNodeID.IsValid() ||
		!destination.resolution.IsValid() || !destination.protocol.IsValid() ||
		len(destination.destinationPortRanges) > policy.MaximumPortRangesPerRule {
		return false
	}
	if destination.protocol == policy.ProtocolICMP {
		return len(destination.destinationPortRanges) == 0
	}
	if len(destination.destinationPortRanges) == 0 {
		return false
	}
	previousLast := uint16(0)
	for index, portRange := range destination.destinationPortRanges {
		if portRange.First() == 0 || portRange.Last() < portRange.First() ||
			(index > 0 && (previousLast == ^uint16(0) || portRange.First() <= previousLast+1)) {
			return false
		}
		previousLast = portRange.Last()
	}
	return true
}

func cloneImportedResourceDestinations(
	destinations []ImportedResourceDestination,
) []ImportedResourceDestination {
	cloned := make([]ImportedResourceDestination, len(destinations))
	for index, destination := range destinations {
		cloned[index] = destination
		cloned[index].destinationPortRanges = slices.Clone(destination.destinationPortRanges)
	}
	return cloned
}

func compareImportedResourceDestinations(
	first, second ImportedResourceDestination,
) int {
	if comparison := strings.Compare(first.ruleID.String(), second.ruleID.String()); comparison != 0 {
		return comparison
	}
	return strings.Compare(
		first.resolution.ImportedResourceID().String(),
		second.resolution.ImportedResourceID().String(),
	)
}
