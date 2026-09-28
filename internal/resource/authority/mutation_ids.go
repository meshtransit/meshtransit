package authority

import (
	"errors"
	"fmt"
	"slices"

	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/resource"
)

// ErrInvalidMutationIDs reports incomplete or aliased durable identities.
var ErrInvalidMutationIDs = errors.New("resource authority: invalid mutation IDs")

// MutationIDs names every row written by one authority mutation.
type MutationIDs struct {
	changeID      publicid.ID
	auditEventID  publicid.ID
	outboxEventID publicid.ID
	resourceID    resource.ID
	groupID       resource.GroupID
	projectionIDs []publicid.ID
}

// NewMutationIDs validates and owns one operation-specific identity set.
func NewMutationIDs(
	changeID, auditEventID, outboxEventID publicid.ID,
	resourceID resource.ID,
	groupID resource.GroupID,
	projectionIDs []publicid.ID,
) (MutationIDs, error) {
	ids := MutationIDs{
		changeID: changeID, auditEventID: auditEventID, outboxEventID: outboxEventID,
		resourceID: resourceID, groupID: groupID,
		projectionIDs: slices.Clone(projectionIDs),
	}
	if !ids.baseValid() {
		return MutationIDs{}, ErrInvalidMutationIDs
	}
	return ids, nil
}

// ChangeID returns transaction correlation authority.
func (ids MutationIDs) ChangeID() publicid.ID { return ids.changeID }

// AuditEventID returns immutable audit identity.
func (ids MutationIDs) AuditEventID() publicid.ID { return ids.auditEventID }

// OutboxEventID returns durable outbox identity.
func (ids MutationIDs) OutboxEventID() publicid.ID { return ids.outboxEventID }

// ResourceID returns the aggregate Resource identity when selected.
func (ids MutationIDs) ResourceID() resource.ID { return ids.resourceID }

// GroupID returns the aggregate Resource Group identity when selected.
func (ids MutationIDs) GroupID() resource.GroupID { return ids.groupID }

// ProjectionIDs returns caller-owned target, version, and membership identities.
func (ids MutationIDs) ProjectionIDs() []publicid.ID { return slices.Clone(ids.projectionIDs) }

// IsValidFor reports whether identity shape exactly matches the command.
func (ids MutationIDs) IsValidFor(command Command) bool {
	if !ids.baseValid() || !command.IsValid() {
		return false
	}
	switch command.Operation() {
	case OperationCreateDevice:
		return ids.resourceID.IsValid() && !ids.groupID.IsValid() && len(ids.projectionIDs) == 1
	case OperationCreateGroup:
		return ids.groupID.IsValid() && !ids.resourceID.IsValid() &&
			len(ids.projectionIDs) == len(command.Group().Members())+1
	default:
		return false
	}
}

func (ids MutationIDs) baseValid() bool {
	seen := make(map[publicid.ID]struct{}, len(ids.projectionIDs)+4)
	base := []publicid.ID{ids.changeID, ids.auditEventID, ids.outboxEventID}
	if ids.resourceID.IsValid() {
		base = append(base, publicid.ID(ids.resourceID))
	}
	if ids.groupID.IsValid() {
		base = append(base, publicid.ID(ids.groupID))
	}
	if len(base) != 4 {
		return false
	}
	for _, id := range append(base, ids.projectionIDs...) {
		if !id.IsValid() {
			return false
		}
		if _, exists := seen[id]; exists {
			return false
		}
		seen[id] = struct{}{}
	}
	return len(ids.projectionIDs) > 0 && len(ids.projectionIDs) <= resource.MaximumGroupMembers+1
}

// PublicMutationIDGenerator creates UUIDv7 identities from operating-system entropy.
type PublicMutationIDGenerator struct{}

// NewMutationIDs creates one stable identity set for all transaction attempts.
func (PublicMutationIDGenerator) NewMutationIDs(command Command) (MutationIDs, error) {
	if !command.IsValid() {
		return MutationIDs{}, ErrInvalidMutationIDs
	}
	projectionCount := 1
	if command.Operation() == OperationCreateGroup {
		projectionCount += len(command.Group().Members())
	}
	generated := make([]publicid.ID, projectionCount+4)
	for index := range generated {
		id, err := publicid.New()
		if err != nil {
			return MutationIDs{}, fmt.Errorf("generate resource authority public ID: %w", err)
		}
		generated[index] = id
	}
	var resourceID resource.ID
	var groupID resource.GroupID
	if command.Operation() == OperationCreateDevice {
		resourceID = resource.ID(generated[3])
	} else {
		groupID = resource.GroupID(generated[3])
	}
	return NewMutationIDs(
		generated[0], generated[1], generated[2], resourceID, groupID, generated[4:],
	)
}
