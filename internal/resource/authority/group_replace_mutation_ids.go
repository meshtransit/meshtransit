package authority

import (
	"errors"
	"fmt"
	"slices"

	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/resource"
)

var (
	// ErrInvalidGroupReplaceMutationIDs reports incomplete or duplicate durable identities.
	ErrInvalidGroupReplaceMutationIDs = errors.New("resource group replace: invalid mutation IDs")
)

// GroupReplaceMutationIDs are server-owned identities stable across retries.
type GroupReplaceMutationIDs struct {
	changeID            publicid.ID
	groupVersionID      publicid.ID
	memberIDs           []publicid.ID
	auditEventID        publicid.ID
	outboxEventID       publicid.ID
	idempotencyRecordID publicid.ID
}

// NewGroupReplaceMutationIDs validates one complete durable identity set.
func NewGroupReplaceMutationIDs(
	changeID, groupVersionID publicid.ID,
	memberIDs []publicid.ID,
	auditEventID, outboxEventID, idempotencyRecordID publicid.ID,
) (GroupReplaceMutationIDs, error) {
	ids := GroupReplaceMutationIDs{
		changeID: changeID, groupVersionID: groupVersionID, memberIDs: slices.Clone(memberIDs),
		auditEventID: auditEventID, outboxEventID: outboxEventID,
		idempotencyRecordID: idempotencyRecordID,
	}
	if !ids.IsValid() {
		return GroupReplaceMutationIDs{}, ErrInvalidGroupReplaceMutationIDs
	}
	return ids, nil
}

// ChangeID returns transaction-local authority context identity.
func (ids GroupReplaceMutationIDs) ChangeID() publicid.ID { return ids.changeID }

// GroupVersionID returns the appended immutable definition identity.
func (ids GroupReplaceMutationIDs) GroupVersionID() publicid.ID { return ids.groupVersionID }

// MemberIDs returns caller-owned immutable member-row identities.
func (ids GroupReplaceMutationIDs) MemberIDs() []publicid.ID { return slices.Clone(ids.memberIDs) }

// AuditEventID returns immutable audit identity.
func (ids GroupReplaceMutationIDs) AuditEventID() publicid.ID { return ids.auditEventID }

// OutboxEventID returns durable outbox identity.
func (ids GroupReplaceMutationIDs) OutboxEventID() publicid.ID { return ids.outboxEventID }

// IdempotencyRecordID returns durable replay identity.
func (ids GroupReplaceMutationIDs) IdempotencyRecordID() publicid.ID {
	return ids.idempotencyRecordID
}

// IsValid reports whether all identities are present and distinct.
func (ids GroupReplaceMutationIDs) IsValid() bool {
	if len(ids.memberIDs) == 0 || len(ids.memberIDs) > resource.MaximumGroupMembers {
		return false
	}
	values := make([]publicid.ID, 0, len(ids.memberIDs)+5)
	values = append(values, ids.changeID, ids.groupVersionID)
	values = append(values, ids.memberIDs...)
	values = append(values, ids.auditEventID, ids.outboxEventID, ids.idempotencyRecordID)
	seen := make(map[publicid.ID]struct{}, len(values))
	for _, id := range values {
		if !id.IsValid() {
			return false
		}
		if _, exists := seen[id]; exists {
			return false
		}
		seen[id] = struct{}{}
	}
	return true
}

// IsValidFor reports whether the identity cardinality matches command membership.
func (ids GroupReplaceMutationIDs) IsValidFor(command GroupReplaceCommand) bool {
	return ids.IsValid() && command.IsValid() && len(ids.memberIDs) == len(command.Members())
}

// PublicGroupReplaceMutationIDGenerator creates UUIDv7 evidence identities.
type PublicGroupReplaceMutationIDGenerator struct{}

// NewGroupReplaceMutationIDs creates one stable identity set for every retry.
func (PublicGroupReplaceMutationIDGenerator) NewGroupReplaceMutationIDs(
	command GroupReplaceCommand,
) (GroupReplaceMutationIDs, error) {
	if !command.IsValid() {
		return GroupReplaceMutationIDs{}, ErrInvalidGroupReplaceMutationIDs
	}
	values := make([]publicid.ID, len(command.Members())+5)
	for index := range values {
		id, err := publicid.New()
		if err != nil {
			return GroupReplaceMutationIDs{}, fmt.Errorf(
				"generate Resource Group replacement public ID: %w", err,
			)
		}
		values[index] = id
	}
	memberEnd := 2 + len(command.Members())
	return NewGroupReplaceMutationIDs(
		values[0], values[1], values[2:memberEnd],
		values[memberEnd], values[memberEnd+1], values[memberEnd+2],
	)
}
