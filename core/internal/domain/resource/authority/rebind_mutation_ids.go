package authority

import (
	"errors"
	"fmt"

	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

// ErrInvalidRebindMutationIDs reports incomplete or aliased durable identities.
var ErrInvalidRebindMutationIDs = errors.New("resource rebind: invalid mutation IDs")

// RebindMutationIDs names every row written by one target replacement.
type RebindMutationIDs struct {
	changeID            publicid.ID
	targetID            publicid.ID
	auditEventID        publicid.ID
	outboxEventID       publicid.ID
	idempotencyRecordID publicid.ID
}

// NewRebindMutationIDs validates one rebinding identity set.
func NewRebindMutationIDs(
	changeID, targetID, auditEventID, outboxEventID, idempotencyRecordID publicid.ID,
) (RebindMutationIDs, error) {
	ids := RebindMutationIDs{
		changeID: changeID, targetID: targetID, auditEventID: auditEventID,
		outboxEventID: outboxEventID, idempotencyRecordID: idempotencyRecordID,
	}
	if !ids.IsValid() {
		return RebindMutationIDs{}, ErrInvalidRebindMutationIDs
	}
	return ids, nil
}

// ChangeID returns transaction correlation authority.
func (ids RebindMutationIDs) ChangeID() publicid.ID { return ids.changeID }

// TargetID returns the new immutable binding identity.
func (ids RebindMutationIDs) TargetID() publicid.ID { return ids.targetID }

// AuditEventID returns immutable audit identity.
func (ids RebindMutationIDs) AuditEventID() publicid.ID { return ids.auditEventID }

// OutboxEventID returns durable outbox identity.
func (ids RebindMutationIDs) OutboxEventID() publicid.ID { return ids.outboxEventID }

// IdempotencyRecordID returns durable replay identity.
func (ids RebindMutationIDs) IdempotencyRecordID() publicid.ID { return ids.idempotencyRecordID }

// IsValid reports whether all identities are present and distinct.
func (ids RebindMutationIDs) IsValid() bool {
	values := [...]publicid.ID{
		ids.changeID, ids.targetID, ids.auditEventID, ids.outboxEventID, ids.idempotencyRecordID,
	}
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

// PublicRebindMutationIDGenerator creates UUIDv7 evidence identities.
type PublicRebindMutationIDGenerator struct{}

// NewRebindMutationIDs creates one stable identity set for every retry.
func (PublicRebindMutationIDGenerator) NewRebindMutationIDs(
	command RebindCommand,
) (RebindMutationIDs, error) {
	if !command.IsValid() {
		return RebindMutationIDs{}, ErrInvalidRebindMutationIDs
	}
	var values [5]publicid.ID
	for index := range values {
		id, err := publicid.New()
		if err != nil {
			return RebindMutationIDs{}, fmt.Errorf("generate Resource rebind public ID: %w", err)
		}
		values[index] = id
	}
	return NewRebindMutationIDs(values[0], values[1], values[2], values[3], values[4])
}
