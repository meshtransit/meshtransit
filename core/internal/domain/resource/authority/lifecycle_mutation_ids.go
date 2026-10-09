package authority

import (
	"errors"
	"fmt"

	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

// ErrInvalidLifecycleMutationIDs reports incomplete or aliased durable identities.
var ErrInvalidLifecycleMutationIDs = errors.New("resource lifecycle: invalid mutation IDs")

// LifecycleMutationIDs names every evidence row written by one transition.
type LifecycleMutationIDs struct {
	changeID            publicid.ID
	auditEventID        publicid.ID
	outboxEventID       publicid.ID
	idempotencyRecordID publicid.ID
}

// NewLifecycleMutationIDs validates one lifecycle identity set.
func NewLifecycleMutationIDs(
	changeID, auditEventID, outboxEventID, idempotencyRecordID publicid.ID,
) (LifecycleMutationIDs, error) {
	ids := LifecycleMutationIDs{
		changeID: changeID, auditEventID: auditEventID,
		outboxEventID: outboxEventID, idempotencyRecordID: idempotencyRecordID,
	}
	if !ids.IsValid() {
		return LifecycleMutationIDs{}, ErrInvalidLifecycleMutationIDs
	}
	return ids, nil
}

// ChangeID returns transaction correlation authority.
func (ids LifecycleMutationIDs) ChangeID() publicid.ID { return ids.changeID }

// AuditEventID returns immutable audit identity.
func (ids LifecycleMutationIDs) AuditEventID() publicid.ID { return ids.auditEventID }

// OutboxEventID returns durable outbox identity.
func (ids LifecycleMutationIDs) OutboxEventID() publicid.ID { return ids.outboxEventID }

// IdempotencyRecordID returns durable replay identity.
func (ids LifecycleMutationIDs) IdempotencyRecordID() publicid.ID {
	return ids.idempotencyRecordID
}

// IsValid reports whether all four IDs are present and distinct.
func (ids LifecycleMutationIDs) IsValid() bool {
	values := [...]publicid.ID{
		ids.changeID, ids.auditEventID, ids.outboxEventID, ids.idempotencyRecordID,
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

// PublicLifecycleMutationIDGenerator creates UUIDv7 evidence identities.
type PublicLifecycleMutationIDGenerator struct{}

// NewLifecycleMutationIDs creates one stable identity set for every retry.
func (PublicLifecycleMutationIDGenerator) NewLifecycleMutationIDs(
	command LifecycleCommand,
) (LifecycleMutationIDs, error) {
	if !command.IsValid() {
		return LifecycleMutationIDs{}, ErrInvalidLifecycleMutationIDs
	}
	var values [4]publicid.ID
	for index := range values {
		id, err := publicid.New()
		if err != nil {
			return LifecycleMutationIDs{}, fmt.Errorf("generate lifecycle public ID: %w", err)
		}
		values[index] = id
	}
	return NewLifecycleMutationIDs(values[0], values[1], values[2], values[3])
}
