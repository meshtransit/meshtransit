package revocation

import (
	"errors"
	"fmt"

	"github.com/meshtransit/meshtransit/internal/publicid"
)

// ErrInvalidMutationIDs reports missing or aliased durable row identities.
var ErrInvalidMutationIDs = errors.New("device revocation: invalid mutation IDs")

// MutationIDParams names every public identity created by one revocation.
type MutationIDParams struct {
	IdempotencyRecordID publicid.ID
	ChangeID            publicid.ID
	AuditEventID        publicid.ID
	OutboxEventID       publicid.ID
}

// MutationIDs is an immutable set reused across complete transaction retries.
type MutationIDs struct {
	idempotencyRecordID publicid.ID
	changeID            publicid.ID
	auditEventID        publicid.ID
	outboxEventID       publicid.ID
}

// NewMutationIDs validates that every required UUIDv7 is distinct.
func NewMutationIDs(params MutationIDParams) (MutationIDs, error) {
	values := [...]publicid.ID{
		params.IdempotencyRecordID,
		params.ChangeID,
		params.AuditEventID,
		params.OutboxEventID,
	}
	for index, value := range values {
		if !value.IsValid() {
			return MutationIDs{}, ErrInvalidMutationIDs
		}
		for previous := range index {
			if value == values[previous] {
				return MutationIDs{}, ErrInvalidMutationIDs
			}
		}
	}
	return MutationIDs{
		idempotencyRecordID: params.IdempotencyRecordID,
		changeID:            params.ChangeID,
		auditEventID:        params.AuditEventID,
		outboxEventID:       params.OutboxEventID,
	}, nil
}

// IdempotencyRecordID returns the proposed replay-record identity.
func (ids MutationIDs) IdempotencyRecordID() publicid.ID { return ids.idempotencyRecordID }

// ChangeID returns the authority-mutation correlation identity.
func (ids MutationIDs) ChangeID() publicid.ID { return ids.changeID }

// AuditEventID returns the immutable audit event identity.
func (ids MutationIDs) AuditEventID() publicid.ID { return ids.auditEventID }

// OutboxEventID returns the durable revision wakeup identity.
func (ids MutationIDs) OutboxEventID() publicid.ID { return ids.outboxEventID }

// IsValid reports whether the complete set remains non-aliased.
func (ids MutationIDs) IsValid() bool {
	validated, err := NewMutationIDs(MutationIDParams{
		IdempotencyRecordID: ids.idempotencyRecordID,
		ChangeID:            ids.changeID,
		AuditEventID:        ids.auditEventID,
		OutboxEventID:       ids.outboxEventID,
	})
	return err == nil && validated == ids
}

// PublicMutationIDGenerator creates UUIDv7 identities using OS entropy.
type PublicMutationIDGenerator struct{}

// NewMutationIDs returns one fresh identity set for a replayable revocation.
func (PublicMutationIDGenerator) NewMutationIDs() (MutationIDs, error) {
	var generated [4]publicid.ID
	for index := range generated {
		id, err := publicid.New()
		if err != nil {
			return MutationIDs{}, fmt.Errorf("generate device revocation public ID: %w", err)
		}
		generated[index] = id
	}
	return NewMutationIDs(MutationIDParams{
		IdempotencyRecordID: generated[0],
		ChangeID:            generated[1],
		AuditEventID:        generated[2],
		OutboxEventID:       generated[3],
	})
}
