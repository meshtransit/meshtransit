package authority

import (
	"errors"
	"fmt"

	"meshtransit.net/core/internal/domain/publicid"
)

var (
	// ErrInvalidAuthorityChangeRequestMutationIDs reports incomplete proposal identities.
	ErrInvalidAuthorityChangeRequestMutationIDs = errors.New("resource authority change: invalid request mutation ids")
	// ErrInvalidAuthorityChangeConfirmationMutationIDs reports incomplete confirmation identities.
	ErrInvalidAuthorityChangeConfirmationMutationIDs = errors.New("resource authority change: invalid confirmation mutation ids")
)

// ChangeRequestMutationIDs are proposal identities stable across retries.
type ChangeRequestMutationIDs struct {
	changeID            publicid.ID
	requestID           ChangeRequestID
	stepUpEvidenceID    publicid.ID
	auditEventID        publicid.ID
	outboxEventID       publicid.ID
	idempotencyRecordID publicid.ID
}

// NewAuthorityChangeRequestMutationIDs validates one complete proposal identity set.
func NewAuthorityChangeRequestMutationIDs(
	changeID publicid.ID,
	requestID ChangeRequestID,
	stepUpEvidenceID, auditEventID, outboxEventID, idempotencyRecordID publicid.ID,
) (ChangeRequestMutationIDs, error) {
	ids := ChangeRequestMutationIDs{
		changeID: changeID, requestID: requestID, stepUpEvidenceID: stepUpEvidenceID,
		auditEventID: auditEventID, outboxEventID: outboxEventID,
		idempotencyRecordID: idempotencyRecordID,
	}
	if !ids.IsValid() {
		return ChangeRequestMutationIDs{}, ErrInvalidAuthorityChangeRequestMutationIDs
	}
	return ids, nil
}

// ChangeID returns transaction-local authority context identity.
func (ids ChangeRequestMutationIDs) ChangeID() publicid.ID { return ids.changeID }

// RequestID returns durable pending request identity.
func (ids ChangeRequestMutationIDs) RequestID() ChangeRequestID {
	return ids.requestID
}

// StepUpEvidenceID returns single-use requester evidence identity.
func (ids ChangeRequestMutationIDs) StepUpEvidenceID() publicid.ID {
	return ids.stepUpEvidenceID
}

// AuditEventID returns immutable audit identity.
func (ids ChangeRequestMutationIDs) AuditEventID() publicid.ID {
	return ids.auditEventID
}

// OutboxEventID returns durable outbox identity.
func (ids ChangeRequestMutationIDs) OutboxEventID() publicid.ID {
	return ids.outboxEventID
}

// IdempotencyRecordID returns durable replay identity.
func (ids ChangeRequestMutationIDs) IdempotencyRecordID() publicid.ID {
	return ids.idempotencyRecordID
}

// IsValid reports whether all proposal identities are present and distinct.
func (ids ChangeRequestMutationIDs) IsValid() bool {
	values := []publicid.ID{
		ids.changeID, publicid.ID(ids.requestID), ids.stepUpEvidenceID,
		ids.auditEventID, ids.outboxEventID, ids.idempotencyRecordID,
	}
	return distinctAuthorityChangeIDs(values)
}

// ChangeConfirmationMutationIDs are final identities stable across retries.
type ChangeConfirmationMutationIDs struct {
	changeID            publicid.ID
	stepUpEvidenceID    publicid.ID
	auditEventID        publicid.ID
	outboxEventID       publicid.ID
	idempotencyRecordID publicid.ID
}

// NewAuthorityChangeConfirmationMutationIDs validates a complete confirmation set.
func NewAuthorityChangeConfirmationMutationIDs(
	changeID, stepUpEvidenceID, auditEventID, outboxEventID,
	idempotencyRecordID publicid.ID,
) (ChangeConfirmationMutationIDs, error) {
	ids := ChangeConfirmationMutationIDs{
		changeID: changeID, stepUpEvidenceID: stepUpEvidenceID,
		auditEventID: auditEventID, outboxEventID: outboxEventID,
		idempotencyRecordID: idempotencyRecordID,
	}
	if !ids.IsValid() {
		return ChangeConfirmationMutationIDs{}, ErrInvalidAuthorityChangeConfirmationMutationIDs
	}
	return ids, nil
}

// ChangeID returns transaction-local authority context identity.
func (ids ChangeConfirmationMutationIDs) ChangeID() publicid.ID {
	return ids.changeID
}

// StepUpEvidenceID returns single-use confirmer evidence identity.
func (ids ChangeConfirmationMutationIDs) StepUpEvidenceID() publicid.ID {
	return ids.stepUpEvidenceID
}

// AuditEventID returns immutable audit identity.
func (ids ChangeConfirmationMutationIDs) AuditEventID() publicid.ID {
	return ids.auditEventID
}

// OutboxEventID returns durable outbox identity.
func (ids ChangeConfirmationMutationIDs) OutboxEventID() publicid.ID {
	return ids.outboxEventID
}

// IdempotencyRecordID returns durable replay identity.
func (ids ChangeConfirmationMutationIDs) IdempotencyRecordID() publicid.ID {
	return ids.idempotencyRecordID
}

// IsValid reports whether all confirmation identities are present and distinct.
func (ids ChangeConfirmationMutationIDs) IsValid() bool {
	return distinctAuthorityChangeIDs([]publicid.ID{
		ids.changeID, ids.stepUpEvidenceID, ids.auditEventID,
		ids.outboxEventID, ids.idempotencyRecordID,
	})
}

func distinctAuthorityChangeIDs(values []publicid.ID) bool {
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

// PublicAuthorityChangeMutationIDGenerator creates UUIDv7 protected evidence.
type PublicAuthorityChangeMutationIDGenerator struct{}

// NewAuthorityChangeRequestMutationIDs allocates one stable proposal identity set.
func (PublicAuthorityChangeMutationIDGenerator) NewAuthorityChangeRequestMutationIDs(
	command ChangeRequestCommand,
) (ChangeRequestMutationIDs, error) {
	if !command.IsValid() {
		return ChangeRequestMutationIDs{}, ErrInvalidAuthorityChangeRequestMutationIDs
	}
	values, err := newAuthorityChangePublicIDs(6)
	if err != nil {
		return ChangeRequestMutationIDs{}, err
	}
	requestID := ChangeRequestID(values[1])
	return NewAuthorityChangeRequestMutationIDs(
		values[0], requestID, values[2], values[3], values[4], values[5],
	)
}

// NewAuthorityChangeConfirmationMutationIDs allocates final stable identities.
func (PublicAuthorityChangeMutationIDGenerator) NewAuthorityChangeConfirmationMutationIDs(
	command ChangeConfirmationCommand,
) (ChangeConfirmationMutationIDs, error) {
	if !command.IsValid() {
		return ChangeConfirmationMutationIDs{}, ErrInvalidAuthorityChangeConfirmationMutationIDs
	}
	values, err := newAuthorityChangePublicIDs(5)
	if err != nil {
		return ChangeConfirmationMutationIDs{}, err
	}
	return NewAuthorityChangeConfirmationMutationIDs(
		values[0], values[1], values[2], values[3], values[4],
	)
}

func newAuthorityChangePublicIDs(count int) ([]publicid.ID, error) {
	values := make([]publicid.ID, count)
	for index := range values {
		id, err := publicid.New()
		if err != nil {
			return nil, fmt.Errorf("generate Resource authority change public id: %w", err)
		}
		values[index] = id
	}
	return values, nil
}
