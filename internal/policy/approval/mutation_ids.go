package approval

import (
	"errors"

	"github.com/meshtransit/meshtransit/internal/publicid"
)

var (
	// ErrInvalidRequestMutationIDs reports incomplete or aliased proposal identities.
	ErrInvalidRequestMutationIDs = errors.New("policy approval: invalid request mutation ids")
	// ErrInvalidApprovalMutationIDs reports incomplete or aliased decision identities.
	ErrInvalidApprovalMutationIDs = errors.New("policy approval: invalid approval mutation ids")
)

// RequestMutationIDParams contains every durable identity allocated for a proposal.
type RequestMutationIDParams struct {
	RequestID           RequestID
	ChangeID            publicid.ID
	IdempotencyRecordID publicid.ID
	AuditEventID        publicid.ID
	OutboxEventID       publicid.ID
}

// RequestMutationIDs are allocated once and reused across transaction retries.
type RequestMutationIDs struct {
	requestID           RequestID
	changeID            publicid.ID
	idempotencyRecordID publicid.ID
	auditEventID        publicid.ID
	outboxEventID       publicid.ID
}

// NewRequestMutationIDs validates a complete distinct proposal identity set.
func NewRequestMutationIDs(params RequestMutationIDParams) (RequestMutationIDs, error) {
	ids := RequestMutationIDs{
		requestID: params.RequestID, changeID: params.ChangeID,
		idempotencyRecordID: params.IdempotencyRecordID,
		auditEventID:        params.AuditEventID, outboxEventID: params.OutboxEventID,
	}
	if !ids.IsValid() {
		return RequestMutationIDs{}, ErrInvalidRequestMutationIDs
	}
	return ids, nil
}

// RequestID returns the durable pending-request identity.
func (ids RequestMutationIDs) RequestID() RequestID { return ids.requestID }

// ChangeID returns the authority mutation correlation identity.
func (ids RequestMutationIDs) ChangeID() publicid.ID { return ids.changeID }

// IdempotencyRecordID returns the durable replay-record identity.
func (ids RequestMutationIDs) IdempotencyRecordID() publicid.ID {
	return ids.idempotencyRecordID
}

// AuditEventID returns the append-only audit identity.
func (ids RequestMutationIDs) AuditEventID() publicid.ID { return ids.auditEventID }

// OutboxEventID returns the atomic outbox identity.
func (ids RequestMutationIDs) OutboxEventID() publicid.ID { return ids.outboxEventID }

// IsValid reports whether every proposal identity is present and distinct.
func (ids RequestMutationIDs) IsValid() bool {
	return ids.requestID.IsValid() && distinctIDs([]publicid.ID{
		publicid.ID(ids.requestID), ids.changeID, ids.idempotencyRecordID,
		ids.auditEventID, ids.outboxEventID,
	})
}

// MutationIDParams contains every durable identity allocated for a decision.
type MutationIDParams struct {
	EvidenceID          EvidenceID
	ChangeID            publicid.ID
	IdempotencyRecordID publicid.ID
	AuditEventID        publicid.ID
	OutboxEventID       publicid.ID
}

// MutationIDs are allocated once and reused across transaction retries.
type MutationIDs struct {
	evidenceID          EvidenceID
	changeID            publicid.ID
	idempotencyRecordID publicid.ID
	auditEventID        publicid.ID
	outboxEventID       publicid.ID
}

// NewMutationIDs validates a complete distinct decision identity set.
func NewMutationIDs(params MutationIDParams) (MutationIDs, error) {
	ids := MutationIDs{
		evidenceID: params.EvidenceID, changeID: params.ChangeID,
		idempotencyRecordID: params.IdempotencyRecordID,
		auditEventID:        params.AuditEventID, outboxEventID: params.OutboxEventID,
	}
	if !ids.IsValid() {
		return MutationIDs{}, ErrInvalidApprovalMutationIDs
	}
	return ids, nil
}

// EvidenceID returns the immutable approval artifact identity.
func (ids MutationIDs) EvidenceID() EvidenceID { return ids.evidenceID }

// ChangeID returns the authority mutation correlation identity.
func (ids MutationIDs) ChangeID() publicid.ID { return ids.changeID }

// IdempotencyRecordID returns the durable replay-record identity.
func (ids MutationIDs) IdempotencyRecordID() publicid.ID {
	return ids.idempotencyRecordID
}

// AuditEventID returns the append-only audit identity.
func (ids MutationIDs) AuditEventID() publicid.ID { return ids.auditEventID }

// OutboxEventID returns the atomic outbox identity.
func (ids MutationIDs) OutboxEventID() publicid.ID { return ids.outboxEventID }

// IsValid reports whether every decision identity is present and distinct.
func (ids MutationIDs) IsValid() bool {
	return ids.evidenceID.IsValid() && distinctIDs([]publicid.ID{
		publicid.ID(ids.evidenceID), ids.changeID, ids.idempotencyRecordID,
		ids.auditEventID, ids.outboxEventID,
	})
}

func distinctIDs(values []publicid.ID) bool {
	seen := make(map[publicid.ID]struct{}, len(values))
	for _, value := range values {
		if !value.IsValid() {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}
