package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/enrollment/registration"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

const registrationOutboxEventClass = "network.revision.advanced"

type registrationAuditPayload struct {
	CredentialID   string `json:"credential_id"`
	Disposition    string `json:"disposition"`
	Hostname       string `json:"hostname"`
	RegistrationID string `json:"registration_id"`
}

type registrationOutboxPayload struct {
	InventoryRevision int64 `json:"inventory_revision"`
	NetworkRevision   int64 `json:"network_revision"`
}

func (transaction *registrationTransaction) advanceRegistrationRevision(
	ctx context.Context,
) (networkRevision int64, inventoryRevision int64, resultErr error) {
	if err := transaction.database.QueryRow(ctx, advanceRegistrationRevisionSQL).Scan(
		&networkRevision,
		&inventoryRevision,
	); err != nil {
		return 0, 0, fmt.Errorf("advance Network inventory revision: %w", err)
	}
	if networkRevision != transaction.locked.currentNetworkRevision+1 ||
		inventoryRevision != transaction.locked.currentInventoryRevision+1 {
		return 0, 0, ErrRegistrationEvidence
	}
	return networkRevision, inventoryRevision, nil
}

func (transaction *registrationTransaction) completePendingRegistration(
	ctx context.Context,
	change registration.Change,
	deviceInternalID int64,
	hostname node.Hostname,
	networkRevision int64,
) error {
	result, err := transaction.database.Exec(
		ctx,
		completePendingRegistrationSQL,
		transaction.locked.pending.internalID,
		deviceInternalID,
		hostname.String(),
		registrationDispositionValue(change.Disposition()),
		networkRevision,
		change.OccurredAt(),
		transaction.locked.pending.version,
	)
	if err != nil {
		return fmt.Errorf("complete pending registration: %w", err)
	}
	if result.RowsAffected() != 1 {
		return ErrRegistrationEvidence
	}
	return nil
}

func (transaction *registrationTransaction) appendRegistrationEvidence(
	ctx context.Context,
	change registration.Change,
	hostname node.Hostname,
	deviceVersion int64,
	networkRevision int64,
	inventoryRevision int64,
) error {
	action := "device.registered"
	if change.Disposition() == registration.DispositionResumed {
		action = "device.resumed"
	}
	auditPayload, err := json.Marshal(registrationAuditPayload{
		CredentialID:   change.Credential().ID().String(),
		Disposition:    registrationDispositionValue(change.Disposition()),
		Hostname:       hostname.String(),
		RegistrationID: change.Registration().ID().String(),
	})
	if err != nil {
		return fmt.Errorf("encode registration audit payload: %w", err)
	}
	outboxPayload, err := json.Marshal(registrationOutboxPayload{
		InventoryRevision: inventoryRevision,
		NetworkRevision:   networkRevision,
	})
	if err != nil {
		return fmt.Errorf("encode registration outbox payload: %w", err)
	}
	requestHash := transaction.locked.resolution.RequestHash().Bytes()
	auditPayloadHash := sha256.Sum256(auditPayload)
	outboxPayloadHash := sha256.Sum256(outboxPayload)
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash:      transaction.locked.audit.previousHash,
		EventID:           change.MutationIDs().AuditEventID(),
		ChangeID:          change.MutationIDs().ChangeID(),
		AggregateKind:     "device",
		AggregateID:       publicid.ID(change.NodeID()),
		AggregateVersion:  deviceVersion,
		NetworkRevision:   networkRevision,
		ActorPrincipalID:  publicid.ID(change.OwnerID()),
		Action:            action,
		Permission:        "device.register",
		CorrelationID:     publicid.ID(change.Registration().ID()),
		AfterSemanticHash: requestHash,
		AuditPayloadHash:  auditPayloadHash,
		OutboxEventClass:  registrationOutboxEventClass,
		OutboxPayloadHash: outboxPayloadHash,
	})
	if err != nil {
		return fmt.Errorf("hash registration audit event: %w", err)
	}

	var appendedSequence int64
	if err := transaction.database.QueryRow(
		ctx,
		appendRegistrationEvidenceSQL,
		transaction.locked.audit.streamInternalID,
		change.MutationIDs().AuditEventID().String(),
		change.MutationIDs().OutboxEventID().String(),
		transaction.locked.audit.nextSequence,
		transaction.locked.audit.previousHash[:],
		eventHash[:],
		change.NodeID().String(),
		deviceVersion,
		networkRevision,
		change.OwnerID().String(),
		action,
		change.Registration().ID().String(),
		requestHash[:],
		auditPayload,
		outboxPayload,
	).Scan(&appendedSequence); err != nil {
		return fmt.Errorf("append registration audit and outbox evidence: %w", err)
	}
	if appendedSequence != transaction.locked.audit.nextSequence {
		return ErrRegistrationEvidence
	}
	return nil
}

func registrationDispositionValue(disposition registration.Disposition) string {
	switch disposition {
	case registration.DispositionCreated:
		return "created"
	case registration.DispositionResumed:
		return "resumed"
	default:
		return ""
	}
}
