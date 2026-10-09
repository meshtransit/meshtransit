package registrationintake

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/meshtransit/meshtransit/core/internal/domain/audit"
	appintake "github.com/meshtransit/meshtransit/core/internal/domain/enrollment/registration/intake"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

const registrationPendingEventClass = "registration.pending.created"

type auditPayload struct {
	CredentialID   string `json:"credential_id"`
	Hostname       string `json:"hostname"`
	RegistrationID string `json:"registration_id"`
}

type outboxPayload struct {
	NetworkRevision int64  `json:"network_revision"`
	RegistrationID  string `json:"registration_id"`
}

func (transaction *transaction) appendEvidence(
	ctx context.Context,
	change appintake.Change,
	version int64,
) error {
	command := change.Command()
	auditValue, err := json.Marshal(auditPayload{
		CredentialID:   command.CredentialID.String(),
		Hostname:       command.Hostname.String(),
		RegistrationID: command.RegistrationID.String(),
	})
	if err != nil {
		return fmt.Errorf("encode registration-intake audit payload: %w", err)
	}
	outboxValue, err := json.Marshal(outboxPayload{
		NetworkRevision: transaction.locked.currentNetworkRevision,
		RegistrationID:  command.RegistrationID.String(),
	})
	if err != nil {
		return fmt.Errorf("encode registration-intake outbox payload: %w", err)
	}
	actorID, err := identity.ParsePrincipalID(transaction.locked.issuerPublicID)
	if err != nil {
		return ErrEvidence
	}
	requestHash := change.RequestHash().Bytes()
	auditPayloadHash := sha256.Sum256(auditValue)
	outboxPayloadHash := sha256.Sum256(outboxValue)
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash:      transaction.locked.audit.previousHash,
		EventID:           change.EvidenceIDs().AuditEventID(),
		ChangeID:          change.EvidenceIDs().ChangeID(),
		AggregateKind:     "pending_registration",
		AggregateID:       publicid.ID(command.RegistrationID),
		AggregateVersion:  version,
		NetworkRevision:   transaction.locked.currentNetworkRevision,
		ActorPrincipalID:  publicid.ID(actorID),
		Action:            "registration.requested",
		Permission:        "device.register",
		CorrelationID:     publicid.ID(command.RegistrationID),
		AfterSemanticHash: requestHash,
		AuditPayloadHash:  auditPayloadHash,
		OutboxEventClass:  registrationPendingEventClass,
		OutboxPayloadHash: outboxPayloadHash,
	})
	if err != nil {
		return fmt.Errorf("hash registration-intake audit event: %w", err)
	}

	var appendedSequence int64
	if err := transaction.database.QueryRow(
		ctx,
		appendEvidenceSQL,
		transaction.locked.audit.streamInternalID,
		change.EvidenceIDs().AuditEventID().String(),
		change.EvidenceIDs().OutboxEventID().String(),
		transaction.locked.audit.nextSequence,
		transaction.locked.audit.previousHash[:],
		eventHash[:],
		"pending_registration",
		command.RegistrationID.String(),
		version,
		transaction.locked.currentNetworkRevision,
		actorID.String(),
		"registration.requested",
		"device.register",
		command.RegistrationID.String(),
		requestHash[:],
		auditValue,
		registrationPendingEventClass,
		outboxValue,
	).Scan(&appendedSequence); err != nil {
		return fmt.Errorf("append registration-intake audit and outbox evidence: %w", err)
	}
	if appendedSequence != transaction.locked.audit.nextSequence {
		return ErrEvidence
	}
	return nil
}
