package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/meshtransit/meshtransit/internal/audit"
	"github.com/meshtransit/meshtransit/internal/node/revocation"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

const deviceRevocationOutboxEventClass = "network.revision.advanced"

type deviceRevocationAuditPayload struct {
	AuditReason               string `json:"audit_reason"`
	PreviousDeviceVersion     int64  `json:"previous_device_version"`
	DeviceVersion             int64  `json:"device_version"`
	PreviousSessionGeneration int64  `json:"previous_session_generation"`
	SessionGeneration         int64  `json:"session_generation"`
	MachineKeyEpoch           int64  `json:"machine_key_epoch"`
	NodeKeyEpoch              int64  `json:"node_key_epoch"`
}

func (transaction *deviceRevocationTransaction) appendDeviceRevocationEvidence(
	ctx context.Context,
	change revocation.Change,
	deviceVersion int64,
	sessionGeneration int64,
	networkRevision int64,
	inventoryRevision int64,
) error {
	command := change.Command()
	resolution := change.Resolution()
	auditPayload, err := json.Marshal(deviceRevocationAuditPayload{
		AuditReason:               command.Reason().String(),
		PreviousDeviceVersion:     resolution.DeviceVersion(),
		DeviceVersion:             deviceVersion,
		PreviousSessionGeneration: resolution.SessionGeneration(),
		SessionGeneration:         sessionGeneration,
		MachineKeyEpoch:           resolution.MachineKeyEpoch(),
		NodeKeyEpoch:              resolution.NodeKeyEpoch(),
	})
	if err != nil {
		return fmt.Errorf("encode Device revocation audit payload: %w", err)
	}
	resultPayload, err := json.Marshal(deviceRevocationResultPayload{
		NetworkRevision:   networkRevision,
		InventoryRevision: inventoryRevision,
		DevicePublicID:    command.NodeID().String(),
		DeviceVersion:     deviceVersion,
		SessionGeneration: sessionGeneration,
		Terminal:          true,
	})
	if err != nil {
		return fmt.Errorf("encode Device revocation result payload: %w", err)
	}
	auditPayloadHash := sha256.Sum256(auditPayload)
	resultPayloadHash := sha256.Sum256(resultPayload)
	beforeSemanticHash := change.BeforeSemanticHash()
	afterSemanticHash := change.AfterSemanticHash()
	ids := change.Attempt().MutationIDs()
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash:       transaction.audit.previousHash,
		EventID:            ids.AuditEventID(),
		ChangeID:           ids.ChangeID(),
		AggregateKind:      "device",
		AggregateID:        publicid.ID(command.NodeID()),
		AggregateVersion:   deviceVersion,
		NetworkRevision:    networkRevision,
		ActorPrincipalID:   publicid.ID(command.ActorPrincipalID()),
		Action:             "device.revoked",
		Permission:         "device.manage",
		CorrelationID:      resolution.IdempotencyRecordID(),
		BeforeSemanticHash: beforeSemanticHash,
		AfterSemanticHash:  afterSemanticHash,
		AuditPayloadHash:   auditPayloadHash,
		OutboxEventClass:   deviceRevocationOutboxEventClass,
		OutboxPayloadHash:  resultPayloadHash,
	})
	if err != nil {
		return fmt.Errorf("hash Device revocation audit event: %w", err)
	}

	var appendedSequence int64
	if err := transaction.database.QueryRow(
		ctx,
		appendDeviceRevocationEvidenceSQL,
		transaction.audit.streamInternalID,
		ids.AuditEventID().String(),
		ids.OutboxEventID().String(),
		transaction.audit.nextSequence,
		transaction.audit.previousHash[:],
		eventHash[:],
		command.NodeID().String(),
		deviceVersion,
		networkRevision,
		command.ActorPrincipalID().String(),
		resolution.IdempotencyRecordID().String(),
		beforeSemanticHash[:],
		afterSemanticHash[:],
		auditPayload,
		resultPayload,
	).Scan(&appendedSequence); err != nil {
		return fmt.Errorf("append Device revocation audit and outbox evidence: %w", err)
	}
	if appendedSequence != transaction.audit.nextSequence {
		return ErrDeviceRevocationEvidence
	}

	requestHash := resolution.RequestHash().Bytes()
	proof := command.IdempotencyEvidence()
	digest := proof.Digest()
	var completedRecordID string
	if err := transaction.database.QueryRow(
		ctx,
		completeDeviceRevocationIdempotencySQL,
		resolution.IdempotencyRecordID().String(),
		command.ActorPrincipalID().String(),
		deviceRevocationOperation,
		proof.DigestKeyID(),
		digest[:],
		requestHash[:],
		deviceRevocationResultKind,
		command.NodeID().String(),
		deviceVersion,
		networkRevision,
		resultPayload,
		ids.OutboxEventID().String(),
		change.Attempt().OccurredAt(),
	).Scan(&completedRecordID); err != nil {
		return fmt.Errorf("complete Device revocation idempotency evidence: %w", err)
	}
	if completedRecordID != resolution.IdempotencyRecordID().String() {
		return ErrDeviceRevocationEvidence
	}
	return nil
}
