package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/meshtransit/meshtransit/core/internal/domain/audit"
	"github.com/meshtransit/meshtransit/core/internal/domain/node/keyrotation"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

type nodeKeyRotationAuditPayload struct {
	AuthenticationKind        string `json:"authentication_kind"`
	PreviousDeviceVersion     int64  `json:"previous_device_version"`
	DeviceVersion             int64  `json:"device_version"`
	PreviousNodeKeyEpoch      int64  `json:"previous_node_key_epoch"`
	NodeKeyEpoch              int64  `json:"node_key_epoch"`
	PreviousSessionGeneration int64  `json:"previous_session_generation"`
	SessionGeneration         int64  `json:"session_generation"`
}

type nodeKeyRotationOutboxPayload struct {
	InventoryRevision int64 `json:"inventory_revision"`
	NetworkRevision   int64 `json:"network_revision"`
}

func (transaction *nodeKeyRotationTransaction) appendNodeKeyRotationEvidence(
	ctx context.Context,
	change keyrotation.Change,
	deviceVersion int64,
	sessionGeneration int64,
	networkRevision int64,
	inventoryRevision int64,
) error {
	resolution := change.Resolution()
	auditPayload, err := json.Marshal(nodeKeyRotationAuditPayload{
		AuthenticationKind:        "noise_machine_key",
		PreviousDeviceVersion:     resolution.DeviceVersion(),
		DeviceVersion:             deviceVersion,
		PreviousNodeKeyEpoch:      resolution.NodeKeyEpoch(),
		NodeKeyEpoch:              resolution.NodeKeyEpoch() + 1,
		PreviousSessionGeneration: resolution.SessionGeneration(),
		SessionGeneration:         sessionGeneration,
	})
	if err != nil {
		return fmt.Errorf("encode Node-key rotation audit payload: %w", err)
	}
	outboxPayload, err := json.Marshal(nodeKeyRotationOutboxPayload{
		InventoryRevision: inventoryRevision,
		NetworkRevision:   networkRevision,
	})
	if err != nil {
		return fmt.Errorf("encode Node-key rotation outbox payload: %w", err)
	}
	currentNodeKey := resolution.CurrentNodeKey().Bytes()
	newNodeKey := change.Command().NewNodeKey().Bytes()
	beforeMaterial := append([]byte("meshtransit/node-key-state/v1\x00"), currentNodeKey[:]...)
	afterMaterial := append([]byte("meshtransit/node-key-state/v1\x00"), newNodeKey[:]...)
	beforeSemanticHash := sha256.Sum256(beforeMaterial)
	afterSemanticHash := sha256.Sum256(afterMaterial)
	auditPayloadHash := sha256.Sum256(auditPayload)
	outboxPayloadHash := sha256.Sum256(outboxPayload)
	ids := change.MutationIDs()
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash:       transaction.audit.previousHash,
		EventID:            ids.AuditEventID(),
		ChangeID:           ids.ChangeID(),
		AggregateKind:      "device",
		AggregateID:        publicid.ID(resolution.NodeID()),
		AggregateVersion:   deviceVersion,
		NetworkRevision:    networkRevision,
		Action:             "device.node_key_rotated",
		Permission:         "device.node_key.rotate",
		CorrelationID:      publicid.ID(change.Command().OperationID()),
		BeforeSemanticHash: beforeSemanticHash,
		AfterSemanticHash:  afterSemanticHash,
		AuditPayloadHash:   auditPayloadHash,
		OutboxEventClass:   "network.revision.advanced",
		OutboxPayloadHash:  outboxPayloadHash,
	})
	if err != nil {
		return fmt.Errorf("hash Node-key rotation audit event: %w", err)
	}

	var appendedSequence int64
	if err := transaction.database.QueryRow(
		ctx,
		appendNodeKeyRotationEvidenceSQL,
		transaction.audit.streamInternalID,
		ids.AuditEventID().String(),
		ids.OutboxEventID().String(),
		transaction.audit.nextSequence,
		transaction.audit.previousHash[:],
		eventHash[:],
		resolution.NodeID().String(),
		deviceVersion,
		networkRevision,
		change.Command().OperationID().String(),
		beforeSemanticHash[:],
		afterSemanticHash[:],
		auditPayload,
		outboxPayload,
	).Scan(&appendedSequence); err != nil {
		return fmt.Errorf("append Node-key rotation audit and outbox evidence: %w", err)
	}
	if appendedSequence != transaction.audit.nextSequence {
		return ErrNodeKeyRotationEvidence
	}
	return nil
}
