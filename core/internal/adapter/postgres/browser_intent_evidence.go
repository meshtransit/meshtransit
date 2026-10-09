package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

const lockBrowserIntentAuditSQL = `SELECT
    stream_internal_id, next_sequence, latest_event_hash
FROM mesh_audit.lock_deployment_stream_head($1::UUID)`

const setBrowserIntentChangeSQL = `SELECT pg_catalog.set_config(
    'mesh.change_public_id', $1::TEXT, TRUE
)`

const appendBrowserIntentEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
    $1::BIGINT, $2::UUID, $3::UUID, $4::BIGINT, $5::BYTEA, $6::BYTEA,
    'browser_registration_intent', $7::UUID, 1::BIGINT, NULL::BIGINT,
    NULL::UUID, 'registration.browser.requested', 'device.register',
    $7::UUID, NULL::BYTEA, $8::BYTEA, $9::JSONB,
    'registration.browser.requested', $10::JSONB
)`

func appendBrowserIntentEvidence(
	ctx context.Context, transaction accountSessionTransaction,
	deploymentID deployment.ID, intentID enrollment.BrowserIntentID,
	identity node.RegistrationIdentity, eventID, outboxID publicid.ID,
) error {
	if err := transaction.Exec(ctx, setBrowserIntentChangeSQL, intentID.String()); err != nil {
		return errors.Join(ErrBrowserIntentIssueUnavailable, err)
	}
	var streamID, sequence int64
	var previousBytes []byte
	if err := transaction.QueryRow(ctx, lockBrowserIntentAuditSQL,
		deploymentID.String()).Scan(&streamID, &sequence, &previousBytes); err != nil ||
		streamID <= 0 || sequence <= 0 || len(previousBytes) != sha256.Size {
		return errors.Join(ErrBrowserIntentIssueEvidence, err)
	}
	var previousHash [sha256.Size]byte
	copy(previousHash[:], previousBytes)
	machineFingerprint := identity.MachineKey().Fingerprint()
	nodeKey := identity.NodeKey().Bytes()
	intentBytes := intentID.Bytes()
	semantic := sha256.New()
	_, _ = semantic.Write([]byte("meshtransit/browser-intent-issued/v1\x00"))
	_, _ = semantic.Write(intentBytes[:])
	_, _ = semantic.Write(machineFingerprint[:])
	_, _ = semantic.Write(nodeKey[:])
	var afterSemanticHash [sha256.Size]byte
	copy(afterSemanticHash[:], semantic.Sum(nil))
	auditPayload, err := json.Marshal(struct {
		IntentID string `json:"intent_id"`
	}{IntentID: intentID.String()})
	if err != nil {
		return errors.Join(ErrBrowserIntentIssueEvidence, err)
	}
	outboxPayload, err := json.Marshal(struct {
		IntentID string `json:"intent_id"`
	}{IntentID: intentID.String()})
	if err != nil {
		return errors.Join(ErrBrowserIntentIssueEvidence, err)
	}
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: previousHash, EventID: eventID,
		ChangeID: publicid.ID(intentID), AggregateKind: "browser_registration_intent",
		AggregateID: publicid.ID(intentID), AggregateVersion: 1,
		Action: "registration.browser.requested", Permission: "device.register",
		CorrelationID: publicid.ID(intentID), AfterSemanticHash: afterSemanticHash,
		AuditPayloadHash:  sha256.Sum256(auditPayload),
		OutboxEventClass:  "registration.browser.requested",
		OutboxPayloadHash: sha256.Sum256(outboxPayload),
	})
	if err != nil {
		return errors.Join(ErrBrowserIntentIssueEvidence, err)
	}
	var appendedSequence int64
	if err := transaction.QueryRow(ctx, appendBrowserIntentEvidenceSQL,
		streamID, eventID.String(), outboxID.String(), sequence,
		previousHash[:], eventHash[:], intentID.String(),
		afterSemanticHash[:], auditPayload, outboxPayload,
	).Scan(&appendedSequence); err != nil || appendedSequence != sequence {
		return errors.Join(ErrBrowserIntentIssueEvidence, err)
	}
	return nil
}
