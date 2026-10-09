package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/identity/oidcauth"
	"meshtransit.net/core/internal/domain/publicid"
)

// Closed no-grant payload. No proof, subject, SID, digest, ciphertext or topology.
type authExpiryPayload struct {
	TransactionID   string    `json:"transaction_public_id"`
	PreviousState   string    `json:"previous_state"`
	PreviousVersion int64     `json:"previous_version"`
	ExpiresAt       time.Time `json:"expires_at"`
	ConsumedAt      time.Time `json:"consumed_at"`
	ExpiredAt       time.Time `json:"expired_at"`
}

func (unit *authExpiryTransaction) appendExpiryEvidence(
	ctx context.Context, command oidcauth.ExpiryCommand, terminal oidcauth.Expired, head authTransactionAuditHead,
) error {
	snapshot, ids := command.Snapshot(), command.MutationIDs()
	payload, err := json.Marshal(authExpiryPayload{
		TransactionID: snapshot.TransactionID().String(),
		PreviousState: snapshot.State(), PreviousVersion: snapshot.Version(),
		ExpiresAt: snapshot.ExpiresAt(), ConsumedAt: terminal.ConsumedAt(), ExpiredAt: terminal.ExpiredAt(),
	})
	if err != nil {
		return ErrAuthTransactionEvidence
	}
	before, after := terminal.BeforeSemanticHash(), terminal.AfterSemanticHash()
	hash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: head.previousHash, EventID: ids.AuditEventID(), ChangeID: ids.ChangeID(),
		AggregateKind: "auth_transaction", AggregateID: publicid.ID(snapshot.TransactionID()),
		AggregateVersion: terminal.Version(), Action: "auth_transaction.expired", Permission: "system.lifecycle",
		CorrelationID:      publicid.ID(snapshot.TransactionID()),
		BeforeSemanticHash: before, AfterSemanticHash: after, AuditPayloadHash: sha256.Sum256(payload),
		OutboxEventClass: "identity.auth_transaction.expired", OutboxPayloadHash: sha256.Sum256(payload),
	})
	if err != nil {
		return ErrAuthTransactionEvidence
	}
	var sequence int64
	if err := unit.database.QueryRow(
		ctx,
		appendAuthExpirySQL,
		snapshot.DeploymentID().String(),
		snapshot.TransactionID().String(),
		head.streamInternalID,
		ids.AuditEventID().String(),
		ids.OutboxEventID().String(),
		head.nextSequence,
		head.previousHash[:],
		hash[:],
		before[:],
		after[:],
		payload,
	).Scan(&sequence); err != nil {
		return err
	}
	if sequence != head.nextSequence {
		return ErrAuthTransactionEvidence
	}
	return nil
}
