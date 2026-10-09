package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/audit"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/oidcauth"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

const authTransactionOutboxEventClass = "identity.auth_transaction.created"

type authTransactionAuditPayload struct {
	ProviderPublicID   string    `json:"provider_public_id"`
	ClientPublicID     string    `json:"client_public_id"`
	ProviderGeneration int64     `json:"provider_generation"`
	RecoveryEpoch      int64     `json:"deployment_recovery_epoch"`
	RedirectID         string    `json:"redirect_id"`
	ReturnRouteID      string    `json:"return_route_id"`
	ExpiresAt          time.Time `json:"expires_at"`
}

type authTransactionOutboxPayload struct {
	TransactionPublicID string    `json:"transaction_public_id"`
	ProviderPublicID    string    `json:"provider_public_id"`
	ProviderGeneration  int64     `json:"provider_generation"`
	RecoveryEpoch       int64     `json:"deployment_recovery_epoch"`
	ExpiresAt           time.Time `json:"expires_at"`
}

func (transaction *authTransactionTransaction) appendAuthTransactionEvidence(
	ctx context.Context,
	pending oidcauth.Pending,
	created oidcauth.Created,
) error {
	route := pending.Route()
	auditPayload, err := json.Marshal(authTransactionAuditPayload{
		ProviderPublicID:   route.ProviderID().String(),
		ClientPublicID:     route.ClientID().String(),
		ProviderGeneration: route.ProviderGeneration(),
		RecoveryEpoch:      route.RecoveryEpoch(),
		RedirectID:         route.RedirectID(),
		ReturnRouteID:      route.ReturnRouteID(),
		ExpiresAt:          created.ExpiresAt(),
	})
	if err != nil {
		return fmt.Errorf("encode auth transaction audit payload: %w", err)
	}
	outboxPayload, err := json.Marshal(authTransactionOutboxPayload{
		TransactionPublicID: created.TransactionID().String(),
		ProviderPublicID:    route.ProviderID().String(),
		ProviderGeneration:  route.ProviderGeneration(),
		RecoveryEpoch:       route.RecoveryEpoch(),
		ExpiresAt:           created.ExpiresAt(),
	})
	if err != nil {
		return fmt.Errorf("encode auth transaction outbox payload: %w", err)
	}
	auditPayloadHash := sha256.Sum256(auditPayload)
	outboxPayloadHash := sha256.Sum256(outboxPayload)
	afterSemanticHash := pending.SemanticHash()
	ids := pending.MutationIDs()
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash:      transaction.audit.previousHash,
		EventID:           ids.AuditEventID(),
		ChangeID:          ids.ChangeID(),
		AggregateKind:     "auth_transaction",
		AggregateID:       publicid.ID(pending.TransactionID()),
		AggregateVersion:  created.Version(),
		NetworkRevision:   0,
		Action:            "auth_transaction.created",
		Permission:        "identity.authenticate",
		CorrelationID:     publicid.ID(pending.TransactionID()),
		AfterSemanticHash: afterSemanticHash,
		AuditPayloadHash:  auditPayloadHash,
		OutboxEventClass:  authTransactionOutboxEventClass,
		OutboxPayloadHash: outboxPayloadHash,
	})
	if err != nil {
		return fmt.Errorf("hash auth transaction audit event: %w", err)
	}

	var appendedSequence int64
	if err := transaction.database.QueryRow(
		ctx,
		appendAuthTransactionEvidenceSQL,
		transaction.audit.streamInternalID,
		ids.AuditEventID().String(),
		ids.OutboxEventID().String(),
		transaction.audit.nextSequence,
		transaction.audit.previousHash[:],
		eventHash[:],
		pending.TransactionID().String(),
		created.Version(),
		pending.TransactionID().String(),
		afterSemanticHash[:],
		auditPayload,
		outboxPayload,
	).Scan(&appendedSequence); err != nil {
		return fmt.Errorf("append auth transaction audit and outbox evidence: %w", err)
	}
	if appendedSequence != transaction.audit.nextSequence {
		return ErrAuthTransactionEvidence
	}
	return nil
}
