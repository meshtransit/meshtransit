package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"time"

	"github.com/meshtransit/meshtransit/internal/audit"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

type authFailureAuditPayload struct {
	authClaimAuditPayload
	State        string    `json:"state"`
	FailureClass string    `json:"failure_class"`
	TerminatedAt time.Time `json:"terminated_at"`
}
type authFailureOutboxPayload struct {
	authClaimOutboxPayload
	State        string    `json:"state"`
	FailureClass string    `json:"failure_class"`
	TerminatedAt time.Time `json:"terminated_at"`
}

func (unit *authFailureTransaction) appendFailureEvidence(
	ctx context.Context,
	command oidcauth.FailureCommand,
	terminal oidcauth.Terminated,
	head authTransactionAuditHead,
) error {
	snapshot, ids := command.Snapshot(), command.MutationIDs()
	route := snapshot.Route()
	payload, err := json.Marshal(authFailureAuditPayload{authClaimAuditPayload: authClaimAuditPayload{authTransactionAuditPayload: authTransactionAuditPayload{
		ProviderPublicID: route.ProviderID().String(), ClientPublicID: route.ClientID().String(),
		ProviderGeneration: route.ProviderGeneration(), RecoveryEpoch: route.RecoveryEpoch(), RedirectID: route.RedirectID(), ReturnRouteID: route.ReturnRouteID(), ExpiresAt: snapshot.ExpiresAt(),
	}, ConsumedAt: command.Claimed().ConsumedAt()}, State: terminal.State(), FailureClass: terminal.FailureClass(), TerminatedAt: terminal.TerminatedAt()})
	if err != nil {
		return err
	}
	outbox, err := json.Marshal(authFailureOutboxPayload{authClaimOutboxPayload: authClaimOutboxPayload{authTransactionOutboxPayload: authTransactionOutboxPayload{
		TransactionPublicID: snapshot.TransactionID().String(), ProviderPublicID: route.ProviderID().String(),
		ProviderGeneration: route.ProviderGeneration(), RecoveryEpoch: route.RecoveryEpoch(), ExpiresAt: snapshot.ExpiresAt(),
	}, ConsumedAt: command.Claimed().ConsumedAt()}, State: terminal.State(), FailureClass: terminal.FailureClass(), TerminatedAt: terminal.TerminatedAt()})
	if err != nil {
		return err
	}
	before, after := terminal.BeforeSemanticHash(), terminal.AfterSemanticHash()
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: head.previousHash, EventID: ids.AuditEventID(), ChangeID: ids.ChangeID(), AggregateKind: "auth_transaction", AggregateID: publicid.ID(snapshot.TransactionID()), AggregateVersion: 3,
		Action: "auth_transaction.terminated", Permission: "identity.authenticate", CorrelationID: publicid.ID(snapshot.TransactionID()), BeforeSemanticHash: before, AfterSemanticHash: after,
		AuditPayloadHash: sha256.Sum256(payload), OutboxEventClass: "identity.auth_transaction.terminated", OutboxPayloadHash: sha256.Sum256(outbox),
	})
	if err != nil {
		return err
	}
	var appended int64
	if err := unit.database.QueryRow(ctx, appendAuthFailureEvidenceSQL,
		head.streamInternalID,
		ids.AuditEventID().String(),
		ids.OutboxEventID().String(),
		head.nextSequence,
		head.previousHash[:],
		eventHash[:],
		snapshot.TransactionID().String(),
		terminal.Version(),
		snapshot.TransactionID().String(),
		before[:],
		after[:],
		payload,
		outbox,
	).Scan(&appended); err != nil {
		return err
	}
	if appended != head.nextSequence {
		return ErrAuthTransactionEvidence
	}
	return nil
}
