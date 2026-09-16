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

// Safe lifecycle metadata only: no bearer/SID/subject/digests/ACR/AMR/proof.
type authIssuePayload struct {
	TransactionID      string    `json:"transaction_public_id"`
	SessionID          string    `json:"session_public_id"`
	WorkspaceID        string    `json:"workspace_public_id"`
	ProviderID         string    `json:"provider_public_id"`
	ClientID           string    `json:"client_public_id"`
	PrincipalID        string    `json:"principal_public_id"`
	ProviderGeneration int64     `json:"provider_generation"`
	RecoveryEpoch      int64     `json:"deployment_recovery_epoch"`
	IssuedAt           time.Time `json:"issued_at"`
	IdleExpiresAt      time.Time `json:"idle_expires_at"`
	AbsoluteExpiresAt  time.Time `json:"absolute_expires_at"`
}
type authIssueEvent struct {
	auditID, outboxID, aggregateID publicid.ID
	aggregate, action, class       string
	version                        int64
	before, after                  [32]byte
}

func (unit *authIssueTransaction) appendIssueEvidence(
	ctx context.Context, command oidcauth.IssueCommand, issued oidcauth.Issued, head authTransactionAuditHead,
) error {
	route, ids := command.Lookup().Snapshot().Route(), command.IDs()
	payload, err := json.Marshal(authIssuePayload{
		TransactionID: command.Lookup().Claimed().TransactionID().String(), SessionID: ids.SessionID().String(),
		WorkspaceID: route.WorkspaceID().String(), ProviderID: route.ProviderID().String(),
		ClientID: route.ClientID().String(), PrincipalID: issued.Session().PrincipalID().String(),
		ProviderGeneration: route.ProviderGeneration(), RecoveryEpoch: route.RecoveryEpoch(),
		IssuedAt: issued.IssuedAt(), IdleExpiresAt: issued.Session().IdleExpiresAt(),
		AbsoluteExpiresAt: issued.Session().AbsoluteExpiresAt(),
	})
	if err != nil {
		return err
	}
	events := [2]authIssueEvent{
		{
			auditID: ids.SessionAuditID(), outboxID: ids.SessionOutboxID(),
			aggregateID: publicid.ID(ids.SessionID()), aggregate: "account_session", version: 1,
			action: "account_session.created", class: "identity.account_session.created",
			after: issued.SessionSemanticHash(),
		},
		{
			auditID: ids.SuccessAuditID(), outboxID: ids.SuccessOutboxID(),
			aggregateID: publicid.ID(command.Lookup().Claimed().TransactionID()), aggregate: "auth_transaction", version: 3,
			action: "auth_transaction.succeeded", class: "identity.auth_transaction.succeeded",
			before: command.Lookup().Claimed().AfterSemanticHash(), after: issued.SuccessSemanticHash(),
		},
	}
	for _, event := range events {
		hash, err := audit.HashEvent(audit.EventHashMaterial{
			PreviousHash: head.previousHash, EventID: event.auditID, ChangeID: ids.ChangeID(),
			AggregateKind: event.aggregate, AggregateID: event.aggregateID, AggregateVersion: event.version,
			ActorPrincipalID: publicid.ID(issued.Session().PrincipalID()), Action: event.action,
			Permission: "identity.authenticate", CorrelationID: publicid.ID(command.Lookup().Claimed().TransactionID()),
			BeforeSemanticHash: event.before, AfterSemanticHash: event.after, AuditPayloadHash: sha256.Sum256(payload),
			OutboxEventClass: event.class, OutboxPayloadHash: sha256.Sum256(payload),
		})
		if err != nil {
			return err
		}
		var sequence int64
		if err := unit.database.QueryRow(
			ctx, appendAuthIssueEvidenceSQL,
			head.streamInternalID, event.auditID.String(), event.outboxID.String(), head.nextSequence,
			head.previousHash[:], hash[:],
			event.aggregate, event.aggregateID.String(), event.version, issued.Session().PrincipalID().String(), event.action,
			command.Lookup().Claimed().TransactionID().String(), event.before[:], event.after[:], payload, event.class, payload,
		).Scan(&sequence); err != nil {
			return err
		}
		if sequence != head.nextSequence {
			return ErrAuthTransactionEvidence
		}
		head.nextSequence++
		head.previousHash = hash
	}
	return nil
}
