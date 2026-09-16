//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/audit"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

type integrationIssueCollisionMaterial struct{ duplicate publicid.ID }

func (material integrationIssueCollisionMaterial) NewIssueMaterial(
	ctx context.Context, dep deployment.ID, epoch int64,
) (oidcauth.IssueIDs, accountsession.Token, error) {
	ids, token, err := (oidcauth.SystemIssueMaterial{}).NewIssueMaterial(ctx, dep, epoch)
	if err != nil {
		return oidcauth.IssueIDs{}, accountsession.Token{}, err
	}
	colliding, err := oidcauth.NewIssueIDs(oidcauth.IssueIDParams{
		SessionID: ids.SessionID(), ChangeID: ids.ChangeID(), SessionAuditID: ids.SessionAuditID(),
		SessionOutboxID: ids.SessionOutboxID(), SuccessAuditID: ids.SuccessAuditID(),
		SuccessOutboxID: material.duplicate,
	})
	return colliding, token, err
}

func setIssueMembershipExpiry(ctx context.Context, t *testing.T, admin *pgx.Conn, suffix string, expiry time.Time) {
	t.Helper()
	var version int64
	if err := admin.QueryRow(ctx, `SELECT version FROM mesh.workspace_membership
WHERE public_id='01890f00-0000-7000-8000-000000000fa1'`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	commitAuditedAuthorityFixture(ctx, t, admin, authorityEvidenceFixture{
		changePublicID: "01890f01-0000-7000-8000-000000000" + suffix,
		eventPublicID:  "01890f02-0000-7000-8000-000000000" + suffix,
		outboxPublicID: "01890f03-0000-7000-8000-000000000" + suffix,
		streamID:       1, aggregateKind: "workspace_membership",
		aggregatePublicID: "01890f00-0000-7000-8000-000000000fa1", aggregateVersion: version + 1,
		actorPrincipalPublicID: "01890f00-0000-7000-8000-000000000011",
		action:                 "workspace_membership.updated", permission: "system.bootstrap",
		outboxEventClass: "workspace_membership.updated",
	}, func(tx pgx.Tx) {
		var value any
		if !expiry.IsZero() {
			value = expiry
		}
		if _, err := tx.Exec(ctx, `UPDATE mesh.workspace_membership SET expires_at=$1,
version=version+1,authority_generation=authority_generation+1,updated_at=GREATEST(updated_at,clock_timestamp())
WHERE public_id='01890f00-0000-7000-8000-000000000fa1'`, value); err != nil {
			t.Fatal(err)
		}
	})
}

func assertIssueEvidenceChain(ctx context.Context, t *testing.T, admin *pgx.Conn, command oidcauth.IssueCommand) {
	t.Helper()
	var at, idle, absolute time.Time
	if err := admin.QueryRow(ctx, `SELECT created_at,idle_expires_at,absolute_expires_at
FROM mesh.account_session WHERE public_id=$1::UUID`, command.IDs().SessionID().String()).Scan(
		&at, &idle, &absolute,
	); err != nil {
		t.Fatal(err)
	}
	at, idle, absolute = at.UTC(), idle.UTC(), absolute.UTC()
	issued, err := oidcauth.NewIssued(oidcauth.IssuedParams{
		Command: command, SessionID: command.IDs().SessionID(), Version: 1,
		IssuedAt: at, IdleExpiresAt: idle, AbsoluteExpiresAt: absolute,
	})
	if err != nil {
		t.Fatal(err)
	}
	ids := command.IDs()
	var lastSequence int64
	var lastHash []byte
	for index, event := range []struct {
		auditID, outboxID, targetID publicid.ID
		kind, action, class         string
		version                     int64
		before, after               [32]byte
	}{
		{ids.SessionAuditID(), ids.SessionOutboxID(), publicid.ID(ids.SessionID()),
			"account_session", "account_session.created", "identity.account_session.created",
			1, [32]byte{}, issued.SessionSemanticHash()},
		{ids.SuccessAuditID(), ids.SuccessOutboxID(), publicid.ID(command.Lookup().Claimed().TransactionID()),
			"auth_transaction", "auth_transaction.succeeded", "identity.auth_transaction.succeeded",
			3, command.Lookup().Claimed().AfterSemanticHash(), issued.SuccessSemanticHash()},
	} {
		var sequence, version int64
		var previous, hash, before, after, auditPayload, outboxPayload []byte
		var kind, target, action, permission, class string
		if err := admin.QueryRow(ctx, `SELECT i.stream_sequence,i.previous_event_hash,i.event_hash,
e.target_kind,e.target_public_id::TEXT,e.action,e.permission,e.before_semantic_hash,e.after_semantic_hash,e.payload,
o.aggregate_version,o.event_class,o.payload
FROM mesh_audit.audit_event_identity i
JOIN mesh_audit.audit_event e ON e.event_identity_id=i.id AND e.occurred_at=i.occurred_at
JOIN mesh_ops.outbox_event o ON o.public_id=$2::UUID AND o.change_public_id=i.change_public_id
WHERE i.public_id=$1::UUID AND i.change_public_id=$3::UUID`,
			event.auditID.String(), event.outboxID.String(), ids.ChangeID().String(),
		).Scan(&sequence, &previous, &hash, &kind, &target, &action, &permission, &before, &after,
			&auditPayload, &version, &class, &outboxPayload); err != nil {
			t.Fatal(err)
		}
		if kind != event.kind || target != event.targetID.String() || action != event.action ||
			permission != "identity.authenticate" || version != event.version || class != event.class ||
			!bytes.Equal(before, event.before[:]) || !bytes.Equal(after, event.after[:]) ||
			!bytes.Equal(auditPayload, outboxPayload) || len(previous) != 32 || len(hash) != 32 {
			t.Fatal("two-aggregate audit/outbox semantics changed")
		}
		if index == 1 && (sequence != lastSequence+1 || !bytes.Equal(previous, lastHash)) {
			t.Fatal("second event not chained directly to Session creation")
		}
		var payload map[string]json.RawMessage
		if err := json.Unmarshal(auditPayload, &payload); err != nil || len(payload) != 11 {
			t.Fatal("invalid safe lifecycle payload")
		}
		for _, key := range []string{
			"transaction_public_id", "session_public_id", "workspace_public_id", "provider_public_id",
			"client_public_id", "principal_public_id", "provider_generation", "deployment_recovery_epoch",
			"issued_at", "idle_expires_at", "absolute_expires_at",
		} {
			if _, ok := payload[key]; !ok {
				t.Fatal("payload changed or secret field added")
			}
		}
		var previousHash [32]byte
		copy(previousHash[:], previous)
		// SQL stores canonical JSONB, whereas hashes bind the original encoded
		// payload. Re-encode in application field order before verifying hashes.
		canonicalPayload, err := json.Marshal(struct {
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
		}{command.Lookup().Claimed().TransactionID().String(), ids.SessionID().String(),
			command.Lookup().Snapshot().Route().WorkspaceID().String(), command.Lookup().Snapshot().Route().ProviderID().String(),
			command.Lookup().Snapshot().Route().ClientID().String(), command.Subject().PrincipalID().String(),
			command.Lookup().Snapshot().Route().ProviderGeneration(), command.Lookup().Snapshot().Route().RecoveryEpoch(), at, idle, absolute})
		if err != nil {
			t.Fatal(err)
		}
		expectedHash, err := audit.HashEvent(audit.EventHashMaterial{
			PreviousHash: previousHash, EventID: event.auditID, ChangeID: ids.ChangeID(),
			AggregateKind: event.kind, AggregateID: event.targetID, AggregateVersion: event.version,
			ActorPrincipalID: publicid.ID(command.Subject().PrincipalID()), Action: event.action,
			Permission: "identity.authenticate", CorrelationID: publicid.ID(command.Lookup().Claimed().TransactionID()),
			BeforeSemanticHash: event.before, AfterSemanticHash: event.after,
			AuditPayloadHash: sha256.Sum256(canonicalPayload), OutboxEventClass: event.class,
			OutboxPayloadHash: sha256.Sum256(canonicalPayload),
		})
		if err != nil || !bytes.Equal(hash, expectedHash[:]) {
			t.Fatal("durable audit hash not bound to exact issuance evidence")
		}
		lastSequence, lastHash = sequence, hash
	}
}
