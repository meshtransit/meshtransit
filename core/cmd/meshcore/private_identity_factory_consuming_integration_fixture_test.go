//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/identity/oidcauth"
	"meshtransit.net/core/internal/domain/publicid"
)

type privateFactoryProofFingerprint struct {
	algorithm, keyID string
	ciphertextHash   [32]byte
}

func (storage *privateFactoryIntegrationStorage) privateFactoryProof(
	t *testing.T,
	transactionID string,
) privateFactoryProofFingerprint {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var fingerprint privateFactoryProofFingerprint
	var ciphertext []byte
	if storage.admin.QueryRow(ctx, `SELECT pkce_verifier_encryption_algorithm,pkce_verifier_encryption_key_id,
pkce_verifier_ciphertext FROM mesh.auth_transaction WHERE public_id=$1::UUID`, transactionID).Scan(
		&fingerprint.algorithm, &fingerprint.keyID, &ciphertext,
	) != nil || len(ciphertext) == 0 || fingerprint.algorithm == "" || fingerprint.keyID == "" {
		t.Fatal("read original encrypted proof fingerprint")
	}
	fingerprint.ciphertextHash = sha256.Sum256(ciphertext)
	clear(ciphertext)
	return fingerprint
}

func (storage *privateFactoryIntegrationStorage) originalConsumingExpiry(
	t *testing.T,
	pending oidcauth.ExpirySnapshot,
	route oidcauth.Route,
) oidcauth.ExpirySnapshot {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	params := pending.Params()
	params.State, params.Version = "consuming", 2
	hash := pending.SemanticHash()
	if storage.admin.QueryRow(ctx, `SELECT consumed_at FROM mesh.auth_transaction
WHERE public_id=$1::UUID AND state='consuming' AND version=2 AND created_at=$2 AND expires_at=$3
AND binding_semantic_hash=$4 AND failure_class IS NULL AND principal_id IS NULL
AND consumed_result_kind IS NULL AND consumed_result_public_id IS NULL
AND pkce_verifier_encryption_algorithm IS NOT NULL AND pkce_verifier_encryption_key_id IS NOT NULL
AND pkce_verifier_ciphertext IS NOT NULL`, pending.TransactionID().String(), pending.CreatedAt(),
		pending.ExpiresAt(), hash[:]).Scan(&params.ConsumedAt) != nil {
		t.Fatal("checked provider barrier lacked original confirmed consuming claim")
	}
	snapshot, err := oidcauth.NewExpirySnapshot(params)
	if err != nil {
		t.Fatal("validate original consuming timestamp without reconstruction")
	}
	// NewExpired supplies the published claim-lifecycle hash without pretending
	// expiry has happened. Only the durable worker oracle below proves expiry.
	original, originalErr := oidcauth.NewExpired(pending, pending.ExpiresAt())
	claimed, claimedErr := oidcauth.NewExpired(snapshot, snapshot.ExpiresAt())
	if originalErr != nil || claimedErr != nil {
		t.Fatal("construct canonical no-grant lifecycle hash reference")
	}
	evidence := storage.consumingLifecycleEvidence(t, snapshot, 2)
	wantAudit := privateFactoryClaimAuditPayload{
		ProviderID: route.ProviderID().String(), ClientID: route.ClientID().String(),
		ProviderGeneration: route.ProviderGeneration(), RecoveryEpoch: route.RecoveryEpoch(),
		RedirectID: route.RedirectID(), ReturnRouteID: route.ReturnRouteID(),
		ExpiresAt: snapshot.ExpiresAt(), ConsumedAt: snapshot.ConsumedAt(),
	}
	wantOutbox := privateFactoryClaimOutboxPayload{
		TransactionID: snapshot.TransactionID().String(), ProviderID: route.ProviderID().String(),
		ProviderGeneration: route.ProviderGeneration(), RecoveryEpoch: route.RecoveryEpoch(),
		ExpiresAt: snapshot.ExpiresAt(), ConsumedAt: snapshot.ConsumedAt(),
	}
	var decodedAudit privateFactoryClaimAuditPayload
	var decodedOutbox privateFactoryClaimOutboxPayload
	if json.Unmarshal(evidence.payload, &decodedAudit) != nil || json.Unmarshal(evidence.outboxPayload, &decodedOutbox) != nil {
		t.Fatal("decode closed claim payloads")
	}
	canonicalAudit := privateFactoryCanonicalPayload(t, decodedAudit, wantAudit)
	canonicalOutbox := privateFactoryCanonicalPayload(t, decodedOutbox, wantOutbox)
	evidence.assertHash(t, audit.EventHashMaterial{
		AggregateKind: "auth_transaction", AggregateID: publicid.ID(snapshot.TransactionID()), AggregateVersion: 2,
		Action: "auth_transaction.claimed", Permission: "identity.authenticate", CorrelationID: publicid.ID(snapshot.TransactionID()),
		BeforeSemanticHash: original.BeforeSemanticHash(), AfterSemanticHash: claimed.BeforeSemanticHash(),
		AuditPayloadHash: sha256.Sum256(canonicalAudit), OutboxEventClass: "identity.auth_transaction.claimed",
		OutboxPayloadHash: sha256.Sum256(canonicalOutbox),
	})
	return snapshot
}

// A separate strict consuming2 -> expired3 oracle, not a widened pending2 or
// quarantine assertion. All reads belong to the test owner, with no held unit.
func (storage *privateFactoryIntegrationStorage) assertNaturalConsumingExpiry(
	t *testing.T,
	snapshot oidcauth.ExpirySnapshot,
) {
	t.Helper()
	evidence := storage.consumingLifecycleEvidence(t, snapshot, 3)
	terminal, err := oidcauth.NewExpired(snapshot, evidence.at)
	if err != nil || terminal.Version() != 3 || !terminal.ConsumedAt().Equal(snapshot.ConsumedAt()) {
		t.Fatal("natural expiry changed original consuming time or exclusive deadline")
	}
	want := privateFactoryExpiryPayload{
		TransactionID: snapshot.TransactionID().String(), PreviousState: "consuming", PreviousVersion: 2,
		ExpiresAt: snapshot.ExpiresAt(), ConsumedAt: snapshot.ConsumedAt(), ExpiredAt: evidence.at,
	}
	var decoded privateFactoryExpiryPayload
	if json.Unmarshal(evidence.payload, &decoded) != nil || !bytes.Equal(evidence.payload, evidence.outboxPayload) {
		t.Fatal("decode exact matching no-grant expiry payloads")
	}
	canonical := privateFactoryCanonicalPayload(t, decoded, want)
	evidence.assertHash(t, audit.EventHashMaterial{
		AggregateKind: "auth_transaction", AggregateID: publicid.ID(snapshot.TransactionID()), AggregateVersion: 3,
		Action: "auth_transaction.expired", Permission: "system.lifecycle", CorrelationID: publicid.ID(snapshot.TransactionID()),
		BeforeSemanticHash: terminal.BeforeSemanticHash(), AfterSemanticHash: terminal.AfterSemanticHash(),
		AuditPayloadHash: sha256.Sum256(canonical), OutboxEventClass: "identity.auth_transaction.expired",
		OutboxPayloadHash: sha256.Sum256(canonical),
	})
}

type privateFactoryLifecycleEvidence struct {
	at                                 time.Time
	before, after, eventHash, previous []byte
	payload, outboxPayload             []byte
	eventID, changeID                  publicid.ID
}

func (storage *privateFactoryIntegrationStorage) consumingLifecycleEvidence(
	t *testing.T,
	snapshot oidcauth.ExpirySnapshot,
	version int64,
) privateFactoryLifecycleEvidence {
	t.Helper()
	state, action, permission := "consuming", "auth_transaction.claimed", "identity.authenticate"
	if version == 3 {
		state, action, permission = "expired", "auth_transaction.expired", "system.lifecycle"
	} else if version != 2 {
		t.Fatal("refuse unsupported consuming lifecycle evidence")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var evidence privateFactoryLifecycleEvidence
	var eventText, changeText string
	var safe bool
	hash := snapshot.SemanticHash()
	if storage.admin.QueryRow(ctx, `SELECT auth.updated_at,e.before_semantic_hash,e.after_semantic_hash,
i.event_hash,i.previous_event_hash,e.payload,o.payload,i.public_id::TEXT,i.change_public_id::TEXT,
auth.state=$6 AND auth.version=$2 AND auth.created_at=$3 AND auth.expires_at=$4 AND auth.binding_semantic_hash=$5
AND auth.consumed_at=$7 AND auth.consumed_at>=auth.created_at AND auth.consumed_at<auth.expires_at
AND auth.principal_id IS NULL AND auth.operation_kind='login' AND auth.flow_kind='browser_authorization_code'
AND auth.consumed_result_kind IS NULL AND auth.consumed_result_public_id IS NULL
AND auth.deployment_recovery_epoch=1 AND d.installation_public_id=$8::UUID
AND d.version=1 AND d.authority_generation=1 AND d.recovery_epoch=1 AND d.recovery_state='verified'
AND (($2=2 AND auth.failure_class IS NULL AND auth.updated_at=auth.consumed_at
AND auth.pkce_verifier_encryption_algorithm IS NOT NULL AND auth.pkce_verifier_encryption_key_id IS NOT NULL
AND auth.pkce_verifier_ciphertext IS NOT NULL)
OR ($2=3 AND auth.failure_class='deadline_expired' AND auth.updated_at>=auth.expires_at
AND auth.pkce_verifier_encryption_algorithm IS NULL AND auth.pkce_verifier_encryption_key_id IS NULL
AND auth.pkce_verifier_ciphertext IS NULL))
AND m.before_version=$2-1 AND m.after_version=$2 AND m.operation='update'
AND e.target_kind='auth_transaction' AND e.target_public_id=auth.public_id
AND e.action=$9 AND e.permission=$10 AND e.actor_principal_public_id IS NULL
AND e.network_id IS NULL AND e.correlation_public_id=auth.public_id
AND o.aggregate_kind='auth_transaction' AND o.aggregate_public_id=auth.public_id
AND o.aggregate_version=$2 AND o.event_class=$11 AND o.network_revision IS NULL
AND s.id=1 AND s.deployment_id=auth.deployment_id AND s.scope_kind='deployment'
AND i.previous_event_hash=(SELECT prior.event_hash FROM mesh_audit.audit_event_identity prior
WHERE prior.stream_id=i.stream_id AND prior.stream_sequence=i.stream_sequence-1)
AND ($2=2 OR EXISTS (SELECT 1 FROM mesh_audit.audit_event_identity prior
JOIN mesh_audit.audit_event pe ON pe.event_identity_id=prior.id AND pe.occurred_at=prior.occurred_at
WHERE prior.stream_id=i.stream_id AND prior.stream_sequence=i.stream_sequence-1
AND pe.target_public_id=auth.public_id AND pe.action='auth_transaction.claimed'))
FROM mesh.auth_transaction auth JOIN mesh.deployment d ON d.id=auth.deployment_id
JOIN mesh_audit.authority_mutation m ON m.row_public_id=auth.public_id AND m.aggregate_kind='auth_transaction' AND m.after_version=$2
JOIN mesh_audit.audit_event_identity i ON i.change_public_id=m.change_public_id AND i.transaction_id=m.transaction_id
JOIN mesh_audit.audit_stream s ON s.id=i.stream_id
JOIN mesh_audit.audit_event e ON e.event_identity_id=i.id AND e.occurred_at=i.occurred_at
JOIN mesh_ops.outbox_event o ON o.change_public_id=m.change_public_id AND o.transaction_id=m.transaction_id
WHERE auth.public_id=$1::UUID`, snapshot.TransactionID().String(), version, snapshot.CreatedAt(), snapshot.ExpiresAt(),
		hash[:], state, snapshot.ConsumedAt(), snapshot.DeploymentID().String(), action, permission, "identity."+action).Scan(
		&evidence.at, &evidence.before, &evidence.after, &evidence.eventHash, &evidence.previous,
		&evidence.payload, &evidence.outboxPayload, &eventText, &changeText, &safe,
	) != nil || !safe || len(evidence.previous) != sha256.Size || len(evidence.eventHash) != sha256.Size {
		t.Fatal("consuming lifecycle lost exact atomic no-grant metadata or chained evidence")
	}
	var eventErr, changeErr error
	evidence.eventID, eventErr = publicid.Parse(eventText)
	evidence.changeID, changeErr = publicid.Parse(changeText)
	if eventErr != nil || changeErr != nil {
		t.Fatal("decode exact fresh consuming evidence identities")
	}
	return evidence
}

func (evidence privateFactoryLifecycleEvidence) assertHash(t *testing.T, material audit.EventHashMaterial) {
	t.Helper()
	copy(material.PreviousHash[:], evidence.previous)
	material.EventID, material.ChangeID = evidence.eventID, evidence.changeID
	want, err := audit.HashEvent(material)
	if err != nil || !bytes.Equal(evidence.eventHash, want[:]) ||
		!bytes.Equal(evidence.before, material.BeforeSemanticHash[:]) || !bytes.Equal(evidence.after, material.AfterSemanticHash[:]) {
		t.Fatal("consuming lifecycle canonical hashes changed")
	}
}

func privateFactoryCanonicalPayload(t *testing.T, decoded, expected any) []byte {
	t.Helper()
	got, gotErr := json.Marshal(decoded)
	want, wantErr := json.Marshal(expected)
	if gotErr != nil || wantErr != nil || !bytes.Equal(got, want) {
		t.Fatal("closed consuming lifecycle payload differs from original metadata")
	}
	return want
}

// Pre-issue lifecycle payloads name no Workspace: none is chosen before issue.
type privateFactoryClaimAuditPayload struct {
	ProviderID         string    `json:"provider_public_id"`
	ClientID           string    `json:"client_public_id"`
	ProviderGeneration int64     `json:"provider_generation"`
	RecoveryEpoch      int64     `json:"deployment_recovery_epoch"`
	RedirectID         string    `json:"redirect_id"`
	ReturnRouteID      string    `json:"return_route_id"`
	ExpiresAt          time.Time `json:"expires_at"`
	ConsumedAt         time.Time `json:"consumed_at"`
}

type privateFactoryClaimOutboxPayload struct {
	TransactionID      string    `json:"transaction_public_id"`
	ProviderID         string    `json:"provider_public_id"`
	ProviderGeneration int64     `json:"provider_generation"`
	RecoveryEpoch      int64     `json:"deployment_recovery_epoch"`
	ExpiresAt          time.Time `json:"expires_at"`
	ConsumedAt         time.Time `json:"consumed_at"`
}
