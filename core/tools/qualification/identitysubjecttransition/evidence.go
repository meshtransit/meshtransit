package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/publicid"
)

const applyEventClass = "identity.subject_transition.applied"

type applySemanticSnapshot struct {
	MigrationID           string `json:"migration_id"`
	ManifestSHA256        string `json:"manifest_sha256"`
	SourceProviderID      string `json:"source_provider_id"`
	TargetProviderID      string `json:"target_provider_id"`
	SourceProviderState   string `json:"source_provider_state"`
	SourceProviderVersion int64  `json:"source_provider_version"`
	SubjectCount          int64  `json:"subject_count"`
	SessionCount          int64  `json:"session_count"`
	AuthTransactionCount  int64  `json:"auth_transaction_count"`
}

type applyAuditPayload struct {
	SchemaVersion          string `json:"schema_version"`
	MigrationID            string `json:"migration_id"`
	ManifestSHA256         string `json:"manifest_sha256"`
	AuditReason            string `json:"audit_reason"`
	SourceProviderID       string `json:"source_provider_id"`
	TargetProviderID       string `json:"target_provider_id"`
	MigratedSubjects       int64  `json:"migrated_subjects"`
	RevokedSessions        int64  `json:"revoked_sessions"`
	FailedAuthTransactions int64  `json:"failed_auth_transactions"`
}

type applyOutboxPayload struct {
	SchemaVersion          string `json:"schema_version"`
	MigrationID            string `json:"migration_id"`
	ManifestSHA256         string `json:"manifest_sha256"`
	SourceProviderID       string `json:"source_provider_id"`
	TargetProviderID       string `json:"target_provider_id"`
	MigratedSubjects       int64  `json:"migrated_subjects"`
	RevokedSessions        int64  `json:"revoked_sessions"`
	FailedAuthTransactions int64  `json:"failed_auth_transactions"`
}

type applyAuditHead struct {
	streamInternalID int64
	nextSequence     int64
	previousHash     [sha256.Size]byte
}

func appendApplyEvidence(
	ctx context.Context,
	transaction pgx.Tx,
	spec planSpec,
	snapshot validatedSnapshot,
	result applyResult,
) error {
	head, err := lockApplyAuditHead(
		ctx,
		transaction,
		snapshot.authority.deploymentInternalID,
	)
	if err != nil {
		return err
	}
	before := applySemanticSnapshot{
		MigrationID: spec.migrationID.String(), ManifestSHA256: spec.manifestSHA256,
		SourceProviderID:      spec.sourceProviderID.String(),
		TargetProviderID:      spec.targetProviderID.String(),
		SourceProviderState:   "active",
		SourceProviderVersion: spec.manifest.Source.ExpectedProviderVersion,
		SubjectCount:          int64(len(snapshot.subjects)),
		SessionCount:          snapshot.activeSessions,
		AuthTransactionCount:  snapshot.openAuthTransactions,
	}
	after := before
	after.SourceProviderState = "suspended"
	after.SourceProviderVersion = result.sourceProviderVersion
	beforeHash, err := hashApplySnapshot(before)
	if err != nil {
		return err
	}
	afterHash, err := hashApplySnapshot(after)
	if err != nil {
		return err
	}
	auditPayload, err := json.Marshal(applyAuditPayload{
		SchemaVersion: manifestSchemaVersion,
		MigrationID:   spec.migrationID.String(), ManifestSHA256: spec.manifestSHA256,
		AuditReason:            spec.manifest.AuditReason,
		SourceProviderID:       spec.sourceProviderID.String(),
		TargetProviderID:       spec.targetProviderID.String(),
		MigratedSubjects:       result.migratedSubjects,
		RevokedSessions:        result.revokedSessions,
		FailedAuthTransactions: result.failedAuthTransactions,
	})
	if err != nil {
		return fmt.Errorf("encode identity subject transition audit payload: %w", err)
	}
	outboxPayload, err := json.Marshal(applyOutboxPayload{
		SchemaVersion: manifestSchemaVersion,
		MigrationID:   spec.migrationID.String(), ManifestSHA256: spec.manifestSHA256,
		SourceProviderID:       spec.sourceProviderID.String(),
		TargetProviderID:       spec.targetProviderID.String(),
		MigratedSubjects:       result.migratedSubjects,
		RevokedSessions:        result.revokedSessions,
		FailedAuthTransactions: result.failedAuthTransactions,
	})
	if err != nil {
		return fmt.Errorf("encode identity subject transition outbox payload: %w", err)
	}
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash:       head.previousHash,
		EventID:            spec.auditEventID,
		ChangeID:           spec.migrationID,
		AggregateKind:      "identity_provider",
		AggregateID:        publicid.ID(spec.sourceProviderID),
		AggregateVersion:   result.sourceProviderVersion,
		ActorPrincipalID:   publicid.ID(spec.actorPrincipalID),
		Action:             applyEventClass,
		Permission:         "identity_provider.manage",
		CorrelationID:      spec.migrationID,
		BeforeSemanticHash: beforeHash,
		AfterSemanticHash:  afterHash,
		AuditPayloadHash:   sha256.Sum256(auditPayload),
		OutboxEventClass:   applyEventClass,
		OutboxPayloadHash:  sha256.Sum256(outboxPayload),
	})
	if err != nil {
		return fmt.Errorf("hash identity subject transition evidence: %w", err)
	}
	var appendedSequence int64
	if err := transaction.QueryRow(
		ctx,
		appendApplyEvidenceSQL,
		head.streamInternalID,
		spec.auditEventID.String(),
		spec.outboxEventID.String(),
		head.nextSequence,
		head.previousHash[:],
		eventHash[:],
		spec.sourceProviderID.String(),
		result.sourceProviderVersion,
		spec.actorPrincipalID.String(),
		spec.migrationID.String(),
		beforeHash[:],
		afterHash[:],
		auditPayload,
		outboxPayload,
	).Scan(&appendedSequence); err != nil {
		return fmt.Errorf("append identity subject transition evidence: %w", err)
	}
	if appendedSequence != head.nextSequence {
		return errors.New("identity subject transition audit sequence changed")
	}
	return nil
}

func lockApplyAuditHead(
	ctx context.Context,
	transaction pgx.Tx,
	deploymentInternalID int64,
) (applyAuditHead, error) {
	var head applyAuditHead
	var previousHash []byte
	if err := transaction.QueryRow(
		ctx,
		lockDeploymentAuditStreamSQL,
		deploymentInternalID,
	).Scan(&head.streamInternalID, &head.nextSequence, &previousHash); err != nil {
		return applyAuditHead{}, fmt.Errorf("lock identity transition audit stream: %w", err)
	}
	if head.streamInternalID <= 0 || head.nextSequence <= 0 ||
		len(previousHash) != sha256.Size {
		return applyAuditHead{}, errors.New("invalid identity transition audit stream")
	}
	copy(head.previousHash[:], previousHash)
	return head, nil
}

func hashApplySnapshot(snapshot applySemanticSnapshot) ([sha256.Size]byte, error) {
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("encode identity transition snapshot: %w", err)
	}
	return sha256.Sum256(encoded), nil
}
