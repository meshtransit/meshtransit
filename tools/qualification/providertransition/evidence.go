package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/audit"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

const transitionEventClass = "identity.provider_client.scopes_changed"

type transitionSemanticSnapshot struct {
	ProviderID         string   `json:"provider_id"`
	ClientID           string   `json:"client_id"`
	ProviderGeneration int64    `json:"provider_generation"`
	ProviderVersion    int64    `json:"provider_version"`
	GenerationVersion  int64    `json:"generation_version"`
	ClientVersion      int64    `json:"client_version"`
	AllowedScopes      []string `json:"allowed_scopes"`
}

type transitionAuditPayload struct {
	AuditReason        string   `json:"audit_reason"`
	ProviderID         string   `json:"provider_id"`
	ClientID           string   `json:"client_id"`
	GenerationID       string   `json:"generation_id"`
	PreviousGeneration int64    `json:"previous_generation"`
	CurrentGeneration  int64    `json:"current_generation"`
	PreviousScopes     []string `json:"previous_scopes"`
	CurrentScopes      []string `json:"current_scopes"`
}

type transitionOutboxPayload struct {
	ProviderID         string   `json:"provider_id"`
	ClientID           string   `json:"client_id"`
	GenerationID       string   `json:"generation_id"`
	ProviderGeneration int64    `json:"provider_generation"`
	AllowedScopes      []string `json:"allowed_scopes"`
}

type transitionAuditHead struct {
	streamInternalID int64
	nextSequence     int64
	previousHash     [sha256.Size]byte
}

func appendTransitionEvidence(
	ctx context.Context,
	transaction pgx.Tx,
	spec transitionSpec,
	state transitionState,
	result transitionResult,
	ids transitionIDs,
) error {
	head, err := lockTransitionAuditHead(ctx, transaction, state.deploymentInternalID)
	if err != nil {
		return err
	}
	before := transitionSemanticSnapshot{
		ProviderID: spec.providerID.String(), ClientID: spec.clientID.String(),
		ProviderGeneration: spec.expectedGeneration,
		ProviderVersion:    spec.expectedProviderVersion,
		GenerationVersion:  spec.expectedGenerationVersion,
		ClientVersion:      spec.expectedClientVersion,
		AllowedScopes:      previousScopes,
	}
	after := transitionSemanticSnapshot{
		ProviderID: spec.providerID.String(), ClientID: spec.clientID.String(),
		ProviderGeneration: result.providerGeneration,
		ProviderVersion:    result.providerVersion,
		GenerationVersion:  1,
		ClientVersion:      result.clientVersion,
		AllowedScopes:      currentScopes,
	}
	beforeHash, err := hashTransitionSnapshot(before)
	if err != nil {
		return err
	}
	afterHash, err := hashTransitionSnapshot(after)
	if err != nil {
		return err
	}
	auditPayload, err := json.Marshal(transitionAuditPayload{
		AuditReason: spec.auditReason,
		ProviderID:  spec.providerID.String(), ClientID: spec.clientID.String(),
		GenerationID:       ids.generation.String(),
		PreviousGeneration: spec.expectedGeneration,
		CurrentGeneration:  result.providerGeneration,
		PreviousScopes:     previousScopes, CurrentScopes: currentScopes,
	})
	if err != nil {
		return fmt.Errorf("encode provider transition audit payload: %w", err)
	}
	outboxPayload, err := json.Marshal(transitionOutboxPayload{
		ProviderID: spec.providerID.String(), ClientID: spec.clientID.String(),
		GenerationID:       ids.generation.String(),
		ProviderGeneration: result.providerGeneration,
		AllowedScopes:      currentScopes,
	})
	if err != nil {
		return fmt.Errorf("encode provider transition outbox payload: %w", err)
	}
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash:       head.previousHash,
		EventID:            ids.auditEvent,
		ChangeID:           ids.change,
		AggregateKind:      "identity_provider",
		AggregateID:        publicid.ID(spec.providerID),
		AggregateVersion:   result.providerVersion,
		ActorPrincipalID:   publicid.ID(spec.actorPrincipalID),
		Action:             transitionEventClass,
		Permission:         "identity.provider.configure",
		CorrelationID:      ids.generation,
		BeforeSemanticHash: beforeHash,
		AfterSemanticHash:  afterHash,
		AuditPayloadHash:   sha256.Sum256(auditPayload),
		OutboxEventClass:   transitionEventClass,
		OutboxPayloadHash:  sha256.Sum256(outboxPayload),
	})
	if err != nil {
		return fmt.Errorf("hash provider transition evidence: %w", err)
	}
	var appendedSequence int64
	if err := transaction.QueryRow(
		ctx,
		appendTransitionEvidenceSQL,
		head.streamInternalID,
		ids.auditEvent.String(),
		ids.outboxEvent.String(),
		head.nextSequence,
		head.previousHash[:],
		eventHash[:],
		spec.providerID.String(),
		result.providerVersion,
		spec.actorPrincipalID.String(),
		ids.generation.String(),
		beforeHash[:],
		afterHash[:],
		auditPayload,
		outboxPayload,
	).Scan(&appendedSequence); err != nil {
		return fmt.Errorf("append provider transition evidence: %w", err)
	}
	if appendedSequence != head.nextSequence {
		return errors.New("provider transition audit sequence changed")
	}
	return nil
}

func lockTransitionAuditHead(
	ctx context.Context,
	transaction pgx.Tx,
	deploymentInternalID int64,
) (transitionAuditHead, error) {
	var head transitionAuditHead
	var previousHash []byte
	if err := transaction.QueryRow(
		ctx,
		lockDeploymentAuditStreamSQL,
		deploymentInternalID,
	).Scan(&head.streamInternalID, &head.nextSequence, &previousHash); err != nil {
		return transitionAuditHead{}, fmt.Errorf("lock deployment audit stream: %w", err)
	}
	if head.streamInternalID <= 0 || head.nextSequence <= 0 || len(previousHash) != sha256.Size {
		return transitionAuditHead{}, errors.New("invalid deployment audit stream")
	}
	copy(head.previousHash[:], previousHash)
	return head, nil
}

func hashTransitionSnapshot(snapshot transitionSemanticSnapshot) ([sha256.Size]byte, error) {
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("encode provider transition snapshot: %w", err)
	}
	return sha256.Sum256(encoded), nil
}
