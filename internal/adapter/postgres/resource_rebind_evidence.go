package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/meshtransit/meshtransit/internal/audit"
	"github.com/meshtransit/meshtransit/internal/publicid"
	authority "github.com/meshtransit/meshtransit/internal/resource/authority"
)

type resourceRebindAuditPayload struct {
	AuditReason                   string   `json:"audit_reason"`
	ExpectedResourceVersion       int64    `json:"expected_resource_version"`
	PreviousDeviceID              string   `json:"previous_device_id"`
	DeviceID                      string   `json:"device_id"`
	TargetGeneration              int64    `json:"target_generation"`
	ImpactHash                    string   `json:"impact_hash"`
	AffectedResourceGroupIDs      []string `json:"affected_resource_group_ids"`
	ApprovalStatus                string   `json:"approval_status"`
	AccountSessionID              string   `json:"account_session_id"`
	RoleBindingID                 string   `json:"role_binding_id"`
	RoleDefinitionID              string   `json:"role_definition_id"`
	ScopeAuthorityGeneration      int64    `json:"scope_authority_generation"`
	MembershipAuthorityGeneration int64    `json:"membership_authority_generation"`
	BindingAuthorityGeneration    int64    `json:"binding_authority_generation"`
	RoleAuthorityGeneration       int64    `json:"role_authority_generation"`
}

func (transaction *resourceRebindTransaction) appendRebindEvidence(
	ctx context.Context,
	change authority.RebindChange,
	result authority.RebindResult,
) error {
	command := change.Command()
	impact := change.Resolution().Impact()
	groupIDs := impact.AffectedGroupIDs()
	affectedGroups := make([]string, len(groupIDs))
	for index, groupID := range groupIDs {
		affectedGroups[index] = groupID.String()
	}
	impactHash := impact.Hash().Bytes()
	auditPayload, err := json.Marshal(resourceRebindAuditPayload{
		AuditReason: command.AuditReason().String(), ExpectedResourceVersion: command.ExpectedVersion(),
		PreviousDeviceID: impact.CurrentDeviceID().String(), DeviceID: result.DeviceID().String(),
		TargetGeneration: result.TargetGeneration(), ImpactHash: hex.EncodeToString(impactHash[:]),
		AffectedResourceGroupIDs: affectedGroups, ApprovalStatus: "not_required",
		AccountSessionID:              transaction.authorization.accountSessionID.String(),
		RoleBindingID:                 transaction.authorization.roleBindingID.String(),
		RoleDefinitionID:              transaction.authorization.roleDefinitionID.String(),
		ScopeAuthorityGeneration:      transaction.authorization.scopeAuthorityGeneration,
		MembershipAuthorityGeneration: transaction.authorization.membershipAuthorityGeneration,
		BindingAuthorityGeneration:    transaction.authorization.bindingAuthorityGeneration,
		RoleAuthorityGeneration:       transaction.authorization.roleAuthorityGeneration,
	})
	if err != nil {
		return fmt.Errorf("encode Resource rebind audit payload: %w", err)
	}
	outboxPayload, err := json.Marshal(resourceAuthorityOutboxPayload{
		NetworkRevision: result.NetworkRevision(), Subsystem: "inventory",
		SubsystemRevision: result.InventoryRevision(),
	})
	if err != nil {
		return fmt.Errorf("encode Resource rebind outbox payload: %w", err)
	}
	semanticHash := result.SemanticHash().Bytes()
	resultPayload, err := json.Marshal(resourceRebindResultPayload{
		DeviceID: result.DeviceID().String(), TargetGeneration: result.TargetGeneration(),
		InventoryRevision: result.InventoryRevision(), SemanticHash: hex.EncodeToString(semanticHash[:]),
		ImpactHash: hex.EncodeToString(impactHash[:]),
	})
	if err != nil {
		return fmt.Errorf("encode Resource rebind result payload: %w", err)
	}
	auditPayloadHash := sha256.Sum256(auditPayload)
	outboxPayloadHash := sha256.Sum256(outboxPayload)
	beforeHash := impact.CurrentSemanticHash().Bytes()
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: transaction.audit.previousHash,
		EventID:      change.MutationIDs().AuditEventID(), ChangeID: change.MutationIDs().ChangeID(),
		AggregateKind: "resource", AggregateID: publicid.ID(command.ResourceID()),
		AggregateVersion: result.Version(), NetworkRevision: result.NetworkRevision(),
		ActorPrincipalID: publicid.ID(command.AccountSession().PrincipalID()),
		Action:           "resource.rebound", Permission: "resource.manage",
		CorrelationID:      change.Resolution().IdempotencyRecordID(),
		BeforeSemanticHash: beforeHash, AfterSemanticHash: semanticHash,
		AuditPayloadHash: auditPayloadHash, OutboxEventClass: resourceAuthorityOutboxEventClass,
		OutboxPayloadHash: outboxPayloadHash,
	})
	if err != nil {
		return fmt.Errorf("hash Resource rebind audit event: %w", err)
	}
	var appendedSequence int64
	if err := transaction.database.QueryRow(
		ctx,
		appendResourceAuthorityEvidenceSQL,
		transaction.audit.streamInternalID,
		change.MutationIDs().AuditEventID().String(),
		change.MutationIDs().OutboxEventID().String(),
		transaction.audit.nextSequence,
		transaction.audit.previousHash[:],
		eventHash[:],
		"resource",
		command.ResourceID().String(),
		result.Version(),
		result.NetworkRevision(),
		command.AccountSession().PrincipalID().String(),
		"resource.rebound",
		"resource.manage",
		change.Resolution().IdempotencyRecordID().String(),
		beforeHash[:],
		semanticHash[:],
		auditPayload,
		resourceAuthorityOutboxEventClass,
		outboxPayload,
	).Scan(&appendedSequence); err != nil {
		return fmt.Errorf("append Resource rebind evidence: %w", err)
	}
	if appendedSequence != transaction.audit.nextSequence {
		return ErrResourceAuthorityEvidence
	}
	requestHash := change.Resolution().RequestHash().Bytes()
	proof := command.IdempotencyEvidence()
	digest := proof.Digest()
	var completedRecordID string
	if err := transaction.database.QueryRow(
		ctx,
		completeResourceAuthorityIdempotencySQL,
		change.Resolution().IdempotencyRecordID().String(),
		command.AccountSession().PrincipalID().String(),
		"resource.rebind",
		proof.DigestKeyID(),
		digest[:],
		requestHash[:],
		resourceRebindResultKind,
		command.ResourceID().String(),
		result.Version(),
		result.NetworkRevision(),
		resultPayload,
		change.MutationIDs().OutboxEventID().String(),
		change.OccurredAt(),
	).Scan(&completedRecordID); err != nil {
		return fmt.Errorf("complete Resource rebind idempotency evidence: %w", err)
	}
	if completedRecordID != change.Resolution().IdempotencyRecordID().String() {
		return ErrResourceAuthorityEvidence
	}
	return nil
}
