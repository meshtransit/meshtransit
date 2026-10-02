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

type resourceLifecycleAuditPayload struct {
	AuditReason                       string `json:"audit_reason"`
	ExpectedAggregateVersion          int64  `json:"expected_aggregate_version"`
	TargetState                       string `json:"target_state"`
	AccountSessionID                  string `json:"account_session_id"`
	RoleBindingID                     string `json:"role_binding_id,omitempty"`
	RoleDefinitionID                  string `json:"role_definition_id,omitempty"`
	ScopeAuthorityGeneration          int64  `json:"scope_authority_generation"`
	MembershipAuthorityGeneration     int64  `json:"membership_authority_generation"`
	BindingAuthorityGeneration        int64  `json:"binding_authority_generation"`
	RoleAuthorityGeneration           int64  `json:"role_authority_generation"`
	WorkspaceOwnerAuthorityGeneration int64  `json:"workspace_owner_authority_generation,omitempty"`
}

func (transaction *resourceLifecycleTransaction) appendLifecycleEvidence(
	ctx context.Context,
	change authority.LifecycleChange,
	result authority.LifecycleResult,
) error {
	command := change.Command()
	auditEvidence := resourceLifecycleAuditPayload{
		AuditReason:                       command.AuditReason().String(),
		ExpectedAggregateVersion:          command.ExpectedVersion(),
		TargetState:                       resourceLifecycleState(result.State()),
		AccountSessionID:                  transaction.authorization.accountSessionID.String(),
		RoleBindingID:                     authorizationIDString(transaction.authorization.roleBindingID),
		RoleDefinitionID:                  authorizationIDString(transaction.authorization.roleDefinitionID),
		ScopeAuthorityGeneration:          transaction.authorization.scopeAuthorityGeneration,
		MembershipAuthorityGeneration:     transaction.authorization.membershipAuthorityGeneration,
		BindingAuthorityGeneration:        transaction.authorization.bindingAuthorityGeneration,
		RoleAuthorityGeneration:           transaction.authorization.roleAuthorityGeneration,
		WorkspaceOwnerAuthorityGeneration: transaction.authorization.workspaceOwnerAuthorityGeneration,
	}
	aggregateKind := "resource"
	permission := "resource.manage"
	subsystem := "inventory"
	if command.Operation().IsGroup() {
		aggregateKind = "resource_group"
		permission = "resource_group.manage"
		subsystem = "group"
	}
	auditPayload, err := json.Marshal(auditEvidence)
	if err != nil {
		return fmt.Errorf("encode lifecycle audit payload: %w", err)
	}
	outboxPayload, err := json.Marshal(resourceAuthorityOutboxPayload{
		NetworkRevision:   result.NetworkRevision(),
		Subsystem:         subsystem,
		SubsystemRevision: result.SubsystemRevision(),
	})
	if err != nil {
		return fmt.Errorf("encode lifecycle outbox payload: %w", err)
	}
	semanticHash := result.SemanticHash().Bytes()
	resultPayload, err := json.Marshal(resourceLifecycleResultPayload{
		Operation:         resourceLifecycleOperation(command),
		State:             resourceLifecycleState(result.State()),
		SubsystemRevision: result.SubsystemRevision(),
		SemanticHash:      hex.EncodeToString(semanticHash[:]),
	})
	if err != nil {
		return fmt.Errorf("encode lifecycle result payload: %w", err)
	}
	auditPayloadHash := sha256.Sum256(auditPayload)
	outboxPayloadHash := sha256.Sum256(outboxPayload)
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash:       transaction.audit.previousHash,
		EventID:            change.MutationIDs().AuditEventID(),
		ChangeID:           change.MutationIDs().ChangeID(),
		AggregateKind:      aggregateKind,
		AggregateID:        command.AggregateID(),
		AggregateVersion:   result.Version(),
		NetworkRevision:    result.NetworkRevision(),
		ActorPrincipalID:   publicid.ID(command.AccountSession().PrincipalID()),
		Action:             resourceLifecycleAction(command),
		Permission:         permission,
		CorrelationID:      change.Resolution().IdempotencyRecordID(),
		BeforeSemanticHash: semanticHash,
		AfterSemanticHash:  semanticHash,
		AuditPayloadHash:   auditPayloadHash,
		OutboxEventClass:   resourceAuthorityOutboxEventClass,
		OutboxPayloadHash:  outboxPayloadHash,
	})
	if err != nil {
		return fmt.Errorf("hash lifecycle audit event: %w", err)
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
		aggregateKind,
		command.AggregateID().String(),
		result.Version(),
		result.NetworkRevision(),
		command.AccountSession().PrincipalID().String(),
		resourceLifecycleAction(command),
		permission,
		change.Resolution().IdempotencyRecordID().String(),
		semanticHash[:],
		semanticHash[:],
		auditPayload,
		resourceAuthorityOutboxEventClass,
		outboxPayload,
	).Scan(&appendedSequence); err != nil {
		return fmt.Errorf("append lifecycle evidence: %w", err)
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
		resourceLifecycleOperation(command),
		proof.DigestKeyID(),
		digest[:],
		requestHash[:],
		resourceLifecycleResultType(command),
		command.AggregateID().String(),
		result.Version(),
		result.NetworkRevision(),
		resultPayload,
		change.MutationIDs().OutboxEventID().String(),
		change.OccurredAt(),
	).Scan(&completedRecordID); err != nil {
		return fmt.Errorf("complete lifecycle idempotency evidence: %w", err)
	}
	if completedRecordID != change.Resolution().IdempotencyRecordID().String() {
		return ErrResourceAuthorityEvidence
	}
	return nil
}
