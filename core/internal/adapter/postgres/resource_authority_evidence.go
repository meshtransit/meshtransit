package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/meshtransit/meshtransit/core/internal/domain/audit"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	authority "github.com/meshtransit/meshtransit/core/internal/domain/resource/authority"
)

const resourceAuthorityOutboxEventClass = "network.revision.advanced"

type resourceGroupMemberPayload struct {
	MemberPublicID   string `json:"member_public_id"`
	Ordinal          int    `json:"ordinal"`
	ResourcePublicID string `json:"resource_public_id"`
	ResourceVersion  int64  `json:"resource_version"`
	TargetGeneration int64  `json:"target_generation"`
}

type resourceAuthorityAuditPayload struct {
	AuditReason                       string `json:"audit_reason"`
	ExpectedSubsystemRevision         int64  `json:"expected_subsystem_revision"`
	MemberCount                       int    `json:"member_count,omitempty"`
	AccountSessionID                  string `json:"account_session_id"`
	RoleBindingID                     string `json:"role_binding_id,omitempty"`
	RoleDefinitionID                  string `json:"role_definition_id,omitempty"`
	ScopeAuthorityGeneration          int64  `json:"scope_authority_generation"`
	MembershipAuthorityGeneration     int64  `json:"membership_authority_generation"`
	BindingAuthorityGeneration        int64  `json:"binding_authority_generation"`
	RoleAuthorityGeneration           int64  `json:"role_authority_generation"`
	WorkspaceOwnerAuthorityGeneration int64  `json:"workspace_owner_authority_generation,omitempty"`
}

type resourceAuthorityOutboxPayload struct {
	NetworkRevision   int64  `json:"network_revision"`
	Subsystem         string `json:"subsystem"`
	SubsystemRevision int64  `json:"subsystem_revision"`
}

func encodeResourceGroupMembers(change authority.Change) ([]byte, error) {
	members := change.Command().Group().Members()
	projectionIDs := change.MutationIDs().ProjectionIDs()
	if len(projectionIDs) != len(members)+1 {
		return nil, ErrResourceAuthorityEvidence
	}
	payload := make([]resourceGroupMemberPayload, len(members))
	for index, member := range members {
		payload[index] = resourceGroupMemberPayload{
			MemberPublicID: projectionIDs[index+1].String(), Ordinal: index + 1,
			ResourcePublicID: member.ResourceID().String(),
			ResourceVersion:  member.ResourceVersion(),
			TargetGeneration: member.TargetGeneration(),
		}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode Resource Group members: %w", err)
	}
	return encoded, nil
}

func (transaction *resourceAuthorityTransaction) appendEvidence(
	ctx context.Context,
	change authority.Change,
	aggregateVersion, networkRevision, subsystemRevision int64,
) error {
	command := change.Command()
	auditEvidence := resourceAuthorityAuditPayload{
		AuditReason:                       command.AuditReason().String(),
		ExpectedSubsystemRevision:         command.ExpectedSubsystemRevision(),
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
	action := "resource.created"
	permission := "resource.manage"
	subsystem := "inventory"
	aggregateID := publicid.ID(change.MutationIDs().ResourceID())
	if command.Operation() == authority.OperationCreateGroup {
		auditEvidence.MemberCount = len(command.Group().Members())
		aggregateKind = "resource_group"
		action = "resource_group.created"
		permission = "resource_group.manage"
		subsystem = "group"
		aggregateID = publicid.ID(change.MutationIDs().GroupID())
	}
	auditPayload, err := json.Marshal(auditEvidence)
	if err != nil {
		return fmt.Errorf("encode Resource authority audit payload: %w", err)
	}
	outboxPayload, err := json.Marshal(resourceAuthorityOutboxPayload{
		NetworkRevision:   networkRevision,
		Subsystem:         subsystem,
		SubsystemRevision: subsystemRevision,
	})
	if err != nil {
		return fmt.Errorf("encode Resource authority outbox payload: %w", err)
	}
	semanticHashBytes := command.SemanticHash().Bytes()
	resultPayload, err := json.Marshal(resourceAuthorityResultPayload{
		Operation:         resourceAuthorityOperation(command),
		SubsystemRevision: subsystemRevision,
		SemanticHash:      hex.EncodeToString(semanticHashBytes[:]),
	})
	if err != nil {
		return fmt.Errorf("encode Resource authority result payload: %w", err)
	}
	auditPayloadHash := sha256.Sum256(auditPayload)
	outboxPayloadHash := sha256.Sum256(outboxPayload)
	afterSemanticHash := command.SemanticHash().Bytes()
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash:      transaction.audit.previousHash,
		EventID:           change.MutationIDs().AuditEventID(),
		ChangeID:          change.MutationIDs().ChangeID(),
		AggregateKind:     aggregateKind,
		AggregateID:       aggregateID,
		AggregateVersion:  aggregateVersion,
		NetworkRevision:   networkRevision,
		ActorPrincipalID:  publicid.ID(command.AccountSession().PrincipalID()),
		Action:            action,
		Permission:        permission,
		CorrelationID:     change.Resolution().IdempotencyRecordID(),
		AfterSemanticHash: afterSemanticHash,
		AuditPayloadHash:  auditPayloadHash,
		OutboxEventClass:  resourceAuthorityOutboxEventClass,
		OutboxPayloadHash: outboxPayloadHash,
	})
	if err != nil {
		return fmt.Errorf("hash Resource authority audit event: %w", err)
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
		aggregateID.String(),
		aggregateVersion,
		networkRevision,
		command.AccountSession().PrincipalID().String(),
		action,
		permission,
		change.Resolution().IdempotencyRecordID().String(),
		nil,
		afterSemanticHash[:],
		auditPayload,
		resourceAuthorityOutboxEventClass,
		outboxPayload,
	).Scan(&appendedSequence); err != nil {
		return fmt.Errorf("append Resource authority evidence: %w", err)
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
		resourceAuthorityOperation(command),
		proof.DigestKeyID(),
		digest[:],
		requestHash[:],
		resourceAuthorityResultKind(command),
		aggregateID.String(),
		aggregateVersion,
		networkRevision,
		resultPayload,
		change.MutationIDs().OutboxEventID().String(),
		change.OccurredAt(),
	).Scan(&completedRecordID); err != nil {
		return fmt.Errorf("complete Resource authority idempotency evidence: %w", err)
	}
	if completedRecordID != change.Resolution().IdempotencyRecordID().String() {
		return ErrResourceAuthorityEvidence
	}
	return nil
}
