package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/meshtransit/meshtransit/internal/audit"
	"github.com/meshtransit/meshtransit/internal/publicid"
	authority "github.com/meshtransit/meshtransit/internal/resource/authority"
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
	AuditReason                   string `json:"audit_reason"`
	ExpectedSubsystemRevision     int64  `json:"expected_subsystem_revision"`
	MemberCount                   int    `json:"member_count,omitempty"`
	AccountSessionID              string `json:"account_session_id"`
	RoleBindingID                 string `json:"role_binding_id"`
	RoleDefinitionID              string `json:"role_definition_id"`
	ScopeAuthorityGeneration      int64  `json:"scope_authority_generation"`
	MembershipAuthorityGeneration int64  `json:"membership_authority_generation"`
	BindingAuthorityGeneration    int64  `json:"binding_authority_generation"`
	RoleAuthorityGeneration       int64  `json:"role_authority_generation"`
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
		AuditReason:                   command.AuditReason().String(),
		ExpectedSubsystemRevision:     command.ExpectedSubsystemRevision(),
		AccountSessionID:              transaction.authorization.accountSessionID.String(),
		RoleBindingID:                 transaction.authorization.roleBindingID.String(),
		RoleDefinitionID:              transaction.authorization.roleDefinitionID.String(),
		ScopeAuthorityGeneration:      transaction.authorization.scopeAuthorityGeneration,
		MembershipAuthorityGeneration: transaction.authorization.membershipAuthorityGeneration,
		BindingAuthorityGeneration:    transaction.authorization.bindingAuthorityGeneration,
		RoleAuthorityGeneration:       transaction.authorization.roleAuthorityGeneration,
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
		CorrelationID:     aggregateID,
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
		aggregateID.String(),
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
	return nil
}
