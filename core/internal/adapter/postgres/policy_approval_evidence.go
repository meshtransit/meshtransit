package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/meshtransit/meshtransit/core/internal/domain/audit"
	approval "github.com/meshtransit/meshtransit/core/internal/domain/policy/approval"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

const (
	policyApprovalRequestedEventClass = "policy.approval.requested"
	policyApprovalApprovedEventClass  = "policy.approval.approved"
)

type policyApprovalAuditPayload struct {
	AuditReason                       string `json:"audit_reason"`
	AccountSessionID                  string `json:"account_session_id"`
	RoleBindingID                     string `json:"role_binding_id,omitempty"`
	RoleDefinitionID                  string `json:"role_definition_id,omitempty"`
	ScopeAuthorityGeneration          int64  `json:"scope_authority_generation"`
	MembershipAuthorityGeneration     int64  `json:"membership_authority_generation"`
	BindingAuthorityGeneration        int64  `json:"binding_authority_generation"`
	RoleAuthorityGeneration           int64  `json:"role_authority_generation"`
	WorkspaceOwnerAuthorityGeneration int64  `json:"workspace_owner_authority_generation,omitempty"`
	CandidateSemanticHash             string `json:"candidate_semantic_hash"`
	ImpactHash                        string `json:"impact_hash"`
	BaselineNetworkRevision           int64  `json:"baseline_network_revision"`
	BaselinePolicyRevision            int64  `json:"baseline_policy_revision"`
	ProposedNetworkRevision           int64  `json:"proposed_network_revision"`
	ProposedPolicyRevision            int64  `json:"proposed_policy_revision"`
}

type policyApprovalOutboxPayload struct {
	RequestID      string `json:"request_id"`
	EvidenceID     string `json:"evidence_id,omitempty"`
	RequestVersion int64  `json:"request_version"`
	State          string `json:"state"`
}

func (transaction *policyApprovalRequestTransaction) appendRequestEvidence(
	ctx context.Context,
	change approval.RequestChange,
	result approval.RequestResult,
) error {
	command := change.Command()
	return transaction.appendEvidence(
		ctx,
		policyApprovalAuditAppend{
			mutationAuditID:  change.MutationIDs().AuditEventID(),
			mutationOutboxID: change.MutationIDs().OutboxEventID(),
			changeID:         change.MutationIDs().ChangeID(),
			aggregateKind:    policyApprovalRequestResultKind,
			aggregateID:      publicid.ID(result.RequestID()),
			aggregateVersion: result.RequestVersion(),
			networkRevision:  result.Binding().BaselineVector().NetworkRevision(),
			actorPrincipalID: publicid.ID(command.AccountSession().PrincipalID()),
			action:           policyApprovalRequestedEventClass,
			permission:       "policy.validate",
			correlationID:    publicid.ID(result.RequestID()),
			binding:          result.Binding(),
			auditReason:      command.AuditReason().String(),
			outboxClass:      policyApprovalRequestedEventClass,
			outboxPayload: policyApprovalOutboxPayload{
				RequestID:      result.RequestID().String(),
				RequestVersion: result.RequestVersion(),
				State:          result.State().String(),
			},
		},
	)
}

func (transaction *policyApprovalRequestTransaction) appendEvidence(
	ctx context.Context,
	value policyApprovalAuditAppend,
) error {
	return appendPolicyApprovalAudit(ctx, transaction.core.database, &transaction.core, value)
}

func (transaction *policyApprovalDecisionTransaction) appendDecisionEvidence(
	ctx context.Context,
	change approval.Change,
	result approval.Result,
) error {
	command := change.Command()
	return appendPolicyApprovalAudit(
		ctx,
		transaction.core.database,
		&transaction.core,
		policyApprovalAuditAppend{
			mutationAuditID:  change.MutationIDs().AuditEventID(),
			mutationOutboxID: change.MutationIDs().OutboxEventID(),
			changeID:         change.MutationIDs().ChangeID(),
			aggregateKind:    policyApprovalDecisionResultKind,
			aggregateID:      publicid.ID(result.EvidenceID()),
			aggregateVersion: result.EvidenceVersion(),
			networkRevision:  result.Binding().BaselineVector().NetworkRevision(),
			actorPrincipalID: publicid.ID(command.AccountSession().PrincipalID()),
			action:           policyApprovalApprovedEventClass,
			permission:       "policy.approve",
			correlationID:    publicid.ID(result.RequestID()),
			binding:          result.Binding(),
			auditReason:      command.AuditReason().String(),
			outboxClass:      policyApprovalApprovedEventClass,
			outboxPayload: policyApprovalOutboxPayload{
				RequestID:      result.RequestID().String(),
				EvidenceID:     result.EvidenceID().String(),
				RequestVersion: result.RequestVersion(),
				State:          result.State().String(),
			},
		},
	)
}

type policyApprovalAuditAppend struct {
	mutationAuditID  publicid.ID
	mutationOutboxID publicid.ID
	changeID         publicid.ID
	aggregateKind    string
	aggregateID      publicid.ID
	aggregateVersion int64
	networkRevision  int64
	actorPrincipalID publicid.ID
	action           string
	permission       string
	correlationID    publicid.ID
	binding          approval.Binding
	auditReason      string
	outboxClass      string
	outboxPayload    policyApprovalOutboxPayload
}

func appendPolicyApprovalAudit(
	ctx context.Context,
	database policyApprovalDatabaseTransaction,
	transaction *policyApprovalTransactionCore,
	value policyApprovalAuditAppend,
) error {
	if database == nil || transaction == nil || !transaction.authorization.isValid() ||
		!value.mutationAuditID.IsValid() || !value.mutationOutboxID.IsValid() ||
		!value.changeID.IsValid() || !value.aggregateID.IsValid() ||
		value.aggregateVersion <= 0 || value.networkRevision <= 0 ||
		!value.actorPrincipalID.IsValid() || !value.correlationID.IsValid() ||
		!value.binding.IsValid() || value.auditReason == "" || value.action == "" ||
		value.permission == "" || value.outboxClass == "" {
		return ErrPolicyApprovalEvidence
	}
	candidateHash := value.binding.CandidateSemanticHash().Bytes()
	impactHash := value.binding.ImpactHash().Bytes()
	baseline := value.binding.BaselineVector()
	proposed := value.binding.ProposedVector()
	authorization := transaction.authorization
	auditPayload, err := json.Marshal(policyApprovalAuditPayload{
		AuditReason:                       value.auditReason,
		AccountSessionID:                  authorization.accountSessionID.String(),
		RoleBindingID:                     authorizationIDString(authorization.roleBindingID),
		RoleDefinitionID:                  authorizationIDString(authorization.roleDefinitionID),
		ScopeAuthorityGeneration:          authorization.scopeAuthorityGeneration,
		MembershipAuthorityGeneration:     authorization.membershipAuthorityGeneration,
		BindingAuthorityGeneration:        authorization.bindingAuthorityGeneration,
		RoleAuthorityGeneration:           authorization.roleAuthorityGeneration,
		WorkspaceOwnerAuthorityGeneration: authorization.workspaceOwnerAuthorityGeneration,
		CandidateSemanticHash:             hex.EncodeToString(candidateHash[:]),
		ImpactHash:                        hex.EncodeToString(impactHash[:]),
		BaselineNetworkRevision:           baseline.NetworkRevision(),
		BaselinePolicyRevision:            baseline.PolicyRevision(),
		ProposedNetworkRevision:           proposed.NetworkRevision(),
		ProposedPolicyRevision:            proposed.PolicyRevision(),
	})
	if err != nil {
		return fmt.Errorf("encode Policy approval audit payload: %w", err)
	}
	outboxPayload, err := json.Marshal(value.outboxPayload)
	if err != nil {
		return fmt.Errorf("encode Policy approval outbox payload: %w", err)
	}
	auditPayloadHash := sha256.Sum256(auditPayload)
	outboxPayloadHash := sha256.Sum256(outboxPayload)
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash:      transaction.audit.previousHash,
		EventID:           value.mutationAuditID,
		ChangeID:          value.changeID,
		AggregateKind:     value.aggregateKind,
		AggregateID:       value.aggregateID,
		AggregateVersion:  value.aggregateVersion,
		NetworkRevision:   value.networkRevision,
		ActorPrincipalID:  value.actorPrincipalID,
		Action:            value.action,
		Permission:        value.permission,
		CorrelationID:     value.correlationID,
		AfterSemanticHash: candidateHash,
		AuditPayloadHash:  auditPayloadHash,
		OutboxEventClass:  value.outboxClass,
		OutboxPayloadHash: outboxPayloadHash,
	})
	if err != nil {
		return fmt.Errorf("hash Policy approval audit event: %w", err)
	}
	var appendedSequence int64
	if err := database.QueryRow(
		ctx,
		appendPolicyApprovalEvidenceSQL,
		transaction.audit.streamInternalID,
		value.mutationAuditID.String(),
		value.mutationOutboxID.String(),
		transaction.audit.nextSequence,
		transaction.audit.previousHash[:],
		eventHash[:],
		value.aggregateKind,
		value.aggregateID.String(),
		value.aggregateVersion,
		value.networkRevision,
		value.actorPrincipalID.String(),
		value.action,
		value.permission,
		value.correlationID.String(),
		nil,
		candidateHash[:],
		auditPayload,
		value.outboxClass,
		outboxPayload,
	).Scan(&appendedSequence); err != nil {
		return fmt.Errorf("append Policy approval audit and outbox evidence: %w", err)
	}
	if appendedSequence != transaction.audit.nextSequence {
		return ErrPolicyApprovalEvidence
	}
	return nil
}
