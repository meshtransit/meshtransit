package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/meshtransit/meshtransit/internal/audit"
	publication "github.com/meshtransit/meshtransit/internal/policy/publication"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

const policyPublicationOutboxEventClass = "network.revision.advanced"

type policyPublicationRulePayload struct {
	ProjectionPublicID                         string                         `json:"projection_public_id"`
	AccessRulePublicID                         string                         `json:"access_rule_public_id"`
	SourceNodePublicID                         string                         `json:"source_node_public_id"`
	DestinationNodePublicID                    string                         `json:"destination_node_public_id,omitempty"`
	Protocol                                   string                         `json:"protocol"`
	PortRangeFirst                             []int                          `json:"port_range_first"`
	PortRangeLast                              []int                          `json:"port_range_last"`
	DestinationResourcePublicID                string                         `json:"destination_resource_public_id,omitempty"`
	DestinationResourceVersion                 int64                          `json:"destination_resource_version,omitempty"`
	DestinationTargetGeneration                int64                          `json:"destination_target_generation,omitempty"`
	DestinationInventoryRevision               int64                          `json:"destination_inventory_revision,omitempty"`
	DestinationResourceSemanticHash            string                         `json:"destination_resource_semantic_hash,omitempty"`
	DestinationResourceGroupPublicID           string                         `json:"destination_resource_group_public_id,omitempty"`
	DestinationResourceGroupVersion            int64                          `json:"destination_resource_group_version,omitempty"`
	DestinationGroupDefinitionVersion          int64                          `json:"destination_group_definition_version,omitempty"`
	DestinationGroupRevision                   int64                          `json:"destination_group_revision,omitempty"`
	DestinationResourceGroupSemanticHash       string                         `json:"destination_resource_group_semantic_hash,omitempty"`
	DestinationGroupMemberResourcePublicID     string                         `json:"destination_group_member_resource_public_id,omitempty"`
	DestinationGroupMemberResourceVersion      int64                          `json:"destination_group_member_resource_version,omitempty"`
	DestinationGroupMemberTargetGeneration     int64                          `json:"destination_group_member_target_generation,omitempty"`
	DestinationGroupMemberInventoryRevision    int64                          `json:"destination_group_member_inventory_revision,omitempty"`
	DestinationGroupMemberResourceSemanticHash string                         `json:"destination_group_member_resource_semantic_hash,omitempty"`
	DestinationImportedResourcePublicID        string                         `json:"destination_imported_resource_public_id,omitempty"`
	DestinationImportedResourceVersion         int64                          `json:"destination_imported_resource_version,omitempty"`
	DestinationTrustContractPublicID           string                         `json:"destination_trust_contract_public_id,omitempty"`
	DestinationTrustContractVersion            int64                          `json:"destination_trust_contract_version,omitempty"`
	DestinationShareOfferPublicID              string                         `json:"destination_share_offer_public_id,omitempty"`
	DestinationResourceExportPublicID          string                         `json:"destination_resource_export_public_id,omitempty"`
	DestinationResourceExportVersion           int64                          `json:"destination_resource_export_version,omitempty"`
	DestinationProviderWorkspacePublicID       string                         `json:"destination_provider_workspace_public_id,omitempty"`
	DestinationProviderNetworkPublicID         string                         `json:"destination_provider_network_public_id,omitempty"`
	DestinationProviderResourcePublicID        string                         `json:"destination_provider_resource_public_id,omitempty"`
	DestinationProviderResourceVersion         int64                          `json:"destination_provider_resource_version,omitempty"`
	DestinationProviderTargetGeneration        int64                          `json:"destination_provider_target_generation,omitempty"`
	DestinationProviderResourceSemanticHash    string                         `json:"destination_provider_resource_semantic_hash,omitempty"`
	DestinationProviderInventoryRevision       int64                          `json:"destination_provider_inventory_revision,omitempty"`
	DestinationProviderSharingRevision         int64                          `json:"destination_provider_sharing_revision,omitempty"`
	DestinationConsumerSharingRevision         int64                          `json:"destination_consumer_sharing_revision,omitempty"`
	DestinationProviderAuthorityGeneration     int64                          `json:"destination_provider_authority_generation,omitempty"`
	DestinationConsumerAuthorityGeneration     int64                          `json:"destination_consumer_authority_generation,omitempty"`
	DestinationRecoveryEpoch                   int64                          `json:"destination_recovery_epoch,omitempty"`
	DestinationContractExpiresAt               string                         `json:"destination_contract_expires_at,omitempty"`
	DestinationConstraintHash                  string                         `json:"destination_constraint_hash,omitempty"`
	DestinationAuthorityEvaluatedAt            string                         `json:"destination_authority_evaluated_at,omitempty"`
	DestinationContractConstraints             []resourceSharingTrafficRecord `json:"destination_contract_constraints,omitempty"`
}

type policyPublicationAuditPayload struct {
	AuditReason                               string                                   `json:"audit_reason"`
	BasePolicyRevision                        int64                                    `json:"base_policy_revision"`
	CompilerFormatVersion                     int                                      `json:"compiler_format_version"`
	RuleCount                                 int                                      `json:"rule_count"`
	GuardrailFindings                         []guardrailFindingEvidence               `json:"guardrail_findings,omitempty"`
	AccountSessionID                          string                                   `json:"account_session_id,omitempty"`
	RoleBindingID                             string                                   `json:"role_binding_id,omitempty"`
	RoleDefinitionID                          string                                   `json:"role_definition_id,omitempty"`
	ScopeAuthorityGeneration                  int64                                    `json:"scope_authority_generation,omitempty"`
	MembershipAuthorityGeneration             int64                                    `json:"membership_authority_generation,omitempty"`
	BindingAuthorityGeneration                int64                                    `json:"binding_authority_generation,omitempty"`
	RoleAuthorityGeneration                   int64                                    `json:"role_authority_generation,omitempty"`
	WorkspaceOwnerAuthorityGeneration         int64                                    `json:"workspace_owner_authority_generation,omitempty"`
	ApprovalRequestID                         string                                   `json:"approval_request_id,omitempty"`
	ApprovalEvidenceID                        string                                   `json:"approval_evidence_id,omitempty"`
	ApprovalImpactHash                        string                                   `json:"approval_impact_hash,omitempty"`
	ApprovalBaselineVector                    *policyPublicationAuthorityVectorPayload `json:"approval_baseline_vector,omitempty"`
	ApprovalProposedVector                    *policyPublicationAuthorityVectorPayload `json:"approval_proposed_vector,omitempty"`
	ApproverAccountSessionID                  string                                   `json:"approver_account_session_id,omitempty"`
	ApproverRoleBindingID                     string                                   `json:"approver_role_binding_id,omitempty"`
	ApproverRoleDefinitionID                  string                                   `json:"approver_role_definition_id,omitempty"`
	ApproverScopeAuthorityGeneration          int64                                    `json:"approver_scope_authority_generation,omitempty"`
	ApproverMembershipAuthorityGeneration     int64                                    `json:"approver_membership_authority_generation,omitempty"`
	ApproverBindingAuthorityGeneration        int64                                    `json:"approver_binding_authority_generation,omitempty"`
	ApproverRoleAuthorityGeneration           int64                                    `json:"approver_role_authority_generation,omitempty"`
	ApproverWorkspaceOwnerAuthorityGeneration int64                                    `json:"approver_workspace_owner_authority_generation,omitempty"`
}

type policyPublicationAuthorityVectorPayload struct {
	NetworkRevision     int64 `json:"network_revision"`
	InventoryRevision   int64 `json:"inventory_revision"`
	GroupRevision       int64 `json:"group_revision"`
	PolicyRevision      int64 `json:"policy_revision"`
	DNSRevision         int64 `json:"dns_revision"`
	RouteRevision       int64 `json:"route_revision"`
	SharingRevision     int64 `json:"sharing_revision"`
	IsolationGeneration int64 `json:"isolation_generation"`
}

type policyPublicationOutboxPayload struct {
	NetworkRevision int64 `json:"network_revision"`
	PolicyRevision  int64 `json:"policy_revision"`
}

func encodePolicyPublicationRules(change publication.Change) ([]byte, error) {
	candidate := change.Command().Candidate()
	rules := candidate.Snapshot().Rules()
	importedDestinations := candidate.ImportedResourceDestinations()
	projectionIDs := change.MutationIDs().ProjectionIDs()
	if len(projectionIDs) != len(rules)+len(importedDestinations) {
		return nil, ErrPolicyPublicationEvidence
	}
	type destinationKey struct{ ruleID, nodeID string }
	resourceDestinations := make(map[destinationKey]publication.ResourceDestination)
	for _, destination := range candidate.ResourceDestinations() {
		key := destinationKey{
			ruleID: destination.RuleID().String(),
			nodeID: destination.DestinationNodeID().String(),
		}
		if _, duplicate := resourceDestinations[key]; duplicate {
			return nil, ErrPolicyPublicationEvidence
		}
		resourceDestinations[key] = destination
	}
	type groupMemberDestination struct {
		group  publication.ResourceGroupDestination
		member publication.ResourceGroupMemberDestination
	}
	groupDestinations := make(map[destinationKey]groupMemberDestination)
	for _, destination := range candidate.ResourceGroupDestinations() {
		for _, member := range destination.Members() {
			key := destinationKey{
				ruleID: destination.RuleID().String(), nodeID: member.DestinationNodeID().String(),
			}
			if _, duplicate := groupDestinations[key]; duplicate {
				return nil, ErrPolicyPublicationEvidence
			}
			if _, collision := resourceDestinations[key]; collision {
				return nil, ErrPolicyPublicationEvidence
			}
			groupDestinations[key] = groupMemberDestination{group: destination, member: member}
		}
	}
	payload := make([]policyPublicationRulePayload, len(rules)+len(importedDestinations))
	for index, rule := range rules {
		portRanges := rule.DestinationPortRanges()
		first := make([]int, len(portRanges))
		last := make([]int, len(portRanges))
		for portIndex, portRange := range portRanges {
			first[portIndex] = int(portRange.First())
			last[portIndex] = int(portRange.Last())
		}
		payload[index] = policyPublicationRulePayload{
			ProjectionPublicID:      projectionIDs[index].String(),
			AccessRulePublicID:      rule.ID().String(),
			SourceNodePublicID:      rule.SourceNodeID().String(),
			DestinationNodePublicID: rule.DestinationNodeID().String(),
			Protocol:                rule.Protocol().String(),
			PortRangeFirst:          first,
			PortRangeLast:           last,
		}
		key := destinationKey{ruleID: rule.ID().String(), nodeID: rule.DestinationNodeID().String()}
		if destination, found := resourceDestinations[key]; found {
			reference := destination.Reference()
			hash := destination.ResourceSemanticHash().Bytes()
			payload[index].DestinationResourcePublicID = reference.ResourceID().String()
			payload[index].DestinationResourceVersion = reference.ResourceVersion()
			payload[index].DestinationTargetGeneration = reference.TargetGeneration()
			payload[index].DestinationInventoryRevision = destination.InventoryRevision()
			payload[index].DestinationResourceSemanticHash = hex.EncodeToString(hash[:])
			delete(resourceDestinations, key)
		} else if destination, found := groupDestinations[key]; found {
			groupHash := destination.group.GroupSemanticHash().Bytes()
			memberReference := destination.member.Reference()
			memberHash := destination.member.ResourceSemanticHash().Bytes()
			payload[index].DestinationResourceGroupPublicID = destination.group.ResourceGroupID().String()
			payload[index].DestinationResourceGroupVersion = destination.group.GroupVersion()
			payload[index].DestinationGroupDefinitionVersion = destination.group.DefinitionVersion()
			payload[index].DestinationGroupRevision = destination.group.GroupRevision()
			payload[index].DestinationResourceGroupSemanticHash = hex.EncodeToString(groupHash[:])
			payload[index].DestinationGroupMemberResourcePublicID = memberReference.ResourceID().String()
			payload[index].DestinationGroupMemberResourceVersion = memberReference.ResourceVersion()
			payload[index].DestinationGroupMemberTargetGeneration = memberReference.TargetGeneration()
			payload[index].DestinationGroupMemberInventoryRevision = destination.member.InventoryRevision()
			payload[index].DestinationGroupMemberResourceSemanticHash = hex.EncodeToString(memberHash[:])
			delete(groupDestinations, key)
		}
	}
	for index, destination := range importedDestinations {
		resolution := destination.Resolution()
		contract := resolution.Contract()
		binding := contract.Resource()
		resourceHash := binding.SemanticHash().Bytes()
		constraintHash := contract.MaximumTraffic().Hash()
		portRanges := destination.DestinationPortRanges()
		first := make([]int, len(portRanges))
		last := make([]int, len(portRanges))
		for rangeIndex, portRange := range portRanges {
			first[rangeIndex] = int(portRange.First())
			last[rangeIndex] = int(portRange.Last())
		}
		payload[len(rules)+index] = policyPublicationRulePayload{
			ProjectionPublicID:                      projectionIDs[len(rules)+index].String(),
			AccessRulePublicID:                      destination.RuleID().String(),
			SourceNodePublicID:                      destination.SourceNodeID().String(),
			Protocol:                                destination.Protocol().String(),
			PortRangeFirst:                          first,
			PortRangeLast:                           last,
			DestinationImportedResourcePublicID:     resolution.ImportedResourceID().String(),
			DestinationImportedResourceVersion:      resolution.ImportedResourceVersion(),
			DestinationTrustContractPublicID:        contract.ID().String(),
			DestinationTrustContractVersion:         contract.Version(),
			DestinationResourceExportPublicID:       contract.ExportID().String(),
			DestinationResourceExportVersion:        resolution.ExportVersion(),
			DestinationProviderWorkspacePublicID:    contract.ProviderScope().WorkspaceID().String(),
			DestinationProviderNetworkPublicID:      contract.ProviderScope().NetworkID().String(),
			DestinationProviderResourcePublicID:     binding.ResourceID().String(),
			DestinationProviderResourceVersion:      binding.ResourceVersion(),
			DestinationProviderTargetGeneration:     binding.TargetGeneration(),
			DestinationProviderResourceSemanticHash: hex.EncodeToString(resourceHash[:]),
			DestinationProviderInventoryRevision:    resolution.ProviderInventoryRevision(),
			DestinationProviderSharingRevision:      resolution.ProviderSharingRevision(),
			DestinationConsumerSharingRevision:      resolution.ConsumerSharingRevision(),
			DestinationProviderAuthorityGeneration:  contract.ProviderAuthorityGeneration(),
			DestinationConsumerAuthorityGeneration:  contract.ConsumerAuthorityGeneration(),
			DestinationRecoveryEpoch:                contract.RecoveryEpoch(),
			DestinationContractExpiresAt:            contract.ExpiresAt().UTC().Format(time.RFC3339Nano),
			DestinationConstraintHash:               hex.EncodeToString(constraintHash[:]),
		}
	}
	if len(resourceDestinations) != 0 || len(groupDestinations) != 0 {
		return nil, ErrPolicyPublicationEvidence
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode compiled policy rules: %w", err)
	}
	return encoded, nil
}

func (transaction *policyPublicationTransaction) appendPolicyPublicationEvidence(
	ctx context.Context,
	change publication.Change,
	releaseVersion int64,
	networkRevision int64,
) error {
	command := change.Command()
	policyRevision := command.Candidate().Snapshot().Revision()
	auditEvidence := policyPublicationAuditPayload{
		AuditReason:           command.AuditReason().String(),
		BasePolicyRevision:    command.BasePolicyRevision(),
		CompilerFormatVersion: command.Candidate().CompilerFormatVersion(),
		RuleCount:             len(command.Candidate().Snapshot().Rules()) + len(command.Candidate().ImportedResourceDestinations()),
		GuardrailFindings:     guardrailFindingsEvidence(transaction.guardrailFindings),
	}
	if transaction.authorization.isValid() {
		auditEvidence.AccountSessionID = transaction.authorization.accountSessionID.String()
		auditEvidence.RoleBindingID = authorizationIDString(transaction.authorization.roleBindingID)
		auditEvidence.RoleDefinitionID = authorizationIDString(transaction.authorization.roleDefinitionID)
		auditEvidence.ScopeAuthorityGeneration = transaction.authorization.scopeAuthorityGeneration
		auditEvidence.MembershipAuthorityGeneration = transaction.authorization.membershipAuthorityGeneration
		auditEvidence.BindingAuthorityGeneration = transaction.authorization.bindingAuthorityGeneration
		auditEvidence.RoleAuthorityGeneration = transaction.authorization.roleAuthorityGeneration
		auditEvidence.WorkspaceOwnerAuthorityGeneration = transaction.authorization.workspaceOwnerAuthorityGeneration
	}
	if command.HasApprovalEvidence() {
		gate := change.Resolution().ApprovalGate()
		impactHash := gate.ImpactHash().Bytes()
		baseline := policyPublicationAuthorityVectorAuditPayload(gate.BaselineVector())
		proposed := policyPublicationAuthorityVectorAuditPayload(gate.ProposedVector())
		auditEvidence.ApprovalRequestID = gate.RequestID().String()
		auditEvidence.ApprovalEvidenceID = gate.EvidenceID().String()
		auditEvidence.ApprovalImpactHash = hex.EncodeToString(impactHash[:])
		auditEvidence.ApprovalBaselineVector = &baseline
		auditEvidence.ApprovalProposedVector = &proposed
	}
	if transaction.approvalAuthorization.isValid() {
		authorization := transaction.approvalAuthorization
		auditEvidence.ApproverAccountSessionID = authorization.accountSessionID.String()
		auditEvidence.ApproverRoleBindingID = authorizationIDString(authorization.roleBindingID)
		auditEvidence.ApproverRoleDefinitionID = authorizationIDString(authorization.roleDefinitionID)
		auditEvidence.ApproverScopeAuthorityGeneration = authorization.scopeAuthorityGeneration
		auditEvidence.ApproverMembershipAuthorityGeneration = authorization.membershipAuthorityGeneration
		auditEvidence.ApproverBindingAuthorityGeneration = authorization.bindingAuthorityGeneration
		auditEvidence.ApproverRoleAuthorityGeneration = authorization.roleAuthorityGeneration
		auditEvidence.ApproverWorkspaceOwnerAuthorityGeneration = authorization.workspaceOwnerAuthorityGeneration
	}
	auditPayload, err := json.Marshal(auditEvidence)
	if err != nil {
		return fmt.Errorf("encode policy publication audit payload: %w", err)
	}
	outboxPayload, err := json.Marshal(policyPublicationOutboxPayload{
		NetworkRevision: networkRevision,
		PolicyRevision:  policyRevision,
	})
	if err != nil {
		return fmt.Errorf("encode policy publication outbox payload: %w", err)
	}
	auditPayloadHash := sha256.Sum256(auditPayload)
	outboxPayloadHash := sha256.Sum256(outboxPayload)
	afterSemanticHash := command.Candidate().SemanticHash().Bytes()
	var beforeSemanticHash [sha256.Size]byte
	if _, hash, found := transaction.resolution.ActiveRelease(); found {
		beforeSemanticHash = hash.Bytes()
	}
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash:       transaction.audit.previousHash,
		EventID:            change.MutationIDs().AuditEventID(),
		ChangeID:           change.MutationIDs().ChangeID(),
		AggregateKind:      "policy_release",
		AggregateID:        publicid.ID(change.MutationIDs().ReleaseID()),
		AggregateVersion:   releaseVersion,
		NetworkRevision:    networkRevision,
		ActorPrincipalID:   publicid.ID(command.ActorPrincipalID()),
		Action:             "policy.published",
		Permission:         "policy.publish",
		CorrelationID:      publicid.ID(change.MutationIDs().ReleaseID()),
		BeforeSemanticHash: beforeSemanticHash,
		AfterSemanticHash:  afterSemanticHash,
		AuditPayloadHash:   auditPayloadHash,
		OutboxEventClass:   policyPublicationOutboxEventClass,
		OutboxPayloadHash:  outboxPayloadHash,
	})
	if err != nil {
		return fmt.Errorf("hash policy publication audit event: %w", err)
	}

	var beforeSemanticHashArgument any
	if beforeSemanticHash != ([sha256.Size]byte{}) {
		beforeSemanticHashArgument = beforeSemanticHash[:]
	}
	var appendedSequence int64
	if err := transaction.database.QueryRow(
		ctx,
		appendPolicyPublicationEvidenceSQL,
		transaction.audit.streamInternalID,
		change.MutationIDs().AuditEventID().String(),
		change.MutationIDs().OutboxEventID().String(),
		transaction.audit.nextSequence,
		transaction.audit.previousHash[:],
		eventHash[:],
		change.MutationIDs().ReleaseID().String(),
		releaseVersion,
		networkRevision,
		command.ActorPrincipalID().String(),
		"policy.published",
		change.MutationIDs().ReleaseID().String(),
		beforeSemanticHashArgument,
		afterSemanticHash[:],
		auditPayload,
		outboxPayload,
	).Scan(&appendedSequence); err != nil {
		return fmt.Errorf("append policy publication audit and outbox evidence: %w", err)
	}
	if appendedSequence != transaction.audit.nextSequence {
		return ErrPolicyPublicationEvidence
	}
	return nil
}

func policyPublicationAuthorityVectorAuditPayload(
	vector publication.AuthorityVector,
) policyPublicationAuthorityVectorPayload {
	return policyPublicationAuthorityVectorPayload{
		NetworkRevision:     vector.NetworkRevision(),
		InventoryRevision:   vector.InventoryRevision(),
		GroupRevision:       vector.GroupRevision(),
		PolicyRevision:      vector.PolicyRevision(),
		DNSRevision:         vector.DNSRevision(),
		RouteRevision:       vector.RouteRevision(),
		SharingRevision:     vector.SharingRevision(),
		IsolationGeneration: vector.IsolationGeneration(),
	}
}
