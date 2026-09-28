package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/meshtransit/meshtransit/internal/audit"
	publication "github.com/meshtransit/meshtransit/internal/policy/publication"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

const policyPublicationOutboxEventClass = "network.revision.advanced"

type policyPublicationRulePayload struct {
	ProjectionPublicID              string `json:"projection_public_id"`
	AccessRulePublicID              string `json:"access_rule_public_id"`
	SourceNodePublicID              string `json:"source_node_public_id"`
	DestinationNodePublicID         string `json:"destination_node_public_id"`
	Protocol                        string `json:"protocol"`
	PortRangeFirst                  []int  `json:"port_range_first"`
	PortRangeLast                   []int  `json:"port_range_last"`
	DestinationResourcePublicID     string `json:"destination_resource_public_id,omitempty"`
	DestinationResourceVersion      int64  `json:"destination_resource_version,omitempty"`
	DestinationTargetGeneration     int64  `json:"destination_target_generation,omitempty"`
	DestinationInventoryRevision    int64  `json:"destination_inventory_revision,omitempty"`
	DestinationResourceSemanticHash string `json:"destination_resource_semantic_hash,omitempty"`
}

type policyPublicationAuditPayload struct {
	AuditReason                   string `json:"audit_reason"`
	BasePolicyRevision            int64  `json:"base_policy_revision"`
	CompilerFormatVersion         int    `json:"compiler_format_version"`
	RuleCount                     int    `json:"rule_count"`
	AccountSessionID              string `json:"account_session_id,omitempty"`
	RoleBindingID                 string `json:"role_binding_id,omitempty"`
	RoleDefinitionID              string `json:"role_definition_id,omitempty"`
	ScopeAuthorityGeneration      int64  `json:"scope_authority_generation,omitempty"`
	MembershipAuthorityGeneration int64  `json:"membership_authority_generation,omitempty"`
	BindingAuthorityGeneration    int64  `json:"binding_authority_generation,omitempty"`
	RoleAuthorityGeneration       int64  `json:"role_authority_generation,omitempty"`
}

type policyPublicationOutboxPayload struct {
	NetworkRevision int64 `json:"network_revision"`
	PolicyRevision  int64 `json:"policy_revision"`
}

func encodePolicyPublicationRules(change publication.Change) ([]byte, error) {
	candidate := change.Command().Candidate()
	rules := candidate.Snapshot().Rules()
	projectionIDs := change.MutationIDs().ProjectionIDs()
	if len(projectionIDs) != len(rules) {
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
	payload := make([]policyPublicationRulePayload, len(rules))
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
		}
	}
	if len(resourceDestinations) != 0 {
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
		RuleCount:             len(command.Candidate().Snapshot().Rules()),
	}
	if transaction.authorization.isValid() {
		auditEvidence.AccountSessionID = transaction.authorization.accountSessionID.String()
		auditEvidence.RoleBindingID = transaction.authorization.roleBindingID.String()
		auditEvidence.RoleDefinitionID = transaction.authorization.roleDefinitionID.String()
		auditEvidence.ScopeAuthorityGeneration = transaction.authorization.scopeAuthorityGeneration
		auditEvidence.MembershipAuthorityGeneration = transaction.authorization.membershipAuthorityGeneration
		auditEvidence.BindingAuthorityGeneration = transaction.authorization.bindingAuthorityGeneration
		auditEvidence.RoleAuthorityGeneration = transaction.authorization.roleAuthorityGeneration
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
