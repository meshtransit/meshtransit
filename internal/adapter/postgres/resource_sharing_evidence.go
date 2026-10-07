package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"time"

	"github.com/meshtransit/meshtransit/internal/audit"
	"github.com/meshtransit/meshtransit/internal/authorization"
	"github.com/meshtransit/meshtransit/internal/idempotency"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/sharing"
)

type resourceSharingAuditPayload struct {
	AuditReason                       string `json:"audit_reason"`
	ScopeRelation                     string `json:"scope_relation"`
	AuthoritySide                     string `json:"authority_side"`
	EvidenceNetwork                   string `json:"evidence_network"`
	ProviderNetwork                   string `json:"provider_network"`
	ConsumerNetwork                   string `json:"consumer_network"`
	AccountSessionID                  string `json:"account_session_id"`
	RoleBindingID                     string `json:"role_binding_id,omitempty"`
	RoleDefinitionID                  string `json:"role_definition_id,omitempty"`
	ScopeAuthorityGeneration          int64  `json:"scope_authority_generation"`
	MembershipAuthorityGeneration     int64  `json:"membership_authority_generation"`
	BindingAuthorityGeneration        int64  `json:"binding_authority_generation"`
	RoleAuthorityGeneration           int64  `json:"role_authority_generation"`
	WorkspaceOwnerAuthorityGeneration int64  `json:"workspace_owner_authority_generation,omitempty"`
}

// resourceSharingCounterpartAuditPayload is what the other side's Network
// records about a decision. A share joins two parties that may belong to
// different Workspaces, so the acting side's stated reason, Session and role
// evidence stay in the acting Network's record only.
type resourceSharingCounterpartAuditPayload struct {
	ScopeRelation     string `json:"scope_relation"`
	AuthoritySide     string `json:"authority_side"`
	EvidenceNetwork   string `json:"evidence_network"`
	ProviderNetwork   string `json:"provider_network"`
	ConsumerNetwork   string `json:"consumer_network"`
	ActingSideDetails string `json:"acting_side_details"`
}

// resourceSharingDetailsInActingNetwork tells a reader where the reason and
// authorization evidence of a counterpart record live.
const resourceSharingDetailsInActingNetwork = "recorded_in_acting_network"

type resourceSharingAuditTarget struct {
	state    resourceSharingNetworkState
	head     resourceAuthorityAuditHead
	auditID  publicid.ID
	outboxID publicid.ID
}

func readResourceSharingAuditHead(
	ctx context.Context,
	transaction resourceAuthorityDatabaseTransaction,
) (resourceAuthorityAuditHead, error) {
	var head resourceAuthorityAuditHead
	var previousHash []byte
	if err := transaction.QueryRow(ctx, lockResourceAuthorityAuditStreamSQL).Scan(
		&head.streamInternalID, &head.nextSequence, &previousHash,
	); err != nil {
		return resourceAuthorityAuditHead{}, resourceSharingDatabaseError(ctx, err)
	}
	if head.streamInternalID <= 0 || head.nextSequence <= 0 || len(previousHash) != sha256.Size {
		return resourceAuthorityAuditHead{}, sharing.ErrUnavailable
	}
	copy(head.previousHash[:], previousHash)
	return head, nil
}

func setResourceSharingChange(
	ctx context.Context,
	transaction resourceAuthorityDatabaseTransaction,
	changeID publicid.ID,
) error {
	if !changeID.IsValid() {
		return sharing.ErrUnavailable
	}
	if err := transaction.Exec(ctx, setResourceAuthorityChangeSQL, changeID.String()); err != nil {
		return resourceSharingDatabaseError(ctx, err)
	}
	return nil
}

func appendResourceSharingMutationEvidence(
	ctx context.Context,
	transaction resourceAuthorityDatabaseTransaction,
	session accountsession.Session,
	reason sharing.AuditReason,
	proof idempotency.Proof,
	localScope network.Scope,
	authorizationEvidence resourceAuthorityAuthorizationEvidence,
	locator resourceSharingScopeLocator,
	heads map[network.Scope]resourceAuthorityAuditHead,
	ids resourceSharingMutationIDs,
	idempotencyRecord resourceAuthorityIdempotencyRecord,
	requestHash [sha256.Size]byte,
	aggregateKind string,
	aggregateID publicid.ID,
	aggregateVersion int64,
	action string,
	permission authorization.Permission,
	payload resourceSharingIdempotencyPayload,
	occurredAt time.Time,
) error {
	relation := sharing.ClassifyScopeRelation(locator.provider.scope, locator.consumer.scope)
	authoritySide := resourceSharingAuthoritySide(localScope, locator)
	if !session.IsValid() || !reason.IsValid() || !proof.IsValid() || !localScope.IsValid() ||
		!authorizationEvidence.isValid() || len(heads) != 2 || !aggregateID.IsValid() ||
		aggregateVersion <= 0 || action == "" || !validResourceSharingPermission(permission) ||
		idempotencyRecord.publicID == "" || requestHash == ([sha256.Size]byte{}) ||
		occurredAt.IsZero() || !relation.IsValid() || authoritySide == "" {
		return sharing.ErrUnavailable
	}
	correlationID, err := publicid.Parse(idempotencyRecord.publicID)
	if err != nil {
		return sharing.ErrUnavailable
	}
	targets := []resourceSharingAuditTarget{
		{
			state: locator.provider, head: heads[locator.provider.scope],
			auditID: ids.providerAuditID, outboxID: ids.providerOutboxID,
		},
		{
			state: locator.consumer, head: heads[locator.consumer.scope],
			auditID: ids.consumerAuditID, outboxID: ids.consumerOutboxID,
		},
	}
	slices.SortFunc(targets, func(first, second resourceSharingAuditTarget) int {
		if first.head.streamInternalID < second.head.streamInternalID {
			return -1
		}
		if first.head.streamInternalID > second.head.streamInternalID {
			return 1
		}
		return 0
	})
	for _, target := range targets {
		networkRevision, sharingRevision := resourceSharingTargetRevisions(target.state.scope, locator, payload)
		if networkRevision <= 0 || sharingRevision <= 0 ||
			networkRevision < sharingRevision || target.head.streamInternalID <= 0 ||
			target.head.nextSequence <= 0 || !target.auditID.IsValid() || !target.outboxID.IsValid() {
			return sharing.ErrUnavailable
		}
		var auditDocument any = resourceSharingCounterpartAuditPayload{
			ScopeRelation: relation.String(), AuthoritySide: authoritySide,
			EvidenceNetwork:   resourceSharingScopeKey(target.state.scope),
			ProviderNetwork:   resourceSharingScopeKey(locator.provider.scope),
			ConsumerNetwork:   resourceSharingScopeKey(locator.consumer.scope),
			ActingSideDetails: resourceSharingDetailsInActingNetwork,
		}
		if target.state.scope == localScope {
			auditDocument = resourceSharingAuditPayload{
				AuditReason: reason.String(), ScopeRelation: relation.String(), AuthoritySide: authoritySide,
				EvidenceNetwork:                   resourceSharingScopeKey(target.state.scope),
				ProviderNetwork:                   resourceSharingScopeKey(locator.provider.scope),
				ConsumerNetwork:                   resourceSharingScopeKey(locator.consumer.scope),
				AccountSessionID:                  authorizationEvidence.accountSessionID.String(),
				RoleBindingID:                     authorizationIDString(authorizationEvidence.roleBindingID),
				RoleDefinitionID:                  authorizationIDString(authorizationEvidence.roleDefinitionID),
				ScopeAuthorityGeneration:          authorizationEvidence.scopeAuthorityGeneration,
				MembershipAuthorityGeneration:     authorizationEvidence.membershipAuthorityGeneration,
				BindingAuthorityGeneration:        authorizationEvidence.bindingAuthorityGeneration,
				RoleAuthorityGeneration:           authorizationEvidence.roleAuthorityGeneration,
				WorkspaceOwnerAuthorityGeneration: authorizationEvidence.workspaceOwnerAuthorityGeneration,
			}
		}
		auditPayload, err := json.Marshal(auditDocument)
		if err != nil {
			return sharing.ErrUnavailable
		}
		outboxPayload, err := json.Marshal(resourceAuthorityOutboxPayload{
			NetworkRevision: networkRevision, Subsystem: "sharing",
			SubsystemRevision: sharingRevision,
		})
		if err != nil {
			return sharing.ErrUnavailable
		}
		auditPayloadHash := sha256.Sum256(auditPayload)
		outboxPayloadHash := sha256.Sum256(outboxPayload)
		eventHash, err := audit.HashEvent(audit.EventHashMaterial{
			PreviousHash:      target.head.previousHash,
			EventID:           target.auditID,
			ChangeID:          ids.changeID,
			AggregateKind:     aggregateKind,
			AggregateID:       aggregateID,
			AggregateVersion:  aggregateVersion,
			NetworkRevision:   networkRevision,
			ActorPrincipalID:  publicid.ID(session.PrincipalID()),
			Action:            action,
			Permission:        string(permission),
			CorrelationID:     correlationID,
			AfterSemanticHash: requestHash,
			AuditPayloadHash:  auditPayloadHash,
			OutboxEventClass:  resourceAuthorityOutboxEventClass,
			OutboxPayloadHash: outboxPayloadHash,
		})
		if err != nil {
			return sharing.ErrUnavailable
		}
		var appendedSequence int64
		if err := transaction.QueryRow(
			ctx,
			appendResourceAuthorityEvidenceSQL,
			target.head.streamInternalID,
			target.auditID.String(),
			target.outboxID.String(),
			target.head.nextSequence,
			target.head.previousHash[:],
			eventHash[:],
			aggregateKind,
			aggregateID.String(),
			aggregateVersion,
			networkRevision,
			session.PrincipalID().String(),
			action,
			string(permission),
			correlationID.String(),
			nil,
			requestHash[:],
			auditPayload,
			resourceAuthorityOutboxEventClass,
			outboxPayload,
		).Scan(&appendedSequence); err != nil {
			return resourceSharingDatabaseError(ctx, err)
		}
		if appendedSequence != target.head.nextSequence {
			return sharing.ErrUnavailable
		}
	}
	resultPayload, err := json.Marshal(payload)
	if err != nil {
		return sharing.ErrUnavailable
	}
	localNetworkRevision, _ := resourceSharingTargetRevisions(localScope, locator, payload)
	localOutboxID := ids.consumerOutboxID
	if localScope == locator.provider.scope {
		localOutboxID = ids.providerOutboxID
	}
	digest := proof.Digest()
	var completedRecordID string
	if err := transaction.QueryRow(
		ctx,
		completeResourceAuthorityIdempotencySQL,
		idempotencyRecord.publicID,
		session.PrincipalID().String(),
		payload.Operation,
		proof.DigestKeyID(),
		digest[:],
		requestHash[:],
		"resource_sharing_mutation",
		aggregateID.String(),
		aggregateVersion,
		localNetworkRevision,
		resultPayload,
		localOutboxID.String(),
		occurredAt,
	).Scan(&completedRecordID); err != nil {
		return resourceSharingDatabaseError(ctx, err)
	}
	if completedRecordID != idempotencyRecord.publicID {
		return sharing.ErrUnavailable
	}
	return nil
}

func resourceSharingAuthoritySide(
	localScope network.Scope,
	locator resourceSharingScopeLocator,
) string {
	if localScope == locator.provider.scope {
		return "provider"
	}
	if localScope == locator.consumer.scope {
		return "consumer"
	}
	return ""
}

func validResourceSharingPermission(permission authorization.Permission) bool {
	return permission == authorization.PermissionShareOffer ||
		permission == authorization.PermissionShareAccept ||
		permission == authorization.PermissionShareRevoke
}

func resourceSharingTargetRevisions(
	scope network.Scope,
	locator resourceSharingScopeLocator,
	payload resourceSharingIdempotencyPayload,
) (int64, int64) {
	if scope == locator.provider.scope {
		return payload.ProviderNetworkRevision, payload.ProviderSharingRevision
	}
	if scope == locator.consumer.scope {
		return payload.ConsumerNetworkRevision, payload.ConsumerSharingRevision
	}
	return 0, 0
}
