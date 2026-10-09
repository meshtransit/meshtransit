package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/audit"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
	authority "github.com/meshtransit/meshtransit/core/internal/domain/resource/authority"
)

type resourceAuthorityChangeAuditPayload struct {
	AuditReason                       string   `json:"audit_reason"`
	RequestID                         string   `json:"request_id"`
	SubjectKind                       string   `json:"subject_kind"`
	SubjectPublicID                   string   `json:"subject_public_id"`
	Action                            string   `json:"action"`
	TargetPrincipalID                 string   `json:"target_principal_id"`
	ExpectedSubjectVersion            int64    `json:"expected_subject_version"`
	ExpectedRequestVersion            int64    `json:"expected_request_version,omitempty"`
	ImpactHash                        string   `json:"impact_hash"`
	RequiredConfirmations             int      `json:"required_confirmations"`
	RequestExpiresAt                  string   `json:"request_expires_at"`
	EvidenceRole                      string   `json:"evidence_role"`
	AuthenticationTime                string   `json:"authentication_time"`
	ACR                               string   `json:"acr"`
	AMR                               []string `json:"amr"`
	AccountSessionID                  string   `json:"account_session_id"`
	RoleBindingID                     string   `json:"role_binding_id,omitempty"`
	RoleDefinitionID                  string   `json:"role_definition_id,omitempty"`
	ScopeAuthorityGeneration          int64    `json:"scope_authority_generation"`
	MembershipAuthorityGeneration     int64    `json:"membership_authority_generation"`
	BindingAuthorityGeneration        int64    `json:"binding_authority_generation"`
	RoleAuthorityGeneration           int64    `json:"role_authority_generation"`
	WorkspaceOwnerAuthorityGeneration int64    `json:"workspace_owner_authority_generation,omitempty"`
}

func authorityChangeAuditIdentity(
	kind authority.SubjectKind,
) (aggregateKind, permission, subsystem string) {
	if kind == authority.AuthoritySubjectGroup {
		return "resource_group", "resource_group.transfer", "group"
	}
	return "resource", "resource.transfer", "inventory"
}

func (transaction *resourceAuthorityChangeRequestTransaction) appendAuthorityChangeRequestEvidence(
	ctx context.Context,
	change authority.ChangeRequestChange,
	result authority.ChangeRequestResult,
) error {
	command := change.Command()
	preview := command.Preview()
	impact := change.Resolution().Impact()
	impactHash := impact.Hash().Bytes()
	_, permission, subsystem := authorityChangeAuditIdentity(preview.SubjectKind())
	auditPayload, err := json.Marshal(resourceAuthorityChangeAuditPayload{
		AuditReason: command.AuditReason().String(), RequestID: result.RequestID().String(),
		SubjectKind:     preview.SubjectKind().String(),
		SubjectPublicID: preview.SubjectPublicID().String(), Action: preview.Action().String(),
		TargetPrincipalID:      preview.TargetPrincipalID().String(),
		ExpectedSubjectVersion: preview.ExpectedVersion(),
		ImpactHash:             hex.EncodeToString(impactHash[:]),
		RequiredConfirmations:  impact.RequiredConfirmations(),
		RequestExpiresAt:       result.ExpiresAt().UTC().Format(time.RFC3339Nano),
		EvidenceRole:           "requester",
		AuthenticationTime:     preview.AccountSession().AuthenticationTime().UTC().Format(time.RFC3339Nano),
		ACR:                    preview.AccountSession().ACR(), AMR: preview.AccountSession().AMR(),
		AccountSessionID:                  transaction.authorization.accountSessionID.String(),
		RoleBindingID:                     authorizationIDString(transaction.authorization.roleBindingID),
		RoleDefinitionID:                  authorizationIDString(transaction.authorization.roleDefinitionID),
		ScopeAuthorityGeneration:          transaction.authorization.scopeAuthorityGeneration,
		MembershipAuthorityGeneration:     transaction.authorization.membershipAuthorityGeneration,
		BindingAuthorityGeneration:        transaction.authorization.bindingAuthorityGeneration,
		RoleAuthorityGeneration:           transaction.authorization.roleAuthorityGeneration,
		WorkspaceOwnerAuthorityGeneration: transaction.authorization.workspaceOwnerAuthorityGeneration,
	})
	if err != nil {
		return fmt.Errorf("encode Resource authority request audit payload: %w", err)
	}
	outboxPayload, err := json.Marshal(resourceAuthorityOutboxPayload{
		NetworkRevision: result.NetworkRevision(), Subsystem: subsystem,
		SubsystemRevision: result.SubsystemRevision(),
	})
	if err != nil {
		return fmt.Errorf("encode Resource authority request outbox payload: %w", err)
	}
	resultPayload, err := json.Marshal(resourceAuthorityChangeRequestPayload{
		SubjectKind:     preview.SubjectKind().String(),
		SubjectPublicID: preview.SubjectPublicID().String(), Action: preview.Action().String(),
		TargetPrincipalID: preview.TargetPrincipalID().String(),
		SubsystemRevision: result.SubsystemRevision(),
		ImpactHash:        hex.EncodeToString(impactHash[:]),
		ExpiresAt:         result.ExpiresAt().UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return fmt.Errorf("encode Resource authority request result payload: %w", err)
	}
	auditPayloadHash := sha256.Sum256(auditPayload)
	outboxPayloadHash := sha256.Sum256(outboxPayload)
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash:  transaction.audit.previousHash,
		EventID:       change.MutationIDs().AuditEventID(),
		ChangeID:      change.MutationIDs().ChangeID(),
		AggregateKind: "resource_authority_change_request",
		AggregateID:   publicid.ID(result.RequestID()), AggregateVersion: result.RequestVersion(),
		NetworkRevision:  result.NetworkRevision(),
		ActorPrincipalID: publicid.ID(preview.AccountSession().PrincipalID()),
		Action:           preview.SubjectKind().String() + ".authority_change_requested",
		Permission:       permission, CorrelationID: change.Resolution().IdempotencyRecordID(),
		AfterSemanticHash: impactHash, AuditPayloadHash: auditPayloadHash,
		OutboxEventClass:  resourceAuthorityOutboxEventClass,
		OutboxPayloadHash: outboxPayloadHash,
	})
	if err != nil {
		return fmt.Errorf("hash Resource authority request audit event: %w", err)
	}
	if err := appendAuthorityChangeEvidence(
		ctx, transaction.database, transaction.audit,
		change.MutationIDs().AuditEventID(), change.MutationIDs().OutboxEventID(),
		"resource_authority_change_request",
		publicid.ID(result.RequestID()), result.RequestVersion(), result.NetworkRevision(),
		publicid.ID(preview.AccountSession().PrincipalID()),
		preview.SubjectKind().String()+".authority_change_requested", permission,
		change.Resolution().IdempotencyRecordID(), nil, impactHash[:],
		auditPayload, outboxPayload, eventHash,
	); err != nil {
		return err
	}
	requestHash := change.Resolution().RequestHash().Bytes()
	proof := command.IdempotencyEvidence()
	digest := proof.Digest()
	return completeAuthorityChangeIdempotency(
		ctx, transaction.database, change.Resolution().IdempotencyRecordID(),
		preview.AccountSession().PrincipalID().String(), resourceAuthorityChangeRequestOperation,
		proof.DigestKeyID(), digest[:], requestHash[:], resourceAuthorityChangeRequestResultKind,
		result.RequestID().String(), result.RequestVersion(), result.NetworkRevision(),
		resultPayload, change.MutationIDs().OutboxEventID(), change.OccurredAt(),
	)
}

func (transaction *resourceAuthorityChangeConfirmationTransaction) appendAuthorityChangeConfirmationEvidence(
	ctx context.Context,
	change authority.ChangeConfirmationChange,
	result authority.ChangeConfirmationResult,
) error {
	command := change.Command()
	impact := change.Resolution().Impact()
	preview := impact.Preview()
	impactHash := impact.Hash().Bytes()
	aggregateKind, permission, subsystem := authorityChangeAuditIdentity(command.SubjectKind())
	auditPayload, err := json.Marshal(resourceAuthorityChangeAuditPayload{
		AuditReason: command.AuditReason().String(), RequestID: command.RequestID().String(),
		SubjectKind:     command.SubjectKind().String(),
		SubjectPublicID: command.SubjectPublicID().String(), Action: preview.Action().String(),
		TargetPrincipalID:      preview.TargetPrincipalID().String(),
		ExpectedSubjectVersion: preview.ExpectedVersion(),
		ExpectedRequestVersion: command.ExpectedRequestVersion(),
		ImpactHash:             hex.EncodeToString(impactHash[:]),
		RequiredConfirmations:  impact.RequiredConfirmations(),
		RequestExpiresAt:       change.Resolution().RequestExpiresAt().UTC().Format(time.RFC3339Nano),
		EvidenceRole:           "confirmer",
		AuthenticationTime:     command.AccountSession().AuthenticationTime().UTC().Format(time.RFC3339Nano),
		ACR:                    command.AccountSession().ACR(), AMR: command.AccountSession().AMR(),
		AccountSessionID:                  transaction.authorization.accountSessionID.String(),
		RoleBindingID:                     authorizationIDString(transaction.authorization.roleBindingID),
		RoleDefinitionID:                  authorizationIDString(transaction.authorization.roleDefinitionID),
		ScopeAuthorityGeneration:          transaction.authorization.scopeAuthorityGeneration,
		MembershipAuthorityGeneration:     transaction.authorization.membershipAuthorityGeneration,
		BindingAuthorityGeneration:        transaction.authorization.bindingAuthorityGeneration,
		RoleAuthorityGeneration:           transaction.authorization.roleAuthorityGeneration,
		WorkspaceOwnerAuthorityGeneration: transaction.authorization.workspaceOwnerAuthorityGeneration,
	})
	if err != nil {
		return fmt.Errorf("encode Resource authority confirmation audit payload: %w", err)
	}
	outboxPayload, err := json.Marshal(resourceAuthorityOutboxPayload{
		NetworkRevision: result.NetworkRevision(), Subsystem: subsystem,
		SubsystemRevision: result.SubsystemRevision(),
	})
	if err != nil {
		return fmt.Errorf("encode Resource authority confirmation outbox payload: %w", err)
	}
	semanticHash := result.SemanticHash().Bytes()
	resultPayload, err := json.Marshal(resourceAuthorityChangeResultPayload{
		SubjectKind:     command.SubjectKind().String(),
		SubjectPublicID: command.SubjectPublicID().String(), Action: preview.Action().String(),
		RequestVersion: result.RequestVersion(), SubsystemRevision: result.SubsystemRevision(),
		OwnerPrincipalID:     result.OwnerPrincipalID().String(),
		CustodianPrincipalID: result.CustodianPrincipalID().String(),
		SemanticHash:         hex.EncodeToString(semanticHash[:]),
		ImpactHash:           hex.EncodeToString(impactHash[:]),
	})
	if err != nil {
		return fmt.Errorf("encode Resource authority confirmation result payload: %w", err)
	}
	auditPayloadHash := sha256.Sum256(auditPayload)
	outboxPayloadHash := sha256.Sum256(outboxPayload)
	beforeHash := impact.CurrentSemanticHash().Bytes()
	action := command.SubjectKind().String() + "." + preview.Action().String()
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash: transaction.audit.previousHash,
		EventID:      change.MutationIDs().AuditEventID(),
		ChangeID:     change.MutationIDs().ChangeID(), AggregateKind: aggregateKind,
		AggregateID: command.SubjectPublicID(), AggregateVersion: result.SubjectVersion(),
		NetworkRevision:  result.NetworkRevision(),
		ActorPrincipalID: publicid.ID(command.AccountSession().PrincipalID()),
		Action:           action, Permission: permission,
		CorrelationID:      change.Resolution().IdempotencyRecordID(),
		BeforeSemanticHash: beforeHash, AfterSemanticHash: semanticHash,
		AuditPayloadHash: auditPayloadHash, OutboxEventClass: resourceAuthorityOutboxEventClass,
		OutboxPayloadHash: outboxPayloadHash,
	})
	if err != nil {
		return fmt.Errorf("hash Resource authority confirmation audit event: %w", err)
	}
	if err := appendAuthorityChangeEvidence(
		ctx, transaction.database, transaction.audit,
		change.MutationIDs().AuditEventID(), change.MutationIDs().OutboxEventID(),
		aggregateKind, command.SubjectPublicID(),
		result.SubjectVersion(), result.NetworkRevision(),
		publicid.ID(command.AccountSession().PrincipalID()), action, permission,
		change.Resolution().IdempotencyRecordID(), beforeHash[:], semanticHash[:],
		auditPayload, outboxPayload, eventHash,
	); err != nil {
		return err
	}
	requestHash := change.Resolution().RequestHash().Bytes()
	proof := command.IdempotencyEvidence()
	digest := proof.Digest()
	return completeAuthorityChangeIdempotency(
		ctx, transaction.database, change.Resolution().IdempotencyRecordID(),
		command.AccountSession().PrincipalID().String(),
		resourceAuthorityChangeConfirmationOperation, proof.DigestKeyID(), digest[:], requestHash[:],
		resourceAuthorityChangeResultKind, command.SubjectPublicID().String(),
		result.SubjectVersion(), result.NetworkRevision(), resultPayload,
		change.MutationIDs().OutboxEventID(), change.OccurredAt(),
	)
}

func appendAuthorityChangeEvidence(
	ctx context.Context,
	database resourceAuthorityDatabaseTransaction,
	auditHead resourceAuthorityAuditHead,
	auditEventID, outboxEventID publicid.ID,
	aggregateKind string,
	aggregateID publicid.ID,
	aggregateVersion, networkRevision int64,
	actorPrincipalID publicid.ID,
	action, permission string,
	correlationID publicid.ID,
	beforeHash, afterHash []byte,
	auditPayload, outboxPayload []byte,
	eventHash [sha256.Size]byte,
) error {
	var appendedSequence int64
	if err := database.QueryRow(
		ctx, appendResourceAuthorityEvidenceSQL,
		auditHead.streamInternalID, auditEventID.String(), outboxEventID.String(),
		auditHead.nextSequence, auditHead.previousHash[:], eventHash[:],
		aggregateKind, aggregateID.String(), aggregateVersion, networkRevision,
		actorPrincipalID.String(), action, permission, correlationID.String(),
		beforeHash, afterHash, auditPayload, resourceAuthorityOutboxEventClass, outboxPayload,
	).Scan(&appendedSequence); err != nil {
		return fmt.Errorf("append Resource authority change evidence: %w", err)
	}
	if appendedSequence != auditHead.nextSequence {
		return ErrResourceAuthorityEvidence
	}
	return nil
}

func completeAuthorityChangeIdempotency(
	ctx context.Context,
	database resourceAuthorityDatabaseTransaction,
	recordID publicid.ID,
	principalID, operation, digestKeyID string,
	digest, requestHash []byte,
	resultKind, resultPublicID string,
	resultVersion, networkRevision int64,
	resultPayload []byte,
	outboxEventID publicid.ID,
	occurredAt time.Time,
) error {
	var completedRecordID string
	if err := database.QueryRow(
		ctx, completeResourceAuthorityIdempotencySQL,
		recordID.String(), principalID, operation, digestKeyID, digest, requestHash,
		resultKind, resultPublicID, resultVersion, networkRevision, resultPayload,
		outboxEventID.String(), occurredAt,
	).Scan(&completedRecordID); err != nil {
		return fmt.Errorf("complete Resource authority change idempotency: %w", err)
	}
	if completedRecordID != recordID.String() {
		return ErrResourceAuthorityEvidence
	}
	return nil
}
