package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/internal/domain/audit"
	"meshtransit.net/core/internal/domain/publicid"
)

const seedOutboxEventClass = "qualification.management_session.seeded"

func insertSeedAuthority(
	ctx context.Context,
	transaction pgx.Tx,
	spec seedSpec,
	database databaseSettings,
	scope seedScope,
	ids seedIDs,
	digest [sha256.Size]byte,
	material seedIdentityMaterial,
) (time.Time, error) {
	if transaction == nil || !spec.isValid() || !scope.isValid() ||
		digest == ([sha256.Size]byte{}) || len(material.issuerDigest) != sha256.Size ||
		len(material.subjectDigest) != sha256.Size ||
		material.trustHash == ([sha256.Size]byte{}) {
		return time.Time{}, errInvalidInput
	}

	accountID, err := insertInternalID(
		ctx,
		transaction,
		"qualification Account",
		insertSeedAccountSQL,
		ids.account.String(),
		scope.deploymentInternalID,
		scope.principalInternalID,
	)
	if err != nil {
		return time.Time{}, err
	}
	if !validPositiveInt64(accountID) {
		return time.Time{}, errInvalidInput
	}

	providerID, err := insertInternalID(
		ctx,
		transaction,
		"qualification identity provider",
		insertSeedProviderSQL,
		ids.provider.String(),
		scope.deploymentInternalID,
		qualificationIssuer,
		material.issuerDigest,
		qualificationDiscoveryURI,
		qualificationJWKSURI,
	)
	if err != nil {
		return time.Time{}, err
	}
	if _, err := insertInternalID(
		ctx,
		transaction,
		"qualification identity provider generation",
		insertSeedProviderGenerationSQL,
		ids.providerGeneration.String(),
		scope.deploymentInternalID,
		providerID,
		material.trustHash[:],
	); err != nil {
		return time.Time{}, err
	}
	providerClientID, err := insertInternalID(
		ctx,
		transaction,
		"qualification identity provider client",
		insertSeedProviderClientSQL,
		ids.providerClient.String(),
		scope.deploymentInternalID,
		providerID,
	)
	if err != nil {
		return time.Time{}, err
	}
	subjectID, err := insertInternalID(
		ctx,
		transaction,
		"qualification identity subject",
		insertSeedSubjectSQL,
		ids.subject.String(),
		scope.deploymentInternalID,
		providerID,
		scope.principalInternalID,
		material.subjectDigest,
	)
	if err != nil {
		return time.Time{}, err
	}

	expirySeconds := int64(spec.expiresIn / time.Second)
	var sessionID int64
	var expiresAt time.Time
	if err := transaction.QueryRow(
		ctx,
		insertSeedSessionSQL,
		ids.session.String(),
		scope.deploymentInternalID,
		scope.principalInternalID,
		providerID,
		subjectID,
		providerClientID,
		scope.workspaceInternalID,
		database.digestKeyID.String(),
		digest[:],
		scope.principalAuthorityGeneration,
		scope.recoveryEpoch,
		expirySeconds,
	).Scan(&sessionID, &expiresAt); err != nil {
		return time.Time{}, fmt.Errorf("insert qualification Account Session: %w", err)
	}
	if !validPositiveInt64(sessionID) || expiresAt.IsZero() {
		return time.Time{}, errInvalidInput
	}

	membershipID, err := insertInternalID(
		ctx,
		transaction,
		"qualification Workspace membership",
		insertSeedMembershipSQL,
		ids.membership.String(),
		scope.deploymentInternalID,
		scope.workspaceInternalID,
		scope.principalInternalID,
		expirySeconds,
	)
	if err != nil {
		return time.Time{}, err
	}
	roleDefinitionID, err := insertInternalID(
		ctx,
		transaction,
		"qualification RoleDefinition",
		insertSeedRoleDefinitionSQL,
		ids.roleDefinition.String(),
		scope.deploymentInternalID,
		scope.workspaceInternalID,
	)
	if err != nil {
		return time.Time{}, err
	}
	if _, err := insertInternalID(
		ctx,
		transaction,
		"qualification RolePermission",
		insertSeedRolePermissionSQL,
		ids.rolePermission.String(),
		scope.deploymentInternalID,
		scope.workspaceInternalID,
		roleDefinitionID,
	); err != nil {
		return time.Time{}, err
	}
	if _, err := insertInternalID(
		ctx,
		transaction,
		"qualification RoleBinding",
		insertSeedRoleBindingSQL,
		ids.roleBinding.String(),
		scope.deploymentInternalID,
		scope.workspaceInternalID,
		scope.networkInternalID,
		scope.principalInternalID,
		membershipID,
		roleDefinitionID,
		expirySeconds,
	); err != nil {
		return time.Time{}, err
	}
	return expiresAt.UTC(), nil
}

func insertInternalID(
	ctx context.Context,
	transaction pgx.Tx,
	label string,
	query string,
	arguments ...any,
) (int64, error) {
	var internalID int64
	if err := transaction.QueryRow(ctx, query, arguments...).Scan(&internalID); err != nil {
		return 0, fmt.Errorf("insert %s: %w", label, err)
	}
	if !validPositiveInt64(internalID) {
		return 0, errInvalidInput
	}
	return internalID, nil
}

func appendSeedEvidence(
	ctx context.Context,
	transaction pgx.Tx,
	spec seedSpec,
	scope seedScope,
	ids seedIDs,
	expiresAt time.Time,
) error {
	if transaction == nil || !spec.isValid() || !scope.isValid() || expiresAt.IsZero() {
		return errInvalidInput
	}
	var streamID int64
	var nextSequence int64
	var previousHashBytes []byte
	if err := transaction.QueryRow(
		ctx,
		lockSeedAuditStreamSQL,
		scope.deploymentInternalID,
		scope.workspaceInternalID,
		scope.networkInternalID,
	).Scan(&streamID, &nextSequence, &previousHashBytes); err != nil {
		return fmt.Errorf("lock qualification audit stream: %w", err)
	}
	if !validPositiveInt64(streamID) || !validPositiveInt64(nextSequence) ||
		len(previousHashBytes) != sha256.Size {
		return errInvalidInput
	}
	var previousHash [sha256.Size]byte
	copy(previousHash[:], previousHashBytes)

	auditPayload, err := json.Marshal(seedAuditPayload{
		AuditReason:       spec.auditReason,
		QualificationOnly: true,
		SessionID:         ids.session.String(),
		IdentitySubjectID: ids.subject.String(),
		MembershipID:      ids.membership.String(),
		RoleDefinitionID:  ids.roleDefinition.String(),
		RoleBindingID:     ids.roleBinding.String(),
		Permission:        deviceManagePermission,
		ExpiresAt:         expiresAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return fmt.Errorf("encode qualification audit payload: %w", err)
	}
	outboxPayload, err := json.Marshal(seedOutboxPayload{
		NetworkRevision: scope.networkRevision,
		Fixture:         "management_session",
		ExpiresAt:       expiresAt.UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		return fmt.Errorf("encode qualification outbox payload: %w", err)
	}
	auditPayloadHash := sha256.Sum256(auditPayload)
	outboxPayloadHash := sha256.Sum256(outboxPayload)
	afterSemanticHash := sha256.Sum256([]byte(
		ids.session.String() + "\x00" + ids.membership.String() + "\x00" +
			ids.roleBinding.String() + "\x00" + expiresAt.UTC().Format(time.RFC3339Nano),
	))
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash:      previousHash,
		EventID:           ids.event,
		ChangeID:          ids.change,
		AggregateKind:     "role_binding",
		AggregateID:       ids.roleBinding,
		AggregateVersion:  1,
		NetworkRevision:   scope.networkRevision,
		ActorPrincipalID:  publicid.ID(spec.principalID),
		Action:            seedOutboxEventClass,
		Permission:        "system.bootstrap",
		CorrelationID:     ids.session,
		AfterSemanticHash: afterSemanticHash,
		AuditPayloadHash:  auditPayloadHash,
		OutboxEventClass:  seedOutboxEventClass,
		OutboxPayloadHash: outboxPayloadHash,
	})
	if err != nil {
		return fmt.Errorf("hash qualification audit event: %w", err)
	}

	var appendedSequence int64
	if err := transaction.QueryRow(
		ctx,
		appendSeedEvidenceSQL,
		streamID,
		ids.event.String(),
		ids.outbox.String(),
		nextSequence,
		previousHash[:],
		eventHash[:],
		ids.roleBinding.String(),
		scope.networkRevision,
		spec.principalID.String(),
		ids.session.String(),
		afterSemanticHash[:],
		auditPayload,
		outboxPayload,
	).Scan(&appendedSequence); err != nil {
		return fmt.Errorf("append qualification audit and outbox evidence: %w", err)
	}
	if appendedSequence != nextSequence {
		return errors.New("qualification audit sequence mismatch")
	}
	return nil
}
