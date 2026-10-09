package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/core/internal/domain/audit"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

const renewalOutboxEventClass = "qualification.management_session.renewed"

type renewalFixture struct {
	accountInternalID                 int64
	accountPrincipalInternalID        int64
	accountSessionGeneration          int64
	providerInternalID                int64
	providerGeneration                int64
	providerClientInternalID          int64
	subjectInternalID                 int64
	subjectPublicID                   publicid.ID
	membershipInternalID              int64
	membershipPublicID                publicid.ID
	membershipVersion                 int64
	membershipAuthorityGeneration     int64
	membershipExpiresAt               time.Time
	roleDefinitionInternalID          int64
	roleDefinitionPublicID            publicid.ID
	roleDefinitionVersion             int64
	roleDefinitionAuthorityGeneration int64
	rolePermissionInternalID          int64
	bindingInternalID                 int64
	bindingPublicID                   publicid.ID
	bindingVersion                    int64
	bindingAuthorityGeneration        int64
	bindingExpiresAt                  time.Time
	authenticationTime                time.Time
}

type renewalResult struct {
	sessionInternalID             int64
	expiresAt                     time.Time
	membershipVersion             int64
	membershipAuthorityGeneration int64
	bindingVersion                int64
	bindingAuthorityGeneration    int64
}

type renewalSemanticState struct {
	SessionID                      string `json:"account_session_public_id,omitempty"`
	MembershipID                   string `json:"workspace_membership_public_id"`
	MembershipVersion              int64  `json:"workspace_membership_version"`
	MembershipAuthorityGeneration  int64  `json:"workspace_membership_authority_generation"`
	RoleBindingID                  string `json:"role_binding_public_id"`
	RoleBindingVersion             int64  `json:"role_binding_version"`
	RoleBindingAuthorityGeneration int64  `json:"role_binding_authority_generation"`
	ExpiresAt                      string `json:"expires_at"`
}

type renewalAuditPayload struct {
	AuditReason                    string `json:"audit_reason"`
	QualificationOnly              bool   `json:"qualification_only"`
	SessionID                      string `json:"account_session_public_id"`
	IdentitySubjectID              string `json:"identity_subject_public_id"`
	MembershipID                   string `json:"workspace_membership_public_id"`
	MembershipPreviousVersion      int64  `json:"workspace_membership_previous_version"`
	MembershipVersion              int64  `json:"workspace_membership_version"`
	MembershipAuthorityGeneration  int64  `json:"workspace_membership_authority_generation"`
	RoleDefinitionID               string `json:"role_definition_public_id"`
	RoleBindingID                  string `json:"role_binding_public_id"`
	RoleBindingPreviousVersion     int64  `json:"role_binding_previous_version"`
	RoleBindingVersion             int64  `json:"role_binding_version"`
	RoleBindingAuthorityGeneration int64  `json:"role_binding_authority_generation"`
	Permission                     string `json:"permission"`
	PreviousExpiresAt              string `json:"previous_expires_at"`
	ExpiresAt                      string `json:"expires_at"`
}

func loadRenewalFixture(
	ctx context.Context,
	database seedRowQuerier,
	scope seedScope,
	spec seedSpec,
	settings databaseSettings,
) (renewalFixture, time.Time, error) {
	var fixture renewalFixture
	var evaluatedAt time.Time
	var subjectPublicID string
	var membershipPublicID string
	var roleDefinitionPublicID string
	var bindingPublicID string
	if database == nil || !scope.isValid() || !spec.isValid() ||
		!spec.renewExpiredFixture || !settings.digestKeyID.IsValid() {
		return renewalFixture{}, time.Time{}, errInvalidInput
	}
	trustHash := qualificationTrustHash()
	err := database.QueryRow(
		ctx,
		loadRenewalFixtureSQL,
		scope.deploymentInternalID,
		scope.workspaceInternalID,
		scope.networkInternalID,
		scope.principalInternalID,
		settings.digestKeyID.String(),
		trustHash[:],
	).Scan(
		&fixture.accountInternalID,
		&fixture.accountPrincipalInternalID,
		&fixture.accountSessionGeneration,
		&fixture.providerInternalID,
		&fixture.providerGeneration,
		&fixture.providerClientInternalID,
		&fixture.subjectInternalID,
		&subjectPublicID,
		&fixture.membershipInternalID,
		&membershipPublicID,
		&fixture.membershipVersion,
		&fixture.membershipAuthorityGeneration,
		&fixture.membershipExpiresAt,
		&fixture.roleDefinitionInternalID,
		&roleDefinitionPublicID,
		&fixture.roleDefinitionVersion,
		&fixture.roleDefinitionAuthorityGeneration,
		&fixture.rolePermissionInternalID,
		&fixture.bindingInternalID,
		&bindingPublicID,
		&fixture.bindingVersion,
		&fixture.bindingAuthorityGeneration,
		&fixture.bindingExpiresAt,
		&fixture.authenticationTime,
		&evaluatedAt,
	)
	if err != nil {
		return renewalFixture{}, time.Time{}, fmt.Errorf(
			"resolve exact expired qualification fixture: %w",
			err,
		)
	}
	fixture.subjectPublicID, err = publicid.Parse(subjectPublicID)
	if err != nil {
		return renewalFixture{}, time.Time{}, errInvalidInput
	}
	fixture.membershipPublicID, err = publicid.Parse(membershipPublicID)
	if err != nil {
		return renewalFixture{}, time.Time{}, errInvalidInput
	}
	fixture.roleDefinitionPublicID, err = publicid.Parse(roleDefinitionPublicID)
	if err != nil {
		return renewalFixture{}, time.Time{}, errInvalidInput
	}
	fixture.bindingPublicID, err = publicid.Parse(bindingPublicID)
	if err != nil || !fixture.isValid(scope, evaluatedAt) {
		return renewalFixture{}, time.Time{}, errInvalidInput
	}
	return fixture, evaluatedAt.UTC(), nil
}

func (fixture renewalFixture) isValid(scope seedScope, evaluatedAt time.Time) bool {
	return scope.isValid() && !evaluatedAt.IsZero() &&
		validPositiveInt64(fixture.accountInternalID) &&
		fixture.accountPrincipalInternalID == scope.principalInternalID &&
		validPositiveInt64(fixture.accountSessionGeneration) &&
		validPositiveInt64(fixture.providerInternalID) &&
		validPositiveInt64(fixture.providerGeneration) &&
		validPositiveInt64(fixture.providerClientInternalID) &&
		validPositiveInt64(fixture.subjectInternalID) && fixture.subjectPublicID.IsValid() &&
		validPositiveInt64(fixture.membershipInternalID) && fixture.membershipPublicID.IsValid() &&
		validRenewalCounter(fixture.membershipVersion) &&
		fixture.membershipAuthorityGeneration == fixture.membershipVersion &&
		!fixture.membershipExpiresAt.IsZero() &&
		!fixture.membershipExpiresAt.After(evaluatedAt) &&
		validPositiveInt64(fixture.roleDefinitionInternalID) &&
		fixture.roleDefinitionPublicID.IsValid() && fixture.roleDefinitionVersion == 1 &&
		fixture.roleDefinitionAuthorityGeneration == 1 &&
		validPositiveInt64(fixture.rolePermissionInternalID) &&
		validPositiveInt64(fixture.bindingInternalID) && fixture.bindingPublicID.IsValid() &&
		validRenewalCounter(fixture.bindingVersion) &&
		fixture.bindingAuthorityGeneration == fixture.bindingVersion &&
		!fixture.bindingExpiresAt.IsZero() &&
		fixture.bindingExpiresAt.Equal(fixture.membershipExpiresAt) &&
		!fixture.bindingExpiresAt.After(evaluatedAt) &&
		!fixture.authenticationTime.IsZero() &&
		!fixture.authenticationTime.After(evaluatedAt)
}

func validRenewalCounter(value int64) bool {
	return value > 0 && value < math.MaxInt64
}

func renewFixtureAuthority(
	ctx context.Context,
	transaction pgx.Tx,
	spec seedSpec,
	settings databaseSettings,
	scope seedScope,
	fixture renewalFixture,
	sessionID publicid.ID,
	digest [sha256.Size]byte,
	evaluatedAt time.Time,
) (renewalResult, error) {
	if transaction == nil || !spec.isValid() || !scope.isValid() ||
		!fixture.isValid(scope, evaluatedAt) || !sessionID.IsValid() ||
		digest == ([sha256.Size]byte{}) {
		return renewalResult{}, errInvalidInput
	}
	expirySeconds := int64(spec.expiresIn / time.Second)
	var result renewalResult
	if err := transaction.QueryRow(
		ctx,
		insertRenewalSessionSQL,
		sessionID.String(),
		scope.deploymentInternalID,
		scope.principalInternalID,
		fixture.providerInternalID,
		fixture.subjectInternalID,
		fixture.providerClientInternalID,
		scope.workspaceInternalID,
		settings.digestKeyID.String(),
		digest[:],
		fixture.providerGeneration,
		fixture.authenticationTime,
		scope.principalAuthorityGeneration,
		fixture.accountSessionGeneration,
		scope.recoveryEpoch,
		expirySeconds,
	).Scan(&result.sessionInternalID, &result.expiresAt); err != nil {
		return renewalResult{}, fmt.Errorf("insert renewed qualification Account Session: %w", err)
	}
	var membershipExpiresAt time.Time
	if err := transaction.QueryRow(
		ctx,
		renewMembershipSQL,
		fixture.membershipInternalID,
		fixture.membershipPublicID.String(),
		fixture.membershipVersion,
		fixture.membershipAuthorityGeneration,
		expirySeconds,
	).Scan(
		&result.membershipVersion,
		&result.membershipAuthorityGeneration,
		&membershipExpiresAt,
	); err != nil {
		return renewalResult{}, fmt.Errorf("renew qualification Workspace membership: %w", err)
	}
	var bindingExpiresAt time.Time
	if err := transaction.QueryRow(
		ctx,
		renewRoleBindingSQL,
		fixture.bindingInternalID,
		fixture.bindingPublicID.String(),
		fixture.bindingVersion,
		fixture.bindingAuthorityGeneration,
		expirySeconds,
	).Scan(
		&result.bindingVersion,
		&result.bindingAuthorityGeneration,
		&bindingExpiresAt,
	); err != nil {
		return renewalResult{}, fmt.Errorf("renew qualification RoleBinding: %w", err)
	}
	if !validPositiveInt64(result.sessionInternalID) || result.expiresAt.IsZero() ||
		result.membershipVersion != fixture.membershipVersion+1 ||
		result.membershipAuthorityGeneration != fixture.membershipAuthorityGeneration+1 ||
		result.bindingVersion != fixture.bindingVersion+1 ||
		result.bindingAuthorityGeneration != fixture.bindingAuthorityGeneration+1 ||
		!result.expiresAt.Equal(membershipExpiresAt) ||
		!result.expiresAt.Equal(bindingExpiresAt) || !result.expiresAt.After(evaluatedAt) {
		return renewalResult{}, errInvalidInput
	}
	result.expiresAt = result.expiresAt.UTC()
	return result, nil
}

func appendRenewalEvidence(
	ctx context.Context,
	transaction pgx.Tx,
	spec seedSpec,
	scope seedScope,
	ids seedIDs,
	fixture renewalFixture,
	result renewalResult,
) error {
	if transaction == nil || !spec.isValid() || !scope.isValid() ||
		!fixture.isValid(scope, fixture.bindingExpiresAt) || result.expiresAt.IsZero() {
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
		return fmt.Errorf("lock renewal audit stream: %w", err)
	}
	if !validPositiveInt64(streamID) || !validPositiveInt64(nextSequence) ||
		len(previousHashBytes) != sha256.Size {
		return errInvalidInput
	}
	var previousHash [sha256.Size]byte
	copy(previousHash[:], previousHashBytes)

	previousExpiry := fixture.bindingExpiresAt.UTC().Format(time.RFC3339Nano)
	newExpiry := result.expiresAt.UTC().Format(time.RFC3339Nano)
	beforePayload, err := json.Marshal(renewalSemanticState{
		MembershipID:                   fixture.membershipPublicID.String(),
		MembershipVersion:              fixture.membershipVersion,
		MembershipAuthorityGeneration:  fixture.membershipAuthorityGeneration,
		RoleBindingID:                  fixture.bindingPublicID.String(),
		RoleBindingVersion:             fixture.bindingVersion,
		RoleBindingAuthorityGeneration: fixture.bindingAuthorityGeneration,
		ExpiresAt:                      previousExpiry,
	})
	if err != nil {
		return fmt.Errorf("encode renewal before state: %w", err)
	}
	afterPayload, err := json.Marshal(renewalSemanticState{
		SessionID:                      ids.session.String(),
		MembershipID:                   fixture.membershipPublicID.String(),
		MembershipVersion:              result.membershipVersion,
		MembershipAuthorityGeneration:  result.membershipAuthorityGeneration,
		RoleBindingID:                  fixture.bindingPublicID.String(),
		RoleBindingVersion:             result.bindingVersion,
		RoleBindingAuthorityGeneration: result.bindingAuthorityGeneration,
		ExpiresAt:                      newExpiry,
	})
	if err != nil {
		return fmt.Errorf("encode renewal after state: %w", err)
	}
	auditPayload, err := json.Marshal(renewalAuditPayload{
		AuditReason:                    spec.auditReason,
		QualificationOnly:              true,
		SessionID:                      ids.session.String(),
		IdentitySubjectID:              fixture.subjectPublicID.String(),
		MembershipID:                   fixture.membershipPublicID.String(),
		MembershipPreviousVersion:      fixture.membershipVersion,
		MembershipVersion:              result.membershipVersion,
		MembershipAuthorityGeneration:  result.membershipAuthorityGeneration,
		RoleDefinitionID:               fixture.roleDefinitionPublicID.String(),
		RoleBindingID:                  fixture.bindingPublicID.String(),
		RoleBindingPreviousVersion:     fixture.bindingVersion,
		RoleBindingVersion:             result.bindingVersion,
		RoleBindingAuthorityGeneration: result.bindingAuthorityGeneration,
		Permission:                     deviceManagePermission,
		PreviousExpiresAt:              previousExpiry,
		ExpiresAt:                      newExpiry,
	})
	if err != nil {
		return fmt.Errorf("encode renewal audit payload: %w", err)
	}
	outboxPayload, err := json.Marshal(seedOutboxPayload{
		NetworkRevision: scope.networkRevision,
		Fixture:         "management_session_renewal",
		ExpiresAt:       newExpiry,
	})
	if err != nil {
		return fmt.Errorf("encode renewal outbox payload: %w", err)
	}
	beforeSemanticHash := sha256.Sum256(beforePayload)
	afterSemanticHash := sha256.Sum256(afterPayload)
	auditPayloadHash := sha256.Sum256(auditPayload)
	outboxPayloadHash := sha256.Sum256(outboxPayload)
	eventHash, err := audit.HashEvent(audit.EventHashMaterial{
		PreviousHash:       previousHash,
		EventID:            ids.event,
		ChangeID:           ids.change,
		AggregateKind:      "role_binding",
		AggregateID:        fixture.bindingPublicID,
		AggregateVersion:   result.bindingVersion,
		NetworkRevision:    scope.networkRevision,
		ActorPrincipalID:   publicid.ID(spec.principalID),
		Action:             renewalOutboxEventClass,
		Permission:         "system.bootstrap",
		CorrelationID:      ids.session,
		BeforeSemanticHash: beforeSemanticHash,
		AfterSemanticHash:  afterSemanticHash,
		AuditPayloadHash:   auditPayloadHash,
		OutboxEventClass:   renewalOutboxEventClass,
		OutboxPayloadHash:  outboxPayloadHash,
	})
	if err != nil {
		return fmt.Errorf("hash renewal audit event: %w", err)
	}
	var appendedSequence int64
	if err := transaction.QueryRow(
		ctx,
		appendRenewalEvidenceSQL,
		streamID,
		ids.event.String(),
		ids.outbox.String(),
		nextSequence,
		previousHash[:],
		eventHash[:],
		fixture.bindingPublicID.String(),
		result.bindingVersion,
		scope.networkRevision,
		spec.principalID.String(),
		ids.session.String(),
		beforeSemanticHash[:],
		afterSemanticHash[:],
		auditPayload,
		outboxPayload,
	).Scan(&appendedSequence); err != nil {
		return fmt.Errorf("append renewal audit and outbox evidence: %w", err)
	}
	if appendedSequence != nextSequence {
		return errors.New("renewal audit sequence mismatch")
	}
	return nil
}
