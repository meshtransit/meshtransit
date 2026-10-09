package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/core/internal/domain/authorization"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	publication "github.com/meshtransit/meshtransit/core/internal/domain/policy/publication"
	"github.com/meshtransit/meshtransit/core/internal/domain/publicid"
)

type policyPublicationApprovalRecord struct {
	requestID         string
	evidenceID        string
	baseline          [8]int64
	proposed          [8]int64
	candidateHash     []byte
	compilerFormat    int
	impactHash        []byte
	requestVersion    int64
	evidenceVersion   int64
	approvedAt        time.Time
	expiresAt         time.Time
	sessionID         string
	deploymentID      string
	principalID       string
	identitySubjectID string
	sessionVersion    int64
	principalGen      int64
	accountGen        int64
	providerGen       int64
	recoveryEpoch     int64
}

func scanPolicyPublicationApproval(row policyPublicationRow) (policyPublicationApprovalRecord, error) {
	var record policyPublicationApprovalRecord
	destinations := []any{&record.requestID, &record.evidenceID}
	for index := range record.baseline {
		destinations = append(destinations, &record.baseline[index])
	}
	for index := range record.proposed {
		destinations = append(destinations, &record.proposed[index])
	}
	destinations = append(
		destinations,
		&record.candidateHash, &record.compilerFormat, &record.impactHash,
		&record.requestVersion, &record.evidenceVersion, &record.approvedAt, &record.expiresAt,
		&record.sessionID, &record.deploymentID, &record.principalID, &record.identitySubjectID,
		&record.sessionVersion, &record.principalGen, &record.accountGen,
		&record.providerGen, &record.recoveryEpoch,
	)
	if err := row.Scan(destinations...); err != nil {
		return policyPublicationApprovalRecord{}, err
	}
	return record, nil
}

func (record policyPublicationApprovalRecord) gate(scope network.Scope) (publication.ApprovalGate, error) {
	requestID, requestErr := publication.ParseApprovalRequestID(record.requestID)
	evidenceID, evidenceErr := publication.ParseApprovalEvidenceID(record.evidenceID)
	baseline, baselineErr := policyPublicationAuthorityVector(record.baseline)
	proposed, proposedErr := policyPublicationAuthorityVector(record.proposed)
	candidateHash, candidateErr := policyPublicationSemanticHash(record.candidateHash)
	impactHash, impactErr := policyPublicationApprovalImpactHash(record.impactHash)
	if requestErr != nil || evidenceErr != nil || baselineErr != nil || proposedErr != nil ||
		candidateErr != nil || impactErr != nil {
		return publication.ApprovalGate{}, errors.Join(
			publication.ErrInvalidApprovalGate,
			requestErr, evidenceErr, baselineErr, proposedErr, candidateErr, impactErr,
		)
	}
	return publication.NewApprovalGate(publication.ApprovalGateParams{
		Scope: scope, RequestID: requestID, EvidenceID: evidenceID,
		BaselineVector: baseline, ProposedVector: proposed,
		CandidateSemanticHash: candidateHash, CompilerFormatVersion: record.compilerFormat,
		ImpactHash: impactHash, RequestVersion: record.requestVersion,
		EvidenceVersion: record.evidenceVersion,
		ApprovedAt:      record.approvedAt, ExpiresAt: record.expiresAt,
	})
}

func policyPublicationAuthorityVector(values [8]int64) (publication.AuthorityVector, error) {
	return publication.NewAuthorityVector(publication.AuthorityVectorParams{
		NetworkRevision: values[0], InventoryRevision: values[1], GroupRevision: values[2],
		PolicyRevision: values[3], DNSRevision: values[4], RouteRevision: values[5],
		SharingRevision: values[6], IsolationGeneration: values[7],
	})
}

func policyPublicationApprovalImpactHash(value []byte) (publication.ApprovalImpactHash, error) {
	if len(value) != sha256.Size {
		return publication.ApprovalImpactHash{}, publication.ErrInvalidApprovalGate
	}
	var hashValue [sha256.Size]byte
	copy(hashValue[:], value)
	return publication.NewApprovalImpactHash(hashValue)
}

func (transaction *policyPublicationTransaction) resolveApprovalGate(
	ctx context.Context,
	command publication.Command,
	evaluatedAt time.Time,
) (publication.ApprovalGate, error) {
	record, err := scanPolicyPublicationApproval(transaction.database.QueryRow(
		ctx,
		lockPolicyPublicationApprovalSQL,
		command.ApprovalEvidenceID().String(),
		evaluatedAt,
	))
	if errors.Is(err, pgx.ErrNoRows) {
		return publication.ApprovalGate{}, publication.ErrApprovalUnavailable
	}
	if err != nil {
		return publication.ApprovalGate{}, fmt.Errorf("lock Policy approval evidence: %w", err)
	}
	gate, err := record.gate(transaction.scope)
	if err != nil || gate.EvidenceID() != command.ApprovalEvidenceID() ||
		gate.CandidateSemanticHash() != command.Candidate().SemanticHash() ||
		gate.CompilerFormatVersion() != command.Candidate().CompilerFormatVersion() ||
		!gate.ExpiresAt().After(evaluatedAt) {
		return publication.ApprovalGate{}, errors.Join(publication.ErrApprovalUnavailable, err)
	}
	authorizationEvidence, err := transaction.resolveApprovalAuthorization(ctx, record, evaluatedAt)
	if err != nil {
		return publication.ApprovalGate{}, err
	}
	transaction.approvalAuthorization = authorizationEvidence
	return gate, nil
}

func (transaction *policyPublicationTransaction) resolveApprovalAuthorization(
	ctx context.Context,
	record policyPublicationApprovalRecord,
	evaluatedAt time.Time,
) (policyPublicationAuthorizationEvidence, error) {
	var bindingIDValue, roleIDValue string
	var scopeGeneration, membershipGeneration, bindingGeneration, roleGeneration int64
	var ownerGeneration int64
	var hasExpiry bool
	var expiresAt time.Time
	err := transaction.database.QueryRow(
		ctx,
		authorizePolicyPublicationSQL,
		record.sessionID,
		record.deploymentID,
		record.principalID,
		record.identitySubjectID,
		record.sessionVersion,
		record.principalGen,
		record.accountGen,
		record.providerGen,
		record.recoveryEpoch,
		transaction.scope.WorkspaceID().String(),
		transaction.scope.NetworkID().String(),
		string(authorization.PermissionPolicyApprove),
		evaluatedAt,
	).Scan(
		&bindingIDValue, &roleIDValue, &scopeGeneration, &membershipGeneration,
		&bindingGeneration, &roleGeneration, &hasExpiry, &expiresAt, &ownerGeneration,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return policyPublicationAuthorizationEvidence{}, publication.ErrApprovalUnavailable
	}
	if err != nil {
		return policyPublicationAuthorizationEvidence{}, fmt.Errorf("authorize policy.approve: %w", err)
	}
	if hasExpiry && !expiresAt.After(evaluatedAt) {
		return policyPublicationAuthorizationEvidence{}, publication.ErrApprovalUnavailable
	}
	sessionID, sessionErr := publicid.Parse(record.sessionID)
	bindingID, roleID, authorityErr := parseNetworkPermissionAuthority(bindingIDValue, roleIDValue, ownerGeneration)
	evidence := policyPublicationAuthorizationEvidence{
		accountSessionID: sessionID, roleBindingID: bindingID, roleDefinitionID: roleID,
		scopeAuthorityGeneration:          scopeGeneration,
		membershipAuthorityGeneration:     membershipGeneration,
		bindingAuthorityGeneration:        bindingGeneration,
		roleAuthorityGeneration:           roleGeneration,
		workspaceOwnerAuthorityGeneration: ownerGeneration,
	}
	if sessionErr != nil || authorityErr != nil || !evidence.isValid() {
		return policyPublicationAuthorizationEvidence{}, ErrPolicyPublicationEvidence
	}
	return evidence, nil
}
