package postgres

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/resource"
	authority "github.com/meshtransit/meshtransit/internal/resource/authority"
	"github.com/meshtransit/meshtransit/internal/workspace"
)

const (
	resourceAuthorityChangeRequestOperation      = "resource_authority_change.request"
	resourceAuthorityChangeConfirmationOperation = "resource_authority_change.confirm"
	resourceAuthorityChangeRequestResultKind     = "resource_authority_change_request"
	resourceAuthorityChangeResultKind            = "resource_authority_change"
)

type resourceAuthorityChangeRequestPayload struct {
	SubjectKind       string `json:"subject_kind"`
	SubjectPublicID   string `json:"subject_public_id"`
	Action            string `json:"action"`
	TargetPrincipalID string `json:"target_principal_id"`
	SubsystemRevision int64  `json:"subsystem_revision"`
	ImpactHash        string `json:"impact_hash"`
	ExpiresAt         string `json:"expires_at"`
}

type resourceAuthorityChangeResultPayload struct {
	SubjectKind          string `json:"subject_kind"`
	SubjectPublicID      string `json:"subject_public_id"`
	Action               string `json:"action"`
	RequestVersion       int64  `json:"request_version"`
	SubsystemRevision    int64  `json:"subsystem_revision"`
	OwnerPrincipalID     string `json:"owner_principal_id"`
	CustodianPrincipalID string `json:"custodian_principal_id"`
	SemanticHash         string `json:"semantic_hash"`
	ImpactHash           string `json:"impact_hash"`
}

func scanResourceAuthorityChangeImpact(
	row resourceAuthorityRow,
	preview authority.ChangePreview,
) (authority.ChangeImpact, error) {
	if preview.SubjectKind() == authority.AuthoritySubjectGroup {
		return scanResourceGroupAuthorityChangeImpact(row, preview)
	}
	var displayNameValue, ownerIDValue, custodianIDValue, stateValue string
	var deviceIDValue, targetPrincipalIDValue string
	var version, targetGeneration int64
	var semanticHashValue []byte
	if err := row.Scan(
		&displayNameValue, &ownerIDValue, &custodianIDValue, &stateValue,
		&version, &semanticHashValue, &deviceIDValue, &targetGeneration,
		&targetPrincipalIDValue,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return authority.ChangeImpact{}, authority.ErrAuthorityChangeNotFound
		}
		return authority.ChangeImpact{}, err
	}
	if version != preview.ExpectedVersion() {
		return authority.ChangeImpact{}, authority.ErrAuthorityChangeVersionConflict
	}
	if stateValue == "deleted" {
		return authority.ChangeImpact{}, authority.ErrAuthorityChangeStateConflict
	}
	displayName, err := resource.ParseDisplayName(displayNameValue)
	if err != nil {
		return authority.ChangeImpact{}, ErrResourceAuthorityEvidence
	}
	ownerID, custodianID, targetPrincipalID, err := parseAuthorityChangePrincipals(
		ownerIDValue, custodianIDValue, targetPrincipalIDValue,
	)
	if err != nil || targetPrincipalID != preview.TargetPrincipalID() {
		return authority.ChangeImpact{}, ErrResourceAuthorityEvidence
	}
	if ownerID != preview.AccountSession().PrincipalID() {
		return authority.ChangeImpact{}, authority.ErrForbidden
	}
	if preview.Action() == authority.AuthorityChangeDelegateCustodian &&
		targetPrincipalID == custodianID {
		return authority.ChangeImpact{}, authority.ErrAuthorityChangeTargetConflict
	}
	deviceID, err := parseAuthorityChangeDeviceID(deviceIDValue)
	if err != nil {
		return authority.ChangeImpact{}, err
	}
	currentRevision, err := resource.NewDeviceRevision(resource.DeviceRevisionParams{
		Scope: preview.Scope(), DisplayName: displayName,
		OwnerPrincipalID: ownerID, CustodianPrincipalID: custodianID,
		DeviceID: deviceID, TargetGeneration: targetGeneration,
	})
	if err != nil {
		return authority.ChangeImpact{}, ErrResourceAuthorityEvidence
	}
	currentHash, err := resourceSemanticHash(semanticHashValue)
	if err != nil || currentRevision.SemanticHash() != currentHash {
		return authority.ChangeImpact{}, ErrResourceAuthorityEvidence
	}
	proposedOwnerID, proposedCustodianID := proposedAuthorityChangePrincipals(
		preview.Action(), ownerID, custodianID, targetPrincipalID,
	)
	proposedRevision, err := resource.NewDeviceRevision(resource.DeviceRevisionParams{
		Scope: preview.Scope(), DisplayName: displayName,
		OwnerPrincipalID: proposedOwnerID, CustodianPrincipalID: proposedCustodianID,
		DeviceID: deviceID, TargetGeneration: targetGeneration,
	})
	if err != nil {
		return authority.ChangeImpact{}, ErrResourceAuthorityEvidence
	}
	return newResourceAuthorityChangeImpact(
		preview, ownerID, custodianID, proposedOwnerID, proposedCustodianID,
		currentHash, proposedRevision.SemanticHash(),
	)
}

func scanResourceGroupAuthorityChangeImpact(
	row resourceAuthorityRow,
	preview authority.ChangePreview,
) (authority.ChangeImpact, error) {
	var displayNameValue, ownerIDValue, custodianIDValue, stateValue string
	var targetPrincipalIDValue string
	var version, definitionVersion int64
	var semanticHashValue, membersValue []byte
	if err := row.Scan(
		&displayNameValue, &ownerIDValue, &custodianIDValue, &stateValue,
		&version, &definitionVersion, &semanticHashValue, &membersValue,
		&targetPrincipalIDValue,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return authority.ChangeImpact{}, authority.ErrAuthorityChangeNotFound
		}
		return authority.ChangeImpact{}, err
	}
	if version != preview.ExpectedVersion() {
		return authority.ChangeImpact{}, authority.ErrAuthorityChangeVersionConflict
	}
	if stateValue == "deleted" {
		return authority.ChangeImpact{}, authority.ErrAuthorityChangeStateConflict
	}
	displayName, err := resource.ParseDisplayName(displayNameValue)
	if err != nil {
		return authority.ChangeImpact{}, ErrResourceAuthorityEvidence
	}
	ownerID, custodianID, targetPrincipalID, err := parseAuthorityChangePrincipals(
		ownerIDValue, custodianIDValue, targetPrincipalIDValue,
	)
	if err != nil || targetPrincipalID != preview.TargetPrincipalID() {
		return authority.ChangeImpact{}, ErrResourceAuthorityEvidence
	}
	if ownerID != preview.AccountSession().PrincipalID() {
		return authority.ChangeImpact{}, authority.ErrForbidden
	}
	if preview.Action() == authority.AuthorityChangeDelegateCustodian &&
		targetPrincipalID == custodianID {
		return authority.ChangeImpact{}, authority.ErrAuthorityChangeTargetConflict
	}
	members, err := parseResourceGroupReferences(membersValue, preview.Scope())
	if err != nil {
		return authority.ChangeImpact{}, err
	}
	currentRevision, err := resource.NewGroupRevision(resource.GroupRevisionParams{
		Scope: preview.Scope(), DefinitionVersion: definitionVersion,
		DisplayName: displayName, OwnerPrincipalID: ownerID,
		CustodianPrincipalID: custodianID, Members: members,
	})
	if err != nil {
		return authority.ChangeImpact{}, ErrResourceAuthorityEvidence
	}
	currentHash, err := resourceSemanticHash(semanticHashValue)
	if err != nil || currentRevision.SemanticHash() != currentHash {
		return authority.ChangeImpact{}, ErrResourceAuthorityEvidence
	}
	proposedOwnerID, proposedCustodianID := proposedAuthorityChangePrincipals(
		preview.Action(), ownerID, custodianID, targetPrincipalID,
	)
	proposedRevision, err := resource.NewGroupRevision(resource.GroupRevisionParams{
		Scope: preview.Scope(), DefinitionVersion: definitionVersion,
		DisplayName: displayName, OwnerPrincipalID: proposedOwnerID,
		CustodianPrincipalID: proposedCustodianID, Members: members,
	})
	if err != nil {
		return authority.ChangeImpact{}, ErrResourceAuthorityEvidence
	}
	return newResourceAuthorityChangeImpact(
		preview, ownerID, custodianID, proposedOwnerID, proposedCustodianID,
		currentHash, proposedRevision.SemanticHash(),
	)
}

func parseAuthorityChangePrincipals(
	ownerValue, custodianValue, targetValue string,
) (identity.PrincipalID, identity.PrincipalID, identity.PrincipalID, error) {
	ownerID, err := identity.ParsePrincipalID(ownerValue)
	if err != nil {
		return identity.PrincipalID{}, identity.PrincipalID{}, identity.PrincipalID{},
			ErrResourceAuthorityEvidence
	}
	custodianID, err := identity.ParsePrincipalID(custodianValue)
	if err != nil {
		return identity.PrincipalID{}, identity.PrincipalID{}, identity.PrincipalID{},
			ErrResourceAuthorityEvidence
	}
	targetID, err := identity.ParsePrincipalID(targetValue)
	if err != nil {
		return identity.PrincipalID{}, identity.PrincipalID{}, identity.PrincipalID{},
			ErrResourceAuthorityEvidence
	}
	return ownerID, custodianID, targetID, nil
}

func parseAuthorityChangeDeviceID(value string) (node.ID, error) {
	parsed, err := node.ParseID(value)
	if err != nil {
		return node.ID{}, ErrResourceAuthorityEvidence
	}
	return parsed, nil
}

func proposedAuthorityChangePrincipals(
	action authority.ChangeAction,
	ownerID, custodianID, targetID identity.PrincipalID,
) (identity.PrincipalID, identity.PrincipalID) {
	if action == authority.AuthorityChangeTransferOwner {
		return targetID, custodianID
	}
	return ownerID, targetID
}

func newResourceAuthorityChangeImpact(
	preview authority.ChangePreview,
	ownerID, custodianID, proposedOwnerID, proposedCustodianID identity.PrincipalID,
	currentHash, proposedHash resource.SemanticHash,
) (authority.ChangeImpact, error) {
	impact, err := authority.NewAuthorityChangeImpact(authority.ChangeImpactParams{
		Preview: preview, CurrentOwnerPrincipalID: ownerID,
		CurrentCustodianPrincipalID:  custodianID,
		ProposedOwnerPrincipalID:     proposedOwnerID,
		ProposedCustodianPrincipalID: proposedCustodianID,
		CurrentSemanticHash:          currentHash, ProposedSemanticHash: proposedHash,
	})
	if err != nil {
		return authority.ChangeImpact{}, ErrResourceAuthorityEvidence
	}
	return impact, nil
}

type resourceAuthorityChangeRequestRecord struct {
	subjectKind            string
	subjectPublicID        string
	action                 string
	targetPrincipalID      string
	expectedSubjectVersion int64
	impactHash             []byte
	requestVersion         int64
	requestState           string
	expiresAt              time.Time
	requesterSession       accountsession.Session
}

func scanResourceAuthorityChangeRequest(
	row resourceAuthorityRow,
) (resourceAuthorityChangeRequestRecord, error) {
	var record resourceAuthorityChangeRequestRecord
	var sessionIDValue, deploymentIDValue, principalIDValue, subjectIDValue string
	var loginWorkspaceIDValue string
	var authenticationTime, idleExpiresAt, absoluteExpiresAt time.Time
	var acr *string
	var amr []string
	var sessionVersion, principalGeneration, accountGeneration int64
	var providerGeneration, recoveryEpoch int64
	if err := row.Scan(
		&record.subjectKind, &record.subjectPublicID, &record.action,
		&record.targetPrincipalID, &record.expectedSubjectVersion,
		&record.impactHash, &record.requestVersion, &record.requestState,
		&record.expiresAt, &sessionIDValue, &deploymentIDValue, &principalIDValue,
		&subjectIDValue, &loginWorkspaceIDValue, &authenticationTime, &acr, &amr,
		&sessionVersion, &principalGeneration, &accountGeneration,
		&providerGeneration, &recoveryEpoch, &idleExpiresAt, &absoluteExpiresAt,
	); err != nil {
		return resourceAuthorityChangeRequestRecord{}, err
	}
	sessionID, err := accountsession.ParseID(sessionIDValue)
	if err != nil {
		return resourceAuthorityChangeRequestRecord{}, ErrResourceAuthorityEvidence
	}
	deploymentID, err := deployment.ParseID(deploymentIDValue)
	if err != nil {
		return resourceAuthorityChangeRequestRecord{}, ErrResourceAuthorityEvidence
	}
	principalID, err := identity.ParsePrincipalID(principalIDValue)
	if err != nil {
		return resourceAuthorityChangeRequestRecord{}, ErrResourceAuthorityEvidence
	}
	subjectID, err := accountsession.ParseIdentitySubjectID(subjectIDValue)
	if err != nil {
		return resourceAuthorityChangeRequestRecord{}, ErrResourceAuthorityEvidence
	}
	loginWorkspaceID, err := workspace.ParseID(loginWorkspaceIDValue)
	if err != nil {
		return resourceAuthorityChangeRequestRecord{}, ErrResourceAuthorityEvidence
	}
	acrValue := ""
	if acr != nil {
		acrValue = *acr
	}
	record.requesterSession, err = accountsession.NewSession(accountsession.Params{
		ID: sessionID, DeploymentID: deploymentID, PrincipalID: principalID,
		IdentitySubjectID: subjectID, LoginWorkspaceID: loginWorkspaceID,
		HasLoginWorkspace: true, AuthenticationTime: authenticationTime,
		ACR: acrValue, AMR: amr, Version: sessionVersion,
		PrincipalAuthorityGeneration: principalGeneration,
		AccountSessionGeneration:     accountGeneration, ProviderGeneration: providerGeneration,
		DeploymentRecoveryEpoch: recoveryEpoch, IdleExpiresAt: idleExpiresAt,
		AbsoluteExpiresAt: absoluteExpiresAt,
	})
	if err != nil {
		return resourceAuthorityChangeRequestRecord{}, ErrResourceAuthorityEvidence
	}
	record.expiresAt = record.expiresAt.UTC()
	return record, nil
}

func authorityChangeImpactHash(value []byte) (authority.ChangeImpactHash, error) {
	var fixed [32]byte
	if len(value) != len(fixed) {
		return authority.ChangeImpactHash{}, ErrResourceAuthorityEvidence
	}
	copy(fixed[:], value)
	hash, err := authority.NewAuthorityChangeImpactHash(fixed)
	if err != nil {
		return authority.ChangeImpactHash{}, ErrResourceAuthorityEvidence
	}
	return hash, nil
}

func authorityChangeRequestHash(value []byte) (authority.ChangeRequestHash, error) {
	var fixed [32]byte
	if len(value) != len(fixed) {
		return authority.ChangeRequestHash{}, ErrResourceAuthorityEvidence
	}
	copy(fixed[:], value)
	hash, err := authority.NewAuthorityChangeRequestHash(fixed)
	if err != nil {
		return authority.ChangeRequestHash{}, ErrResourceAuthorityEvidence
	}
	return hash, nil
}

func authorityChangeConfirmationHash(
	value []byte,
) (authority.ChangeConfirmationHash, error) {
	var fixed [32]byte
	if len(value) != len(fixed) {
		return authority.ChangeConfirmationHash{}, ErrResourceAuthorityEvidence
	}
	copy(fixed[:], value)
	hash, err := authority.NewAuthorityChangeConfirmationHash(fixed)
	if err != nil {
		return authority.ChangeConfirmationHash{}, ErrResourceAuthorityEvidence
	}
	return hash, nil
}

func decodeAuthorityChangeImpactHash(value string) (authority.ChangeImpactHash, error) {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return authority.ChangeImpactHash{}, ErrResourceAuthorityEvidence
	}
	return authorityChangeImpactHash(decoded)
}

func decodeAuthorityChangePayload(
	value string,
	destination any,
) error {
	if err := json.Unmarshal([]byte(value), destination); err != nil {
		return ErrResourceAuthorityEvidence
	}
	return nil
}
