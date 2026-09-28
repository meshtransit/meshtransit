package authority

import (
	"crypto/sha256"
	"errors"
	"math"
	"time"

	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/publicid"
	"github.com/meshtransit/meshtransit/internal/resource"
)

const (
	authorityChangeImpactHashDomain = "meshtransit/resource-authority-change-impact/v1\x00"

	// MaximumAuthorityChangeStepUpAge bounds provider authentication evidence.
	MaximumAuthorityChangeStepUpAge = 5 * time.Minute
	// AuthorityChangeRequestLifetime bounds an unconfirmed two-person request.
	AuthorityChangeRequestLifetime = 10 * time.Minute
	// RequiredAuthorityChangeConfirmations is the v1 second-actor quorum.
	RequiredAuthorityChangeConfirmations = 1
)

var (
	// ErrInvalidAuthorityChangePreview reports incomplete protected-change intent.
	ErrInvalidAuthorityChangePreview = errors.New("resource authority change: invalid preview")
	// ErrInvalidAuthorityChangeImpact reports inconsistent before/after evidence.
	ErrInvalidAuthorityChangeImpact = errors.New("resource authority change: invalid impact")
	// ErrAuthorityChangeNotFound hides absent and cross-scope authority.
	ErrAuthorityChangeNotFound = errors.New("resource authority change: authority unavailable")
	// ErrAuthorityChangeVersionConflict reports a stale object precondition.
	ErrAuthorityChangeVersionConflict = errors.New("resource authority change: stale version")
	// ErrAuthorityChangeStateConflict reports ineligible retained authority.
	ErrAuthorityChangeStateConflict = errors.New("resource authority change: state conflict")
	// ErrAuthorityChangeTargetConflict reports an ineligible proposed Principal.
	ErrAuthorityChangeTargetConflict = errors.New("resource authority change: target conflict")
	// ErrAuthorityChangeImpactChanged reports stale acknowledged evidence.
	ErrAuthorityChangeImpactChanged = errors.New("resource authority change: impact changed")
	// ErrAuthorityChangeStepUpRequired reports absent, stale, reused, or weak evidence.
	ErrAuthorityChangeStepUpRequired = errors.New("resource authority change: step-up required")
	// ErrAuthorityChangeConfirmationRequired reports a pending second-actor quorum.
	ErrAuthorityChangeConfirmationRequired = errors.New("resource authority change: confirmation required")
)

// SubjectKind identifies the protected aggregate type.
type SubjectKind uint8

const (
	// AuthoritySubjectUnknown is the unusable zero value.
	AuthoritySubjectUnknown SubjectKind = iota
	// AuthoritySubjectResource changes Device Resource authority.
	AuthoritySubjectResource
	// AuthoritySubjectGroup changes Resource Group authority.
	AuthoritySubjectGroup
)

// String returns the stable persistence and audit identifier.
func (kind SubjectKind) String() string {
	switch kind {
	case AuthoritySubjectResource:
		return "resource"
	case AuthoritySubjectGroup:
		return "resource_group"
	default:
		return "unknown"
	}
}

// ParseAuthoritySubjectKind validates a persistence boundary value.
func ParseAuthoritySubjectKind(value string) (SubjectKind, error) {
	switch value {
	case "resource":
		return AuthoritySubjectResource, nil
	case "resource_group":
		return AuthoritySubjectGroup, nil
	default:
		return AuthoritySubjectUnknown, ErrInvalidAuthorityChangePreview
	}
}

// ChangeAction identifies the one authority field that may change.
type ChangeAction uint8

const (
	// AuthorityChangeUnknown is the unusable zero value.
	AuthorityChangeUnknown ChangeAction = iota
	// AuthorityChangeTransferOwner transfers ownership to a consenting Principal.
	AuthorityChangeTransferOwner
	// AuthorityChangeDelegateCustodian delegates custody to a consenting Principal.
	AuthorityChangeDelegateCustodian
)

// String returns the stable wire, persistence, and audit identifier.
func (action ChangeAction) String() string {
	switch action {
	case AuthorityChangeTransferOwner:
		return "owner_transfer"
	case AuthorityChangeDelegateCustodian:
		return "custodian_delegation"
	default:
		return "unknown"
	}
}

// ParseAuthorityChangeAction validates a wire or persistence boundary value.
func ParseAuthorityChangeAction(value string) (ChangeAction, error) {
	switch value {
	case "owner_transfer":
		return AuthorityChangeTransferOwner, nil
	case "custodian_delegation":
		return AuthorityChangeDelegateCustodian, nil
	default:
		return AuthorityChangeUnknown, ErrInvalidAuthorityChangePreview
	}
}

// ChangePreview is one authenticated, version-bound protected intent.
type ChangePreview struct {
	scope             network.Scope
	subjectKind       SubjectKind
	resourceID        resource.ID
	groupID           resource.GroupID
	expectedVersion   int64
	action            ChangeAction
	targetPrincipalID identity.PrincipalID
	accountSession    accountsession.Session
}

// NewResourceAuthorityChangePreview validates Resource authority-change intent.
func NewResourceAuthorityChangePreview(
	scope network.Scope,
	resourceID resource.ID,
	expectedVersion int64,
	action ChangeAction,
	targetPrincipalID identity.PrincipalID,
	session accountsession.Session,
) (ChangePreview, error) {
	preview := ChangePreview{
		scope: scope, subjectKind: AuthoritySubjectResource, resourceID: resourceID,
		expectedVersion: expectedVersion, action: action,
		targetPrincipalID: targetPrincipalID, accountSession: session,
	}
	if !preview.IsValid() {
		return ChangePreview{}, ErrInvalidAuthorityChangePreview
	}
	return preview, nil
}

// NewGroupAuthorityChangePreview validates Resource Group authority-change intent.
func NewGroupAuthorityChangePreview(
	scope network.Scope,
	groupID resource.GroupID,
	expectedVersion int64,
	action ChangeAction,
	targetPrincipalID identity.PrincipalID,
	session accountsession.Session,
) (ChangePreview, error) {
	preview := ChangePreview{
		scope: scope, subjectKind: AuthoritySubjectGroup, groupID: groupID,
		expectedVersion: expectedVersion, action: action,
		targetPrincipalID: targetPrincipalID, accountSession: session,
	}
	if !preview.IsValid() {
		return ChangePreview{}, ErrInvalidAuthorityChangePreview
	}
	return preview, nil
}

// Scope returns the exact home Network scope.
func (preview ChangePreview) Scope() network.Scope { return preview.scope }

// SubjectKind returns the protected aggregate type.
func (preview ChangePreview) SubjectKind() SubjectKind {
	return preview.subjectKind
}

// ResourceID returns the Resource identity when SubjectKind is Resource.
func (preview ChangePreview) ResourceID() resource.ID { return preview.resourceID }

// GroupID returns the Resource Group identity when SubjectKind is Group.
func (preview ChangePreview) GroupID() resource.GroupID { return preview.groupID }

// SubjectPublicID returns the exact aggregate identity without erasing its kind.
func (preview ChangePreview) SubjectPublicID() publicid.ID {
	if preview.subjectKind == AuthoritySubjectGroup {
		return publicid.ID(preview.groupID)
	}
	return publicid.ID(preview.resourceID)
}

// ExpectedVersion returns the aggregate CAS base.
func (preview ChangePreview) ExpectedVersion() int64 { return preview.expectedVersion }

// Action returns the requested protected authority operation.
func (preview ChangePreview) Action() ChangeAction { return preview.action }

// TargetPrincipalID returns the consenting proposed authority holder.
func (preview ChangePreview) TargetPrincipalID() identity.PrincipalID {
	return preview.targetPrincipalID
}

// AccountSession returns current authenticated request evidence.
func (preview ChangePreview) AccountSession() accountsession.Session {
	return preview.accountSession
}

// IsValid reports whether intent is complete, typed, and bounded.
func (preview ChangePreview) IsValid() bool {
	if !preview.scope.IsValid() || preview.expectedVersion <= 0 ||
		preview.expectedVersion == math.MaxInt64 || !preview.targetPrincipalID.IsValid() ||
		!preview.accountSession.IsValid() ||
		preview.targetPrincipalID == preview.accountSession.PrincipalID() ||
		preview.action <= AuthorityChangeUnknown ||
		preview.action > AuthorityChangeDelegateCustodian {
		return false
	}
	switch preview.subjectKind {
	case AuthoritySubjectResource:
		return preview.resourceID.IsValid() && !preview.groupID.IsValid()
	case AuthoritySubjectGroup:
		return preview.groupID.IsValid() && !preview.resourceID.IsValid()
	default:
		return false
	}
}

// ChangeImpactParams contains authoritative before and proposed state.
type ChangeImpactParams struct {
	Preview                      ChangePreview
	CurrentOwnerPrincipalID      identity.PrincipalID
	CurrentCustodianPrincipalID  identity.PrincipalID
	ProposedOwnerPrincipalID     identity.PrincipalID
	ProposedCustodianPrincipalID identity.PrincipalID
	CurrentSemanticHash          resource.SemanticHash
	ProposedSemanticHash         resource.SemanticHash
}

// ChangeImpact is deterministic two-person acknowledgement evidence.
type ChangeImpact struct {
	preview                      ChangePreview
	currentOwnerPrincipalID      identity.PrincipalID
	currentCustodianPrincipalID  identity.PrincipalID
	proposedOwnerPrincipalID     identity.PrincipalID
	proposedCustodianPrincipalID identity.PrincipalID
	currentSemanticHash          resource.SemanticHash
	proposedSemanticHash         resource.SemanticHash
	hash                         ChangeImpactHash
}

// NewAuthorityChangeImpact validates and hashes one protected authority change.
func NewAuthorityChangeImpact(
	params ChangeImpactParams,
) (ChangeImpact, error) {
	impact := ChangeImpact{
		preview:                      params.Preview,
		currentOwnerPrincipalID:      params.CurrentOwnerPrincipalID,
		currentCustodianPrincipalID:  params.CurrentCustodianPrincipalID,
		proposedOwnerPrincipalID:     params.ProposedOwnerPrincipalID,
		proposedCustodianPrincipalID: params.ProposedCustodianPrincipalID,
		currentSemanticHash:          params.CurrentSemanticHash,
		proposedSemanticHash:         params.ProposedSemanticHash,
	}
	if !validAuthorityChangeImpactFields(impact) {
		return ChangeImpact{}, ErrInvalidAuthorityChangeImpact
	}
	impact.hash = hashAuthorityChangeImpact(impact)
	return impact, nil
}

// Preview returns exact protected intent.
func (impact ChangeImpact) Preview() ChangePreview { return impact.preview }

// CurrentOwnerPrincipalID returns current ownership authority.
func (impact ChangeImpact) CurrentOwnerPrincipalID() identity.PrincipalID {
	return impact.currentOwnerPrincipalID
}

// CurrentCustodianPrincipalID returns current operational custody.
func (impact ChangeImpact) CurrentCustodianPrincipalID() identity.PrincipalID {
	return impact.currentCustodianPrincipalID
}

// ProposedOwnerPrincipalID returns ownership after confirmation.
func (impact ChangeImpact) ProposedOwnerPrincipalID() identity.PrincipalID {
	return impact.proposedOwnerPrincipalID
}

// ProposedCustodianPrincipalID returns custody after confirmation.
func (impact ChangeImpact) ProposedCustodianPrincipalID() identity.PrincipalID {
	return impact.proposedCustodianPrincipalID
}

// CurrentSemanticHash returns the exact before-state digest.
func (impact ChangeImpact) CurrentSemanticHash() resource.SemanticHash {
	return impact.currentSemanticHash
}

// ProposedSemanticHash returns the exact confirmed after-state digest.
func (impact ChangeImpact) ProposedSemanticHash() resource.SemanticHash {
	return impact.proposedSemanticHash
}

// ConfirmationPrincipalID returns the required independent actor.
func (impact ChangeImpact) ConfirmationPrincipalID() identity.PrincipalID {
	return impact.preview.TargetPrincipalID()
}

// RequiredConfirmations returns the fixed v1 second-actor quorum.
func (ChangeImpact) RequiredConfirmations() int {
	return RequiredAuthorityChangeConfirmations
}

// MaximumStepUpAge returns the operation-bound authentication maximum age.
func (ChangeImpact) MaximumStepUpAge() time.Duration {
	return MaximumAuthorityChangeStepUpAge
}

// Hash returns exact acknowledgement evidence.
func (impact ChangeImpact) Hash() ChangeImpactHash { return impact.hash }

// IsValid reports whether all fields and the digest agree.
func (impact ChangeImpact) IsValid() bool {
	return validAuthorityChangeImpactFields(impact) && impact.hash.IsValid() &&
		impact.hash == hashAuthorityChangeImpact(impact)
}

// Equal reports exact deterministic impact equality.
func (impact ChangeImpact) Equal(other ChangeImpact) bool {
	return impact.IsValid() && other.IsValid() && impact.hash == other.hash
}

func validAuthorityChangeImpactFields(impact ChangeImpact) bool {
	preview := impact.preview
	if !preview.IsValid() || !impact.currentOwnerPrincipalID.IsValid() ||
		!impact.currentCustodianPrincipalID.IsValid() ||
		!impact.proposedOwnerPrincipalID.IsValid() ||
		!impact.proposedCustodianPrincipalID.IsValid() ||
		!impact.currentSemanticHash.IsValid() || !impact.proposedSemanticHash.IsValid() ||
		impact.currentSemanticHash == impact.proposedSemanticHash ||
		impact.currentOwnerPrincipalID != preview.AccountSession().PrincipalID() {
		return false
	}
	switch preview.Action() {
	case AuthorityChangeTransferOwner:
		return impact.proposedOwnerPrincipalID == preview.TargetPrincipalID() &&
			impact.proposedOwnerPrincipalID != impact.currentOwnerPrincipalID &&
			impact.proposedCustodianPrincipalID == impact.currentCustodianPrincipalID
	case AuthorityChangeDelegateCustodian:
		return impact.proposedCustodianPrincipalID == preview.TargetPrincipalID() &&
			impact.proposedCustodianPrincipalID != impact.currentCustodianPrincipalID &&
			impact.proposedOwnerPrincipalID == impact.currentOwnerPrincipalID
	default:
		return false
	}
}

func hashAuthorityChangeImpact(impact ChangeImpact) ChangeImpactHash {
	preview := impact.preview
	material := make([]byte, 0, 512)
	material = append(material, authorityChangeImpactHashDomain...)
	for _, value := range [...]string{
		preview.Scope().WorkspaceID().String(), preview.Scope().NetworkID().String(),
		preview.SubjectKind().String(), preview.SubjectPublicID().String(), preview.Action().String(),
		preview.TargetPrincipalID().String(), impact.currentOwnerPrincipalID.String(),
		impact.currentCustodianPrincipalID.String(), impact.proposedOwnerPrincipalID.String(),
		impact.proposedCustodianPrincipalID.String(),
	} {
		material = appendAuthorityText(material, value)
	}
	material = appendAuthorityInt64(material, preview.ExpectedVersion())
	material = appendAuthorityInt64(material, int64(RequiredAuthorityChangeConfirmations))
	material = appendAuthorityInt64(material, int64(MaximumAuthorityChangeStepUpAge/time.Second))
	currentHash := impact.currentSemanticHash.Bytes()
	proposedHash := impact.proposedSemanticHash.Bytes()
	material = append(material, currentHash[:]...)
	material = append(material, proposedHash[:]...)
	return ChangeImpactHash(sha256.Sum256(material))
}

// ChangeImpactHash is deterministic protected-change evidence.
type ChangeImpactHash [sha256.Size]byte

// NewAuthorityChangeImpactHash validates a non-zero boundary digest.
func NewAuthorityChangeImpactHash(
	value [sha256.Size]byte,
) (ChangeImpactHash, error) {
	hash := ChangeImpactHash(value)
	if !hash.IsValid() {
		return ChangeImpactHash{}, ErrInvalidAuthorityChangeImpact
	}
	return hash, nil
}

// Bytes returns a defensive copy of the digest.
func (hash ChangeImpactHash) Bytes() [sha256.Size]byte {
	return [sha256.Size]byte(hash)
}

// IsValid reports whether acknowledgement evidence is present.
func (hash ChangeImpactHash) IsValid() bool {
	return hash != ChangeImpactHash{}
}
