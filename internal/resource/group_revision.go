package resource

import (
	"math"
	"slices"
	"strings"

	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/network"
)

// GroupRevisionParams contains one complete immutable Resource Group definition.
type GroupRevisionParams struct {
	Scope                network.Scope
	DisplayName          DisplayName
	OwnerPrincipalID     identity.PrincipalID
	CustodianPrincipalID identity.PrincipalID
	DefinitionVersion    int64
	Members              []Reference
}

// GroupRevision is one immutable Resource Group definition version.
type GroupRevision struct {
	scope                network.Scope
	displayName          DisplayName
	ownerPrincipalID     identity.PrincipalID
	custodianPrincipalID identity.PrincipalID
	definitionVersion    int64
	members              []Reference
	semanticHash         SemanticHash
}

// NewGroupRevision validates, canonicalizes, and hashes one complete definition version.
func NewGroupRevision(params GroupRevisionParams) (GroupRevision, error) {
	members := slices.Clone(params.Members)
	slices.SortFunc(members, func(left, right Reference) int {
		return strings.Compare(left.ResourceID().String(), right.ResourceID().String())
	})
	revision := GroupRevision{
		scope: params.Scope, displayName: params.DisplayName,
		ownerPrincipalID: params.OwnerPrincipalID, custodianPrincipalID: params.CustodianPrincipalID,
		definitionVersion: params.DefinitionVersion, members: members,
	}
	if !validGroupRevisionFields(revision) {
		return GroupRevision{}, ErrInvalidGroupDefinition
	}
	revision.semanticHash = hashGroupRevision(revision)
	return revision, nil
}

// Scope returns the exact home Network scope.
func (revision GroupRevision) Scope() network.Scope { return revision.scope }

// DisplayName returns immutable presentation text.
func (revision GroupRevision) DisplayName() DisplayName { return revision.displayName }

// OwnerPrincipalID returns the immutable accountability owner.
func (revision GroupRevision) OwnerPrincipalID() identity.PrincipalID {
	return revision.ownerPrincipalID
}

// CustodianPrincipalID returns the immutable operational custodian.
func (revision GroupRevision) CustodianPrincipalID() identity.PrincipalID {
	return revision.custodianPrincipalID
}

// DefinitionVersion returns the monotonic immutable definition version.
func (revision GroupRevision) DefinitionVersion() int64 { return revision.definitionVersion }

// Members returns a caller-owned canonical membership snapshot.
func (revision GroupRevision) Members() []Reference { return slices.Clone(revision.members) }

// SemanticHash returns canonical definition semantics.
func (revision GroupRevision) SemanticHash() SemanticHash { return revision.semanticHash }

// IsValid reports whether fields, canonical order, and digest agree.
func (revision GroupRevision) IsValid() bool {
	return validGroupRevisionFields(revision) && revision.semanticHash.IsValid() &&
		revision.semanticHash == hashGroupRevision(revision)
}

func validGroupRevisionFields(revision GroupRevision) bool {
	if !revision.scope.IsValid() || !revision.displayName.IsValid() ||
		!revision.ownerPrincipalID.IsValid() || !revision.custodianPrincipalID.IsValid() ||
		revision.definitionVersion <= 0 || revision.definitionVersion == math.MaxInt64 ||
		len(revision.members) == 0 || len(revision.members) > MaximumGroupMembers {
		return false
	}
	for index, member := range revision.members {
		if !member.IsValid() || member.Scope() != revision.scope ||
			(index > 0 && revision.members[index-1].ResourceID().String() >= member.ResourceID().String()) {
			return false
		}
	}
	return true
}

func hashGroupRevision(revision GroupRevision) SemanticHash {
	return hashGroupDefinition(GroupDefinition{
		scope: revision.scope, displayName: revision.displayName,
		ownerPrincipalID:     revision.ownerPrincipalID,
		custodianPrincipalID: revision.custodianPrincipalID,
		members:              revision.members,
	})
}
