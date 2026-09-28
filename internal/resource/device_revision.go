package resource

import (
	"crypto/sha256"

	"github.com/meshtransit/meshtransit/internal/identity"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/publicid"
)

// DeviceRevisionParams contains the full authoritative semantics of one
// Device-backed Resource revision.
type DeviceRevisionParams struct {
	Scope                network.Scope
	DisplayName          DisplayName
	OwnerPrincipalID     identity.PrincipalID
	CustodianPrincipalID identity.PrincipalID
	DeviceID             node.ID
	TargetGeneration     int64
}

// DeviceRevision is a complete immutable semantic snapshot used when a stable
// Resource is rebound to another Device.
type DeviceRevision struct {
	scope                network.Scope
	displayName          DisplayName
	ownerPrincipalID     identity.PrincipalID
	custodianPrincipalID identity.PrincipalID
	deviceID             node.ID
	targetGeneration     int64
	semanticHash         SemanticHash
}

// NewDeviceRevision validates and hashes one Device-backed Resource revision.
func NewDeviceRevision(params DeviceRevisionParams) (DeviceRevision, error) {
	revision := DeviceRevision{
		scope: params.Scope, displayName: params.DisplayName,
		ownerPrincipalID: params.OwnerPrincipalID, custodianPrincipalID: params.CustodianPrincipalID,
		deviceID: params.DeviceID, targetGeneration: params.TargetGeneration,
	}
	if !validDeviceRevisionFields(revision) {
		return DeviceRevision{}, ErrInvalidDeviceDefinition
	}
	revision.semanticHash = hashDeviceRevision(revision)
	return revision, nil
}

// Scope returns the exact home Network scope.
func (revision DeviceRevision) Scope() network.Scope { return revision.scope }

// DisplayName returns non-authoritative presentation text.
func (revision DeviceRevision) DisplayName() DisplayName { return revision.displayName }

// OwnerPrincipalID returns the current accountability owner.
func (revision DeviceRevision) OwnerPrincipalID() identity.PrincipalID {
	return revision.ownerPrincipalID
}

// CustodianPrincipalID returns the current operational custodian.
func (revision DeviceRevision) CustodianPrincipalID() identity.PrincipalID {
	return revision.custodianPrincipalID
}

// DeviceID returns the proposed typed target.
func (revision DeviceRevision) DeviceID() node.ID { return revision.deviceID }

// TargetGeneration returns the proposed monotonically increasing binding generation.
func (revision DeviceRevision) TargetGeneration() int64 { return revision.targetGeneration }

// SemanticHash returns canonical Resource semantics for this revision.
func (revision DeviceRevision) SemanticHash() SemanticHash { return revision.semanticHash }

// IsValid reports whether all fields and the semantic digest agree.
func (revision DeviceRevision) IsValid() bool {
	return validDeviceRevisionFields(revision) && revision.semanticHash.IsValid() &&
		revision.semanticHash == hashDeviceRevision(revision)
}

func validDeviceRevisionFields(revision DeviceRevision) bool {
	return revision.scope.IsValid() && revision.displayName.IsValid() &&
		revision.ownerPrincipalID.IsValid() && revision.custodianPrincipalID.IsValid() &&
		revision.deviceID.IsValid() && revision.targetGeneration > 0
}

func hashDeviceRevision(revision DeviceRevision) SemanticHash {
	encoded := make([]byte, 0, 160)
	encoded = append(encoded, deviceHashDomain...)
	encoded = appendScope(encoded, revision.scope)
	encoded = appendText(encoded, revision.displayName.String())
	ownerID := revision.ownerPrincipalID.Bytes()
	custodianID := revision.custodianPrincipalID.Bytes()
	deviceID := publicid.ID(revision.deviceID).Bytes()
	encoded = append(encoded, ownerID[:]...)
	encoded = append(encoded, custodianID[:]...)
	encoded = append(encoded, deviceID[:]...)
	encoded = appendInt64(encoded, revision.targetGeneration)
	return SemanticHash(sha256.Sum256(encoded))
}
