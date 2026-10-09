package resource

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

const (
	maximumDisplayNameRunes = 128
	deviceHashDomain        = "meshtransit/resource/device/v1\x00"
	groupHashDomain         = "meshtransit/resource-group/v1\x00"
	// MaximumGroupMembers bounds one immutable Resource Group version.
	MaximumGroupMembers = 256
)

var (
	// ErrInvalidDisplayName reports an empty, malformed, or unsafe presentation name.
	ErrInvalidDisplayName = errors.New("resource: invalid display name")
	// ErrInvalidDeviceDefinition reports inconsistent Resource authority.
	ErrInvalidDeviceDefinition = errors.New("resource: invalid device definition")
	// ErrInvalidReference reports an invalid version-pinned Resource reference.
	ErrInvalidReference = errors.New("resource: invalid reference")
	// ErrInvalidGroupDefinition reports inconsistent Resource Group authority.
	ErrInvalidGroupDefinition = errors.New("resource: invalid group definition")
	// ErrInvalidSemanticHash reports missing or malformed durable semantics.
	ErrInvalidSemanticHash = errors.New("resource: invalid semantic hash")
)

// Kind identifies the typed target schema used by a Resource.
type Kind uint8

const (
	// KindUnknown is the unusable zero value.
	KindUnknown Kind = iota
	// KindDevice targets one logical Device through an explicit binding row.
	KindDevice
)

// State is the lifecycle state of Resource or Resource Group authority.
type State uint8

const (
	// StateUnknown is the unusable zero value.
	StateUnknown State = iota
	// StateActive permits resolution and membership.
	StateActive
	// StateSuspended retains authority while denying active use.
	StateSuspended
	// StateDeleted is the retained terminal state.
	StateDeleted
)

// Provenance identifies how Resource authority entered the local control plane.
type Provenance uint8

const (
	// ProvenanceUnknown is the unusable zero value.
	ProvenanceUnknown Provenance = iota
	// ProvenanceManual denotes an authenticated management mutation.
	ProvenanceManual
)

// SemanticHash is a canonical non-zero SHA-256 digest of authoritative semantics.
type SemanticHash [sha256.Size]byte

// NewSemanticHash validates a digest loaded from a durable boundary.
func NewSemanticHash(value [sha256.Size]byte) (SemanticHash, error) {
	hash := SemanticHash(value)
	if !hash.IsValid() {
		return SemanticHash{}, ErrInvalidSemanticHash
	}
	return hash, nil
}

// Bytes returns a copy of the digest.
func (hash SemanticHash) Bytes() [sha256.Size]byte { return [sha256.Size]byte(hash) }

// IsValid reports whether the digest is non-zero.
func (hash SemanticHash) IsValid() bool { return hash != SemanticHash{} }

// DisplayName is presentation text and never an identity or authorization input.
type DisplayName struct{ value string }

// ParseDisplayName validates presentation text without changing it.
func ParseDisplayName(value string) (DisplayName, error) {
	if value == "" || !utf8.ValidString(value) || strings.TrimSpace(value) != value ||
		utf8.RuneCountInString(value) > maximumDisplayNameRunes {
		return DisplayName{}, ErrInvalidDisplayName
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return DisplayName{}, ErrInvalidDisplayName
		}
	}
	return DisplayName{value: value}, nil
}

// String returns the display text exactly as validated.
func (name DisplayName) String() string { return name.value }

// Key returns a deterministic case-folded uniqueness key.
func (name DisplayName) Key() string { return strings.ToLower(name.value) }

// IsValid reports whether the name satisfies the presentation contract.
func (name DisplayName) IsValid() bool {
	validated, err := ParseDisplayName(name.value)
	return err == nil && validated == name
}

// DeviceDefinitionParams contains initial authority for a Device Resource.
type DeviceDefinitionParams struct {
	Scope                network.Scope
	DisplayName          DisplayName
	OwnerPrincipalID     identity.PrincipalID
	CustodianPrincipalID identity.PrincipalID
	DeviceID             node.ID
}

// DeviceDefinition is a creator-owned Device Resource definition before ID allocation.
type DeviceDefinition struct {
	scope                network.Scope
	displayName          DisplayName
	ownerPrincipalID     identity.PrincipalID
	custodianPrincipalID identity.PrincipalID
	deviceID             node.ID
	semanticHash         SemanticHash
}

// NewDeviceDefinition validates and hashes one initial Device Resource.
func NewDeviceDefinition(params DeviceDefinitionParams) (DeviceDefinition, error) {
	definition := DeviceDefinition{
		scope:                params.Scope,
		displayName:          params.DisplayName,
		ownerPrincipalID:     params.OwnerPrincipalID,
		custodianPrincipalID: params.CustodianPrincipalID,
		deviceID:             params.DeviceID,
	}
	if !validDeviceFields(definition) {
		return DeviceDefinition{}, ErrInvalidDeviceDefinition
	}
	definition.semanticHash = hashDeviceDefinition(definition)
	return definition, nil
}

// Scope returns the exact home Network scope.
func (definition DeviceDefinition) Scope() network.Scope { return definition.scope }

// DisplayName returns presentation text.
func (definition DeviceDefinition) DisplayName() DisplayName { return definition.displayName }

// NameKey returns the normalized uniqueness key.
func (definition DeviceDefinition) NameKey() string { return definition.displayName.Key() }

// OwnerPrincipalID returns the initial accountability owner.
func (definition DeviceDefinition) OwnerPrincipalID() identity.PrincipalID {
	return definition.ownerPrincipalID
}

// CustodianPrincipalID returns the initial operational custodian.
func (definition DeviceDefinition) CustodianPrincipalID() identity.PrincipalID {
	return definition.custodianPrincipalID
}

// DeviceID returns the typed Device target.
func (definition DeviceDefinition) DeviceID() node.ID { return definition.deviceID }

// Kind returns the typed target kind.
func (DeviceDefinition) Kind() Kind { return KindDevice }

// State returns the initial lifecycle state.
func (DeviceDefinition) State() State { return StateActive }

// Provenance returns the initial authority source.
func (DeviceDefinition) Provenance() Provenance { return ProvenanceManual }

// TargetGeneration returns the initial binding generation.
func (DeviceDefinition) TargetGeneration() int64 { return 1 }

// SemanticHash returns canonical Resource semantics.
func (definition DeviceDefinition) SemanticHash() SemanticHash { return definition.semanticHash }

// IsValid reports whether all fields and their digest agree.
func (definition DeviceDefinition) IsValid() bool {
	return validDeviceFields(definition) && definition.semanticHash.IsValid() &&
		definition.semanticHash == hashDeviceDefinition(definition)
}

func validDeviceFields(definition DeviceDefinition) bool {
	return definition.scope.IsValid() && definition.displayName.IsValid() &&
		definition.ownerPrincipalID.IsValid() && definition.custodianPrincipalID.IsValid() &&
		definition.deviceID.IsValid()
}

// Reference pins one Resource identity, authority version, and target generation.
type Reference struct {
	scope            network.Scope
	resourceID       ID
	resourceVersion  int64
	targetGeneration int64
}

// NewReference constructs one exact Resource Group member reference.
func NewReference(
	scope network.Scope,
	resourceID ID,
	resourceVersion int64,
	targetGeneration int64,
) (Reference, error) {
	reference := Reference{
		scope: scope, resourceID: resourceID, resourceVersion: resourceVersion,
		targetGeneration: targetGeneration,
	}
	if !reference.IsValid() {
		return Reference{}, ErrInvalidReference
	}
	return reference, nil
}

// Scope returns the exact Resource scope.
func (reference Reference) Scope() network.Scope { return reference.scope }

// ResourceID returns the stable Resource identity.
func (reference Reference) ResourceID() ID { return reference.resourceID }

// ResourceVersion returns the pinned authority version.
func (reference Reference) ResourceVersion() int64 { return reference.resourceVersion }

// TargetGeneration returns the pinned target generation.
func (reference Reference) TargetGeneration() int64 { return reference.targetGeneration }

// IsValid reports whether all version-pinned identity fields are present.
func (reference Reference) IsValid() bool {
	return reference.scope.IsValid() && reference.resourceID.IsValid() &&
		reference.resourceVersion > 0 && reference.targetGeneration > 0
}

// GroupDefinitionParams contains one immutable Resource Group version.
type GroupDefinitionParams struct {
	Scope                network.Scope
	DisplayName          DisplayName
	OwnerPrincipalID     identity.PrincipalID
	CustodianPrincipalID identity.PrincipalID
	Members              []Reference
}

// GroupDefinition is an immutable, destination-only collection of Resources.
type GroupDefinition struct {
	scope                network.Scope
	displayName          DisplayName
	ownerPrincipalID     identity.PrincipalID
	custodianPrincipalID identity.PrincipalID
	members              []Reference
	semanticHash         SemanticHash
}

// NewGroupDefinition validates, canonicalizes, and hashes one initial version.
func NewGroupDefinition(params GroupDefinitionParams) (GroupDefinition, error) {
	if !params.Scope.IsValid() || !params.DisplayName.IsValid() ||
		!params.OwnerPrincipalID.IsValid() || !params.CustodianPrincipalID.IsValid() ||
		len(params.Members) == 0 || len(params.Members) > MaximumGroupMembers {
		return GroupDefinition{}, ErrInvalidGroupDefinition
	}
	members := slices.Clone(params.Members)
	for _, member := range members {
		if !member.IsValid() || member.Scope() != params.Scope {
			return GroupDefinition{}, ErrInvalidGroupDefinition
		}
	}
	slices.SortFunc(members, func(left, right Reference) int {
		return strings.Compare(left.ResourceID().String(), right.ResourceID().String())
	})
	for index := 1; index < len(members); index++ {
		if members[index-1].ResourceID() == members[index].ResourceID() {
			return GroupDefinition{}, ErrInvalidGroupDefinition
		}
	}
	definition := GroupDefinition{
		scope: params.Scope, displayName: params.DisplayName,
		ownerPrincipalID:     params.OwnerPrincipalID,
		custodianPrincipalID: params.CustodianPrincipalID,
		members:              members,
	}
	definition.semanticHash = hashGroupDefinition(definition)
	return definition, nil
}

// Scope returns the exact home Network scope.
func (definition GroupDefinition) Scope() network.Scope { return definition.scope }

// DisplayName returns presentation text.
func (definition GroupDefinition) DisplayName() DisplayName { return definition.displayName }

// NameKey returns the normalized uniqueness key.
func (definition GroupDefinition) NameKey() string { return definition.displayName.Key() }

// OwnerPrincipalID returns the initial accountability owner.
func (definition GroupDefinition) OwnerPrincipalID() identity.PrincipalID {
	return definition.ownerPrincipalID
}

// CustodianPrincipalID returns the initial operational custodian.
func (definition GroupDefinition) CustodianPrincipalID() identity.PrincipalID {
	return definition.custodianPrincipalID
}

// Members returns a caller-owned canonical membership snapshot.
func (definition GroupDefinition) Members() []Reference { return slices.Clone(definition.members) }

// DefinitionVersion returns the initial immutable version number.
func (GroupDefinition) DefinitionVersion() int64 { return 1 }

// State returns the initial lifecycle state.
func (GroupDefinition) State() State { return StateActive }

// SemanticHash returns canonical group semantics.
func (definition GroupDefinition) SemanticHash() SemanticHash { return definition.semanticHash }

// IsValid reports whether fields, canonical order, and digest agree.
func (definition GroupDefinition) IsValid() bool {
	if !definition.scope.IsValid() || !definition.displayName.IsValid() ||
		!definition.ownerPrincipalID.IsValid() || !definition.custodianPrincipalID.IsValid() ||
		len(definition.members) == 0 || len(definition.members) > MaximumGroupMembers ||
		!definition.semanticHash.IsValid() {
		return false
	}
	for index, member := range definition.members {
		if !member.IsValid() || member.Scope() != definition.scope ||
			(index > 0 && definition.members[index-1].ResourceID().String() >= member.ResourceID().String()) {
			return false
		}
	}
	return definition.semanticHash == hashGroupDefinition(definition)
}

func hashDeviceDefinition(definition DeviceDefinition) SemanticHash {
	revision := DeviceRevision{
		scope: definition.scope, displayName: definition.displayName,
		ownerPrincipalID: definition.ownerPrincipalID, custodianPrincipalID: definition.custodianPrincipalID,
		deviceID: definition.deviceID, targetGeneration: 1,
	}
	return hashDeviceRevision(revision)
}

func hashGroupDefinition(definition GroupDefinition) SemanticHash {
	encoded := make([]byte, 0, 160+len(definition.members)*32)
	encoded = append(encoded, groupHashDomain...)
	encoded = appendScope(encoded, definition.scope)
	encoded = appendText(encoded, definition.displayName.String())
	ownerID := definition.ownerPrincipalID.Bytes()
	custodianID := definition.custodianPrincipalID.Bytes()
	encoded = append(encoded, ownerID[:]...)
	encoded = append(encoded, custodianID[:]...)
	encoded = appendUint64(encoded, uint64(len(definition.members)))
	for _, member := range definition.members {
		resourceID := member.ResourceID().Bytes()
		encoded = append(encoded, resourceID[:]...)
		encoded = appendInt64(encoded, member.ResourceVersion())
		encoded = appendInt64(encoded, member.TargetGeneration())
	}
	return SemanticHash(sha256.Sum256(encoded))
}

func appendScope(output []byte, scope network.Scope) []byte {
	workspaceID := scope.WorkspaceID().Bytes()
	networkID := scope.NetworkID().Bytes()
	output = append(output, workspaceID[:]...)
	return append(output, networkID[:]...)
}

func appendText(output []byte, value string) []byte {
	output = appendUint64(output, uint64(len(value)))
	return append(output, value...)
}

func appendUint64(output []byte, value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return append(output, encoded[:]...)
}

func appendInt64(output []byte, value int64) []byte {
	var encoded [binary.MaxVarintLen64]byte
	length := binary.PutVarint(encoded[:], value)
	return append(output, encoded[:length]...)
}
