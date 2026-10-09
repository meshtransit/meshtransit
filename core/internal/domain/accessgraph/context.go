package accessgraph

import (
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/sharing"
)

const (
	// MaximumParticipantNameBytes bounds a Device hostname or Resource name in
	// an explanation.
	MaximumParticipantNameBytes = 255
	// MaximumAccessNameBytes bounds the consumer DNS name of a shared Device.
	MaximumAccessNameBytes = 253
)

// ParticipantState says whether a source or target can take part in a
// connection at the evaluation time.
type ParticipantState uint8

const (
	// ParticipantStateUnknown is the invalid zero value.
	ParticipantStateUnknown ParticipantState = iota
	// ParticipantStateActive is usable now.
	ParticipantStateActive
	// ParticipantStateInactive exists in the Network but is not usable now:
	// inactive, deleted, key-expired or ended.
	ParticipantStateInactive
	// ParticipantStateMissing does not exist in the explained Network.
	ParticipantStateMissing
)

// String returns the stable wire spelling.
func (state ParticipantState) String() string {
	switch state {
	case ParticipantStateActive:
		return "active"
	case ParticipantStateInactive:
		return "inactive"
	case ParticipantStateMissing:
		return "missing"
	default:
		return ""
	}
}

// Participant is the source or target as seen inside the explained Network.
type Participant struct {
	state ParticipantState
	name  string
}

// NewParticipant validates a participant. A missing participant has no name.
func NewParticipant(state ParticipantState, name string) (Participant, error) {
	participant := Participant{state: state, name: name}
	if !participant.IsValid() {
		return Participant{}, ErrInvalidSnapshot
	}
	return participant, nil
}

// State returns whether the participant is usable now.
func (participant Participant) State() ParticipantState { return participant.state }

// Name returns the Device hostname or Resource name, which may be empty.
func (participant Participant) Name() string { return participant.name }

// IsValid reports whether the participant is complete and bounded.
func (participant Participant) IsValid() bool {
	switch participant.state {
	case ParticipantStateActive, ParticipantStateInactive:
		return validDisplayText(participant.name, MaximumParticipantNameBytes)
	case ParticipantStateMissing:
		return participant.name == ""
	default:
		return false
	}
}

// TargetKind identifies what the explained connection is aimed at.
type TargetKind uint8

const (
	// TargetKindUnknown is the invalid zero value.
	TargetKindUnknown TargetKind = iota
	// TargetKindDevice is a Device in the explained Network.
	TargetKindDevice
	// TargetKindResource is a Resource in the explained Network.
	TargetKindResource
	// TargetKindImportedResource is a Device shared into the explained Network.
	TargetKindImportedResource
)

// String returns the stable wire spelling.
func (kind TargetKind) String() string {
	switch kind {
	case TargetKindDevice:
		return "device"
	case TargetKindResource:
		return "resource"
	case TargetKindImportedResource:
		return "imported_resource"
	default:
		return ""
	}
}

func (query Query) targetKind() TargetKind {
	switch {
	case query.destinationNodeID.IsValid():
		return TargetKindDevice
	case query.destinationResourceID.IsValid():
		return TargetKindResource
	case query.destinationImportedResourceID.IsValid():
		return TargetKindImportedResource
	default:
		return TargetKindUnknown
	}
}

// ShareContextParams describes the Trust Contract behind a shared target as
// the consumer already sees it. It never carries provider Devices, addresses
// or Resources.
type ShareContextParams struct {
	ContractID sharing.ContractID
	// State is effective at the evaluation time: an active or activating
	// contract past its expiry is reported as expired.
	State                 sharing.ContractState
	ExpiresAt             time.Time // zero means the share never expires
	ProviderWorkspaceCode identity.DisplayCode
	ProviderNetworkCode   identity.DisplayCode
	AccessName            string // optional consumer DNS name
}

// ShareContext is the validated contract context of a shared target.
type ShareContext struct {
	contractID            sharing.ContractID
	state                 sharing.ContractState
	expiresAt             time.Time
	providerWorkspaceCode identity.DisplayCode
	providerNetworkCode   identity.DisplayCode
	accessName            string
}

// NewShareContext validates one share context.
func NewShareContext(params ShareContextParams) (ShareContext, error) {
	share := ShareContext{
		contractID: params.ContractID, state: params.State, expiresAt: params.ExpiresAt.UTC(),
		providerWorkspaceCode: params.ProviderWorkspaceCode, providerNetworkCode: params.ProviderNetworkCode,
		accessName: params.AccessName,
	}
	if params.ExpiresAt.IsZero() {
		share.expiresAt = time.Time{}
	}
	if !share.IsValid() {
		return ShareContext{}, ErrInvalidSnapshot
	}
	return share, nil
}

// ContractID returns the Trust Contract identity.
func (share ShareContext) ContractID() sharing.ContractID { return share.contractID }

// State returns the effective contract state.
func (share ShareContext) State() sharing.ContractState { return share.state }

// ExpiresAt returns the expiry and false when the share never expires.
func (share ShareContext) ExpiresAt() (time.Time, bool) {
	return share.expiresAt, !share.expiresAt.IsZero()
}

// ProviderWorkspaceCode returns the provider Workspace display code.
func (share ShareContext) ProviderWorkspaceCode() identity.DisplayCode {
	return share.providerWorkspaceCode
}

// ProviderNetworkCode returns the provider Network display code.
func (share ShareContext) ProviderNetworkCode() identity.DisplayCode {
	return share.providerNetworkCode
}

// AccessName returns the consumer DNS name, which may be empty.
func (share ShareContext) AccessName() string { return share.accessName }

// IsValid reports whether the share context is complete and bounded.
func (share ShareContext) IsValid() bool {
	return share.contractID.IsValid() && share.state != sharing.ContractStateUnknown &&
		share.state <= sharing.ContractStateInvalidated &&
		share.providerWorkspaceCode.IsValid() && share.providerNetworkCode.IsValid() &&
		validAccessName(share.accessName)
}

// DenyReason says why a connection is denied. It applies only to deny
// decisions; an allow carries DenyReasonUnknown.
type DenyReason uint8

const (
	// DenyReasonUnknown is the zero value and the value of every allow.
	DenyReasonUnknown DenyReason = iota
	// DenyReasonNoActiveRelease means no policy has been published.
	DenyReasonNoActiveRelease
	// DenyReasonSourceInactive means the source Device is not usable now.
	DenyReasonSourceInactive
	// DenyReasonTargetInactive means the target is missing or not usable now.
	DenyReasonTargetInactive
	// DenyReasonShareActivating means the share is accepted but not turned on.
	DenyReasonShareActivating
	// DenyReasonShareEnded means the share was revoked or invalidated.
	DenyReasonShareEnded
	// DenyReasonShareExpired means the share passed its expiry.
	DenyReasonShareExpired
	// DenyReasonNoMatchingActiveRule means no active rule allows the
	// connection: default deny.
	DenyReasonNoMatchingActiveRule
)

// String returns the stable wire spelling.
func (reason DenyReason) String() string {
	switch reason {
	case DenyReasonNoActiveRelease:
		return "no_active_release"
	case DenyReasonSourceInactive:
		return "source_inactive"
	case DenyReasonTargetInactive:
		return "target_inactive"
	case DenyReasonShareActivating:
		return "share_activating"
	case DenyReasonShareEnded:
		return "share_ended"
	case DenyReasonShareExpired:
		return "share_expired"
	case DenyReasonNoMatchingActiveRule:
		return "no_matching_active_rule"
	default:
		return ""
	}
}

// denyReasonFor classifies a denial in a fixed order: policy, source, share,
// target, then default deny. It is called only for snapshots without paths.
func denyReasonFor(snapshot Snapshot) DenyReason {
	if !snapshot.hasActiveRelease {
		return DenyReasonNoActiveRelease
	}
	if snapshot.source.state != ParticipantStateActive {
		return DenyReasonSourceInactive
	}
	if snapshot.targetKind == TargetKindImportedResource {
		if !snapshot.hasShare {
			return DenyReasonTargetInactive
		}
		switch snapshot.share.state {
		case sharing.ContractStateActivating:
			return DenyReasonShareActivating
		case sharing.ContractStateRevoked, sharing.ContractStateInvalidated:
			return DenyReasonShareEnded
		case sharing.ContractStateExpired:
			return DenyReasonShareExpired
		}
	}
	if snapshot.target.state != ParticipantStateActive {
		return DenyReasonTargetInactive
	}
	return DenyReasonNoMatchingActiveRule
}

func validDisplayText(value string, maximumBytes int) bool {
	if len(value) > maximumBytes || !utf8.ValidString(value) {
		return false
	}
	return strings.IndexFunc(value, unicode.IsControl) < 0
}

// validAccessName accepts an empty name or a lowercase DNS name.
func validAccessName(value string) bool {
	if value == "" {
		return true
	}
	if len(value) > MaximumAccessNameBytes {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}
