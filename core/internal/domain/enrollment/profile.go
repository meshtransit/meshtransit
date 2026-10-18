package enrollment

import (
	"errors"
	"time"

	"meshtransit.net/core/internal/domain/network"
)

var (
	// ErrInvalidProfile reports malformed durable enrollment-profile state.
	ErrInvalidProfile = errors.New("enrollment: invalid profile")
	// ErrProfileInactive reports a profile that cannot authorize registration.
	ErrProfileInactive = errors.New("enrollment: profile inactive")
	// ErrCredentialPolicyMismatch reports credential authority wider than its profile.
	ErrCredentialPolicyMismatch = errors.New("enrollment: credential policy mismatch")
)

// ProfileState identifies the durable enrollment-profile lifecycle.
type ProfileState uint8

const (
	// ProfileStateUnknown is the invalid zero value.
	ProfileStateUnknown ProfileState = iota
	// ProfileStateActive permits new registration.
	ProfileStateActive
	// ProfileStateSuspended temporarily denies new registration.
	ProfileStateSuspended
	// ProfileStateDeleted is terminal and denies new registration.
	ProfileStateDeleted
)

// EphemeralMode controls the lifecycle of Devices created by a profile.
type EphemeralMode uint8

const (
	// EphemeralModeUnknown is the invalid zero value.
	EphemeralModeUnknown EphemeralMode = iota
	// EphemeralModePersistent creates a persistent logical Device.
	EphemeralModePersistent
	// EphemeralModeEphemeral creates a Device eligible for ephemeral cleanup.
	EphemeralModeEphemeral
)

// ProfileParams contains the registration-relevant durable profile fields.
type ProfileParams struct {
	ID           ProfileID
	Scope        network.Scope
	State        ProfileState
	NodeLifetime time.Duration
	// NeverExpires gives every Device the profile creates no expiry.
	NeverExpires       bool
	EphemeralMode      EphemeralMode
	CredentialUseLimit UseLimit
}

// Profile is immutable enrollment authority loaded under the registration lock.
type Profile struct {
	id                 ProfileID
	scope              network.Scope
	state              ProfileState
	nodeLifetime       time.Duration
	neverExpires       bool
	ephemeralMode      EphemeralMode
	credentialUseLimit UseLimit
}

// NewProfile validates and rehydrates registration-relevant profile state.
func NewProfile(params ProfileParams) (Profile, error) {
	profile := Profile{
		id:                 params.ID,
		scope:              params.Scope,
		state:              params.State,
		nodeLifetime:       params.NodeLifetime,
		neverExpires:       params.NeverExpires,
		ephemeralMode:      params.EphemeralMode,
		credentialUseLimit: params.CredentialUseLimit,
	}
	if !profile.IsValid() {
		return Profile{}, ErrInvalidProfile
	}
	return profile, nil
}

// ID returns the profile public identity.
func (profile Profile) ID() ProfileID { return profile.id }

// Scope returns the exact Workspace and Network governed by the profile.
func (profile Profile) Scope() network.Scope { return profile.scope }

// State returns the profile lifecycle state.
func (profile Profile) State() ProfileState { return profile.state }

// NodeLifetime returns the lifetime granted to a newly created Device.
func (profile Profile) NodeLifetime() time.Duration { return profile.nodeLifetime }

// NeverExpires reports whether the Devices the profile creates never expire.
func (profile Profile) NeverExpires() bool { return profile.neverExpires }

// IsEphemeral reports whether the profile creates ephemeral Devices.
func (profile Profile) IsEphemeral() bool { return profile.ephemeralMode == EphemeralModeEphemeral }

// CredentialUseLimit returns the maximum authority a credential may carry.
func (profile Profile) CredentialUseLimit() UseLimit { return profile.credentialUseLimit }

// IsValid reports whether the profile can be safely evaluated.
func (profile Profile) IsValid() bool {
	return profile.id.IsValid() && profile.scope.IsValid() && profile.nodeLifetime > 0 &&
		profile.credentialUseLimit.isValid() &&
		(profile.state == ProfileStateActive || profile.state == ProfileStateSuspended ||
			profile.state == ProfileStateDeleted) &&
		(profile.ephemeralMode == EphemeralModePersistent ||
			profile.ephemeralMode == EphemeralModeEphemeral)
}

// ValidateCredential checks that credential authority is within this active profile.
func (profile Profile) ValidateCredential(credential Credential) error {
	if !profile.IsValid() || !credential.IsValid() || credential.ProfileID() != profile.id {
		return ErrInvalidProfile
	}
	if profile.state != ProfileStateActive {
		return ErrProfileInactive
	}
	profileMaximum, profileBounded := profile.credentialUseLimit.Maximum()
	credentialMaximum, credentialBounded := credential.UseLimit().Maximum()
	if profileBounded && (!credentialBounded || credentialMaximum > profileMaximum) {
		return ErrCredentialPolicyMismatch
	}
	return nil
}

// DeviceExpiresAt applies the profile's lifetime to a registration time.
func (profile Profile) DeviceExpiresAt(registeredAt time.Time) (time.Time, error) {
	if !profile.IsValid() || registeredAt.IsZero() {
		return time.Time{}, ErrInvalidProfile
	}
	if profile.state != ProfileStateActive {
		return time.Time{}, ErrProfileInactive
	}
	if profile.neverExpires {
		return DeviceNeverExpiresAt, nil
	}
	expiresAt := registeredAt.UTC().Add(profile.nodeLifetime)
	if !expiresAt.After(registeredAt) {
		return time.Time{}, ErrInvalidProfile
	}
	return expiresAt, nil
}
