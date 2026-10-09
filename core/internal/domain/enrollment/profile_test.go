package enrollment_test

import (
	"errors"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/enrollment"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

func TestProfileValidatesCredentialAuthority(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		profileState    enrollment.ProfileState
		profileLimit    enrollment.UseLimit
		credentialLimit enrollment.UseLimit
		wantError       error
	}{
		{
			name:            "bounded credential within profile",
			profileState:    enrollment.ProfileStateActive,
			profileLimit:    mustBoundedLimit(t, 10),
			credentialLimit: mustBoundedLimit(t, 2),
		},
		{
			name:            "unlimited profile accepts bounded credential",
			profileState:    enrollment.ProfileStateActive,
			profileLimit:    enrollment.NewUnlimitedUseLimit(),
			credentialLimit: mustBoundedLimit(t, 2),
		},
		{
			name:            "unlimited profile accepts unlimited credential",
			profileState:    enrollment.ProfileStateActive,
			profileLimit:    enrollment.NewUnlimitedUseLimit(),
			credentialLimit: enrollment.NewUnlimitedUseLimit(),
		},
		{
			name:            "credential exceeds profile quota",
			profileState:    enrollment.ProfileStateActive,
			profileLimit:    mustBoundedLimit(t, 1),
			credentialLimit: mustBoundedLimit(t, 2),
			wantError:       enrollment.ErrCredentialPolicyMismatch,
		},
		{
			name:            "bounded profile rejects unlimited credential",
			profileState:    enrollment.ProfileStateActive,
			profileLimit:    mustBoundedLimit(t, 1),
			credentialLimit: enrollment.NewUnlimitedUseLimit(),
			wantError:       enrollment.ErrCredentialPolicyMismatch,
		},
		{
			name:            "suspended profile",
			profileState:    enrollment.ProfileStateSuspended,
			profileLimit:    mustBoundedLimit(t, 2),
			credentialLimit: mustBoundedLimit(t, 2),
			wantError:       enrollment.ErrProfileInactive,
		},
		{
			name:            "deleted profile",
			profileState:    enrollment.ProfileStateDeleted,
			profileLimit:    mustBoundedLimit(t, 2),
			credentialLimit: mustBoundedLimit(t, 2),
			wantError:       enrollment.ErrProfileInactive,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			profile := mustProfile(t, test.profileState, test.profileLimit)
			params := validCredentialParams(t, test.credentialLimit)
			credential, err := enrollment.NewCredential(params)
			if err != nil {
				t.Fatalf("NewCredential() error = %v", err)
			}
			err = profile.ValidateCredential(credential)
			if !errors.Is(err, test.wantError) {
				t.Fatalf("ValidateCredential() error = %v, want %v", err, test.wantError)
			}
		})
	}
}

func TestProfileComputesDeviceLifecycle(t *testing.T) {
	t.Parallel()

	profile := mustProfile(t, enrollment.ProfileStateActive, mustBoundedLimit(t, 2))
	expiresAt, err := profile.DeviceExpiresAt(testTime())
	if err != nil {
		t.Fatalf("DeviceExpiresAt() error = %v", err)
	}
	if !expiresAt.Equal(testTime().Add(time.Hour)) || profile.IsEphemeral() {
		t.Fatalf("persistent profile lifecycle = (%s, ephemeral=%t)", expiresAt, profile.IsEphemeral())
	}

	params := validProfileParams(t, enrollment.NewUnlimitedUseLimit())
	params.EphemeralMode = enrollment.EphemeralModeEphemeral
	ephemeral, err := enrollment.NewProfile(params)
	if err != nil {
		t.Fatalf("NewProfile(ephemeral) error = %v", err)
	}
	if !ephemeral.IsEphemeral() {
		t.Fatal("ephemeral profile did not retain lifecycle mode")
	}
}

func TestNewProfileRejectsInvalidState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*enrollment.ProfileParams)
	}{
		{name: "missing id", mutate: func(params *enrollment.ProfileParams) { params.ID = enrollment.ProfileID{} }},
		{name: "missing scope", mutate: func(params *enrollment.ProfileParams) { params.Scope = network.Scope{} }},
		{name: "unknown state", mutate: func(params *enrollment.ProfileParams) { params.State = enrollment.ProfileStateUnknown }},
		{name: "missing lifetime", mutate: func(params *enrollment.ProfileParams) { params.NodeLifetime = 0 }},
		{name: "unknown ephemeral mode", mutate: func(params *enrollment.ProfileParams) { params.EphemeralMode = enrollment.EphemeralModeUnknown }},
		{name: "invalid credential limit", mutate: func(params *enrollment.ProfileParams) { params.CredentialUseLimit = enrollment.UseLimit{} }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			params := validProfileParams(t, mustBoundedLimit(t, 2))
			test.mutate(&params)
			profile, err := enrollment.NewProfile(params)
			if !errors.Is(err, enrollment.ErrInvalidProfile) {
				t.Fatalf("NewProfile() error = %v, want ErrInvalidProfile", err)
			}
			if profile.IsValid() {
				t.Fatal("invalid profile is valid")
			}
		})
	}

	profile := mustProfile(t, enrollment.ProfileStateActive, mustBoundedLimit(t, 2))
	if _, err := profile.DeviceExpiresAt(time.Time{}); !errors.Is(err, enrollment.ErrInvalidProfile) {
		t.Fatalf("DeviceExpiresAt(zero) error = %v, want ErrInvalidProfile", err)
	}
	suspended := mustProfile(t, enrollment.ProfileStateSuspended, mustBoundedLimit(t, 2))
	if _, err := suspended.DeviceExpiresAt(testTime()); !errors.Is(err, enrollment.ErrProfileInactive) {
		t.Fatalf("DeviceExpiresAt(suspended) error = %v, want ErrProfileInactive", err)
	}
}

func mustProfile(
	t *testing.T,
	state enrollment.ProfileState,
	limit enrollment.UseLimit,
) enrollment.Profile {
	t.Helper()

	params := validProfileParams(t, limit)
	params.State = state
	profile, err := enrollment.NewProfile(params)
	if err != nil {
		t.Fatalf("NewProfile() error = %v", err)
	}
	return profile
}

func validProfileParams(t *testing.T, limit enrollment.UseLimit) enrollment.ProfileParams {
	t.Helper()

	workspaceID, err := workspace.ParseID("01890f00-0000-7000-8000-000000000101")
	if err != nil {
		t.Fatalf("workspace.ParseID() error = %v", err)
	}
	networkID, err := network.ParseID("01890f00-0000-7000-8000-000000000201")
	if err != nil {
		t.Fatalf("network.ParseID() error = %v", err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatalf("network.NewScope() error = %v", err)
	}
	return enrollment.ProfileParams{
		ID:                 mustProfileID(t),
		Scope:              scope,
		State:              enrollment.ProfileStateActive,
		NodeLifetime:       time.Hour,
		EphemeralMode:      enrollment.EphemeralModePersistent,
		CredentialUseLimit: limit,
	}
}
