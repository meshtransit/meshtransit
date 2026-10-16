package enrollment_test

import (
	"errors"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/enrollment"
)

func TestDeviceLifetimeBounds(t *testing.T) {
	t.Parallel()

	for name, test := range map[string]struct {
		lifetime time.Duration
		valid    bool
	}{
		"one hour":            {time.Hour, true},
		"180 days":            {180 * 24 * time.Hour, true},
		"below one hour":      {time.Hour - time.Second, false},
		"above 180 days":      {180*24*time.Hour + time.Second, false},
		"not whole seconds":   {time.Hour + time.Millisecond, false},
		"zero is not 'never'": {0, false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			lifetime, err := enrollment.NewDeviceLifetime(test.lifetime)
			if test.valid != (err == nil) {
				t.Fatalf("NewDeviceLifetime(%v) error = %v, want valid=%v", test.lifetime, err, test.valid)
			}
			if err != nil && !errors.Is(err, enrollment.ErrInvalidDeviceLifetime) {
				t.Fatalf("NewDeviceLifetime(%v) error = %v, want ErrInvalidDeviceLifetime", test.lifetime, err)
			}
			if test.valid && (lifetime.Kind() != enrollment.DeviceLifetimeFixed || lifetime.Duration() != test.lifetime) {
				t.Fatalf("NewDeviceLifetime(%v) = %+v", test.lifetime, lifetime)
			}
		})
	}
	never := enrollment.NeverExpiringDeviceLifetime()
	if never.Kind() != enrollment.DeviceLifetimeNever || never.Duration() != 0 {
		t.Fatalf("NeverExpiringDeviceLifetime() = %+v", never)
	}
	if (enrollment.DeviceLifetime{}).Kind() != enrollment.DeviceLifetimeProfile {
		t.Fatal("the zero DeviceLifetime must defer to the profile, as credentials issued before keys chose one")
	}
}

// A Device registered with a credential lives as long as the credential's
// creator chose: a fixed lifetime from registration, never, or (for
// credentials issued before keys carried one) the profile's lifetime.
func TestDeviceExpiresAtFollowsTheCredential(t *testing.T) {
	t.Parallel()

	profile := mustProfile(t, enrollment.ProfileStateActive, mustBoundedLimit(t, 1))
	registeredAt := testTime().Add(10 * time.Minute)
	fixed, err := enrollment.NewDeviceLifetime(48 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		lifetime enrollment.DeviceLifetime
		want     time.Time
	}{
		"profile lifetime": {enrollment.DeviceLifetime{}, registeredAt.Add(time.Hour)},
		"fixed lifetime":   {fixed, registeredAt.Add(48 * time.Hour)},
		"never expires":    {enrollment.NeverExpiringDeviceLifetime(), enrollment.DeviceNeverExpiresAt},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			params := validCredentialParams(t, mustBoundedLimit(t, 1))
			params.DeviceLifetime = test.lifetime
			credential, err := enrollment.NewCredential(params)
			if err != nil {
				t.Fatalf("NewCredential() error = %v", err)
			}
			if credential.DeviceLifetime() != test.lifetime {
				t.Fatalf("DeviceLifetime() = %+v, want %+v", credential.DeviceLifetime(), test.lifetime)
			}
			got, err := profile.DeviceExpiresAtFor(credential, registeredAt)
			if err != nil || !got.Equal(test.want) {
				t.Fatalf("DeviceExpiresAtFor() = %v, %v; want %v", got, err, test.want)
			}
		})
	}
	if !enrollment.DeviceNeverExpiresAt.Equal(time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("DeviceNeverExpiresAt must match mesh_ops.device_never_expires_v1()")
	}
}

func TestCredentialRejectsAnInvalidDeviceLifetime(t *testing.T) {
	t.Parallel()

	params := validCredentialParams(t, mustBoundedLimit(t, 1))
	params.DeviceLifetime = enrollment.DeviceLifetime{}
	if _, err := enrollment.NewCredential(params); err != nil {
		t.Fatalf("a credential deferring to its profile was refused: %v", err)
	}
	forged := enrollment.ForgeDeviceLifetimeForTest(enrollment.DeviceLifetimeFixed, time.Minute)
	params.DeviceLifetime = forged
	if _, err := enrollment.NewCredential(params); !errors.Is(err, enrollment.ErrInvalidCredential) {
		t.Fatalf("NewCredential() with a one-minute Device lifetime error = %v, want ErrInvalidCredential", err)
	}
}
