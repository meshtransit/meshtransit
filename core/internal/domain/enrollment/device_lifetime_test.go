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

func TestProfileDeviceLifetimeResolvesStoredChoice(t *testing.T) {
	t.Parallel()

	const legacy = int64(30 * 24 * 60 * 60)
	day := int64(24 * 60 * 60)
	for name, test := range map[string]struct {
		nameKey   string
		chosen    *int64
		never     bool
		lifetime  time.Duration
		wantNever bool
		valid     bool
	}{
		"interactive default is 180 days": {nameKey: "interactive-login", lifetime: 180 * 24 * time.Hour, valid: true},
		"other profile keeps its own":     {nameKey: "qualification", lifetime: 30 * 24 * time.Hour, valid: true},
		"chosen seconds win":              {nameKey: "interactive-login", chosen: &day, lifetime: 24 * time.Hour, valid: true},
		"never expires":                   {nameKey: "interactive-login", never: true, lifetime: 180 * 24 * time.Hour, wantNever: true, valid: true},
		"never and seconds conflict":      {nameKey: "interactive-login", chosen: &day, never: true},
		"chosen below one hour":           {nameKey: "interactive-login", chosen: ptr(int64(59))},
		"chosen above 180 days":           {nameKey: "interactive-login", chosen: ptr(181 * day)},
		"chosen overflows":                {nameKey: "interactive-login", chosen: ptr(int64(1 << 62))},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			lifetime, never, err := enrollment.ProfileDeviceLifetime(test.nameKey, legacy, test.chosen, test.never)
			if test.valid != (err == nil) {
				t.Fatalf("ProfileDeviceLifetime() error = %v, want valid=%v", err, test.valid)
			}
			if err != nil {
				if !errors.Is(err, enrollment.ErrInvalidDeviceLifetime) {
					t.Fatalf("error = %v, want ErrInvalidDeviceLifetime", err)
				}
				return
			}
			if lifetime != test.lifetime || never != test.wantNever {
				t.Fatalf("ProfileDeviceLifetime() = %v/%v, want %v/%v", lifetime, never, test.lifetime, test.wantNever)
			}
		})
	}
	if _, _, err := enrollment.ProfileDeviceLifetime("interactive-login", 0, nil, false); err == nil {
		t.Fatal("a profile without a legacy lifetime resolved")
	}
}

func TestNeverExpiringProfileGivesDevicesNoExpiry(t *testing.T) {
	t.Parallel()

	params := validProfileParams(t, enrollment.NewUnlimitedUseLimit())
	params.NeverExpires = true
	profile, err := enrollment.NewProfile(params)
	if err != nil {
		t.Fatalf("NewProfile() error = %v", err)
	}
	expiresAt, err := profile.DeviceExpiresAt(testTime())
	if err != nil || !expiresAt.Equal(enrollment.DeviceNeverExpiresAt) || !profile.NeverExpires() {
		t.Fatalf("DeviceExpiresAt() = %v, %v", expiresAt, err)
	}
}

func ptr[T any](value T) *T { return &value }
