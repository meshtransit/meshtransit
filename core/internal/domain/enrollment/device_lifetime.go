package enrollment

import (
	"errors"
	"time"
)

const (
	// MinimumDeviceLifetime is the shortest lifetime a credential may give
	// the Device it enrolls.
	MinimumDeviceLifetime = time.Hour
	// MaximumDeviceLifetime is the longest fixed lifetime; longer means
	// never expires.
	MaximumDeviceLifetime = 180 * 24 * time.Hour
)

// InteractiveProfileNameKey names the enrollment profile every Network gets
// for browser sign-in.
const InteractiveProfileNameKey = "interactive-login"

// DefaultInteractiveDeviceLifetime is how long a signed-in Device lives
// while its Network has chosen no lifetime.
const DefaultInteractiveDeviceLifetime = MaximumDeviceLifetime

// ProfileDeviceLifetime resolves the lifetime an enrollment profile gives
// the Devices it creates from its stored columns: never expires, else the
// chosen seconds, else DefaultInteractiveDeviceLifetime for the interactive
// profile, else the profile's legacy node lifetime. The returned duration
// is positive even when never is true, so older readers stay bounded.
func ProfileDeviceLifetime(nameKey string, legacySeconds int64, chosenSeconds *int64,
	neverExpires bool) (lifetime time.Duration, never bool, err error) {
	const maximumSeconds = int64((1<<63 - 1) / time.Second)
	if legacySeconds <= 0 || legacySeconds > maximumSeconds {
		return 0, false, ErrInvalidDeviceLifetime
	}
	switch {
	case neverExpires && chosenSeconds != nil:
		return 0, false, ErrInvalidDeviceLifetime
	case neverExpires:
		return MaximumDeviceLifetime, true, nil
	case chosenSeconds != nil:
		if *chosenSeconds <= 0 || *chosenSeconds > maximumSeconds {
			return 0, false, ErrInvalidDeviceLifetime
		}
		chosen, err := NewDeviceLifetime(time.Duration(*chosenSeconds) * time.Second)
		if err != nil {
			return 0, false, err
		}
		return chosen.Duration(), false, nil
	case nameKey == InteractiveProfileNameKey:
		return DefaultInteractiveDeviceLifetime, false, nil
	default:
		return time.Duration(legacySeconds) * time.Second, false, nil
	}
}

// DeviceNeverExpiresAt is the expiry of a Device that never expires; it
// equals mesh_ops.device_never_expires_v1().
var DeviceNeverExpiresAt = time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC)

// ErrInvalidDeviceLifetime reports a Device lifetime outside its bounds.
var ErrInvalidDeviceLifetime = errors.New("enrollment: invalid Device lifetime")

// DeviceLifetimeKind says how long a Device a credential enrolls lives.
type DeviceLifetimeKind uint8

const (
	// DeviceLifetimeProfile defers to the enrollment profile. It is the
	// zero value so credentials issued before keys chose a lifetime keep
	// the profile's.
	DeviceLifetimeProfile DeviceLifetimeKind = iota
	// DeviceLifetimeFixed lasts a fixed duration from registration.
	DeviceLifetimeFixed
	// DeviceLifetimeNever never expires.
	DeviceLifetimeNever
)

// DeviceLifetime is the lifetime the creator of a credential chose for the
// Device it enrolls.
type DeviceLifetime struct {
	kind     DeviceLifetimeKind
	duration time.Duration
}

// NewDeviceLifetime returns a fixed lifetime of whole seconds between
// MinimumDeviceLifetime and MaximumDeviceLifetime.
func NewDeviceLifetime(duration time.Duration) (DeviceLifetime, error) {
	lifetime := DeviceLifetime{kind: DeviceLifetimeFixed, duration: duration}
	if !lifetime.isValid() {
		return DeviceLifetime{}, ErrInvalidDeviceLifetime
	}
	return lifetime, nil
}

// NeverExpiringDeviceLifetime returns the lifetime of a Device that never
// expires.
func NeverExpiringDeviceLifetime() DeviceLifetime {
	return DeviceLifetime{kind: DeviceLifetimeNever}
}

// Kind returns how the lifetime is set.
func (lifetime DeviceLifetime) Kind() DeviceLifetimeKind { return lifetime.kind }

// Duration returns a fixed lifetime, or zero for the other kinds.
func (lifetime DeviceLifetime) Duration() time.Duration { return lifetime.duration }

func (lifetime DeviceLifetime) isValid() bool {
	switch lifetime.kind {
	case DeviceLifetimeProfile, DeviceLifetimeNever:
		return lifetime.duration == 0
	case DeviceLifetimeFixed:
		return lifetime.duration >= MinimumDeviceLifetime && lifetime.duration <= MaximumDeviceLifetime &&
			lifetime.duration%time.Second == 0
	default:
		return false
	}
}

// DeviceExpiresAtFor returns the expiry of a Device registered at
// registeredAt with credential: the credential's chosen lifetime, or the
// profile's when the credential defers to it.
func (profile Profile) DeviceExpiresAtFor(credential Credential, registeredAt time.Time) (time.Time, error) {
	if !credential.IsValid() {
		return time.Time{}, ErrInvalidCredential
	}
	profileExpiry, err := profile.DeviceExpiresAt(registeredAt)
	if err != nil {
		return time.Time{}, err
	}
	switch lifetime := credential.DeviceLifetime(); lifetime.kind {
	case DeviceLifetimeNever:
		return DeviceNeverExpiresAt, nil
	case DeviceLifetimeFixed:
		return registeredAt.UTC().Add(lifetime.duration), nil
	default:
		return profileExpiry, nil
	}
}
