package daemon

import "time"

// Device expiry states the status reports, from the Device's own key expiry
// in the current map. A person renews a Device that signs in through the
// browser by signing in again (meshctl login), which keeps its identity,
// addresses and name.
const (
	// DeviceExpiryUnknown means no map has arrived yet.
	DeviceExpiryUnknown = "unknown"
	// DeviceExpiryNever means the Device never expires.
	DeviceExpiryNever = "never"
	// DeviceExpiryOK means more than DeviceExpirySoonWindow remains.
	DeviceExpiryOK = "ok"
	// DeviceExpirySoon means at most DeviceExpirySoonWindow remains.
	DeviceExpirySoon = "soon"
	// DeviceExpiryImminent means at most DeviceExpiryImminentWindow remains.
	DeviceExpiryImminent = "imminent"
	// DeviceExpiryExpired means the expiry has passed.
	DeviceExpiryExpired = "expired"
)

const (
	// DeviceExpirySoonWindow is when a Device starts warning it will expire.
	DeviceExpirySoonWindow = 14 * 24 * time.Hour
	// DeviceExpiryImminentWindow is when the warning becomes urgent.
	DeviceExpiryImminentWindow = 24 * time.Hour
)

// deviceNeverExpiresFrom is the first expiry Core uses for a Device that
// never expires (mesh_ops.device_never_expires_v1, 2200-01-01).
var deviceNeverExpiresFrom = time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC)

// DeviceExpiryState classifies a Device's expiry at now.
func DeviceExpiryState(expiresAt, now time.Time) string {
	switch remaining := expiresAt.Sub(now); {
	case expiresAt.IsZero():
		return DeviceExpiryUnknown
	case !expiresAt.Before(deviceNeverExpiresFrom):
		return DeviceExpiryNever
	case remaining <= 0:
		return DeviceExpiryExpired
	case remaining <= DeviceExpiryImminentWindow:
		return DeviceExpiryImminent
	case remaining <= DeviceExpirySoonWindow:
		return DeviceExpirySoon
	default:
		return DeviceExpiryOK
	}
}

// deviceExpiryOf is the expiry status reports: the last one a map of the
// active profile gave, while that profile is registered.
func deviceExpiryOf(registration string, state syncStatus) time.Time {
	if registration != RegistrationRegistered {
		return time.Time{}
	}
	return state.selfKeyExpiry
}
