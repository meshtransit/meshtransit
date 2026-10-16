package enrollment

import "time"

// ForgeDeviceLifetimeForTest builds a lifetime that bypasses its
// constructor, to check that credentials refuse it.
func ForgeDeviceLifetimeForTest(kind DeviceLifetimeKind, duration time.Duration) DeviceLifetime {
	return DeviceLifetime{kind: kind, duration: duration}
}
