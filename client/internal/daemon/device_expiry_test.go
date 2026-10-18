package daemon

import (
	"testing"
	"time"
)

func TestDeviceExpiryState(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.October, 18, 10, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name      string
		expiresAt time.Time
		want      string
	}{
		{"no map", time.Time{}, DeviceExpiryUnknown},
		{"never", time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC), DeviceExpiryNever},
		{"far off", now.Add(15 * 24 * time.Hour), DeviceExpiryOK},
		{"14 days", now.Add(14 * 24 * time.Hour), DeviceExpirySoon},
		{"a day", now.Add(24 * time.Hour), DeviceExpiryImminent},
		{"a minute", now.Add(time.Minute), DeviceExpiryImminent},
		{"now", now, DeviceExpiryExpired},
		{"past", now.Add(-time.Hour), DeviceExpiryExpired},
	} {
		if got := DeviceExpiryState(test.expiresAt, now); got != test.want {
			t.Errorf("%s: %q, want %q", test.name, got, test.want)
		}
	}
}

func TestSyncStatusKeepsTheDeviceExpiryOfTheSameProfile(t *testing.T) {
	t.Parallel()
	expiry := time.Date(2026, time.November, 1, 10, 0, 0, 0, time.UTC)
	service := &Service{}
	service.setSyncStatus(syncStatus{profileID: "office", state: ControlSessionSynchronized, selfKeyExpiry: expiry})
	// A reconnect and then a stream Core ended carry no map.
	service.setSyncStatus(syncStatus{profileID: "office", state: ControlSessionConnecting})
	service.setSyncStatus(syncStatus{profileID: "office", state: ControlSessionBlocked})
	if got := service.getSyncStatus().selfKeyExpiry; !got.Equal(expiry) {
		t.Fatalf("expiry after reconnect = %v, want %v", got, expiry)
	}
	if got := deviceExpiryOf(RegistrationRegistered, service.getSyncStatus()); !got.Equal(expiry) {
		t.Fatalf("reported expiry = %v", got)
	}
	if got := deviceExpiryOf(RegistrationUnregistered, service.getSyncStatus()); !got.IsZero() {
		t.Fatalf("unregistered profile reported expiry %v", got)
	}
	// A newer map replaces it; another profile starts without one.
	renewed := expiry.Add(180 * 24 * time.Hour)
	service.setSyncStatus(syncStatus{profileID: "office", state: ControlSessionSynchronized, selfKeyExpiry: renewed})
	if got := service.getSyncStatus().selfKeyExpiry; !got.Equal(renewed) {
		t.Fatalf("expiry after renewal = %v, want %v", got, renewed)
	}
	service.setSyncStatus(syncStatus{profileID: "lab", state: ControlSessionConnecting})
	if got := service.getSyncStatus().selfKeyExpiry; !got.IsZero() {
		t.Fatalf("another profile inherited expiry %v", got)
	}
	// Signing in again passes through an unregistered profile: the old expiry
	// is gone before the new registration's first map.
	for _, stop := range []string{ControlSessionInactive, ControlSessionDown} {
		service.setSyncStatus(syncStatus{profileID: "office", state: ControlSessionSynchronized, selfKeyExpiry: expiry})
		service.setSyncStatus(syncStatus{profileID: "office", state: stop})
		service.setSyncStatus(syncStatus{profileID: "office", state: ControlSessionConnecting})
		if got := service.getSyncStatus().selfKeyExpiry; !got.IsZero() {
			t.Fatalf("expiry survived %s: %v", stop, got)
		}
	}
}
