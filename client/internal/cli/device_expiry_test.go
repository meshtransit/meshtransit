package cli

import (
	"testing"
	"time"
)

func TestFormatDeviceExpiry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.October, 18, 10, 0, 0, 0, time.UTC)
	at := func(remaining time.Duration) string { return now.Add(remaining).Format(time.RFC3339) }
	for _, test := range []struct {
		name, state, expiresAt, want string
	}{
		{"never", "never", "", "never"},
		{"no map yet", "unknown", "", "unknown"},
		{"older daemon", "", "", "unknown"},
		{"far off", "ok", at(90 * 24 * time.Hour), "in 90 days (2027-01-16 10:00 UTC)"},
		{
			"two weeks", "soon", at(14 * 24 * time.Hour),
			"in 14 days (2026-11-01 10:00 UTC); sign in again with meshctl login, or enroll with a new key, to keep this Device",
		},
		{
			"last day", "imminent", at(5 * time.Hour),
			"in 5 hours (2026-10-18 15:00 UTC); sign in again with meshctl login, or enroll with a new key, to keep this Device, now",
		},
		{
			"last hour", "imminent", at(10 * time.Minute),
			"in less than an hour (2026-10-18 10:10 UTC); sign in again with meshctl login, or enroll with a new key, to keep this Device, now",
		},
		{"expired", "expired", at(-time.Hour), "expired 2026-10-18 09:00 UTC; sign in again with meshctl login, or enroll with a new key"},
		{"bad time", "soon", "yesterday", "soon"},
	} {
		if got := formatDeviceExpiry(test.state, test.expiresAt, now); got != test.want {
			t.Errorf("%s: %q, want %q", test.name, got, test.want)
		}
	}
}
