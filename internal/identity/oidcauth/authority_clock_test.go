package oidcauth

import (
	"testing"
	"time"
)

func TestAuthorityTimeReachedBoundsPositiveSkew(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, time.September, 26, 15, 0, 0, 0, time.UTC)

	for _, test := range []struct {
		name          string
		now           time.Time
		authorityTime time.Time
		want          bool
	}{
		{name: "reached", now: now, authorityTime: now.Add(-time.Nanosecond), want: true},
		{name: "equal", now: now, authorityTime: now, want: true},
		{name: "bounded skew", now: now, authorityTime: now.Add(authorityClockSkewAllowance), want: true},
		{name: "excessive skew", now: now, authorityTime: now.Add(authorityClockSkewAllowance + time.Nanosecond)},
		{name: "zero local", authorityTime: now},
		{name: "zero authority", now: now},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := authorityTimeReached(test.now, test.authorityTime); got != test.want {
				t.Fatalf("authorityTimeReached() = %t, want %t", got, test.want)
			}
		})
	}
}
