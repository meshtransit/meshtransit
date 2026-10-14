// Package underlaytest helps test that a package's sockets go through the
// underlay protector.
package underlaytest

import (
	"errors"
	"testing"

	"meshtransit.net/client/internal/underlay"
)

// Refuse installs a protector that refuses every socket until the test
// ends, so a socket that is protected fails with underlay.ErrNotProtected
// and one that bypasses the protector does not. The protector is
// process-wide: the calling test must not run in parallel.
func Refuse(t testing.TB) {
	t.Helper()
	underlay.SetProtector(func(uintptr) error { return errors.New("refused by the test") })
	t.Cleanup(func() { underlay.SetProtector(nil) })
}

// RequireProtected fails the test unless err is underlay.ErrNotProtected.
func RequireProtected(t testing.TB, what string, err error) {
	t.Helper()
	if !errors.Is(err, underlay.ErrNotProtected) {
		t.Fatalf("%s: error = %v, want underlay.ErrNotProtected (the socket bypasses the protector)", what, err)
	}
}
