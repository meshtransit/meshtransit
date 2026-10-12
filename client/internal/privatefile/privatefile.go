// Package privatefile keeps meshd's state readable only by the service:
// owner-only mode bits on Unix, a protected DACL for SYSTEM and
// Administrators on Windows, where mode bits mean nothing.
package privatefile

import "errors"

// ErrTooBroad reports a file or directory others can read or change.
var ErrTooBroad = errors.New("privatefile: access is too broad")

// Well-known SIDs allowed on Windows state files.
const (
	sidLocalSystem    = "S-1-5-18"
	sidAdministrators = "S-1-5-32-544"
)

// trustedSIDs reports whether every SID granted access, and the owner, is
// LocalSystem or Administrators.
func trustedSIDs(owner string, allowed []string) bool {
	if owner != sidLocalSystem && owner != sidAdministrators {
		return false
	}
	for _, sid := range allowed {
		if sid != sidLocalSystem && sid != sidAdministrators {
			return false
		}
	}

	return true
}
