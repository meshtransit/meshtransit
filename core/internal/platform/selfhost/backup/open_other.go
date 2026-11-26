//go:build !(linux || darwin)

package backup

const (
	noFollow    = 0
	openSafely  = 0
	openDirOnly = 0
)

// FreeBytes is not measured outside Unix: self-host runs on Linux.
func FreeBytes(string) (uint64, error) { return ^uint64(0), nil }
