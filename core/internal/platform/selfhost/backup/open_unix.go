//go:build linux || darwin

package backup

import "syscall"

const (
	// noFollow refuses a final link; openSafely also never blocks on a FIFO.
	noFollow    = syscall.O_NOFOLLOW
	openSafely  = syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	openDirOnly = syscall.O_DIRECTORY
)

// FreeBytes is the space an unprivileged writer may still use in dir's
// filesystem.
func FreeBytes(dir string) (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(dir, &stat); err != nil {
		return 0, err
	}
	return uint64(stat.Bavail) * uint64(stat.Bsize), nil // #nosec G115 -- block size is positive.
}
