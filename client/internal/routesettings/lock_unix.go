//go:build linux || darwin

package routesettings

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// lockSettings holds an exclusive lock on the lock file next to path until
// the returned function runs. The file lives in the settings directory,
// which only root writes; it is opened without following a link.
func lockSettings(path string) (func(), error) {
	lockPath := path + ".lock"
	descriptor, err := unix.Open(lockPath, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("routesettings: opening %s: %w", lockPath, err)
	}
	for {
		err = unix.Flock(descriptor, unix.LOCK_EX)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		_ = unix.Close(descriptor)
		return nil, fmt.Errorf("routesettings: locking %s: %w", lockPath, err)
	}
	file := os.NewFile(uintptr(descriptor), lockPath)
	// Closing the descriptor releases the lock.
	return func() { _ = file.Close() }, nil
}
