//go:build !windows

package privatefile

import (
	"errors"
	"fmt"
	"os"
)

// CheckFile rejects a file that group or others can access.
func CheckFile(_ string, info os.FileInfo) error {
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: permissions %04o", ErrTooBroad, info.Mode().Perm())
	}

	return nil
}

// RestrictDir makes dir accessible only to its owner.
func RestrictDir(dir string) error {
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // Directories require execute bits.
		return fmt.Errorf("restricting %s: %w", dir, err)
	}

	return nil
}

// SyncDir flushes the directory entry changes of root (renames, links).
func SyncDir(root *os.Root) (syncErr error) {
	directory, err := root.Open(".")
	if err != nil {
		return fmt.Errorf("opening directory for sync: %w", err)
	}
	defer func() { syncErr = errors.Join(syncErr, directory.Close()) }()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("syncing directory: %w", err)
	}

	return nil
}
