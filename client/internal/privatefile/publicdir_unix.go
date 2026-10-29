//go:build !windows

package privatefile

import (
	"fmt"
	"os"
	"syscall"
)

func makePublicDir(dir string) error {
	if err := os.Mkdir(dir, 0o755); err != nil { //nolint:gosec // A public directory: every user reads it.
		return err
	}
	// The service's umask would narrow it.
	return os.Chmod(dir, 0o755) //nolint:gosec // Directories require execute bits.
}

func owner(path string, info os.FileInfo) (uint32, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("%w: cannot read the owner of %s", ErrNotPublicDir, path)
	}
	return stat.Uid, nil
}

// checkStrictPublic: owned by root or the service, written by nobody else.
func checkStrictPublic(path string, info os.FileInfo) error {
	uid, err := owner(path, info)
	if err != nil {
		return err
	}
	if uid != 0 && int64(uid) != int64(os.Geteuid()) {
		return fmt.Errorf("%w: %s is owned by uid %d", ErrNotPublicDir, path, uid)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: %s is writable by others (%04o)", ErrNotPublicDir, path, info.Mode().Perm())
	}
	return nil
}

// checkAncestor: owned by root or the service; writable by others only
// with the sticky bit, so they cannot rename what they do not own.
func checkAncestor(path string, info os.FileInfo) error {
	uid, err := owner(path, info)
	if err != nil {
		return err
	}
	if uid != 0 && int64(uid) != int64(os.Geteuid()) {
		return fmt.Errorf("%w: %s is owned by uid %d", ErrNotPublicDir, path, uid)
	}
	if info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
		return fmt.Errorf("%w: %s is writable by others without the sticky bit", ErrNotPublicDir, path)
	}
	return nil
}

// linksAllowed: a link above the strict levels may be the system's own,
// as macOS /var.
const linksAllowed = true

// checkLink accepts a link above the strict levels only when root owns it:
// whoever owns a link decides where it points.
func checkLink(path string, info os.FileInfo) error {
	uid, err := owner(path, info)
	if err != nil {
		return err
	}
	if uid != 0 {
		return fmt.Errorf("%w: %s is a link owned by uid %d", ErrNotPublicDir, path, uid)
	}
	return nil
}
