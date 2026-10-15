//go:build !windows

package privatefile

import (
	"fmt"
	"os"
	"syscall"
)

func makeDir(dir string, perm os.FileMode) error { return os.Mkdir(dir, perm) }

func isReparsePoint(os.FileInfo) bool { return false }

// checkDirOwner requires the directory to belong to the service's user, so
// nobody else can change its mode or contents later.
func checkDirOwner(dir string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%w: cannot read the owner of %s", ErrNotPrivate, dir)
	}
	if uid := os.Geteuid(); int64(stat.Uid) != int64(uid) {
		return fmt.Errorf("%w: %s is owned by uid %d, not %d", ErrNotPrivate, dir, stat.Uid, uid)
	}

	return nil
}
