//go:build !windows

package kubeconfig

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func isRoot() bool { return os.Geteuid() == 0 }

// ownedByUser refuses a path another user owns: meshctl would leave a file
// that user cannot then change, or change theirs.
func ownedByUser(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("kubeconfig: cannot read the owner")
	}
	if int64(stat.Uid) != int64(os.Getuid()) {
		return fmt.Errorf("%w: %s belongs to uid %d", ErrUnsafe, path, stat.Uid)
	}
	return nil
}

func retryableRename(error) bool { return false }
