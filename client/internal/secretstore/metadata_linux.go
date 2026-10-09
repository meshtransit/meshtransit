//go:build linux

package secretstore

import (
	"fmt"
	"os"
	"syscall"
)

func validateSystemdCredentialMetadata(info os.FileInfo) error {
	permissions := info.Mode().Perm()
	if permissions != 0o400 && permissions != 0o440 {
		return fmt.Errorf("%w: systemd credential permissions are unsafe", ErrKeyInvalid)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Gid != 0 {
		return fmt.Errorf("%w: systemd credential ownership is unsafe", ErrKeyInvalid)
	}

	return nil
}
