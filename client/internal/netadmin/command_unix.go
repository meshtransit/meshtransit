//go:build linux || darwin

package netadmin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// requireTrustedBinary accepts only a canonical absolute path to a regular,
// root-owned file that group and others cannot write.
func requireTrustedBinary(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("path must be absolute and canonical")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspecting %s: %w", path, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || stat.Uid != 0 {
		return errors.New("binary must be a root-owned non-writable regular file")
	}
	return nil
}

func wrapCommandError(context string, err error) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("%s: %w", context, err)
}
