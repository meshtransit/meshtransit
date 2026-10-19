//go:build linux || darwin

package routesettings

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// openSettings opens the settings file without following a symbolic link
// or blocking on a FIFO, in a directory only root may write.
func openSettings(path string) (*os.File, error) {
	// A missing file turns everything off, wherever it would have been.
	if _, err := os.Lstat(path); err != nil {
		return nil, err
	}
	directory, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if err := checkOwner(directory); err != nil {
		return nil, fmt.Errorf("%w: directory %s", err, filepath.Dir(path))
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(descriptor), path), nil
}

// checkOwner refuses a file or directory not owned by root or writable by
// its group or others.
func checkOwner(info fs.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode().Perm()&0o022 != 0 || (!info.Mode().IsRegular() && !info.IsDir()) {
		return ErrUnsafeFile
	}
	return nil
}

// syncDirectory makes a rename in directory durable.
func syncDirectory(directory string) error {
	handle, err := os.Open(directory) //nolint:gosec // G304: the settings directory root chose
	if err != nil {
		return fmt.Errorf("routesettings: syncing %s: %w", directory, err)
	}
	defer func() { _ = handle.Close() }()
	if err := handle.Sync(); err != nil {
		return fmt.Errorf("routesettings: syncing %s: %w", directory, err)
	}
	return nil
}
