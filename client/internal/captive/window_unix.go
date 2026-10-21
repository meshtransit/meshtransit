//go:build unix

package captive

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// openWindowFile opens the window file without following a symbolic link or
// blocking on a FIFO, only when root owns it and its directory and no one
// else may write either: the helper honours no window another user wrote.
func openWindowFile(path string) (*os.File, error) {
	// No window open, wherever the file would have been.
	if _, err := os.Lstat(path); err != nil {
		return nil, err
	}
	directory, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if !rootOnly(directory) {
		return nil, fmt.Errorf("%w: directory %s is not root's alone", ErrWindowInvalid, filepath.Dir(path))
	}
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(descriptor), path)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !rootOnly(info) {
		_ = file.Close()
		return nil, fmt.Errorf("%w: not a file only root writes", ErrWindowInvalid)
	}
	return file, nil
}

// rootOnly reports whether root owns info and its group and others cannot
// write it.
func rootOnly(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && info.Mode().Perm()&0o022 == 0
}
