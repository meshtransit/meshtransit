package routesettings

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"

	"meshtransit.net/client/internal/privatefile"
)

// openSettings opens the settings file only inside a directory that SYSTEM
// or Administrators own and only they may access, which no link replaces,
// and only when the file is no link and as private: nobody else can put a
// file there or swap one in, so meshd, Core and users cannot turn routes on.
func openSettings(path string) (*os.File, error) {
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || reparsePoint(info) {
		return nil, fmt.Errorf("%w: directory %s", ErrUnsafeFile, directory)
	}
	if err := privatefile.CheckFile(directory, info); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsafeFile, err)
	}
	if info, err = os.Lstat(path); err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || reparsePoint(info) {
		return nil, ErrUnsafeFile
	}
	if err := privatefile.CheckFile(path, info); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnsafeFile, err)
	}
	return os.Open(path) //nolint:gosec // G304: the settings path SYSTEM chose
}

// reparsePoint reports junctions and mount points as well as links.
func reparsePoint(info fs.FileInfo) bool {
	data, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return !ok || data.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

// checkOwner accepts a regular file; openSettings checked its access list.
func checkOwner(info fs.FileInfo) error {
	if !info.Mode().IsRegular() {
		return ErrUnsafeFile
	}
	return nil
}

// prepareDirectory creates the settings directory private to SYSTEM and
// Administrators from the start, or checks the one there is no link and
// theirs, then gives it that access list, which the file inherits.
func prepareDirectory(directory string) error {
	if err := privatefile.PrepareDir(directory, 0o700); err != nil {
		return err
	}
	return privatefile.RestrictDir(directory)
}

// syncDirectory does nothing: Windows makes a rename durable itself.
func syncDirectory(string) error { return nil }
