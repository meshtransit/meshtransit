//go:build !linux && !darwin

package routesettings

import (
	"io/fs"
	"os"
)

// openSettings opens the settings file; on Windows the directory's ACL
// admits only SYSTEM and administrators.
func openSettings(path string) (*os.File, error) {
	return os.Open(path) //nolint:gosec // G304: the settings path SYSTEM chose
}

// checkOwner accepts a regular file.
func checkOwner(info fs.FileInfo) error {
	if !info.Mode().IsRegular() {
		return ErrUnsafeFile
	}
	return nil
}

// syncDirectory does nothing: Windows makes a rename durable itself.
func syncDirectory(string) error { return nil }
