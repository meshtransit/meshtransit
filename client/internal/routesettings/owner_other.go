//go:build !linux && !darwin && !windows

package routesettings

import (
	"io/fs"
	"os"
)

// openSettings opens the settings file the embedding app owns.
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

// prepareDirectory creates the directory in the app's own storage.
func prepareDirectory(directory string) error {
	return os.MkdirAll(directory, 0o700)
}
