package routesettings

import (
	"fmt"
	"os"
	"path/filepath"

	"meshtransit.net/client/internal/privatefile"
)

// checkExistingDirectory accepts the settings directory only when it
// exists, is no link or junction, only SYSTEM and Administrators may open
// it, and nobody else may write into its parent or rename, replace or
// re-permission anything above: SYSTEM then writes nowhere a user chose.
func checkExistingDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("%w: directory %s: %w", ErrUnsafeFile, directory, err)
	}
	if !info.IsDir() || reparsePoint(info) {
		return fmt.Errorf("%w: directory %s", ErrUnsafeFile, directory)
	}
	if err := privatefile.CheckFile(directory, info); err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafeFile, err)
	}
	if err := privatefile.CheckPublicDir(filepath.Dir(directory), 1); err != nil {
		return fmt.Errorf("%w: %w", ErrUnsafeFile, err)
	}
	return nil
}
