//go:build !windows

package routesettings

import (
	"fmt"
	"os"
)

// checkExistingDirectory accepts an existing directory: elsewhere meshd
// does not write the settings (a helper or the embedding app does).
func checkExistingDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("%w: directory %s", ErrUnsafeFile, directory)
	}
	return nil
}
