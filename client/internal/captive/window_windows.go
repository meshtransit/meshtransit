package captive

import (
	"fmt"
	"os"
)

// openWindowFile opens the window file, a regular file in the service's
// state directory, which only SYSTEM and administrators may write.
func openWindowFile(path string) (*os.File, error) {
	file, err := os.Open(path) //nolint:gosec // G304: the service's own state file
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("%w: not a regular file", ErrWindowInvalid)
	}
	return file, nil
}
