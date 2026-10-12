package identity

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// HasRecords reports whether stateDir already holds identity records, which
// only the key that sealed them can open: a missing key must then be
// recovered, never replaced by a new one.
func HasRecords(stateDir string) (bool, error) {
	entries, err := os.ReadDir(filepath.Join(stateDir, identityDirName))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("listing identity records: %w", err)
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			return true, nil
		}
	}

	return false, nil
}
