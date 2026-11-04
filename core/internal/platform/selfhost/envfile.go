package selfhost

import (
	"bufio"
	"bytes"
	"fmt"
	"path/filepath"
	"strings"
)

// maximumRenderedBytes bounds every file setup reads back from the
// directories the image user owns.
const maximumRenderedBytes = 64 * 1024

// ReadEnvFile reads a NAME=value file render wrote: a regular file (never
// through a link) of bounded size.
func ReadEnvFile(path string) (map[string]string, error) {
	contents, err := readRegularFile(path, maximumRenderedBytes)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	settings := map[string]string{}
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	for scanner.Scan() {
		name, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok || name == "" {
			return nil, fmt.Errorf("%s: malformed line", filepath.Base(path))
		}
		settings[name] = value
	}
	return settings, scanner.Err()
}
