package dexbroker_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The broker's schema migration runs only in the install and upgrade step
// and in qualification tooling: never in a serving path, where it would run
// with the runtime identity.
var migrateCallers = []string{
	"core/cmd/meshcore/setup_identity_dex.go",
	"core/internal/adapter/dexbroker/postgres_migrate.go",
	"core/internal/adapter/dexbroker/postgres_qualification.go",
}

func TestBrokerSchemaMigrationHasOnlyApprovedCallers(t *testing.T) {
	t.Parallel()

	root := moduleRoot(t)
	var unexpected []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if name := entry.Name(); path != root && (strings.HasPrefix(name, ".") || name == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		contents, err := os.ReadFile(path) // #nosec G304,G122 -- module sources under test.
		if err != nil {
			return err
		}
		if !strings.Contains(string(contents), "MigratePostgreSQLSchema") {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if !slices.Contains(migrateCallers, filepath.ToSlash(relative)) {
			unexpected = append(unexpected, filepath.ToSlash(relative))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scan module: %v", err)
	}
	if len(unexpected) != 0 {
		t.Fatalf("MigratePostgreSQLSchema named outside approved callers: %v", unexpected)
	}
}
