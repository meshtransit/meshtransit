package dexbroker_test

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const (
	dexModulePath      = "github.com/dexidp/dex"
	dexBrokerDirectory = "core/internal/adapter/dexbroker"
)

type importViolation struct {
	file       string
	importPath string
}

func TestDexImportsConfinedToAdapter(t *testing.T) {
	t.Parallel()

	root := moduleRoot(t)
	violations, err := scanDexImports(root)
	if err != nil {
		t.Fatalf("scan dex imports: %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("dex imports outside %s: %v", dexBrokerDirectory, violations)
	}
}

func TestScanDexImports(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		files    map[string]string
		expected []importViolation
	}{
		{
			name: "adapter import is allowed",
			files: map[string]string{
				"core/internal/adapter/dexbroker/runtime.go": "package dexbroker\n\nimport _ \"github.com/dexidp/dex/server\"\n",
			},
		},
		{
			name: "build tagged domain import is rejected",
			files: map[string]string{
				"internal/identity/provider.go": "//go:build future\n\npackage identity\n\nimport dex \"github.com/dexidp/dex/server\"\n",
			},
			expected: []importViolation{
				{
					file:       "internal/identity/provider.go",
					importPath: "github.com/dexidp/dex/server",
				},
			},
		},
		{
			name: "exact module import is rejected",
			files: map[string]string{
				"cmd/meshcore/broker.go": "package main\n\nimport . \"github.com/dexidp/dex\"\n",
			},
			expected: []importViolation{
				{
					file:       "cmd/meshcore/broker.go",
					importPath: "github.com/dexidp/dex",
				},
			},
		},
		{
			name: "lookalike path and source text are ignored",
			files: map[string]string{
				"internal/identity/provider.go": "package identity\n\nimport _ \"example.com/github.com/dexidp/dex\"\n\nconst upstream = \"github.com/dexidp/dex/server\"\n",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			root := t.TempDir()
			for name, source := range tt.files {
				writeSource(t, root, name, source)
			}

			got, err := scanDexImports(root)
			if err != nil {
				t.Fatalf("scan dex imports: %v", err)
			}
			if !slices.Equal(got, tt.expected) {
				t.Fatalf("scan dex imports = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestScanDexImportsRejectsInvalidGoSource(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	writeSource(t, root, "internal/identity/provider.go", "package identity\nimport (\n")

	if _, err := scanDexImports(root); err == nil {
		t.Fatal("scan dex imports succeeded for invalid go source")
	}
}

func scanDexImports(root string) ([]importViolation, error) {
	var violations []importViolation

	err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return rejectGoSourceSymlink(name)
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "vendor":
				if name != root {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if filepath.Ext(name) != ".go" {
			return nil
		}

		relativeName, err := filepath.Rel(root, name)
		if err != nil {
			return fmt.Errorf("resolve relative source path: %w", err)
		}
		relativeName = filepath.ToSlash(relativeName)

		parsed, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			return fmt.Errorf("parse %s: %w", relativeName, err)
		}
		for _, imported := range parsed.Imports {
			importPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil {
				return fmt.Errorf("parse import in %s: %w", relativeName, err)
			}
			if isDexImport(importPath) && filepath.ToSlash(filepath.Dir(relativeName)) != dexBrokerDirectory {
				violations = append(violations, importViolation{
					file:       relativeName,
					importPath: importPath,
				})
			}
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return violations, nil
}

func rejectGoSourceSymlink(name string) error {
	target, err := os.Stat(name)
	if err != nil {
		return fmt.Errorf("inspect symbolic link %s: %w", name, err)
	}
	if target.IsDir() || filepath.Ext(name) == ".go" {
		return fmt.Errorf("go source symbolic link is not allowed: %s", name)
	}
	return nil
}

func isDexImport(importPath string) bool {
	return importPath == dexModulePath || strings.HasPrefix(importPath, dexModulePath+"/")
}

func moduleRoot(t *testing.T) string {
	t.Helper()

	current, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}

	for {
		moduleFile := filepath.Join(current, "go.mod")
		info, err := os.Stat(moduleFile)
		if err == nil && !info.IsDir() {
			return current
		}
		if err != nil && !os.IsNotExist(err) {
			t.Fatalf("inspect %s: %v", moduleFile, err)
		}

		parent := filepath.Dir(current)
		if parent == current {
			t.Fatal("go.mod not found above working directory")
		}
		current = parent
	}
}

func writeSource(t *testing.T, root, name, source string) {
	t.Helper()

	fullName := filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(fullName), 0o750); err != nil {
		t.Fatalf("create source directory: %v", err)
	}
	if err := os.WriteFile(fullName, []byte(source), 0o600); err != nil {
		t.Fatalf("write source: %v", err)
	}
}
