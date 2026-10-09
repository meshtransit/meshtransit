package dexbroker_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const maximumDependencyFileBytes = 1 << 20

type dependencyManifest struct {
	Upstream struct {
		ModulePath    string `json:"module_path"`
		ModuleVersion string `json:"module_version"`
	} `json:"upstream"`
}

func TestDexDependencyMatchesPinnedManifest(t *testing.T) {
	t.Parallel()

	root := moduleRoot(t)
	manifestData := readDependencyFile(
		t,
		filepath.Join(root, "core", "third_party", "dex", "v2.45.1", "manifest.darwin-arm64.json"),
	)
	manifest := dependencyManifest{}
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatalf("decode dependency manifest: %v", err)
	}
	if manifest.Upstream.ModulePath != dexModulePath || manifest.Upstream.ModuleVersion == "" {
		t.Fatalf("invalid Dex module identity in pinned manifest")
	}

	moduleData := readDependencyFile(t, filepath.Join(root, "go.mod"))
	if err := verifyPinnedDexRequirement(
		string(moduleData),
		manifest.Upstream.ModulePath,
		manifest.Upstream.ModuleVersion,
	); err != nil {
		t.Fatalf("verify pinned Dex requirement: %v", err)
	}
}

func TestVerifyPinnedDexRequirement(t *testing.T) {
	t.Parallel()

	const version = "v0.0.0-20260303133905-11d2eeb52b42"
	tests := []struct {
		name      string
		contents  string
		wantError bool
	}{
		{
			name:     "direct requirement",
			contents: "require (\n\tgithub.com/dexidp/dex " + version + "\n)\n",
		},
		{
			name:      "missing requirement",
			contents:  "module meshtransit.net\n",
			wantError: true,
		},
		{
			name:      "wrong version",
			contents:  "require github.com/dexidp/dex v0.0.0-20260303133905-aaaaaaaaaaaa\n",
			wantError: true,
		},
		{
			name:      "indirect requirement",
			contents:  "require github.com/dexidp/dex " + version + " // indirect\n",
			wantError: true,
		},
		{
			name: "replacement block",
			contents: "require github.com/dexidp/dex " + version + "\n" +
				"replace (\n\tgithub.com/dexidp/dex => /tmp/dex\n)\n",
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := verifyPinnedDexRequirement(test.contents, dexModulePath, version)
			if test.wantError && err == nil {
				t.Fatal("verifyPinnedDexRequirement() succeeded")
			}
			if !test.wantError && err != nil {
				t.Fatalf("verifyPinnedDexRequirement() error = %v", err)
			}
		})
	}
}

func verifyPinnedDexRequirement(contents, modulePath, moduleVersion string) error {
	requireCount := 0
	for _, rawLine := range strings.Split(contents, "\n") {
		line, comment, _ := strings.Cut(rawLine, "//")
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if hasModuleReplacement(fields, modulePath) || hasModuleReplacement(fields, modulePath+"/api/v2") {
			return fmt.Errorf("local or alternate Dex replacement is not allowed")
		}
		if (len(fields) == 2 && fields[0] == modulePath && fields[1] == moduleVersion) ||
			(len(fields) == 3 && fields[0] == "require" && fields[1] == modulePath &&
				fields[2] == moduleVersion) {
			if strings.Contains(comment, "indirect") {
				return fmt.Errorf("Dex must remain a direct build-tagged dependency")
			}
			requireCount++
		}
	}
	if requireCount != 1 {
		return fmt.Errorf("expected exactly one Dex requirement, found %d", requireCount)
	}
	return nil
}

func hasModuleReplacement(fields []string, modulePath string) bool {
	arrow := -1
	for index, field := range fields {
		if field == "=>" {
			arrow = index
			break
		}
	}
	if arrow < 1 {
		return false
	}
	pathIndex := 0
	if fields[0] == "replace" {
		pathIndex = 1
	}
	return pathIndex < arrow && fields[pathIndex] == modulePath
}

func readDependencyFile(t *testing.T, name string) []byte {
	t.Helper()

	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() < 0 || info.Size() > maximumDependencyFileBytes {
		t.Fatalf("inspect dependency file: %v", err)
	}
	contents, err := os.ReadFile(name) // #nosec G304 -- test path is rooted in the resolved module checkout.
	if err != nil {
		t.Fatalf("read dependency file: %v", err)
	}
	return contents
}
