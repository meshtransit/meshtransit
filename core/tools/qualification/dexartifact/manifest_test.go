package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testCommit  = "11d2eeb52b42e1980e14cb91e69dd9e3faab2076"
	testDigestA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testDigestB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestArtifactManifestValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		mutate    func(*artifactManifest)
		wantError bool
	}{
		{name: "valid"},
		{
			name: "wrong schema",
			mutate: func(manifest *artifactManifest) {
				manifest.SchemaVersion = "meshtransit.dex-patch/v2"
			},
			wantError: true,
		},
		{
			name: "non https repository",
			mutate: func(manifest *artifactManifest) {
				manifest.Upstream.Repository = "ssh://git.example/dex"
			},
			wantError: true,
		},
		{
			name: "wrong module path",
			mutate: func(manifest *artifactManifest) {
				manifest.Upstream.ModulePath = "example.com/dex"
			},
			wantError: true,
		},
		{
			name: "module version commit mismatch",
			mutate: func(manifest *artifactManifest) {
				manifest.Upstream.ModuleVersion = "v0.0.0-20260303133905-aaaaaaaaaaaa"
			},
			wantError: true,
		},
		{
			name: "duplicate patch id",
			mutate: func(manifest *artifactManifest) {
				manifest.Patches = append(manifest.Patches, patchReference{
					ID: "issuer", Path: "patches/second.patch", SHA256: testDigestB,
				})
			},
			wantError: true,
		},
		{
			name: "duplicate evidence path",
			mutate: func(manifest *artifactManifest) {
				manifest.Evidence.SBOM.Path = manifest.Evidence.LicenseInventory.Path
			},
			wantError: true,
		},
		{
			name: "parent traversal",
			mutate: func(manifest *artifactManifest) {
				manifest.Patches[0].Path = "../patch.diff"
			},
			wantError: true,
		},
		{
			name: "control character build flag",
			mutate: func(manifest *artifactManifest) {
				manifest.Build.Flags[0] = "-trimpath\n"
			},
			wantError: true,
		},
		{
			name: "uppercase digest",
			mutate: func(manifest *artifactManifest) {
				manifest.Build.BinarySHA256 = strings.ToUpper(testDigestB)
			},
			wantError: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			manifest := validTestManifest()
			if test.mutate != nil {
				test.mutate(&manifest)
			}
			err := manifest.validate()
			if test.wantError {
				if !errors.Is(err, errInvalidManifest) {
					t.Fatalf("validate() error = %v, want errInvalidManifest", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validate() error = %v", err)
			}
		})
	}
}

func TestLoadManifestRejectsAmbiguousJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "duplicate name",
			data: []byte(`{"schema_version":"meshtransit.dex-patch/v1","schema_version":"meshtransit.dex-patch/v1"}`),
		},
		{
			name: "unknown field",
			data: appendManifestField(t, validTestManifest(), `"unexpected":true`),
		},
		{
			name: "trailing value",
			data: append(marshalManifest(t, validTestManifest()), []byte(` {}`)...),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			manifestPath := filepath.Join(t.TempDir(), "manifest.json")
			if err := os.WriteFile(manifestPath, test.data, 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := loadManifest(manifestPath)
			if !errors.Is(err, errInvalidManifest) {
				t.Fatalf("loadManifest() error = %v, want errInvalidManifest", err)
			}
		})
	}
}

func TestManifestSchemaIsStrictJSON(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("manifest.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) {
		t.Fatal("manifest.schema.json is not valid JSON")
	}
	if err := rejectDuplicateJSONNames(data); err != nil {
		t.Fatalf("manifest.schema.json duplicate check error = %v", err)
	}
}

func validTestManifest() artifactManifest {
	return artifactManifest{
		SchemaVersion: manifestSchemaVersion,
		Upstream: upstreamReference{
			Repository:    "https://github.com/dexidp/dex.git",
			Version:       "v2.45.1",
			Commit:        testCommit,
			ModulePath:    dexUpstreamModule,
			ModuleVersion: "v0.0.0-20260303133905-11d2eeb52b42",
		},
		Patches: []patchReference{{
			ID: "issuer", Path: "patches/issuer.patch", SHA256: testDigestA,
		}},
		SourceTreeSHA256: testDigestB,
		Build: buildReference{
			GoVersion: "go1.26.8", Flags: []string{"-trimpath"}, BinarySHA256: testDigestA,
		},
		Evidence: evidenceReferences{
			LicenseInventory:    fileReference{Path: "evidence/licenses.json", SHA256: testDigestA},
			SBOM:                fileReference{Path: "evidence/sbom.json", SHA256: testDigestA},
			VulnerabilityReport: fileReference{Path: "evidence/vulnerabilities.json", SHA256: testDigestA},
			QualificationReport: fileReference{Path: "evidence/qualification.json", SHA256: testDigestA},
		},
	}
}

func marshalManifest(t *testing.T, manifest artifactManifest) []byte {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func appendManifestField(t *testing.T, manifest artifactManifest, field string) []byte {
	t.Helper()
	data := marshalManifest(t, manifest)
	if len(data) == 0 || data[len(data)-1] != '}' {
		t.Fatal("manifest encoding did not end with object")
	}
	return append(append(data[:len(data)-1], ','), append([]byte(field), '}')...)
}
