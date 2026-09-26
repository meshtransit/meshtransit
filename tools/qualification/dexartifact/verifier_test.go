package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type artifactFixture struct {
	manifestPath  string
	sourcePath    string
	binaryPath    string
	patchPath     string
	evidencePath  string
	moduleVersion string
}

func TestVerifyArtifact(t *testing.T) {
	t.Parallel()

	fixture := newArtifactFixture(t)
	report, err := verifyArtifact(t.Context(), rawOptions{
		manifestPath: fixture.manifestPath,
		sourcePath:   fixture.sourcePath,
		binaryPath:   fixture.binaryPath,
	})
	if err != nil {
		t.Fatalf("verifyArtifact() error = %v", err)
	}
	if !report.Verified || report.UpstreamVersion != "v2.45.1" || report.PatchCount != 1 ||
		report.SourceTreeSHA256 == "" || report.BinarySHA256 == "" {
		t.Fatalf("verifyArtifact() report = %+v", report)
	}
	contents, err := os.ReadFile(filepath.Join(fixture.sourcePath, "message.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "before\n" {
		t.Fatalf("source checkout was modified: %q", contents)
	}
	status := runGitTest(t, fixture.sourcePath, "status", "--porcelain=v1", "--untracked-files=all")
	if strings.TrimSpace(status) != "" {
		t.Fatalf("source checkout status = %q", status)
	}
}

func TestVerifyArtifactPreparesSource(t *testing.T) {
	t.Parallel()

	fixture := newArtifactFixture(t)
	preparedRoot := t.TempDir()
	report, err := verifyArtifact(t.Context(), rawOptions{
		manifestPath:     fixture.manifestPath,
		sourcePath:       fixture.sourcePath,
		binaryPath:       fixture.binaryPath,
		preparedRootPath: preparedRoot,
	})
	if err != nil {
		t.Fatalf("verifyArtifact() error = %v", err)
	}
	if !report.Verified || !report.SourcePrepared {
		t.Fatalf("verifyArtifact() report = %+v", report)
	}
	preparedSource := filepath.Join(preparedRoot, "source")
	preparedSourceRoot, err := os.OpenRoot(preparedSource)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := preparedSourceRoot.Close(); err != nil {
			t.Errorf("close prepared source root: %v", err)
		}
	}()
	contents, err := preparedSourceRoot.ReadFile("message.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "after\n" {
		t.Fatalf("prepared source = %q, want patched contents", contents)
	}
	if _, err := preparedSourceRoot.Stat(".git"); !os.IsNotExist(err) {
		t.Fatalf("prepared source contains Git metadata: %v", err)
	}

	_, err = verifyArtifact(t.Context(), rawOptions{
		manifestPath:     fixture.manifestPath,
		sourcePath:       fixture.sourcePath,
		binaryPath:       fixture.binaryPath,
		preparedRootPath: preparedRoot,
	})
	if !errors.Is(err, errVerification) {
		t.Fatalf("verifyArtifact() second preparation error = %v, want errVerification", err)
	}
	contents, err = preparedSourceRoot.ReadFile("message.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "after\n" {
		t.Fatalf("existing prepared source was modified: %q", contents)
	}
}

func TestVerifyArtifactPreparesWorkspace(t *testing.T) {
	t.Parallel()

	fixture := newArtifactFixture(t)
	preparedRoot := t.TempDir()
	meshcoreRoot := createMeshCoreModule(t, fixture.moduleVersion, "")
	report, err := verifyArtifact(t.Context(), rawOptions{
		manifestPath:        fixture.manifestPath,
		sourcePath:          fixture.sourcePath,
		binaryPath:          fixture.binaryPath,
		preparedRootPath:    preparedRoot,
		workspaceModulePath: meshcoreRoot,
	})
	if err != nil {
		t.Fatalf("verifyArtifact() error = %v", err)
	}
	if !report.Verified || !report.SourcePrepared || !report.WorkspacePrepared ||
		report.UpstreamModuleVersion != fixture.moduleVersion {
		t.Fatalf("verifyArtifact() report = %+v", report)
	}
	workspace, err := os.ReadFile(filepath.Join(preparedRoot, "go.work")) // #nosec G304 -- preparedRoot is an isolated test directory.
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"go 1.26.8",
		"toolchain go1.26.8",
		filepath.ToSlash(meshcoreRoot),
		filepath.ToSlash(filepath.Join(preparedRoot, "source")),
		filepath.ToSlash(filepath.Join(preparedRoot, "source", "api", "v2")),
	} {
		if !strings.Contains(string(workspace), expected) {
			t.Fatalf("go.work does not contain %q: %s", expected, workspace)
		}
	}
}

func TestValidateWorkspaceModuleRejectsDexReplace(t *testing.T) {
	t.Parallel()

	moduleVersion := "v0.0.0-20260303133905-11d2eeb52b42"
	meshcoreRoot := createMeshCoreModule(
		t,
		moduleVersion,
		"\nreplace github.com/dexidp/dex => /tmp/dex\n",
	)
	if _, err := validateWorkspaceModule(meshcoreRoot, moduleVersion, "go1.26.8"); !errors.Is(err, errVerification) {
		t.Fatalf("validateWorkspaceModule() error = %v, want errVerification", err)
	}
}

func TestPinnedDexManifestFiles(t *testing.T) {
	t.Parallel()

	manifestPath, err := filepath.Abs(filepath.Join(
		"..", "..", "..", "third_party", "dex", "v2.45.1", "manifest.darwin-arm64.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := loadManifest(manifestPath)
	if err != nil {
		t.Fatalf("loadManifest() error = %v", err)
	}
	t.Cleanup(func() {
		if err := loaded.close(); err != nil {
			t.Errorf("close manifest root: %v", err)
		}
	})

	patchPaths, err := verifyManifestFiles(loaded.root, loaded.manifest)
	if err != nil {
		t.Fatalf("verifyManifestFiles() error = %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(patchPaths[0]); err != nil {
			t.Errorf("remove patch copies: %v", err)
		}
	})
	if got := len(loaded.manifest.Patches); got != 8 {
		t.Fatalf("patch count = %d, want 8", got)
	}
}

func TestVerifyArtifactRejectsTampering(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		tamper func(*testing.T, artifactFixture)
	}{
		{
			name: "patch",
			tamper: func(t *testing.T, fixture artifactFixture) {
				t.Helper()
				if err := os.WriteFile(fixture.patchPath, []byte("tampered patch\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "binary",
			tamper: func(t *testing.T, fixture artifactFixture) {
				t.Helper()
				if err := os.WriteFile(fixture.binaryPath, []byte("tampered binary\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "evidence",
			tamper: func(t *testing.T, fixture artifactFixture) {
				t.Helper()
				if err := os.WriteFile(fixture.evidencePath, []byte("tampered evidence\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "non executable binary",
			tamper: func(t *testing.T, fixture artifactFixture) {
				t.Helper()
				if err := os.Chmod(fixture.binaryPath, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "wrong upstream remote",
			tamper: func(t *testing.T, fixture artifactFixture) {
				t.Helper()
				runGitTest(t, fixture.sourcePath, "remote", "set-url", "origin", "https://example.com/dex.git")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			fixture := newArtifactFixture(t)
			test.tamper(t, fixture)
			_, err := verifyArtifact(t.Context(), rawOptions{
				manifestPath: fixture.manifestPath,
				sourcePath:   fixture.sourcePath,
				binaryPath:   fixture.binaryPath,
			})
			if !errors.Is(err, errVerification) {
				t.Fatalf("verifyArtifact() error = %v, want errVerification", err)
			}
		})
	}
}

func TestVerifyArtifactUsesPinnedCommitNotWorkingTree(t *testing.T) {
	t.Parallel()

	fixture := newArtifactFixture(t)
	if err := os.WriteFile(filepath.Join(fixture.sourcePath, "message.txt"), []byte("uncommitted local data\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyArtifact(t.Context(), rawOptions{
		manifestPath: fixture.manifestPath,
		sourcePath:   fixture.sourcePath,
		binaryPath:   fixture.binaryPath,
	}); err != nil {
		t.Fatalf("verifyArtifact() error = %v", err)
	}
	contents, err := os.ReadFile(filepath.Join(fixture.sourcePath, "message.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "uncommitted local data\n" {
		t.Fatalf("source working tree was changed: %q", contents)
	}
}

func TestReadRootRegularFileRejectsSymlink(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(directory, "link")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Errorf("close root: %v", err)
		}
	}()
	if _, err := readRootRegularFile(root, "link", 1024); !errors.Is(err, errVerification) {
		t.Fatalf("readRootRegularFile() error = %v, want errVerification", err)
	}
}

func newArtifactFixture(t *testing.T) artifactFixture {
	t.Helper()

	fixtureRoot := t.TempDir()
	sourcePath := filepath.Join(fixtureRoot, "upstream")
	if err := os.Mkdir(sourcePath, 0o700); err != nil {
		t.Fatal(err)
	}
	runGitTest(t, sourcePath, "init", "--quiet", "--initial-branch=main")
	if err := os.WriteFile(filepath.Join(sourcePath, "message.txt"), []byte("before\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(sourcePath, "api", "v2"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(sourcePath, "go.mod"),
		[]byte("module github.com/dexidp/dex\n\ngo 1.26.0\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(sourcePath, "api", "v2", "go.mod"),
		[]byte("module github.com/dexidp/dex/api/v2\n\ngo 1.26.0\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	runGitTest(t, sourcePath, "add", "--", "message.txt", "go.mod", "api/v2/go.mod")
	runGitTest(
		t,
		sourcePath,
		"-c", "user.name=MeshTransit Test",
		"-c", "user.email=test@meshtransit.example",
		"commit", "--quiet", "-m", "base fixture",
	)
	commit := strings.TrimSpace(runGitTest(t, sourcePath, "rev-parse", "HEAD"))
	commitSeconds, err := strconv.ParseInt(
		strings.TrimSpace(runGitTest(t, sourcePath, "show", "-s", "--format=%ct", commit)),
		10,
		64,
	)
	if err != nil {
		t.Fatal(err)
	}
	moduleVersion, err := moduleVersionForCommit(commit, commitSeconds)
	if err != nil {
		t.Fatal(err)
	}
	runGitTest(t, sourcePath, "tag", "v2.45.1")
	runGitTest(t, sourcePath, "remote", "add", "origin", "https://github.com/dexidp/dex.git")

	artifactRoot := filepath.Join(fixtureRoot, "artifact")
	patchDirectory := filepath.Join(artifactRoot, "patches")
	evidenceDirectory := filepath.Join(artifactRoot, "evidence")
	if err := os.MkdirAll(patchDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(evidenceDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	patchPath := filepath.Join(patchDirectory, "issuer.patch")
	patch := []byte("diff --git a/message.txt b/message.txt\n" +
		"--- a/message.txt\n" +
		"+++ b/message.txt\n" +
		"@@ -1 +1 @@\n" +
		"-before\n" +
		"+after\n")
	if err := os.WriteFile(patchPath, patch, 0o600); err != nil {
		t.Fatal(err)
	}

	licensePath := writeFixtureFile(t, evidenceDirectory, "licenses.json", []byte(`{"licenses":[]}`), 0o600)
	sbomPath := writeFixtureFile(t, evidenceDirectory, "sbom.json", []byte(`{"components":[]}`), 0o600)
	vulnerabilityPath := writeFixtureFile(t, evidenceDirectory, "vulnerabilities.json", []byte(`{"findings":[]}`), 0o600)
	qualificationPath := writeFixtureFile(t, evidenceDirectory, "qualification.json", []byte(`{"passed":true}`), 0o600)
	binaryPath := writeFixtureFile(t, artifactRoot, "dex", []byte("fixture binary\n"), 0o700)

	manifest := artifactManifest{
		SchemaVersion: manifestSchemaVersion,
		Upstream: upstreamReference{
			Repository:    "https://github.com/dexidp/dex.git",
			Version:       "v2.45.1",
			Commit:        commit,
			ModulePath:    dexUpstreamModule,
			ModuleVersion: moduleVersion,
		},
		Patches: []patchReference{{
			ID: "issuer", Path: "patches/issuer.patch", SHA256: digestBytes(patch),
		}},
		Build: buildReference{
			GoVersion: "go1.26.8", Flags: []string{"-trimpath"}, BinarySHA256: digestBytes([]byte("fixture binary\n")),
		},
		Evidence: evidenceReferences{
			LicenseInventory:    fileReference{Path: "evidence/licenses.json", SHA256: digestFileTest(t, licensePath)},
			SBOM:                fileReference{Path: "evidence/sbom.json", SHA256: digestFileTest(t, sbomPath)},
			VulnerabilityReport: fileReference{Path: "evidence/vulnerabilities.json", SHA256: digestFileTest(t, vulnerabilityPath)},
			QualificationReport: fileReference{Path: "evidence/qualification.json", SHA256: digestFileTest(t, qualificationPath)},
		},
	}
	runner, err := newGitRunner()
	if err != nil {
		t.Fatal(err)
	}
	manifest.SourceTreeSHA256, err = verifyPatchedSource(
		t.Context(),
		runner,
		sourcePath,
		manifest,
		[]string{artifactRoot, patchPath},
	)
	if err != nil {
		t.Fatalf("prepare source digest: %v", err)
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(artifactRoot, "manifest.json")
	if err := os.WriteFile(manifestPath, append(manifestData, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return artifactFixture{
		manifestPath:  manifestPath,
		sourcePath:    sourcePath,
		binaryPath:    binaryPath,
		patchPath:     patchPath,
		evidencePath:  licensePath,
		moduleVersion: moduleVersion,
	}
}

func createMeshCoreModule(t *testing.T, moduleVersion, suffix string) string {
	t.Helper()

	root := t.TempDir()
	contents := "module github.com/meshtransit/meshtransit\n\n" +
		"go 1.26.8\n\nrequire github.com/dexidp/dex " + moduleVersion + "\n" + suffix
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

func writeFixtureFile(t *testing.T, directory, name string, contents []byte, mode os.FileMode) string {
	t.Helper()
	filePath := filepath.Join(directory, name)
	if err := os.WriteFile(filePath, contents, mode); err != nil {
		t.Fatal(err)
	}
	return filePath
}

func digestFileTest(t *testing.T, filePath string) string {
	t.Helper()
	digest, err := digestRegularFile(filePath, maximumEvidenceBytes)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func runGitTest(t *testing.T, directory string, args ...string) string {
	t.Helper()
	arguments := append([]string{
		"-c", "core.hooksPath=" + os.DevNull,
		"-c", "protocol.file.allow=always",
		"-C", directory,
	}, args...)
	command := exec.CommandContext(t.Context(), "git", arguments...) // #nosec G204 -- tests use the fixed local git executable with isolated temporary paths.
	command.Env = append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_TERMINAL_PROMPT=0",
		"LC_ALL=C",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git fixture command failed: %v: %s", err, output)
	}
	return string(output)
}
