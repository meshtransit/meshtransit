package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The Makefile and the broker upgrade-restore script accept a prepared
// go.work only through check-dex-workspace.sh; the go.work writeGoWorkspace
// produces must pass it, including roots with spaces, and any other content
// must not.
func TestCheckDexWorkspaceScript(t *testing.T) {
	t.Parallel()

	script, err := filepath.Abs(filepath.Join("..", "..", "..", "scripts", "qualification", "check-dex-workspace.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is unavailable")
	}

	verified := func(t *testing.T, repoRoot, preparedRoot string) string {
		t.Helper()
		if err := writeGoWorkspace(preparedRoot, repoRoot, "go1.26.9"); err != nil {
			t.Fatalf("writeGoWorkspace() error = %v", err)
		}
		contents, err := os.ReadFile(filepath.Join(preparedRoot, "go.work")) // #nosec G304 -- preparedRoot is an isolated test directory.
		if err != nil {
			t.Fatal(err)
		}
		return string(contents)
	}
	tests := []struct {
		name     string
		moduleGo string
		edit     func(string) string
		wantOK   bool
	}{
		{name: "verified workspace", moduleGo: "go 1.26.9", edit: func(s string) string { return s }, wantOK: true},
		{name: "crlf workspace", moduleGo: "go 1.26.9", edit: func(s string) string {
			return strings.ReplaceAll(s, "\n", "\r\n")
		}},
		{name: "swapped use path", moduleGo: "go 1.26.9", edit: func(s string) string {
			return strings.Replace(s, "/source/api/v2", "/other", 1)
		}},
		{name: "go line inside use block", moduleGo: "go 1.26.9", edit: func(s string) string {
			return strings.Replace(strings.Replace(s, "go 1.26.9\n\n", "", 1), "use (\n", "use (\ngo 1.26.9\n", 1)
		}},
		{name: "trailing blank lines", moduleGo: "go 1.26.9", edit: func(s string) string { return s + "\n\n" }},
		{name: "replace directive", moduleGo: "go 1.26.9", edit: func(s string) string {
			return s + "\nreplace golang.org/x/net => golang.org/x/net v0.58.0\n"
		}},
		{name: "godebug directive", moduleGo: "go 1.26.9", edit: func(s string) string {
			return s + "\ngodebug http2debug=1\n"
		}},
		{name: "second use", moduleGo: "go 1.26.9", edit: func(s string) string {
			return s + "\nuse ./other\n"
		}},
		{name: "extra use path", moduleGo: "go 1.26.9", edit: func(s string) string {
			return strings.Replace(s, ")\n", "\t\"/tmp/other\"\n)\n", 1)
		}},
		{name: "newer go line", moduleGo: "go 1.26.9", edit: func(s string) string {
			return strings.Replace(s, "go 1.26.9\n", "go 1.27.0\n", 1)
		}},
		{name: "other toolchain", moduleGo: "go 1.26.9", edit: func(s string) string {
			return strings.Replace(s, "toolchain go1.26.9", "toolchain go1.27.0", 1)
		}},
		{name: "missing toolchain", moduleGo: "go 1.26.9", edit: func(s string) string {
			return strings.Replace(s, "toolchain go1.26.9\n", "", 1)
		}},
		{name: "repeated toolchain", moduleGo: "go 1.26.9", edit: func(s string) string {
			return strings.Replace(s, "toolchain go1.26.9\n", "toolchain go1.26.9\ntoolchain go1.26.9\n", 1)
		}},
		{name: "module names another release", moduleGo: "go 1.26.10", edit: func(s string) string { return s }},
		{name: "module names pre-release", moduleGo: "go 1.27rc1", edit: func(s string) string { return s }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			repoRoot := filepath.Join(t.TempDir(), "mesh core")
			preparedRoot := filepath.Join(t.TempDir(), "prepared root")
			for _, directory := range []string{repoRoot, preparedRoot} {
				if err := os.Mkdir(directory, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			// The verifier writes symlink-resolved roots into go.work.
			var err error
			if repoRoot, err = filepath.EvalSymlinks(repoRoot); err != nil {
				t.Fatal(err)
			}
			if preparedRoot, err = filepath.EvalSymlinks(preparedRoot); err != nil {
				t.Fatal(err)
			}
			module := "module meshtransit.net\n\n" + test.moduleGo + "\n"
			if err := os.WriteFile(filepath.Join(repoRoot, "go.mod"), []byte(module), 0o600); err != nil {
				t.Fatal(err)
			}
			workspace := test.edit(verified(t, repoRoot, preparedRoot))
			if err := os.WriteFile(filepath.Join(preparedRoot, "go.work"), []byte(workspace), 0o600); err != nil {
				t.Fatal(err)
			}

			output, err := exec.CommandContext(t.Context(), "bash", script, preparedRoot, repoRoot).Output() // #nosec G204 -- fixed script with test-owned arguments.
			if test.wantOK {
				if err != nil {
					t.Fatalf("check-dex-workspace.sh error = %v", err)
				}
				if got := strings.TrimSpace(string(output)); got != "go1.26.9" {
					t.Fatalf("check-dex-workspace.sh output = %q, want go1.26.9", got)
				}
				return
			}
			if err == nil {
				t.Fatalf("check-dex-workspace.sh accepted %q", workspace)
			}
		})
	}
}
