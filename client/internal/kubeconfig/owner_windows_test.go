package kubeconfig

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWithin(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		path, dir string
		want      bool
	}{
		{`C:\Users\ann\.kube\config`, `C:\Users\ann`, true},
		{`c:\users\ANN\.kube\config`, `C:\Users\ann`, true},
		{`C:\Users\ann`, `C:\Users\ann\`, true},
		{`C:\Users\ann\`, `C:\Users\ann`, true},
		{`C:/Users/ann/.kube/config`, `C:\Users\ann`, true},
		{`C:\Users\anna\.kube\config`, `C:\Users\ann`, false},
		{`C:\Users\bob\.kube\config`, `C:\Users\ann`, false},
		{`C:\Users\ann\..\bob\config`, `C:\Users\ann`, true}, // final paths hold no "..": not reached
		{"C:\\Users\\\u212Aate\\config", `C:\Users\kate`, false},
	} {
		if got := within(test.path, test.dir); got != test.want {
			t.Errorf("within(%q, %q) = %v", test.path, test.dir, got)
		}
	}
}

func TestOwnedByUser(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// Owned by this user, or by Administrators inside the profile when
	// the test runs elevated.
	if err := ownedByUser(path); err != nil {
		t.Fatalf("this user's file: %v", err)
	}
	if err := ownedByUser(filepath.Join(dir, "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a missing file: %v", err)
	}
	if err := ownedByUser(filepath.Join(dir, "missing", "config")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a missing directory: %v", err)
	}
	// TrustedInstaller owns the Windows directory: never this user's.
	if err := ownedByUser(os.Getenv("SystemRoot")); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("the Windows directory: %v", err)
	}
}

// An Administrators-owned file counts inside this user's profile only,
// and a junction from the profile does not carry it inside (review
// TD-CLI-87 H1).
func TestOwnedByUserAdministrators(t *testing.T) {
	if !elevated(t) {
		t.Skip("needs an elevated token to give files to Administrators")
	}
	token, err := currentToken()
	if err != nil {
		t.Fatal(err)
	}
	profile, err := token.GetUserProfileDirectory()
	_ = token.Close()
	if err != nil {
		t.Fatal(err)
	}
	inside, err := os.MkdirTemp(profile, "meshtransit-kubeconfig-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(inside) })
	giveToAdministrators(t, inside)
	if err := ownedByUser(inside); err != nil {
		t.Fatalf("inside the profile: %v", err)
	}
	outside, err := os.MkdirTemp(os.Getenv("ProgramData"), "meshtransit-kubeconfig-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(outside) }) //nolint:gosec // G703: the test's own directory.
	giveToAdministrators(t, outside)
	if err := ownedByUser(outside); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("outside the profile: %v", err)
	}
	junction := filepath.Join(inside, "junction")
	mklink := exec.CommandContext(t.Context(), "cmd", "/c", "mklink", "/J", junction, outside) //nolint:gosec // G204: the test's paths.
	if output, err := mklink.CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v: %s", err, output)
	}
	if err := ownedByUser(junction); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("a junction out of the profile: %v", err)
	}
	if path, err := writablePath(filepath.Join(junction, "config")); !errors.Is(err, ErrUnsafe) {
		t.Fatalf("a missing file through the junction: %q, %v", path, err)
	}
}

func elevated(t *testing.T) bool {
	t.Helper()
	token, err := currentToken()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = token.Close() }()
	return token.IsElevated()
}

func giveToAdministrators(t *testing.T, path string) {
	t.Helper()
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION,
		administrators, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
}
