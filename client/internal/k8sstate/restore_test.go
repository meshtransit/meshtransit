package k8sstate

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"meshtransit.net/client/internal/identity"
	"meshtransit.net/client/internal/profile"
	"meshtransit.net/client/internal/secretstore"
)

const testIdentityName = "0123456789abcdef0123456789abcdef.json"

// Restore lays the Secret's keys out as the stores expect them, with
// owner-only modes, drops identity files the Secret does not hold and
// temporary files a killed process left, and leaves other files alone.
func TestRestoreLaysOutTheStateDirectory(t *testing.T) {
	t.Parallel()
	stateDir := filepath.Join(t.TempDir(), "state")
	if _, err := Restore(stateDir, map[string][]byte{"identity." + testIdentityName: []byte("stale")}); err != nil {
		t.Fatalf("first Restore() error = %v", err)
	}
	otherName := "fedcba9876543210fedcba9876543210.json"
	leftovers := map[string]string{
		filepath.Join(stateDir, "identities", otherName):            "left over",
		filepath.Join(stateDir, "identities", ".identity-0a0b.tmp"): "torn",
		filepath.Join(stateDir, ".profiles-0a0b.tmp"):               "torn",
		filepath.Join(stateDir, ".restore-0a0b.tmp"):                "torn",
		filepath.Join(stateDir, "exit-pins.json"):                   "pins",
	}
	for path, content := range leftovers {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", path, err)
		}
	}

	data := map[string][]byte{
		"profile.profiles.json":        []byte(`{"profiles":[]}`),
		"identity." + testIdentityName: []byte("record"),
	}
	report, err := Restore(stateDir, data)
	if err != nil {
		t.Fatalf("Restore() error = %v", err)
	}
	for path, want := range map[string]string{
		filepath.Join(stateDir, "profiles.json"):                `{"profiles":[]}`,
		filepath.Join(stateDir, "identities", testIdentityName): "record",
		filepath.Join(stateDir, "exit-pins.json"):               "pins",
	} {
		got, err := os.ReadFile(path) //nolint:gosec // G304: the test's own temporary directory
		if err != nil || string(got) != want {
			t.Fatalf("ReadFile(%s) = %q, %v; want %q", path, got, err, want)
		}
		if runtime.GOOS != "windows" && !strings.HasSuffix(path, "exit-pins.json") {
			if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("Stat(%s) = %v, %v; want mode 0600", path, info, err)
			}
		}
	}
	for _, name := range []string{
		filepath.Join("identities", otherName), filepath.Join("identities", ".identity-0a0b.tmp"),
		".profiles-0a0b.tmp", ".restore-0a0b.tmp",
	} {
		if _, err := os.Lstat(filepath.Join(stateDir, name)); !os.IsNotExist(err) {
			t.Errorf("Lstat(%s) error = %v, want it removed", name, err)
		}
	}
	if len(report.RemovedIdentities) != 1 || report.RemovedIdentities[0] != otherName {
		t.Fatalf("RemovedIdentities = %v, want [%s]", report.RemovedIdentities, otherName)
	}
}

// A Secret without the profile state removes the local one: the Secret is
// all the state there is.
func TestRestoreRemovesStateTheSecretLacks(t *testing.T) {
	t.Parallel()
	stateDir := filepath.Join(t.TempDir(), "state")
	if _, err := Restore(stateDir, map[string][]byte{"profile.profiles.json": []byte("{}")}); err != nil {
		t.Fatalf("first Restore() error = %v", err)
	}
	if _, err := Restore(stateDir, map[string][]byte{}); err != nil {
		t.Fatalf("Restore() error = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(stateDir, "profiles.json")); !os.IsNotExist(err) {
		t.Fatalf("Lstat(profiles.json) error = %v, want it removed", err)
	}
}

// Bad names under the stores' prefixes fail the restore, since they could
// leave the directory. Keys under other prefixes, which a newer version may
// have written before a rollback, are skipped and reported.
func TestRestoreChecksKeys(t *testing.T) {
	t.Parallel()
	for _, key := range []string{
		"profile.other.json",
		"identity.../profiles.json",
		"identity.ABCDEF.json",
		"identity." + strings.Repeat("a", 32),
	} {
		if _, err := Restore(filepath.Join(t.TempDir(), "state"), map[string][]byte{key: []byte("x")}); err == nil {
			t.Errorf("Restore(%q) error = nil, want a refusal", key)
		}
	}
	stateDir := filepath.Join(t.TempDir(), "state")
	report, err := Restore(stateDir, map[string][]byte{"routes.json": []byte("x"), "exit.pins.json": []byte("y")})
	if err != nil {
		t.Fatalf("Restore(newer keys) error = %v", err)
	}
	if strings.Join(report.SkippedKeys, ",") != "exit.pins.json,routes.json" {
		t.Fatalf("SkippedKeys = %v", report.SkippedKeys)
	}
	if _, err := os.Lstat(filepath.Join(stateDir, "routes.json")); !os.IsNotExist(err) {
		t.Fatalf("a skipped key was written: %v", err)
	}
}

// Links in the state directory are never followed: a linked identities
// directory fails the restore, and a linked profile file is replaced, not
// written through.
func TestRestoreDoesNotFollowLinks(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	stateDir := filepath.Join(base, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatalf("Mkdir() error = %v", err)
	}
	target := filepath.Join(outside, "victim.json")
	if err := os.WriteFile(target, []byte("untouched"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Symlink(target, filepath.Join(stateDir, "profiles.json")); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(stateDir, "identities")); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}
	if _, err := Restore(stateDir, map[string][]byte{"profile.profiles.json": []byte("{}")}); err == nil {
		t.Fatal("Restore() through a linked identities directory succeeded")
	}
	if err := os.Remove(filepath.Join(stateDir, "identities")); err != nil {
		t.Fatalf("Remove() error = %v", err)
	}
	if _, err := Restore(stateDir, map[string][]byte{"profile.profiles.json": []byte("{}")}); err != nil {
		t.Fatalf("Restore() error = %v", err)
	}
	got, err := os.ReadFile(target) //nolint:gosec // G304: the test's own temporary directory
	if err != nil || string(got) != "untouched" {
		t.Fatalf("the link target = %q, %v; want it untouched", got, err)
	}
	info, err := os.Lstat(filepath.Join(stateDir, "profiles.json"))
	if err != nil || info.Mode().Type() == os.ModeSymlink {
		t.Fatalf("profiles.json = %v, %v; want the link replaced by a file", info, err)
	}
}

// End to end: a profile and an identity written through the stores with the
// mirror's hooks come back whole from the Secret into an empty directory,
// as when the pod is replaced.
func TestRestoredStateOpensInTheStores(t *testing.T) {
	t.Parallel()
	api := newFakeAPI(t)
	mirror := openMirror(t, api)
	key := bytes.Repeat([]byte{0x51}, secretstore.KeySize)

	profileID, fingerprint := writeState(t, t.TempDir(), mirror, key)

	reopened := openMirror(t, api)
	stateDir := filepath.Join(t.TempDir(), "state")
	if _, err := Restore(stateDir, reopened.Data()); err != nil {
		t.Fatalf("Restore() error = %v", err)
	}
	profiles, err := profile.Open(stateDir)
	if err != nil {
		t.Fatalf("profile.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = profiles.Close() })
	active, err := profiles.Active(t.Context())
	if err != nil || active.ID != profileID {
		t.Fatalf("Active() = %v, %v; want %s", active.ID, err, profileID)
	}
	protector, err := secretstore.New(key)
	if err != nil {
		t.Fatalf("secretstore.New() error = %v", err)
	}
	identities, err := identity.Open(stateDir, protector)
	if err != nil {
		t.Fatalf("identity.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = identities.Close() })
	record, err := identities.Get(t.Context(), profileID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if !record.IsRegistered() || record.ControlKeyFingerprint() != fingerprint {
		t.Fatalf("restored identity = %s, want the registered one", record)
	}
}

func writeState(t *testing.T, dir string, mirror *Mirror, key []byte) (profileID, fingerprint string) {
	t.Helper()
	ctx := context.Background()
	profiles, err := profile.Open(dir, profile.WithPersistHook(mirror.Hook(ProfileKeyPrefix)))
	if err != nil {
		t.Fatalf("profile.Open() error = %v", err)
	}
	defer func() { _ = profiles.Close() }()
	created, err := profiles.Create(ctx, profile.CreateInput{Name: "cluster", ControlURL: "https://control.example.com"})
	if err != nil {
		t.Fatalf("profile Create() error = %v", err)
	}
	protector, err := secretstore.New(key)
	if err != nil {
		t.Fatalf("secretstore.New() error = %v", err)
	}
	identities, err := identity.Open(dir, protector, identity.WithPersistHook(mirror.Hook(IdentityKeyPrefix)))
	if err != nil {
		t.Fatalf("identity.Open() error = %v", err)
	}
	defer func() { _ = identities.Close() }()
	fingerprint = "sha256:" + strings.Repeat("c", 64)
	record, err := identity.NewRecord(created.ID, identity.Material{
		MachinePrivateKey: []byte("machine-secret"),
		NodePrivateKey:    []byte("node-secret"),
		ControlPublicKey:  []byte("control-public"),
	}, fingerprint, time.Now())
	if err != nil {
		t.Fatalf("NewRecord() error = %v", err)
	}
	if err := identities.Create(ctx, record); err != nil {
		t.Fatalf("identity Create() error = %v", err)
	}
	if _, err := identities.SetRegistration(ctx, created.ID, "", true); err != nil {
		t.Fatalf("SetRegistration() error = %v", err)
	}
	return created.ID, fingerprint
}
