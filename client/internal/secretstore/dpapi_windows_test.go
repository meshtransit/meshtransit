//go:build windows

package secretstore

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"meshtransit.net/client/internal/privatefile"
)

// sealWithoutEntropy is how meshd sealed the key before it used entropy.
func sealWithoutEntropy(t *testing.T, plaintext []byte) []byte {
	t.Helper()
	sealed, err := dpapi(plaintext, func(in, out *windows.DataBlob) error {
		return windows.CryptProtectData(in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, out)
	})
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func openWithoutEntropy(sealed []byte) ([]byte, error) {
	return dpapi(sealed, func(in, out *windows.DataBlob) error {
		return windows.CryptUnprotectData(in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, out)
	})
}

// A generic DPAPI unseal, without meshd's entropy, does not open a new key.
func TestCreateDPAPISealsWithEntropy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meshd.identity-key")
	protector, err := CreateDPAPI(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = protector.Close() }()
	sealed, err := os.ReadFile(path) //nolint:gosec // Under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openWithoutEntropy(sealed); err == nil {
		t.Fatal("the key opens without meshd's entropy")
	}
	reopened, err := LoadDPAPI(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = reopened.Close()
}

// A key sealed the old way still opens, with the same key, and the file is
// rewritten so that it needs the entropy from then on.
func TestLoadDPAPIResealsAnOldKey(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	path := filepath.Join(dir, "meshd.identity-key")
	created, err := CreateDPAPI(path) // a restricted directory, as in production
	if err != nil {
		t.Fatal(err)
	}
	_ = created.Close()
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	old := sealWithoutEntropy(t, key)
	if err := os.WriteFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	original, err := New(key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = original.Close() }()
	sealedRecord, err := original.Seal(t.Context(), []byte("record"), []byte("ad"))
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadDPAPI(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = loaded.Close() }()
	if opened, err := loaded.Open(t.Context(), sealedRecord, []byte("ad")); err != nil || string(opened) != "record" {
		t.Fatalf("the old key opened as a different key: %q, %v", opened, err)
	}
	resealed, err := os.ReadFile(path) //nolint:gosec // Under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(resealed, old) {
		t.Fatal("the old key file was not rewritten")
	}
	if _, err := openWithoutEntropy(resealed); err == nil {
		t.Fatal("the rewritten key opens without meshd's entropy")
	}
	// The rewritten file keeps the key directory's access list.
	if err := privatefile.CheckFile(path, nil); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("key directory holds %d entries, %v; want only the key", len(entries), err)
	}
}

// A key that already uses the entropy is left as it is.
func TestLoadDPAPIKeepsANewKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meshd.identity-key")
	created, err := CreateDPAPI(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = created.Close()
	before, err := os.ReadFile(path) //nolint:gosec // Under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadDPAPI(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = loaded.Close()
	after, err := os.ReadFile(path) //nolint:gosec // Under t.TempDir.
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("a key sealed with entropy was rewritten (%v)", err)
	}
}

// When the old key cannot be replaced, it still opens, stays as it was and
// leaves nothing behind; the next start tries again.
func TestLoadDPAPIKeepsAnOldKeyItCannotReplace(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	path := filepath.Join(dir, "meshd.identity-key")
	created, err := CreateDPAPI(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = created.Close()
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	old := sealWithoutEntropy(t, key)
	if err := os.WriteFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	// An open handle without FILE_SHARE_DELETE blocks the rename, as an
	// antivirus or backup reader would.
	holder, err := os.Open(path) //nolint:gosec // Under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadDPAPI(path)
	_ = holder.Close()
	if !errors.Is(err, ErrKeyNotResealed) || loaded == nil {
		t.Fatalf("LoadDPAPI = %v, %v; want a protector and ErrKeyNotResealed", loaded, err)
	}
	_ = loaded.Close()
	kept, err := os.ReadFile(path) //nolint:gosec // Under t.TempDir.
	if err != nil || !bytes.Equal(kept, old) {
		t.Fatalf("the old key file changed (%v)", err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 {
		t.Fatalf("key directory holds %d entries, %v; want only the key", len(entries), err)
	}
}

func TestLoadDPAPIRefusesAnUnopenableKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "meshd.identity-key")
	created, err := CreateDPAPI(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = created.Close()
	if err := os.WriteFile(path, []byte("not a DPAPI blob"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDPAPI(path); !errors.Is(err, ErrKeyInvalid) {
		t.Fatalf("LoadDPAPI = %v, want ErrKeyInvalid", err)
	}
}
