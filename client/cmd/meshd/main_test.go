package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/meshtransit/meshtransit/client/internal/secretstore"
)

func TestLoadIdentityProtectorOwnerOnlyOverride(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "identity-key")
	if err := os.WriteFile(path, make([]byte, secretstore.KeySize), 0o600); err != nil {
		t.Fatal(err)
	}
	protector, err := loadIdentityProtector(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := protector.Close(); err != nil {
		t.Fatal(err)
	}
	//nolint:gosec // Deliberately broad override must fail the owner-only validator.
	if err := os.Chmod(path, 0o440); err != nil {
		t.Fatal(err)
	}
	if _, err := loadIdentityProtector(path); !errors.Is(err, secretstore.ErrKeyInvalid) {
		t.Fatalf("broad override permissions accepted: %v", err)
	}
}

func TestLoadIdentityProtectorConfinesSystemdOverride(t *testing.T) {
	t.Parallel()
	for _, path := range []string{
		"/run/credentials/key",
		"/run/credentials/custom.socket/meshd.identity-key",
		"/run/credentials/custom.service/nested/meshd.identity-key",
		"/run/credentials/../identity-key",
	} {
		t.Run(path, func(t *testing.T) {
			if _, err := loadIdentityProtector(path); !errors.Is(err, secretstore.ErrKeyInvalid) {
				t.Fatalf("malformed systemd credential did not fail closed: %v", err)
			}
		})
	}
}
