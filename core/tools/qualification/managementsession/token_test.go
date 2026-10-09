package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/platform/config"
)

func TestPrepareBearerWritesPrivateFileAndDerivesProductionDigest(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "session-key")
	encodedKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	if err := os.WriteFile(keyPath, []byte(encodedKey+"\n"), 0o600); err != nil {
		t.Fatalf("write digest key: %v", err)
	}
	outputPath := filepath.Join(directory, "bearer")
	spec := mustSeedSpec(t, outputPath)
	keyFile, err := config.NewSecretFile(keyPath)
	if err != nil {
		t.Fatalf("NewSecretFile() error = %v", err)
	}
	keyID, err := accountsession.NewDigestKeyID("session-v1")
	if err != nil {
		t.Fatalf("NewDigestKeyID() error = %v", err)
	}
	database := databaseSettings{digestKeyID: keyID, digestKeyFile: keyFile}

	token, digest, staged, err := prepareBearer(
		spec,
		database,
		1,
		bytes.NewReader(bytes.Repeat([]byte{0x24}, accountSessionSecretBytes)),
	)
	if err != nil {
		t.Fatalf("prepareBearer() error = %v", err)
	}
	t.Cleanup(func() { _ = staged.discard() })
	information, err := os.Stat(outputPath)
	if err != nil {
		t.Fatalf("stat bearer output: %v", err)
	}
	if information.Mode().Perm() != 0o600 || !information.Mode().IsRegular() {
		t.Fatalf("bearer mode = %v, want private regular file", information.Mode())
	}
	// #nosec G304 -- outputPath is test-owned beneath t.TempDir().
	contents, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read bearer output: %v", err)
	}
	persistedToken, err := accountsession.ParseToken(strings.TrimSpace(string(contents)))
	if err != nil || !digest.IsValid() ||
		persistedToken.DeploymentID() != token.DeploymentID() ||
		persistedToken.RecoveryEpoch() != token.RecoveryEpoch() {
		t.Fatalf("parse persisted bearer: %v", err)
	}
	keyring, err := loadSessionKeyring(database)
	if err != nil {
		t.Fatalf("loadSessionKeyring() error = %v", err)
	}
	digests, err := keyring.Digests(persistedToken)
	if err != nil || len(digests) != 1 || digests[0].Bytes() != digest.Bytes() {
		t.Fatalf("production digest mismatch: count=%d error=%v", len(digests), err)
	}
	if err := staged.discard(); err != nil {
		t.Fatalf("discard() error = %v", err)
	}
	if _, err := os.Stat(outputPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("bearer still exists after discard: %v", err)
	}
}

func TestStageBearerFileRefusesOverwrite(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "bearer")
	if err := os.WriteFile(path, []byte("owned\n"), 0o600); err != nil {
		t.Fatalf("write existing bearer: %v", err)
	}
	if _, err := stageBearerFile(path, []byte("replacement\n")); err == nil {
		t.Fatal("stageBearerFile() overwrote an existing path")
	}
	// #nosec G304 -- path is test-owned beneath t.TempDir().
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "owned\n" {
		t.Fatalf("existing bearer changed: contents=%q error=%v", contents, err)
	}
}

func mustSeedSpec(t *testing.T, tokenOutput string) seedSpec {
	t.Helper()
	spec, err := parseSeedSpec(testArguments(tokenOutput), mapLookup(testEnvironment()))
	if err != nil {
		t.Fatalf("parseSeedSpec() error = %v", err)
	}
	return spec
}
