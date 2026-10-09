package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/platform/config"
)

func TestPrepareCredentialWritesPrivateFileAndDerivesProductionDigest(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "enrollment-key")
	encodedKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	if err := os.WriteFile(keyPath, []byte(encodedKey+"\n"), 0o600); err != nil {
		t.Fatalf("write digest key: %v", err)
	}
	outputPath := filepath.Join(directory, "bearer")
	spec := mustIssueSpec(t, outputPath)
	keyFile, err := config.NewSecretFile(keyPath)
	if err != nil {
		t.Fatalf("NewSecretFile() error = %v", err)
	}
	keyID, err := enrollment.NewDigestKeyID("enrollment-v1")
	if err != nil {
		t.Fatalf("NewDigestKeyID() error = %v", err)
	}
	database := databaseSettings{digestKeyID: keyID, digestKeyFile: keyFile}
	credentialID, err := enrollment.ParseCredentialID("01995d00-0000-7000-8000-000000000701")
	if err != nil {
		t.Fatalf("ParseCredentialID() error = %v", err)
	}

	digest, staged, err := prepareCredential(
		spec,
		database,
		credentialID,
		1,
		bytes.NewReader(bytes.Repeat([]byte{0x24}, credentialTokenBytes)),
	)
	if err != nil {
		t.Fatalf("prepareCredential() error = %v", err)
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
	presentation, err := enrollment.ParseCredentialPresentation(strings.TrimSpace(string(contents)))
	if err != nil || presentation.CredentialID() != credentialID || !digest.IsValid() {
		t.Fatalf("parse persisted bearer: %v", err)
	}
	keyring, err := loadCredentialKeyring(database)
	if err != nil {
		t.Fatalf("loadCredentialKeyring() error = %v", err)
	}
	if !keyring.Verify(spec.deploymentID, 1, presentation.Token(), digest) {
		t.Fatal("production digest did not verify persisted credential")
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

func TestPrepareCredentialRejectsZeroEntropyWithoutCreatingFile(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	keyPath := filepath.Join(directory, "enrollment-key")
	encodedKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	if err := os.WriteFile(keyPath, []byte(encodedKey+"\n"), 0o600); err != nil {
		t.Fatalf("write digest key: %v", err)
	}
	outputPath := filepath.Join(directory, "bearer")
	spec := mustIssueSpec(t, outputPath)
	keyFile, err := config.NewSecretFile(keyPath)
	if err != nil {
		t.Fatalf("NewSecretFile() error = %v", err)
	}
	keyID, err := enrollment.NewDigestKeyID("enrollment-v1")
	if err != nil {
		t.Fatalf("NewDigestKeyID() error = %v", err)
	}
	credentialID, err := enrollment.ParseCredentialID("01995d00-0000-7000-8000-000000000701")
	if err != nil {
		t.Fatalf("ParseCredentialID() error = %v", err)
	}
	_, _, err = prepareCredential(
		spec,
		databaseSettings{digestKeyID: keyID, digestKeyFile: keyFile},
		credentialID,
		1,
		bytes.NewReader(make([]byte, credentialTokenBytes)),
	)
	if !errors.Is(err, errInvalidInput) {
		t.Fatalf("prepareCredential() error = %v, want invalid input", err)
	}
	if _, err := os.Stat(outputPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("zero entropy created bearer output: %v", err)
	}
}

func mustIssueSpec(t *testing.T, tokenOutput string) issueSpec {
	t.Helper()
	spec, err := parseIssueSpec(testArguments(tokenOutput), mapLookup(testEnvironment()))
	if err != nil {
		t.Fatalf("parseIssueSpec() error = %v", err)
	}
	return spec
}
