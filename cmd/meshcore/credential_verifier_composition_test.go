package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/enrollment"
)

func TestComposeCredentialVerifierLoadsRotationWindow(t *testing.T) {
	t.Parallel()

	activeMaterial := bytes.Repeat([]byte{0x11}, 32)
	previousMaterial := bytes.Repeat([]byte{0x22}, 32)
	digestConfig := loadCredentialDigestTestConfig(t, activeMaterial, previousMaterial)

	verifier, err := composeCredentialVerifier(digestConfig)
	if err != nil {
		t.Fatalf("composeCredentialVerifier() error = %v", err)
	}
	assertCredentialDigestMatchesMaterial(t, verifier, digestConfig.Active.ID, activeMaterial)
	assertCredentialVerifierAcceptsPreviousMaterial(
		t,
		verifier,
		digestConfig.Previous.ID,
		previousMaterial,
	)
}

func TestComposeCredentialVerifierLoadsActiveKeyOnly(t *testing.T) {
	t.Parallel()

	activeMaterial := bytes.Repeat([]byte{0x33}, 32)
	digestConfig := loadCredentialDigestTestConfig(t, activeMaterial, nil)

	verifier, err := composeCredentialVerifier(digestConfig)
	if err != nil {
		t.Fatalf("composeCredentialVerifier() error = %v", err)
	}
	assertCredentialDigestMatchesMaterial(t, verifier, digestConfig.Active.ID, activeMaterial)
}

func TestComposeCredentialVerifierRejectsUnsafeMaterialWithoutDisclosure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		material []byte
		encoded  string
	}{
		{name: "malformed base64url", encoded: "not+base64"},
		{name: "padded base64url", encoded: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)) + "="},
		{name: "short key", material: bytes.Repeat([]byte{1}, 31)},
		{name: "all zero key", material: make([]byte, 32)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			encoded := test.encoded
			if encoded == "" {
				encoded = base64.RawURLEncoding.EncodeToString(test.material)
			}
			digestConfig, secretPath := loadCredentialDigestTestConfigWithEncodedKey(t, encoded)
			_, err := composeCredentialVerifier(digestConfig)
			if !errors.Is(err, errInvalidCredentialVerifierComposition) {
				t.Fatalf("composeCredentialVerifier() error = %v, want composition error", err)
			}
			if strings.Contains(err.Error(), encoded) || strings.Contains(err.Error(), secretPath) {
				t.Fatalf("composeCredentialVerifier() error disclosed key material or path: %v", err)
			}
		})
	}
}

func TestComposeCredentialVerifierRejectsUnavailableKeyWithoutPathDisclosure(t *testing.T) {
	t.Parallel()

	digestConfig, secretPath := loadCredentialDigestTestConfigWithEncodedKey(
		t,
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
	)
	if err := os.Remove(secretPath); err != nil {
		t.Fatalf("os.Remove() error = %v", err)
	}

	_, err := composeCredentialVerifier(digestConfig)
	if !errors.Is(err, errInvalidCredentialVerifierComposition) {
		t.Fatalf("composeCredentialVerifier() error = %v, want composition error", err)
	}
	if strings.Contains(err.Error(), secretPath) {
		t.Fatalf("composeCredentialVerifier() error disclosed key path: %v", err)
	}
}

func assertCredentialDigestMatchesMaterial(
	t *testing.T,
	verifier *enrollment.CredentialKeyring,
	keyID enrollment.DigestKeyID,
	material []byte,
) {
	t.Helper()

	deploymentID, token := credentialVerifierTestEvidence(t)
	expectedKey, err := enrollment.NewDigestKey(keyID, material)
	if err != nil {
		t.Fatalf("enrollment.NewDigestKey() error = %v", err)
	}
	expectedVerifier, err := enrollment.NewCredentialKeyring(expectedKey)
	if err != nil {
		t.Fatalf("enrollment.NewCredentialKeyring() error = %v", err)
	}
	want, err := expectedVerifier.Digest(deploymentID, 1, token)
	if err != nil {
		t.Fatalf("expected CredentialKeyring.Digest() error = %v", err)
	}
	got, err := verifier.Digest(deploymentID, 1, token)
	if err != nil {
		t.Fatalf("composed CredentialKeyring.Digest() error = %v", err)
	}
	if got.KeyID() != want.KeyID() || got.Bytes() != want.Bytes() {
		t.Fatal("composed credential verifier did not use configured active key material")
	}
}

func assertCredentialVerifierAcceptsPreviousMaterial(
	t *testing.T,
	verifier *enrollment.CredentialKeyring,
	keyID enrollment.DigestKeyID,
	material []byte,
) {
	t.Helper()

	deploymentID, token := credentialVerifierTestEvidence(t)
	previousKey, err := enrollment.NewDigestKey(keyID, material)
	if err != nil {
		t.Fatalf("enrollment.NewDigestKey() error = %v", err)
	}
	previousVerifier, err := enrollment.NewCredentialKeyring(previousKey)
	if err != nil {
		t.Fatalf("enrollment.NewCredentialKeyring() error = %v", err)
	}
	digest, err := previousVerifier.Digest(deploymentID, 1, token)
	if err != nil {
		t.Fatalf("previous CredentialKeyring.Digest() error = %v", err)
	}
	if !verifier.Verify(deploymentID, 1, token, digest) {
		t.Fatal("composed credential verifier rejected configured previous key")
	}
}

func credentialVerifierTestEvidence(t *testing.T) (deployment.ID, enrollment.CredentialToken) {
	t.Helper()

	deploymentID, err := deployment.ParseID("01890f00-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatalf("deployment.ParseID() error = %v", err)
	}
	token, err := enrollment.ParseCredentialToken("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA")
	if err != nil {
		t.Fatalf("enrollment.ParseCredentialToken() error = %v", err)
	}
	return deploymentID, token
}

func loadCredentialDigestTestConfig(
	t *testing.T,
	activeMaterial []byte,
	previousMaterial []byte,
) config.CredentialDigestConfig {
	t.Helper()

	directory := t.TempDir()
	activePath := filepath.Join(directory, "active.key")
	writeCredentialDigestTestKey(t, activePath, base64.RawURLEncoding.EncodeToString(activeMaterial))
	values := credentialDigestTestValues(activePath)
	if previousMaterial != nil {
		previousPath := filepath.Join(directory, "previous.key")
		writeCredentialDigestTestKey(t, previousPath, base64.RawURLEncoding.EncodeToString(previousMaterial))
		values["MESHTRANSIT_ENROLLMENT_DIGEST_PREVIOUS_KEY_ID"] = "previous-v1"
		values["MESHTRANSIT_ENROLLMENT_DIGEST_PREVIOUS_KEY_FILE"] = previousPath
	}
	return loadCredentialDigestConfig(t, values)
}

func loadCredentialDigestTestConfigWithEncodedKey(
	t *testing.T,
	encoded string,
) (config.CredentialDigestConfig, string) {
	t.Helper()

	secretPath := filepath.Join(t.TempDir(), "active.key")
	writeCredentialDigestTestKey(t, secretPath, encoded)
	return loadCredentialDigestConfig(t, credentialDigestTestValues(secretPath)), secretPath
}

func loadCredentialDigestConfig(
	t *testing.T,
	values map[string]string,
) config.CredentialDigestConfig {
	t.Helper()

	processConfig, err := config.Load(func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	})
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	if processConfig.Enrollment == nil {
		t.Fatal("config.Load() returned nil enrollment config")
	}
	return processConfig.Enrollment.CredentialDigest
}

func credentialDigestTestValues(activePath string) map[string]string {
	// #nosec G101 -- these fixtures are file paths, never credential values.
	return map[string]string{
		"MESHTRANSIT_ROLE":                              "control",
		"MESHTRANSIT_POSTGRES_ADDRESS":                  "database.internal:5432",
		"MESHTRANSIT_POSTGRES_DATABASE":                 "meshtransit",
		"MESHTRANSIT_POSTGRES_CA_FILE":                  "/run/secrets/postgres-ca.pem",
		"MESHTRANSIT_POSTGRES_RUNTIME_USER":             "mesh_runtime",
		"MESHTRANSIT_POSTGRES_RUNTIME_PASSWORD_FILE":    "/run/secrets/postgres-runtime-password",
		"MESHTRANSIT_REDIS_ADDRESS":                     "cache.internal:6379",
		"MESHTRANSIT_REDIS_USERNAME":                    "meshcore",
		"MESHTRANSIT_REDIS_PASSWORD_FILE":               "/run/secrets/redis-password",
		"MESHTRANSIT_REDIS_CA_FILE":                     "/run/secrets/redis-ca.pem",
		"MESHTRANSIT_ENROLLMENT_DIGEST_ACTIVE_KEY_ID":   "active-v1",
		"MESHTRANSIT_ENROLLMENT_DIGEST_ACTIVE_KEY_FILE": activePath,
		"MESHTRANSIT_CONTROL_TLS_CERTIFICATE_FILE":      "/run/secrets/control-tls-certificate.pem",
		"MESHTRANSIT_CONTROL_TLS_PRIVATE_KEY_FILE":      "/run/secrets/control-tls-private-key.pem",
		"MESHTRANSIT_CONTROL_NOISE_PRIVATE_KEY_FILE":    "/run/secrets/control-noise-private-key",
	}
}

func writeCredentialDigestTestKey(t *testing.T, path, encoded string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(encoded+"\n"), 0o600); err != nil {
		t.Fatalf("os.WriteFile() error = %v", err)
	}
}
