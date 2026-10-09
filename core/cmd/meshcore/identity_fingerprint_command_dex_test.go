//go:build dexbroker

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"meshtransit.net/core/internal/platform/config"
)

func TestIdentityFingerprintCommandIsMachineReadableAndSecretSafe(t *testing.T) {
	directory := t.TempDir()
	connectorSecretPath := filepath.Join(directory, "connector-secret")
	clientSecretPath := filepath.Join(directory, "client-secret")
	connectorSecret := strings.Repeat("c", 48)
	clientSecret := strings.Repeat("b", 48)
	if err := os.WriteFile(connectorSecretPath, []byte(connectorSecret+"\n"), 0o600); err != nil {
		t.Fatalf("write connector secret: %v", err)
	}
	if err := os.WriteFile(clientSecretPath, []byte(clientSecret+"\n"), 0o600); err != nil {
		t.Fatalf("write client secret: %v", err)
	}
	values := map[string]string{ //nolint:gosec // Fixture values are paths and non-secret identifiers.
		"MESHTRANSIT_IDENTITY_ISSUER":                            "https://id.example.test/oauth2",
		"MESHTRANSIT_IDENTITY_ADDRESS":                           "127.0.0.1:9443",
		"MESHTRANSIT_IDENTITY_TLS_CERTIFICATE_FILE":              "/run/secrets/identity-tls-certificate.pem",
		"MESHTRANSIT_IDENTITY_TLS_PRIVATE_KEY_FILE":              "/run/secrets/identity-tls-private-key.pem",
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_ID":                 "google-v1",
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_DISPLAY_NAME":       "Google",
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_GENERATION":         "1",
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_ISSUER":             "https://accounts.google.com",
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_CLIENT_ID":          "google-client.apps.googleusercontent.com",
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_CLIENT_SECRET_FILE": connectorSecretPath,
		"MESHTRANSIT_IDENTITY_CORE_CLIENT_ID":                    "meshtransit-core",
		"MESHTRANSIT_IDENTITY_CORE_CLIENT_DISPLAY_NAME":          "MeshTransit Core",
		"MESHTRANSIT_IDENTITY_CORE_CLIENT_GENERATION":            "1",
		"MESHTRANSIT_IDENTITY_CORE_CLIENT_SECRET_FILE":           clientSecretPath,
		"MESHTRANSIT_IDENTITY_CORE_CLIENT_REDIRECT_URI":          "https://app.example.test/auth/callback",
		"MESHTRANSIT_IDENTITY_POSTGRES_ADDRESS":                  "identity-db.internal:5432",
		"MESHTRANSIT_IDENTITY_POSTGRES_DATABASE":                 "meshtransit_identity",
		"MESHTRANSIT_IDENTITY_POSTGRES_RUNTIME_USER":             "identity_runtime",
		"MESHTRANSIT_IDENTITY_POSTGRES_RUNTIME_PASSWORD_FILE":    "/run/secrets/identity-runtime-password",
		"MESHTRANSIT_IDENTITY_POSTGRES_CA_FILE":                  "/run/secrets/identity-postgres-ca.pem",
	}
	lookup := func(key string) (string, bool) {
		value, exists := values[key]
		return value, exists
	}
	var output bytes.Buffer
	var errorOutput bytes.Buffer
	if exitCode := runIdentityFingerprint(t.Context(), lookup, &output, &errorOutput); exitCode != 0 {
		t.Fatalf("runIdentityFingerprint() = %d; error output = %s", exitCode, errorOutput.String())
	}
	var result identityFingerprintOutput
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if result.Algorithm != "sha256-v2" ||
		!strings.HasPrefix(result.Fingerprint, "sha256-v2:") ||
		result.SchemaVersion != config.SchemaVersion {
		t.Fatalf("fingerprint output = %+v", result)
	}
	combined := output.String() + errorOutput.String()
	for _, sensitive := range []string{connectorSecret, clientSecret, connectorSecretPath, clientSecretPath} {
		if strings.Contains(combined, sensitive) {
			t.Fatalf("output disclosed sensitive value %q", sensitive)
		}
	}
}
