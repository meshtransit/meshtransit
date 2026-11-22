//go:build dexbroker

package main

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func identityGenericSettings(t *testing.T) map[string]string {
	t.Helper()
	directory := t.TempDir()
	connectorSecretPath := filepath.Join(directory, "connector-secret")
	clientSecretPath := filepath.Join(directory, "client-secret")
	for path, value := range map[string]string{connectorSecretPath: "c", clientSecretPath: "b"} {
		if err := os.WriteFile(path, []byte(strings.Repeat(value, 48)+"\n"), 0o600); err != nil {
			t.Fatalf("write secret: %v", err)
		}
	}
	issuer := "https://sso.example.test:8443/realms/corp"
	return map[string]string{ //nolint:gosec // Fixture values are paths and non-secret identifiers.
		"MESHTRANSIT_IDENTITY_ISSUER":                            "https://id.example.test/oauth2",
		"MESHTRANSIT_IDENTITY_ADDRESS":                           "127.0.0.1:9443",
		"MESHTRANSIT_IDENTITY_TLS_CERTIFICATE_FILE":              "/run/secrets/identity-tls-certificate.pem",
		"MESHTRANSIT_IDENTITY_TLS_PRIVATE_KEY_FILE":              "/run/secrets/identity-tls-private-key.pem",
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_ID":                 "oidc-0123456789abcdef",
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_DISPLAY_NAME":       "Corp SSO",
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_GENERATION":         "1",
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_ISSUER":             issuer,
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_CLIENT_ID":          "meshtransit",
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_CLIENT_SECRET_FILE": connectorSecretPath,
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_AUTHORIZATION_URL":  issuer + "/protocol/openid-connect/auth",
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_TOKEN_URL":          issuer + "/protocol/openid-connect/token",
		"MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_JWKS_URL":           issuer + "/protocol/openid-connect/certs",
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
}

func TestIdentityFingerprintCarriesGenericConnectorOptions(t *testing.T) {
	base := identityGenericSettings(t)
	first, err := identityFingerprintFromSettings(base)
	if err != nil {
		t.Fatalf("generic fingerprint: %v", err)
	}
	options := maps.Clone(base)
	options["MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_PROMPT"] = "login"
	options["MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_PRIVATE_NETWORK_CIDRS"] = "10.20.0.0/16"
	second, err := identityFingerprintFromSettings(options)
	if err != nil {
		t.Fatalf("options fingerprint: %v", err)
	}
	if first == second {
		t.Fatal("connector options did not reach the broker fingerprint")
	}
	// A public range parses but is not private: the broker refuses it.
	public := maps.Clone(base)
	public["MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_PRIVATE_NETWORK_CIDRS"] = "8.8.8.0/24"
	if _, err := identityFingerprintFromSettings(public); err == nil {
		t.Fatal("a public range was accepted as a private network")
	}
}
