package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/app"
)

func TestLoadIdentityUsesIsolatedRuntimeConfiguration(t *testing.T) {
	t.Parallel()

	values := validIdentityProcessValues(map[string]string{
		envIdentityAddress:                      "[::1]:9443",
		envIdentityRequestTimeout:               "9s",
		envIdentityMaxConnections:               "96",
		envIdentityMaxConcurrentRequests:        "48",
		envIdentityPostgreSQLMaxOpenConnections: "12",
		envIdentityPostgreSQLMaxIdleConnections: "4",
		envIdentityPostgreSQLConnectTimeout:     "2s",
		envDependencyCheckTimeout:               "3s",
		envIdentityPostgreSQLConnectionLifetime: "45m",
		envIdentityIDTokenLifetime:              "10m",
		envIdentityAuthRequestLifetime:          "7m",
		envIdentitySigningKeyRotation:           "12h",
		envIdentityGarbageCollection:            "10m",
	})
	got, err := Load(mapLookup(values))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Role != app.RoleIdentity || got.Identity == nil {
		t.Fatalf("identity selection = (%s, %v)", got.Role, got.Identity)
	}
	if got.Storage != nil || got.API != nil || got.Control != nil || got.Enrollment != nil ||
		got.RevisionWorker != nil || got.AuthExpiry != nil || got.PrivateLogin != nil {
		t.Fatal("identity role loaded a Core runtime responsibility")
	}
	identity := got.Identity
	if identity.Issuer != "https://id.example.test/oauth2" ||
		identity.Listener.Address != "[::1]:9443" ||
		identity.Listener.RequestTimeout != 9*time.Second ||
		identity.Listener.MaxConnections != 96 ||
		identity.Listener.MaxConcurrentRequests != 48 ||
		identity.PostgreSQL.Address != "identity-db.internal:5432" ||
		identity.PostgreSQL.Database != "meshtransit_identity" ||
		identity.PostgreSQL.RuntimeUser != "identity_runtime" ||
		identity.PostgreSQL.MaxOpenConnections != 12 ||
		identity.PostgreSQL.MaxIdleConnections != 4 ||
		identity.PostgreSQL.ConnectTimeout != 2*time.Second ||
		identity.PostgreSQL.MaxConnectionLifetime != 45*time.Minute ||
		identity.IDTokenLifetime != 10*time.Minute ||
		identity.AuthRequestLifetime != 7*time.Minute ||
		identity.SigningKeyRotation != 12*time.Hour ||
		identity.GarbageCollectionInterval != 10*time.Minute {
		t.Fatalf("identity config = %+v", identity)
	}
	if len(identity.OIDCConnectors) != 1 || len(identity.Clients) != 1 {
		t.Fatalf("identity static configuration counts = (%d, %d)", len(identity.OIDCConnectors), len(identity.Clients))
	}
	connector := identity.OIDCConnectors[0]
	if connector.ID != "google-v1" || connector.DisplayName != "Google" || connector.Generation != 1 ||
		connector.Issuer != identityGoogleIssuer || connector.ClientID != "google-client.apps.googleusercontent.com" {
		t.Fatalf("identity connector = %v", connector)
	}
	client := identity.Clients[0]
	if client.ID != "meshtransit-core" || client.DisplayName != "MeshTransit Core" ||
		client.Generation != 1 || client.RedirectURI != "https://app.example.test/auth/v1/callback" {
		t.Fatalf("identity client = %v", client)
	}
	if identity.ExpectedFingerprint == (IdentityConfigurationFingerprint{}) {
		t.Fatal("identity expected fingerprint is empty")
	}
}

func TestLoadIdentityAllowsContainerListenerAddresses(t *testing.T) {
	t.Parallel()

	for _, address := range []string{"0.0.0.0:9443", "[::]:9443"} {
		address := address
		t.Run(address, func(t *testing.T) {
			t.Parallel()

			got, err := Load(mapLookup(validIdentityProcessValues(map[string]string{
				envIdentityAddress: address,
			})))
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if got.Identity == nil || got.Identity.Listener.Address != address {
				t.Fatalf("identity listener address = %v, want %q", got.Identity, address)
			}
		})
	}
}

func TestLoadIdentityRequiresDedicatedRuntimeSettingsWithoutFallback(t *testing.T) {
	t.Parallel()

	for _, key := range []string{
		envIdentityIssuer,
		envIdentityConfigurationFingerprint,
		envIdentityAddress,
		envIdentityTLSCertificateFile,
		envIdentityTLSPrivateKeyFile,
		envIdentityOIDCConnectorID,
		envIdentityOIDCConnectorDisplayName,
		envIdentityOIDCConnectorGeneration,
		envIdentityOIDCConnectorIssuer,
		envIdentityOIDCConnectorClientID,
		envIdentityOIDCConnectorClientSecretFile,
		envIdentityCoreClientID,
		envIdentityCoreClientDisplayName,
		envIdentityCoreClientGeneration,
		envIdentityCoreClientSecretFile,
		envIdentityCoreClientRedirectURI,
		envIdentityPostgreSQLAddress,
		envIdentityPostgreSQLDatabase,
		envIdentityPostgreSQLRuntimeUser,
		envIdentityPostgreSQLRuntimePasswordFile,
		envIdentityPostgreSQLCAFile,
	} {
		key := key
		t.Run(key, func(t *testing.T) {
			t.Parallel()

			values := validIdentityProcessValues(nil)
			delete(values, key)
			_, err := Load(mapLookup(values))
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), key) {
				t.Fatalf("Load() error = %v, want redacted setting %s", err, key)
			}
		})
	}
}

func TestLoadIdentityRejectsUnsafeSettingsWithoutEchoingValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, key, value string
	}{
		{name: "http issuer", key: envIdentityIssuer, value: "http://id.example.test/oauth2"},
		{name: "issuer query", key: envIdentityIssuer, value: "https://id.example.test/oauth2?tenant=one"},
		{name: "issuer trailing slash", key: envIdentityIssuer, value: "https://id.example.test/oauth2/"},
		{name: "issuer dot segment", key: envIdentityIssuer, value: "https://id.example.test/a/../oauth2"},
		{name: "dns listener", key: envIdentityAddress, value: "identity.internal:9443"},
		{name: "public listener", key: envIdentityAddress, value: "203.0.113.1:9443"},
		{name: "link local listener", key: envIdentityAddress, value: "169.254.1.1:9443"},
		{name: "zero listener port", key: envIdentityAddress, value: "127.0.0.1:0"},
		{name: "noncanonical listener", key: envIdentityAddress, value: "127.0.0.1:09443"},
		{name: "relative listener certificate", key: envIdentityTLSCertificateFile, value: "server.pem"},
		{name: "relative listener private key", key: envIdentityTLSPrivateKeyFile, value: "server-key.pem"},
		{name: "fractional request timeout", key: envIdentityRequestTimeout, value: "1500ms"},
		{name: "long request timeout", key: envIdentityRequestTimeout, value: "31s"},
		{name: "zero connections", key: envIdentityMaxConnections, value: "0"},
		{name: "too many connections", key: envIdentityMaxConnections, value: "4097"},
		{name: "zero concurrent requests", key: envIdentityMaxConcurrentRequests, value: "0"},
		{name: "concurrency exceeds connections", key: envIdentityMaxConcurrentRequests, value: "257"},
		{name: "connector id uppercase", key: envIdentityOIDCConnectorID, value: "Google"},
		{name: "connector display whitespace", key: envIdentityOIDCConnectorDisplayName, value: " Google"},
		{name: "connector generation zero", key: envIdentityOIDCConnectorGeneration, value: "0"},
		{name: "connector generation signed", key: envIdentityOIDCConnectorGeneration, value: "+1"},
		{name: "non-google phase one issuer", key: envIdentityOIDCConnectorIssuer, value: "https://login.example.test"},
		{name: "connector client id whitespace", key: envIdentityOIDCConnectorClientID, value: "google client"},
		{name: "relative connector secret", key: envIdentityOIDCConnectorClientSecretFile, value: "google-secret"},
		{name: "core client id uppercase", key: envIdentityCoreClientID, value: "MeshTransit"},
		{name: "core client display control", key: envIdentityCoreClientDisplayName, value: "Mesh\nTransit"},
		{name: "core client generation zero", key: envIdentityCoreClientGeneration, value: "0"},
		{name: "relative core client secret", key: envIdentityCoreClientSecretFile, value: "core-secret"},
		{name: "http core redirect", key: envIdentityCoreClientRedirectURI, value: "http://app.example.test/auth/callback"},
		{name: "core redirect query", key: envIdentityCoreClientRedirectURI, value: "https://app.example.test/auth/callback?next=x"},
		{name: "core redirect dot segment", key: envIdentityCoreClientRedirectURI, value: "https://app.example.test/auth/../callback"},
		{name: "fingerprint uppercase", key: envIdentityConfigurationFingerprint, value: identityConfigurationFingerprintPrefix + strings.Repeat("A", 64)},
		{name: "fingerprint all zero", key: envIdentityConfigurationFingerprint, value: identityConfigurationFingerprintPrefix + strings.Repeat("0", 64)},
		{name: "database missing host", key: envIdentityPostgreSQLAddress, value: ":5432"},
		{name: "runtime user whitespace", key: envIdentityPostgreSQLRuntimeUser, value: "identity runtime"},
		{name: "relative password", key: envIdentityPostgreSQLRuntimePasswordFile, value: "runtime-password"},
		{name: "relative ca", key: envIdentityPostgreSQLCAFile, value: "ca.pem"},
		{name: "zero open pool", key: envIdentityPostgreSQLMaxOpenConnections, value: "0"},
		{name: "idle exceeds open", key: envIdentityPostgreSQLMaxIdleConnections, value: "11"},
		{name: "fractional connect timeout", key: envIdentityPostgreSQLConnectTimeout, value: "1500ms"},
		{name: "connect exceeds check", key: envIdentityPostgreSQLConnectTimeout, value: "3s"},
		{name: "short connection lifetime", key: envIdentityPostgreSQLConnectionLifetime, value: "59s"},
		{name: "short id token lifetime", key: envIdentityIDTokenLifetime, value: "59s"},
		{name: "short signing rotation", key: envIdentitySigningKeyRotation, value: "59m"},
		{name: "long garbage collection", key: envIdentityGarbageCollection, value: "61m"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := Load(mapLookup(validIdentityProcessValues(map[string]string{test.key: test.value})))
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Load() error = %v, want ErrInvalid", err)
			}
			if strings.Contains(err.Error(), test.value) {
				t.Fatalf("Load() error exposed rejected value %q: %v", test.value, err)
			}
		})
	}
}

func TestLoadIdentityRejectsSharedSecretAndKeyFiles(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name, key, sharedWith string
	}{
		{name: "certificate and private key", key: envIdentityTLSPrivateKeyFile, sharedWith: envIdentityTLSCertificateFile},
		{name: "database password and private key", key: envIdentityPostgreSQLRuntimePasswordFile, sharedWith: envIdentityTLSPrivateKeyFile},
		{name: "connector and private key", key: envIdentityOIDCConnectorClientSecretFile, sharedWith: envIdentityTLSPrivateKeyFile},
		{name: "client and private key", key: envIdentityCoreClientSecretFile, sharedWith: envIdentityTLSPrivateKeyFile},
		{name: "connector and database password", key: envIdentityOIDCConnectorClientSecretFile, sharedWith: envIdentityPostgreSQLRuntimePasswordFile},
		{name: "client and connector", key: envIdentityCoreClientSecretFile, sharedWith: envIdentityOIDCConnectorClientSecretFile},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			values := validIdentityProcessValues(nil)
			values[test.key] = values[test.sharedWith]
			_, err := Load(mapLookup(values))
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), test.key) {
				t.Fatalf("Load() error = %v, want redacted setting %s", err, test.key)
			}
		})
	}
}

func TestLoadIdentityRejectsHealthListenerConflict(t *testing.T) {
	t.Parallel()

	values := validIdentityProcessValues(map[string]string{
		envHealthAddress:   "127.0.0.1:9443",
		envIdentityAddress: "127.0.0.1:9443",
	})
	_, err := Load(mapLookup(values))
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), envIdentityAddress) {
		t.Fatalf("Load() error = %v, want redacted identity listener conflict", err)
	}
}

func TestLoadAllRejectsIdentityListenerConflicts(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		address string
	}{
		{name: "api", address: defaultAPIAddress},
		{name: "control", address: defaultControlAddress},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := Load(mapLookup(validProcessValues(map[string]string{
				envIdentityAddress: test.address,
			})))
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), envIdentityAddress) {
				t.Fatalf("Load() error = %v, want redacted identity listener conflict", err)
			}
		})
	}
}

func TestLoadAllRejectsSharedIdentityDatabase(t *testing.T) {
	t.Parallel()

	_, err := Load(mapLookup(validProcessValues(map[string]string{
		envIdentityPostgreSQLAddress:  "database.internal:5432",
		envIdentityPostgreSQLDatabase: "meshtransit",
	})))
	if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), envIdentityPostgreSQLDatabase) {
		t.Fatalf("Load() error = %v, want isolated identity database failure", err)
	}
}

func TestLoadAllRejectsSharedIdentitySecretFiles(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name, key, sharedWith string
	}{
		{name: "database password", key: envIdentityPostgreSQLRuntimePasswordFile, sharedWith: envPostgreSQLRuntimePasswordFile},
		{name: "listener private key", key: envIdentityTLSPrivateKeyFile, sharedWith: envAPITLSPrivateKeyFile},
		{name: "connector secret", key: envIdentityOIDCConnectorClientSecretFile, sharedWith: envRedisPasswordFile},
		{name: "core client secret", key: envIdentityCoreClientSecretFile, sharedWith: envEnrollmentDigestActiveKeyFile},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			values := validProcessValues(nil)
			values[test.key] = values[test.sharedWith]
			_, err := Load(mapLookup(values))
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), test.key) {
				t.Fatalf("Load() error = %v, want redacted setting %s", err, test.key)
			}
		})
	}
}

func TestLoadOtherRolesIgnoreIdentitySettings(t *testing.T) {
	t.Parallel()

	values := validProcessValues(map[string]string{
		envRole:           "api",
		envIdentityIssuer: "not an issuer",
	})
	got, err := Load(mapLookup(values))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Identity != nil {
		t.Fatalf("Identity = %v, want nil", got.Identity)
	}
}

func TestIdentityConfigurationConcealsMetadata(t *testing.T) {
	t.Parallel()

	loaded, err := Load(mapLookup(validIdentityProcessValues(nil)))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	for name, value := range map[string]any{
		"identity":    *loaded.Identity,
		"listener":    loaded.Identity.Listener,
		"postgres":    loaded.Identity.PostgreSQL,
		"connector":   loaded.Identity.OIDCConnectors[0],
		"client":      loaded.Identity.Clients[0],
		"fingerprint": loaded.Identity.ExpectedFingerprint,
	} {
		if fmt.Sprint(value) != redactedValue || fmt.Sprintf("%#v", value) != redactedValue {
			t.Fatalf("%s formatting disclosed metadata", name)
		}
		logger, ok := value.(slog.LogValuer)
		if !ok || logger.LogValue().String() != redactedValue {
			t.Fatalf("%s structured formatting disclosed metadata", name)
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrInvalid) {
			t.Fatalf("json.Marshal(%s) error = %v, want ErrInvalid", name, err)
		}
	}
}

func TestLoadIdentityFingerprintInputDoesNotRequireApprovedFingerprint(t *testing.T) {
	t.Parallel()

	values := validIdentityProcessValues(nil)
	delete(values, envIdentityConfigurationFingerprint)
	identity, err := LoadIdentityFingerprintInput(mapLookup(values))
	if err != nil {
		t.Fatalf("LoadIdentityFingerprintInput() error = %v", err)
	}
	if identity.ExpectedFingerprint != (IdentityConfigurationFingerprint{}) ||
		len(identity.OIDCConnectors) != 1 || len(identity.Clients) != 1 {
		t.Fatalf("fingerprint input = %v", identity)
	}
}

func validIdentityProcessValues(overrides map[string]string) map[string]string {
	values := validProcessValues(map[string]string{ //nolint:gosec // G101: fixtures contain file paths, not credentials.
		envRole:                                  "identity",
		envIdentityIssuer:                        "https://id.example.test/oauth2",
		envIdentityConfigurationFingerprint:      identityConfigurationFingerprintPrefix + strings.Repeat("1", 64),
		envIdentityAddress:                       "127.0.0.1:9443",
		envIdentityTLSCertificateFile:            "/run/secrets/identity-tls-certificate.pem",
		envIdentityTLSPrivateKeyFile:             "/run/secrets/identity-tls-private-key.pem",
		envIdentityOIDCConnectorID:               "google-v1",
		envIdentityOIDCConnectorDisplayName:      "Google",
		envIdentityOIDCConnectorGeneration:       "1",
		envIdentityOIDCConnectorIssuer:           identityGoogleIssuer,
		envIdentityOIDCConnectorClientID:         "google-client.apps.googleusercontent.com",
		envIdentityOIDCConnectorClientSecretFile: "/run/secrets/google-oidc-client-secret",
		envIdentityCoreClientID:                  "meshtransit-core",
		envIdentityCoreClientDisplayName:         "MeshTransit Core",
		envIdentityCoreClientGeneration:          "1",
		envIdentityCoreClientSecretFile:          "/run/secrets/meshtransit-core-client-secret",
		envIdentityCoreClientRedirectURI:         "https://app.example.test/auth/v1/callback",
		envIdentityPostgreSQLAddress:             "identity-db.internal:5432",
		envIdentityPostgreSQLDatabase:            "meshtransit_identity",
		envIdentityPostgreSQLRuntimeUser:         "identity_runtime",
		envIdentityPostgreSQLRuntimePasswordFile: "/run/secrets/identity-runtime-password",
		envIdentityPostgreSQLCAFile:              "/run/secrets/identity-postgres-ca.pem",
	})
	for key, value := range overrides {
		values[key] = value
	}
	return values
}
