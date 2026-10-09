package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/core/internal/platform/ratelimit"
)

// #nosec G101 -- canonical token grammar fixture; it has no authority outside this test.
const managementCompositionToken = "mtas1.01890f00-0000-7000-8000-000000000001.7.AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"

func TestComposeManagementAPIBuildsBoundedServer(t *testing.T) {
	t.Parallel()

	processConfig, _ := managementProcessConfigFixture(t, false)
	runtimePool, err := openPostgresRolePool(
		t.Context(),
		postgresadapter.PoolRoleRuntime,
		processConfig.Storage.PostgreSQL,
		*processConfig.Storage.PostgreSQL.Runtime,
		time.Second,
	)
	if err != nil {
		t.Fatalf("openPostgresRolePool() error = %v", err)
	}
	t.Cleanup(func() { _ = runtimePool.Shutdown(context.Background()) })

	server, metrics, err := composeManagementAPI(
		*processConfig.API,
		runtimePool,
		managementCompositionRateLimiter{},
		discardCompositionLogger(),
	)
	if err != nil {
		t.Fatalf("composeManagementAPI() error = %v", err)
	}
	if server == nil || metrics == nil || server.Done() != nil {
		t.Fatalf("composition = (%v, %v), want unstarted server and metrics", server, metrics)
	}
}

func TestComposeAccountSessionKeyringSupportsPreviousKey(t *testing.T) {
	t.Parallel()

	processConfig, _ := managementProcessConfigFixture(t, true)
	keyring, err := composeAccountSessionKeyring(processConfig.API.AccountSessionDigest)
	if err != nil {
		t.Fatalf("composeAccountSessionKeyring() error = %v", err)
	}
	token, err := accountsession.ParseToken(managementCompositionToken)
	if err != nil {
		t.Fatalf("accountsession.ParseToken() error = %v", err)
	}
	digests, err := keyring.Digests(token)
	if err != nil {
		t.Fatalf("Keyring.Digests() error = %v", err)
	}
	if len(digests) != 2 || digests[0].KeyID().String() != "session-v1" ||
		digests[1].KeyID().String() != "session-v0" {
		t.Fatalf("digest key IDs = %+v, want active then previous", digests)
	}
}

func TestManagementCompositionRejectsSecretContentsWithoutDisclosure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pathKey string
		compose func(config.APIConfig) error
	}{
		{
			name: "session key", pathKey: "session",
			compose: func(apiConfig config.APIConfig) error {
				_, err := composeAccountSessionKeyring(apiConfig.AccountSessionDigest)
				return err
			},
		},
		{
			name: "idempotency key", pathKey: "idempotency",
			compose: func(apiConfig config.APIConfig) error {
				_, err := composeIdempotencyDigester(apiConfig.IdempotencyDigest)
				return err
			},
		},
		{
			name: "rate limit key", pathKey: "rate-limit",
			compose: func(apiConfig config.APIConfig) error {
				_, err := composeRateLimitDigester(apiConfig.RateLimitDigest)
				return err
			},
		},
		{
			name: "TLS private key", pathKey: "tls-key",
			compose: func(apiConfig config.APIConfig) error {
				_, err := loadManagementTLSCertificate(apiConfig)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			processConfig, paths := managementProcessConfigFixture(t, false)
			const secret = "do-not-disclose-this-secret"
			if err := os.WriteFile(paths[test.pathKey], []byte(secret), 0o600); err != nil {
				t.Fatalf("os.WriteFile() error = %v", err)
			}
			err := test.compose(*processConfig.API)
			if !errors.Is(err, errInvalidManagementComposition) {
				t.Fatalf("composition error = %v, want errInvalidManagementComposition", err)
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), paths[test.pathKey]) {
				t.Fatalf("composition error disclosed secret input: %v", err)
			}
		})
	}
}

func managementProcessConfigFixture(
	t *testing.T,
	withPrevious bool,
) (config.Config, map[string]string) {
	t.Helper()
	_, controlPaths := controlConfigFixture(t)
	directory := filepath.Dir(controlPaths["certificate.pem"])
	paths := map[string]string{
		"certificate": controlPaths["certificate.pem"],
		"tls-key":     controlPaths["tls.key"],
		"session":     filepath.Join(directory, "session.key"),
		"idempotency": filepath.Join(directory, "idempotency.key"),
		"rate-limit":  filepath.Join(directory, "rate-limit.key"),
		"password":    filepath.Join(directory, "password"),
	}
	writeCredentialDigestTestKey(
		t,
		paths["session"],
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x55}, 32)),
	)
	writeCredentialDigestTestKey(
		t,
		paths["idempotency"],
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x66}, 32)),
	)
	writeCredentialDigestTestKey(
		t,
		paths["rate-limit"],
		base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x77}, 32)),
	)
	writeCredentialDigestTestKey(t, paths["password"], "test-password")
	values := map[string]string{
		"MESHTRANSIT_ROLE":                                       "api",
		"MESHTRANSIT_POSTGRES_ADDRESS":                           "database.internal:5432",
		"MESHTRANSIT_POSTGRES_DATABASE":                          "meshtransit",
		"MESHTRANSIT_POSTGRES_RUNTIME_USER":                      "mesh_runtime",
		"MESHTRANSIT_POSTGRES_RUNTIME_PASSWORD_FILE":             paths["password"],
		"MESHTRANSIT_POSTGRES_CA_FILE":                           paths["certificate"],
		"MESHTRANSIT_REDIS_ADDRESS":                              "cache.internal:6379",
		"MESHTRANSIT_REDIS_USERNAME":                             "meshcore",
		"MESHTRANSIT_REDIS_PASSWORD_FILE":                        paths["password"],
		"MESHTRANSIT_REDIS_CA_FILE":                              paths["certificate"],
		"MESHTRANSIT_API_TLS_CERTIFICATE_FILE":                   paths["certificate"],
		"MESHTRANSIT_API_TLS_PRIVATE_KEY_FILE":                   paths["tls-key"],
		"MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_ACTIVE_KEY_ID":   "session-v1",
		"MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_ACTIVE_KEY_FILE": paths["session"],
		"MESHTRANSIT_API_IDEMPOTENCY_DIGEST_KEY_ID":              "idempotency-v1",
		"MESHTRANSIT_API_IDEMPOTENCY_DIGEST_KEY_FILE":            paths["idempotency"],
		"MESHTRANSIT_API_RATE_LIMIT_DIGEST_KEY_ID":               "rate-limit-v1",
		"MESHTRANSIT_API_RATE_LIMIT_DIGEST_KEY_FILE":             paths["rate-limit"],
	}
	if withPrevious {
		paths["previous"] = filepath.Join(directory, "previous-session.key")
		writeCredentialDigestTestKey(
			t,
			paths["previous"],
			base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x44}, 32)),
		)
		values["MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_PREVIOUS_KEY_ID"] = "session-v0"
		values["MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_PREVIOUS_KEY_FILE"] = paths["previous"]
	}
	processConfig, err := config.Load(func(setting string) (string, bool) {
		value, ok := values[setting]
		return value, ok
	})
	if err != nil {
		t.Fatalf("config.Load() error = %v", err)
	}
	return processConfig, paths
}

type managementCompositionRateLimiter struct{}

func (managementCompositionRateLimiter) Allow(
	context.Context,
	ratelimit.Subject,
	ratelimit.Policy,
) (ratelimit.Decision, error) {
	return ratelimit.NewDecision(true, 1, 0, 0)
}
