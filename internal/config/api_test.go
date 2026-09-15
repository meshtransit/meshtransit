package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLoadAPIConfigForAPIRoles(t *testing.T) {
	t.Parallel()

	for _, role := range []string{"all", "api"} {
		t.Run(role, func(t *testing.T) {
			t.Parallel()
			got, err := Load(mapLookup(validProcessValues(map[string]string{
				envRole:                                 role,
				envAPIAddress:                           "[::]:9444",
				envAPIAccountSessionDigestPreviousKeyID: "session-v0",
				envAPIAccountSessionDigestPreviousKeyFile: "/run/secrets/account-session-digest-previous-key",
				envAPIRequestTimeout:                      "7s",
				envAPIMaxConnections:                      "17",
				envAPIMaxConcurrentRequests:               "9",
			})))
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if got.API == nil {
				t.Fatal("API = nil for API-serving role")
			}
			if got.API.Address != "[::]:9444" || got.API.RequestTimeout != 7*time.Second ||
				got.API.MaxConnections != 17 || got.API.MaxConcurrentRequests != 9 ||
				got.API.AccountSessionDigest.Active.ID.String() != "session-v1" ||
				got.API.AccountSessionDigest.Previous == nil ||
				got.API.AccountSessionDigest.Previous.ID.String() != "session-v0" ||
				got.API.IdempotencyDigest.ID.String() != "idempotency-v1" {
				t.Fatalf("API = %+v, want explicit bounded values", *got.API)
			}
		})
	}
}

func TestLoadAPIConfigRequiresFilesAndKeyIDs(t *testing.T) {
	t.Parallel()

	for _, setting := range []string{
		envAPITLSCertificateFile,
		envAPITLSPrivateKeyFile,
		envAPIAccountSessionDigestActiveKeyID,
		envAPIAccountSessionDigestActiveKeyFile,
		envAPIIdempotencyDigestKeyID,
		envAPIIdempotencyDigestKeyFile,
	} {
		t.Run(setting, func(t *testing.T) {
			t.Parallel()
			values := validProcessValues(map[string]string{envRole: "api"})
			delete(values, setting)
			_, err := Load(mapLookup(values))
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), setting) {
				t.Fatalf("Load() error = %v, want ErrInvalid naming %s", err, setting)
			}
		})
	}
}

func TestLoadAPIConfigRejectsUnsafeValuesWithoutEchoingThem(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		setting  string
		rejected string
	}{
		{name: "invalid address", setting: envAPIAddress, rejected: "public interface"},
		{name: "relative certificate", setting: envAPITLSCertificateFile, rejected: "relative.pem"},
		{name: "invalid session key id", setting: envAPIAccountSessionDigestActiveKeyID, rejected: " session key"},
		{name: "invalid idempotency key id", setting: envAPIIdempotencyDigestKeyID, rejected: "idempotency key"},
		{name: "short request timeout", setting: envAPIRequestTimeout, rejected: "99ms"},
		{name: "long request timeout", setting: envAPIRequestTimeout, rejected: "31s"},
		{name: "zero connections", setting: envAPIMaxConnections, rejected: "0"},
		{name: "unbounded connections", setting: envAPIMaxConnections, rejected: "4097"},
		{name: "zero concurrent requests", setting: envAPIMaxConcurrentRequests, rejected: "0"},
		{name: "requests exceed connections", setting: envAPIMaxConcurrentRequests, rejected: "257"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := Load(mapLookup(validProcessValues(map[string]string{
				envRole: "api", test.setting: test.rejected,
			})))
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), test.setting) {
				t.Fatalf("Load() error = %v, want ErrInvalid naming %s", err, test.setting)
			}
			if strings.Contains(err.Error(), test.rejected) {
				t.Fatalf("Load() error exposed rejected value %q: %v", test.rejected, err)
			}
		})
	}
}

func TestLoadAPIConfigRequiresCompletePreviousKeyPair(t *testing.T) {
	t.Parallel()

	for _, missing := range []string{
		envAPIAccountSessionDigestPreviousKeyID,
		envAPIAccountSessionDigestPreviousKeyFile,
	} {
		values := validProcessValues(map[string]string{
			envRole:                                   "api",
			envAPIAccountSessionDigestPreviousKeyID:   "session-v0",
			envAPIAccountSessionDigestPreviousKeyFile: "/run/secrets/account-session-digest-previous-key",
		})
		delete(values, missing)
		_, err := Load(mapLookup(values))
		if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), missing) {
			t.Fatalf("Load() error = %v, want ErrInvalid naming %s", err, missing)
		}
	}
}

func TestLoadAPIConfigRejectsAddressConflicts(t *testing.T) {
	t.Parallel()

	for name, overrides := range map[string]map[string]string{
		"health":  {envRole: "api", envHealthAddress: "127.0.0.1:8444", envAPIAddress: "0.0.0.0:8444"},
		"control": {envRole: "all", envControlAddress: "[::]:8444", envAPIAddress: "[::1]:8444"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := Load(mapLookup(validProcessValues(overrides)))
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), envAPIAddress) {
				t.Fatalf("Load() error = %v, want API address conflict", err)
			}
		})
	}
}

func TestLoadAPIConfigRejectsSharedSecretFiles(t *testing.T) {
	t.Parallel()

	for name, overrides := range map[string]map[string]string{
		"session and idempotency": {
			envAPIIdempotencyDigestKeyFile: "/run/secrets/account-session-digest-active-key",
		},
		"session and tls": {
			envAPIAccountSessionDigestActiveKeyFile: "/run/secrets/control-tls-private-key.pem",
		},
		"idempotency and enrollment": {
			envAPIIdempotencyDigestKeyFile: "/run/secrets/enrollment-digest-active-key",
		},
		"api tls and control noise": {
			envAPITLSPrivateKeyFile: "/run/secrets/control-noise-private-key",
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := Load(mapLookup(validProcessValues(overrides)))
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Load() error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestLoadIgnoresAPIConfigOutsideAPIRoles(t *testing.T) {
	t.Parallel()

	for _, role := range []string{"control", "worker", "relay"} {
		t.Run(role, func(t *testing.T) {
			t.Parallel()
			got, err := Load(mapLookup(validProcessValues(map[string]string{
				envRole: role, envAPIAddress: "invalid", envAPIMaxConnections: "unbounded",
			})))
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if got.API != nil {
				t.Fatalf("API = %+v, want nil for role %s", got.API, role)
			}
		})
	}
}
