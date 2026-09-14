package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLoadControlConfigForControlRoles(t *testing.T) {
	t.Parallel()

	for _, role := range []string{"all", "control"} {
		t.Run(role, func(t *testing.T) {
			t.Parallel()

			got, err := Load(mapLookup(validProcessValues(map[string]string{
				envRole:                           role,
				envControlAddress:                 "[::]:9443",
				envControlMaxSessions:             "17",
				envControlMaxStreamsPerSession:    "5",
				envControlHandshakeTimeout:        "3s",
				envControlReadIdleTimeout:         "45s",
				envControlPingTimeout:             "10s",
				envControlWriteTimeout:            "12s",
				envControlMapStatementTimeout:     "4s",
				envControlMapTransactionIdleLimit: "6s",
			})))
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if got.Control == nil {
				t.Fatal("Control = nil for control-plane role")
			}
			want := ControlConfig{
				Address:              "[::]:9443",
				TLSCertificateFile:   TrustFile{path: "/run/secrets/control-tls-certificate.pem"},
				TLSPrivateKeyFile:    PrivateKeyFile{path: "/run/secrets/control-tls-private-key.pem"},
				NoisePrivateKeyFile:  SecretFile{path: "/run/secrets/control-noise-private-key"},
				MaxSessions:          17,
				MaxStreamsPerSession: 5,
				HandshakeTimeout:     3 * time.Second,
				ReadIdleTimeout:      45 * time.Second,
				PingTimeout:          10 * time.Second,
				WriteTimeout:         12 * time.Second,
				Map: ControlMapConfig{
					StatementTimeout:     4 * time.Second,
					TransactionIdleLimit: 6 * time.Second,
				},
			}
			if *got.Control != want {
				t.Fatalf("Control = %+v, want %+v", *got.Control, want)
			}
		})
	}
}

func TestLoadControlConfigRequiresKeyFiles(t *testing.T) {
	t.Parallel()

	for _, setting := range []string{
		envControlTLSCertificateFile,
		envControlTLSPrivateKeyFile,
		envControlNoisePrivateKeyFile,
	} {
		t.Run(setting, func(t *testing.T) {
			t.Parallel()

			values := validProcessValues(map[string]string{envRole: "control"})
			delete(values, setting)
			_, err := Load(mapLookup(values))
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), setting) {
				t.Fatalf("Load() error = %v, want ErrInvalid naming %s", err, setting)
			}
		})
	}
}

func TestLoadControlConfigRejectsUnsafeBoundsWithoutEchoingValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		setting  string
		rejected string
	}{
		{name: "invalid address", setting: envControlAddress, rejected: "public interface"},
		{name: "relative certificate", setting: envControlTLSCertificateFile, rejected: "relative.pem"},
		{name: "zero sessions", setting: envControlMaxSessions, rejected: "0"},
		{name: "unbounded sessions", setting: envControlMaxSessions, rejected: "4097"},
		{name: "zero streams", setting: envControlMaxStreamsPerSession, rejected: "0"},
		{name: "unbounded streams", setting: envControlMaxStreamsPerSession, rejected: "65"},
		{name: "short handshake", setting: envControlHandshakeTimeout, rejected: "99ms"},
		{name: "long handshake", setting: envControlHandshakeTimeout, rejected: "31s"},
		{name: "long read idle", setting: envControlReadIdleTimeout, rejected: "6m"},
		{name: "ping exceeds idle", setting: envControlPingTimeout, rejected: "2m"},
		{name: "long write", setting: envControlWriteTimeout, rejected: "6m"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			values := validProcessValues(map[string]string{test.setting: test.rejected})
			if test.setting == envControlPingTimeout {
				values[envControlReadIdleTimeout] = "1m"
			}
			_, err := Load(mapLookup(values))
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), test.setting) {
				t.Fatalf("Load() error = %v, want ErrInvalid naming %s", err, test.setting)
			}
			if strings.Contains(err.Error(), test.rejected) {
				t.Fatalf("Load() error exposed rejected value %q: %v", test.rejected, err)
			}
		})
	}
}

func TestLoadControlConfigRejectsSharedPrivateKeyFiles(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		overrides map[string]string
		setting   string
	}{
		{
			name: "tls and noise",
			overrides: map[string]string{
				envControlNoisePrivateKeyFile: "/run/secrets/control-tls-private-key.pem",
			},
			setting: envControlNoisePrivateKeyFile,
		},
		{
			name: "noise and enrollment",
			overrides: map[string]string{
				envControlNoisePrivateKeyFile: "/run/secrets/enrollment-digest-active-key",
			},
			setting: envControlNoisePrivateKeyFile,
		},
		{
			name: "tls and enrollment",
			overrides: map[string]string{
				envControlTLSPrivateKeyFile: "/run/secrets/enrollment-digest-active-key",
			},
			setting: envControlTLSPrivateKeyFile,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := Load(mapLookup(validProcessValues(test.overrides)))
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), test.setting) {
				t.Fatalf("Load() error = %v, want ErrInvalid naming %s", err, test.setting)
			}
		})
	}
}

func TestLoadIgnoresControlConfigOutsideControlRoles(t *testing.T) {
	t.Parallel()

	for _, role := range []string{"api", "worker", "relay"} {
		t.Run(role, func(t *testing.T) {
			t.Parallel()

			got, err := Load(mapLookup(validProcessValues(map[string]string{
				envRole:                      role,
				envControlAddress:            "invalid",
				envControlTLSCertificateFile: "relative.pem",
				envControlMaxSessions:        "unbounded",
			})))
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if got.Control != nil {
				t.Fatalf("Control = %+v, want nil for role %s", got.Control, role)
			}
		})
	}
}
