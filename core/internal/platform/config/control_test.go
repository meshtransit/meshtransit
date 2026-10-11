package config

import (
	"errors"
	"reflect"
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
				envIdentityAddress:                "127.0.0.1:9445",
				envControlMaxSessions:             "17",
				envControlHandshakeTimeout:        "3s",
				envControlReadIdleTimeout:         "45s",
				envControlMapRequestTimeout:       "9s",
				envControlMapStatementTimeout:     "4s",
				envControlMapTransactionIdleLimit: "6s",
				envControlMapPresenceTTL:          "45s",
				envControlMapCoordinationTimeout:  "4s",
				envControlMapKeepAliveInterval:    "70s",
				envControlMapReconcileInterval:    "20s",
			})))
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if got.Control == nil {
				t.Fatal("Control = nil for control-plane role")
			}
			want := ControlConfig{
				Address:             "[::]:9443",
				TLSCertificateFile:  TrustFile{path: "/run/secrets/control-tls-certificate.pem"},
				TLSPrivateKeyFile:   PrivateKeyFile{path: "/run/secrets/control-tls-private-key.pem"},
				NoisePrivateKeyFile: SecretFile{path: "/run/secrets/control-noise-private-key"},
				MaxSessions:         17,
				HandshakeTimeout:    3 * time.Second,
				ReadIdleTimeout:     45 * time.Second,
				DrainWindow:         defaultControlDrainWindow,
				Rebalance:           true,
				RebalanceInterval:   defaultControlRebalanceEvery,
				Map: ControlMapConfig{
					RequestTimeout:       9 * time.Second,
					StatementTimeout:     4 * time.Second,
					TransactionIdleLimit: 6 * time.Second,
					PresenceTTL:          45 * time.Second,
					CoordinationTimeout:  4 * time.Second,
					KeepAliveInterval:    70 * time.Second,
					ReconcileInterval:    20 * time.Second,

					SharedInventory:           true,
					SharedConnectivity:        true,
					PeerLimit:                 defaultControlMapPeerLimit,
					InventoryStatementTimeout: defaultControlMapInventoryStatement,
				},
			}
			gotControl := *got.Control
			if gotControl.Map.RelayDirectory == nil || *gotControl.Map.RelayDirectory != relayDirectoryConfigFixture(t) {
				t.Fatal("relay directory file not loaded")
			}
			gotControl.Map.RelayDirectory = nil
			if gotControl.MTCP.KeyNotAfter.IsZero() {
				t.Fatal("MTCP key expiry not loaded")
			}
			gotControl.MTCP = ControlMTCPConfig{}
			if !reflect.DeepEqual(gotControl, want) {
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
		{name: "unbounded sessions", setting: envControlMaxSessions, rejected: "16385"},
		{name: "unbounded drain window", setting: envControlDrainWindow, rejected: "6m"},
		{name: "bad rebalance switch", setting: envControlRebalance, rejected: "yes"},
		{name: "fast rebalance", setting: envControlRebalanceInterval, rejected: "100ms"},
		{name: "short handshake", setting: envControlHandshakeTimeout, rejected: "99ms"},
		{name: "long handshake", setting: envControlHandshakeTimeout, rejected: "31s"},
		{name: "long read idle", setting: envControlReadIdleTimeout, rejected: "6m"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			values := validProcessValues(map[string]string{test.setting: test.rejected})
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

func TestLoadControlConfigRefusesRetiredSettings(t *testing.T) {
	t.Parallel()

	for _, setting := range retiredControlSettings {
		values := validProcessValues(map[string]string{envRole: "control", setting: "8"})
		if _, err := Load(mapLookup(values)); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), setting) {
			t.Fatalf("Load() error = %v, want ErrInvalid naming %s", err, setting)
		}
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
