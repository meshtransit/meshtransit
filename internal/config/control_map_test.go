package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLoadControlMapDefaults(t *testing.T) {
	t.Parallel()

	got, err := Load(mapLookup(validProcessValues(map[string]string{envRole: "control"})))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Control == nil {
		t.Fatal("Control = nil for control role")
	}
	want := ControlMapConfig{
		RequestTimeout:       defaultControlMapRequestTimeout,
		StatementTimeout:     defaultControlMapStatementTimeout,
		TransactionIdleLimit: defaultControlMapIdleLimit,
		PresenceTTL:          defaultControlMapPresenceTTL,
		CoordinationTimeout:  defaultControlMapCoordination,
		KeepAliveInterval:    defaultControlMapKeepAlive,
		ReconcileInterval:    defaultControlMapReconcile,
		RelayDirectory:       relayDirectoryConfigFixture(t),
	}
	if got.Control.Map != want {
		t.Fatalf("Control.Map = %+v, want %+v", got.Control.Map, want)
	}
}

func TestLoadControlMapExplicitValues(t *testing.T) {
	t.Parallel()

	got, err := Load(mapLookup(validProcessValues(map[string]string{
		envRole:                           "control",
		envControlMapRequestTimeout:       "13s",
		envControlMapStatementTimeout:     "7s",
		envControlMapTransactionIdleLimit: "11s",
		envControlMapPresenceTTL:          "45s",
		envControlMapCoordinationTimeout:  "4s",
		envControlMapKeepAliveInterval:    "70s",
		envControlMapReconcileInterval:    "20s",
	})))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Control == nil || got.Control.Map != (ControlMapConfig{
		RequestTimeout:       13 * time.Second,
		StatementTimeout:     7 * time.Second,
		TransactionIdleLimit: 11 * time.Second,
		PresenceTTL:          45 * time.Second,
		CoordinationTimeout:  4 * time.Second,
		KeepAliveInterval:    70 * time.Second,
		ReconcileInterval:    20 * time.Second,
		RelayDirectory:       relayDirectoryConfigFixture(t),
	}) {
		t.Fatalf("Control.Map = %+v, want explicit values", got.Control)
	}
}

func TestLoadControlMapRejectsUnsafeBoundsWithoutEchoingValues(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		setting string
		value   string
	}{
		{name: "short request timeout", setting: envControlMapRequestTimeout, value: "99ms"},
		{name: "excess request timeout", setting: envControlMapRequestTimeout, value: "61s"},
		{name: "zero statement timeout", setting: envControlMapStatementTimeout, value: "0s"},
		{name: "excess statement timeout", setting: envControlMapStatementTimeout, value: "61s"},
		{name: "zero idle limit", setting: envControlMapTransactionIdleLimit, value: "0s"},
		{name: "excess idle limit", setting: envControlMapTransactionIdleLimit, value: "61s"},
		{name: "short presence ttl", setting: envControlMapPresenceTTL, value: "2s"},
		{name: "excess presence ttl", setting: envControlMapPresenceTTL, value: "301s"},
		{name: "short coordination timeout", setting: envControlMapCoordinationTimeout, value: "99ms"},
		{name: "excess coordination timeout", setting: envControlMapCoordinationTimeout, value: "31s"},
		{name: "coordination consumes renewal window", setting: envControlMapCoordinationTimeout, value: "10s"},
		{name: "short keepalive", setting: envControlMapKeepAliveInterval, value: "999ms"},
		{name: "excess keepalive", setting: envControlMapKeepAliveInterval, value: "91s"},
		{name: "short reconcile", setting: envControlMapReconcileInterval, value: "999ms"},
		{name: "excess reconcile", setting: envControlMapReconcileInterval, value: "301s"},
		{name: "relative relay file", setting: envRelayDirectoryFile, value: "relay-directory.json"},
		{name: "uppercase relay digest", setting: envRelayDirectorySHA256, value: "sha256:" + strings.Repeat("A", 64)},
		{name: "zero relay digest", setting: envRelayDirectorySHA256, value: "sha256:" + strings.Repeat("0", 64)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := Load(mapLookup(validProcessValues(map[string]string{
				envRole:      "control",
				test.setting: test.value,
			})))
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), test.setting) {
				t.Fatalf("Load() error = %v, want ErrInvalid naming %s", err, test.setting)
			}
			if strings.Contains(err.Error(), test.value) {
				t.Fatalf("Load() error exposed rejected value %q: %v", test.value, err)
			}
		})
	}
}

func TestLoadControlMapRequiresRelayDirectoryReference(t *testing.T) {
	t.Parallel()

	for _, setting := range []string{envRelayDirectoryFile, envRelayDirectorySHA256} {
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

func relayDirectoryConfigFixture(t *testing.T) RelayDirectoryConfig {
	t.Helper()
	config, err := NewRelayDirectoryConfig(
		"/etc/meshtransit/relay-directory.json",
		"sha256:"+strings.Repeat("1", 64),
	)
	if err != nil {
		t.Fatalf("NewRelayDirectoryConfig() error = %v", err)
	}
	return config
}

func TestLoadIgnoresControlMapConfigOutsideControlRoles(t *testing.T) {
	t.Parallel()

	for _, role := range []string{"api", "worker", "relay"} {
		t.Run(role, func(t *testing.T) {
			t.Parallel()
			got, err := Load(mapLookup(validProcessValues(map[string]string{
				envRole:                       role,
				envControlMapStatementTimeout: "invalid",
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
