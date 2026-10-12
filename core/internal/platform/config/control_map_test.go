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
	if got.Control.Map.KeepAliveInterval != 30*time.Second {
		t.Fatalf(
			"Control.Map.KeepAliveInterval = %s, want 30s proxy-safe default",
			got.Control.Map.KeepAliveInterval,
		)
	}
	want := ControlMapConfig{
		RequestTimeout:       defaultControlMapRequestTimeout,
		StatementTimeout:     defaultControlMapStatementTimeout,
		TransactionIdleLimit: defaultControlMapIdleLimit,
		PresenceTTL:          defaultControlMapPresenceTTL,
		CoordinationTimeout:  defaultControlMapCoordination,
		KeepAliveInterval:    defaultControlMapKeepAlive,
		ReconcileInterval:    defaultControlMapReconcile,

		SharedInventory:           true,
		SharedConnectivity:        true,
		PeerLimit:                 defaultControlMapPeerLimit,
		InventoryStatementTimeout: defaultControlMapInventoryStatement,
		ShareStatementTimeout:     defaultControlMapShareStatement,
	}
	directory := got.Control.Map.RelayDirectory
	if directory == nil || *directory != relayDirectoryConfigFixture(t) {
		t.Fatal("Control.Map.RelayDirectory not loaded from the directory file")
	}
	gotMap := got.Control.Map
	gotMap.RelayDirectory = nil
	if gotMap != want {
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
	if got.Control == nil {
		t.Fatal("Control missing")
	}
	gotMap := got.Control.Map
	gotMap.RelayDirectory = nil
	if gotMap != (ControlMapConfig{
		RequestTimeout:       13 * time.Second,
		StatementTimeout:     7 * time.Second,
		TransactionIdleLimit: 11 * time.Second,
		PresenceTTL:          45 * time.Second,
		CoordinationTimeout:  4 * time.Second,
		KeepAliveInterval:    70 * time.Second,
		ReconcileInterval:    20 * time.Second,

		SharedInventory:           true,
		SharedConnectivity:        true,
		PeerLimit:                 defaultControlMapPeerLimit,
		InventoryStatementTimeout: defaultControlMapInventoryStatement,
		ShareStatementTimeout:     defaultControlMapShareStatement,
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
	// Without both directory settings, a control process needs a relay map.
	values := validProcessValues(map[string]string{envRole: "control"})
	delete(values, envRelayDirectoryFile)
	delete(values, envRelayDirectorySHA256)
	if _, err := Load(mapLookup(values)); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), envRelayDirectoryFile) {
		t.Fatalf("Load() without any relay source error = %v", err)
	}
	values[envRelayAuthorityEnabled] = "true"
	values[envRelaySigningKeyFile] = writeSigningSeed(t, 0x31)
	values[envRelayMapFile] = "/etc/meshtransit/relay-map.json"
	values[envRelayMapSHA256] = "sha256:" + strings.Repeat("2", 64)
	got, err := Load(mapLookup(values))
	if err != nil || got.Control == nil || got.Control.Map.RelayDirectory != nil {
		t.Fatalf("Load() with a relay map: %v", err)
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

func TestLoadControlMapSharedInventorySettings(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		values  map[string]string
		shared  bool
		timeout time.Duration
		wantErr string
	}{
		"default on":   {values: map[string]string{}, shared: true, timeout: defaultControlMapInventoryStatement},
		"switched off": {values: map[string]string{envControlMapSharedInventory: "false"}, shared: false, timeout: defaultControlMapInventoryStatement},
		"timeout":      {values: map[string]string{envControlMapInventoryStatementTimeout: "45s"}, shared: true, timeout: 45 * time.Second},
		"bad switch":   {values: map[string]string{envControlMapSharedInventory: "yes"}, wantErr: envControlMapSharedInventory},
		"bad timeout":  {values: map[string]string{envControlMapInventoryStatementTimeout: "2m"}, wantErr: envControlMapInventoryStatementTimeout},
	} {
		got, err := loadControlMapConfig(mapLookup(test.values))
		if test.wantErr != "" {
			if err == nil || !strings.HasSuffix(err.Error(), ": "+test.wantErr) {
				t.Errorf("%s: error = %v, want one naming %s", name, err, test.wantErr)
			}
			continue
		}
		if err != nil || got.SharedInventory != test.shared || got.InventoryStatementTimeout != test.timeout {
			t.Errorf("%s: got %t/%v, %v", name, got.SharedInventory, got.InventoryStatementTimeout, err)
		}
	}
}

func TestLoadControlMapSharedConnectivitySetting(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		values  map[string]string
		shared  bool
		wantErr bool
	}{
		"default on":   {values: map[string]string{}, shared: true},
		"switched off": {values: map[string]string{envControlMapSharedConnectivity: "false"}},
		"bad switch":   {values: map[string]string{envControlMapSharedConnectivity: "1"}, wantErr: true},
	} {
		got, err := loadControlMapConfig(mapLookup(test.values))
		if test.wantErr {
			if err == nil || !strings.HasSuffix(err.Error(), ": "+envControlMapSharedConnectivity) {
				t.Errorf("%s: error = %v, want one naming %s", name, err, envControlMapSharedConnectivity)
			}
			continue
		}
		if err != nil || got.SharedConnectivity != test.shared {
			t.Errorf("%s: got %t, %v", name, got.SharedConnectivity, err)
		}
	}
}

func TestLoadControlMapPeerLimit(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		value string
		want  int
		bad   bool
	}{"default": {want: defaultControlMapPeerLimit}, "lower": {value: "5000", want: 5000},
		"too small": {value: "10", bad: true}, "too large": {value: "10001", bad: true}} {
		values := map[string]string{}
		if test.value != "" {
			values[envControlMapPeerLimit] = test.value
		}
		got, err := loadControlMapConfig(mapLookup(values))
		if test.bad {
			if err == nil || !strings.HasSuffix(err.Error(), ": "+envControlMapPeerLimit) {
				t.Errorf("%s: error = %v", name, err)
			}
			continue
		}
		if err != nil || got.PeerLimit != test.want {
			t.Errorf("%s: got %d, %v", name, got.PeerLimit, err)
		}
	}
}

func TestLoadControlMapShareStatementTimeout(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		values  map[string]string
		timeout time.Duration
		wantErr bool
	}{
		"default":  {values: map[string]string{}, timeout: defaultControlMapShareStatement},
		"explicit": {values: map[string]string{envControlMapShareStatementTimeout: "20s"}, timeout: 20 * time.Second},
		"too long": {values: map[string]string{envControlMapShareStatementTimeout: "2m"}, wantErr: true},
		"zero":     {values: map[string]string{envControlMapShareStatementTimeout: "0s"}, wantErr: true},
	} {
		got, err := loadControlMapConfig(mapLookup(test.values))
		if test.wantErr {
			if err == nil || !strings.HasSuffix(err.Error(), ": "+envControlMapShareStatementTimeout) {
				t.Errorf("%s: error = %v, want one naming %s", name, err, envControlMapShareStatementTimeout)
			}
			continue
		}
		if err != nil || got.ShareStatementTimeout != test.timeout {
			t.Errorf("%s: got %v, %v", name, got.ShareStatementTimeout, err)
		}
	}
}
