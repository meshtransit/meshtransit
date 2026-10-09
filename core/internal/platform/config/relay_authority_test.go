package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"meshtransit.net/core/internal/platform/app"
	"meshtransit.net/shared/key"
)

func writeSigningSeed(t *testing.T, fill byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "signing.key")
	seed := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRelayAuthorityConfigDisabledByDefault(t *testing.T) {
	t.Parallel()

	cfg, err := loadRelayAuthorityConfig(mapLookup(nil), app.RoleControl)
	if err != nil || cfg != nil {
		t.Fatalf("loadRelayAuthorityConfig() = (%v, %v), want disabled", cfg, err)
	}
	_, err = loadRelayAuthorityConfig(mapLookup(map[string]string{
		envRelaySigningKeyFile: "/run/secrets/relay-signing.key",
	}), app.RoleControl)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("setting without enablement error = %v", err)
	}
}

func TestRelayAuthorityConfigLoadsKeysMapAndDrain(t *testing.T) {
	t.Parallel()

	current := writeSigningSeed(t, 0x31)
	next := writeSigningSeed(t, 0x32)
	drained := key.RelayPublic{0x44}
	cfg, err := loadRelayAuthorityConfig(mapLookup(map[string]string{
		envRelayAuthorityEnabled: "true",
		envRelaySigningKeyFile:   current,
		envRelayNextSigningKey:   next,
		envRelayMapFile:          "/etc/meshtransit/relay-map.json",
		envRelayMapSHA256:        "sha256:" + strings.Repeat("1", 64),
		envRelayDrain:            " " + drained.String() + " ",
		envRelayTrustedProxies:   "10.0.0.0/8,fd00::/8",
	}), app.RoleAll)
	if err != nil || cfg == nil {
		t.Fatalf("loadRelayAuthorityConfig() error = %v", err)
	}
	if cfg.MapFile != "/etc/meshtransit/relay-map.json" || cfg.MapDigest[0] != 0x11 ||
		len(cfg.Drain) != 1 || cfg.Drain[0] != drained || len(cfg.TrustedProxyPrefixes) != 2 {
		t.Fatal("map or drain settings not loaded")
	}
	signer, nextSigner, err := cfg.SigningKeys(t.Context())
	if err != nil || nextSigner == nil || signer.IsZero() || signer.Public() == nextSigner.Public() {
		t.Fatalf("SigningKeys() error = %v", err)
	}
	for _, formatted := range []string{fmt.Sprint(*cfg), fmt.Sprintf("%#v", *cfg), cfg.LogValue().String()} {
		if strings.Contains(formatted, "signing.key") || strings.Contains(formatted, "relay-map") {
			t.Fatalf("formatting exposed configuration: %q", formatted)
		}
	}
}

func TestRelayAuthorityConfigRejectsInvalidSettings(t *testing.T) {
	t.Parallel()

	current := writeSigningSeed(t, 0x31)
	base := func(extra map[string]string) map[string]string {
		values := map[string]string{envRelayAuthorityEnabled: "true", envRelaySigningKeyFile: current}
		for name, value := range extra {
			values[name] = value
		}
		return values
	}
	tests := []struct {
		name   string
		values map[string]string
		role   app.Role
	}{
		{name: "bad enablement", values: map[string]string{envRelayAuthorityEnabled: "yes"}, role: app.RoleControl},
		{name: "api role", values: base(nil), role: app.RoleAPI},
		{name: "missing key", values: map[string]string{envRelayAuthorityEnabled: "true"}, role: app.RoleControl},
		{name: "relative key", values: base(map[string]string{envRelaySigningKeyFile: "signing.key"}), role: app.RoleControl},
		{name: "next is current", values: base(map[string]string{envRelayNextSigningKey: current}), role: app.RoleControl},
		{name: "map without digest", values: base(map[string]string{envRelayMapFile: "/etc/meshtransit/relay-map.json"}), role: app.RoleControl},
		{name: "digest without map", values: base(map[string]string{envRelayMapSHA256: "sha256:" + strings.Repeat("1", 64)}), role: app.RoleControl},
		{name: "bad digest", values: base(map[string]string{
			envRelayMapFile: "/etc/meshtransit/relay-map.json", envRelayMapSHA256: strings.Repeat("1", 64),
		}), role: app.RoleControl},
		{name: "bad drain", values: base(map[string]string{envRelayDrain: "relay-a"}), role: app.RoleControl},
		{name: "unmasked proxy", values: base(map[string]string{envRelayTrustedProxies: "10.0.0.1/8"}), role: app.RoleControl},
		{name: "empty drain entry", values: base(map[string]string{envRelayDrain: ""}), role: app.RoleControl},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := loadRelayAuthorityConfig(mapLookup(test.values), test.role); !errors.Is(err, ErrInvalid) {
				t.Fatalf("loadRelayAuthorityConfig() error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestRelayAuthorityConfigRejectsDuplicateNextKeyMaterial(t *testing.T) {
	t.Parallel()

	cfg, err := loadRelayAuthorityConfig(mapLookup(map[string]string{
		envRelayAuthorityEnabled: "true",
		envRelaySigningKeyFile:   writeSigningSeed(t, 0x31),
		envRelayNextSigningKey:   writeSigningSeed(t, 0x31),
	}), app.RoleControl)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := cfg.SigningKeys(t.Context()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("SigningKeys() error = %v, want ErrInvalid", err)
	}
}
