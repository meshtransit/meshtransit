package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLoadAuthExpiryIsExplicitAndWorkerOnly(t *testing.T) {
	t.Parallel()
	for _, role := range []string{"all", "worker", "api", "control", "relay"} {
		t.Run(role, func(t *testing.T) {
			t.Parallel()
			values := validProcessValues(map[string]string{envRole: role})
			loaded, err := Load(mapLookup(values))
			if err != nil || loaded.AuthExpiry != nil {
				t.Fatal("expiry enabled without explicit opt-in", err)
			}
			values["MESHTRANSIT_AUTH_EXPIRY_ENABLED"] = "true"
			values["MESHTRANSIT_AUTH_EXPIRY_DEPLOYMENT_PUBLIC_ID"] = "01958000-0000-7000-8000-000000000001"
			loaded, err = Load(mapLookup(values))
			if role != "all" && role != "worker" {
				if !errors.Is(err, ErrInvalid) {
					t.Fatal("non-worker enabled expiry")
				}
				return
			}
			if err != nil || loaded.AuthExpiry == nil || loaded.AuthExpiry.BatchSize != 8 ||
				loaded.AuthExpiry.PollInterval != time.Second || loaded.AuthExpiry.PassTimeout != 10*time.Second ||
				loaded.AuthExpiry.UnitTimeout != time.Second || loaded.AuthExpiry.RollbackTimeout != time.Second {
				t.Fatal("expiry defaults/assignment not bounded", err)
			}
		})
	}
}

func TestLoadAuthExpiryRejectsUnsafeOrLatentSettingsWithoutEcho(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, key, value string }{
		{name: "invalid flag", key: "MESHTRANSIT_AUTH_EXPIRY_ENABLED", value: "TRUE"},
		{name: "empty flag", key: "MESHTRANSIT_AUTH_EXPIRY_ENABLED", value: ""},
		{name: "missing assignment", key: "MESHTRANSIT_AUTH_EXPIRY_DEPLOYMENT_PUBLIC_ID", value: ""},
		{name: "invalid assignment", key: "MESHTRANSIT_AUTH_EXPIRY_DEPLOYMENT_PUBLIC_ID", value: "private-invalid-scope"},
		{name: "zero batch", key: "MESHTRANSIT_AUTH_EXPIRY_BATCH_SIZE", value: "0"},
		{name: "long batch", key: "MESHTRANSIT_AUTH_EXPIRY_BATCH_SIZE", value: "129"},
		{name: "short poll", key: "MESHTRANSIT_AUTH_EXPIRY_POLL_INTERVAL", value: "99ms"},
		{name: "long poll", key: "MESHTRANSIT_AUTH_EXPIRY_POLL_INTERVAL", value: "61s"},
		{name: "long pass", key: "MESHTRANSIT_AUTH_EXPIRY_SWEEP_TIMEOUT", value: "31s"},
		{name: "short pass", key: "MESHTRANSIT_AUTH_EXPIRY_SWEEP_TIMEOUT", value: "99ms"},
		{name: "unit beyond pass", key: "MESHTRANSIT_AUTH_EXPIRY_UNIT_TIMEOUT", value: "11s"},
		{name: "long cleanup", key: "MESHTRANSIT_AUTH_EXPIRY_ROLLBACK_TIMEOUT", value: "6s"},
		{name: "insufficient shutdown", key: envShutdownTimeout, value: "3s"},
		{name: "disabled latent settings", key: "MESHTRANSIT_AUTH_EXPIRY_ENABLED", value: "false"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			values := validProcessValues(map[string]string{
				envRole:                           "worker",
				"MESHTRANSIT_AUTH_EXPIRY_ENABLED": "true",
				"MESHTRANSIT_AUTH_EXPIRY_DEPLOYMENT_PUBLIC_ID": "01958000-0000-7000-8000-000000000001",
				test.key: test.value,
			})
			_, err := Load(mapLookup(values))
			if !errors.Is(err, ErrInvalid) {
				t.Fatal("unsafe expiry configuration accepted")
			}
			if strings.Contains(err.Error(), "private-invalid-scope") ||
				strings.Contains(err.Error(), values["MESHTRANSIT_AUTH_EXPIRY_DEPLOYMENT_PUBLIC_ID"]) &&
					values["MESHTRANSIT_AUTH_EXPIRY_DEPLOYMENT_PUBLIC_ID"] != "" {
				t.Fatal("configuration value echoed")
			}
		})
	}
}
