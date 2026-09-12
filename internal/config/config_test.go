package config

import (
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/app"
)

func TestLoadDefaults(t *testing.T) {
	t.Parallel()

	got, err := Load(mapLookup(nil))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	want := Config{
		Role:            app.RoleAll,
		HealthAddress:   defaultHealthAddress,
		ShutdownTimeout: defaultShutdownTimeout,
		LogLevel:        slog.LevelInfo,
	}
	if got != want {
		t.Fatalf("Load() = %#v, want %#v", got, want)
	}
}

func TestLoadExplicitValues(t *testing.T) {
	t.Parallel()

	values := map[string]string{
		envRole:            "worker",
		envHealthAddress:   "[::1]:9090",
		envShutdownTimeout: "45s",
		envLogLevel:        "debug",
	}
	got, err := Load(mapLookup(values))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	want := Config{
		Role:            app.RoleWorker,
		HealthAddress:   "[::1]:9090",
		ShutdownTimeout: 45 * time.Second,
		LogLevel:        slog.LevelDebug,
	}
	if got != want {
		t.Fatalf("Load() = %#v, want %#v", got, want)
	}
}

func TestLoadRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "empty explicit role", key: envRole, value: ""},
		{name: "unknown role", key: envRole, value: "scheduler"},
		{name: "role with whitespace", key: envRole, value: "api "},
		{name: "missing health port", key: envHealthAddress, value: "localhost"},
		{name: "zero health port", key: envHealthAddress, value: "localhost:0"},
		{name: "invalid health host", key: envHealthAddress, value: "bad host:8081"},
		{name: "empty timeout", key: envShutdownTimeout, value: ""},
		{name: "zero timeout", key: envShutdownTimeout, value: "0s"},
		{name: "negative timeout", key: envShutdownTimeout, value: "-1s"},
		{name: "unsafe short timeout", key: envShutdownTimeout, value: "999ms"},
		{name: "unbounded timeout", key: envShutdownTimeout, value: "6m"},
		{name: "unknown log level", key: envLogLevel, value: "trace"},
		{name: "uppercase log level", key: envLogLevel, value: "INFO"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := Load(mapLookup(map[string]string{test.key: test.value}))
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Load() error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestLoadRequiresLookup(t *testing.T) {
	t.Parallel()

	_, err := Load(nil)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("Load() error = %v, want ErrInvalid", err)
	}
}

func mapLookup(values map[string]string) LookupFunc {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}
