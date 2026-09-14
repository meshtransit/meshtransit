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
		StatementTimeout:     defaultControlMapStatementTimeout,
		TransactionIdleLimit: defaultControlMapIdleLimit,
	}
	if got.Control.Map != want {
		t.Fatalf("Control.Map = %+v, want %+v", got.Control.Map, want)
	}
}

func TestLoadControlMapExplicitValues(t *testing.T) {
	t.Parallel()

	got, err := Load(mapLookup(validProcessValues(map[string]string{
		envRole:                           "control",
		envControlMapStatementTimeout:     "7s",
		envControlMapTransactionIdleLimit: "11s",
	})))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Control == nil || got.Control.Map != (ControlMapConfig{
		StatementTimeout:     7 * time.Second,
		TransactionIdleLimit: 11 * time.Second,
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
		{name: "zero statement timeout", setting: envControlMapStatementTimeout, value: "0s"},
		{name: "excess statement timeout", setting: envControlMapStatementTimeout, value: "61s"},
		{name: "zero idle limit", setting: envControlMapTransactionIdleLimit, value: "0s"},
		{name: "excess idle limit", setting: envControlMapTransactionIdleLimit, value: "61s"},
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
