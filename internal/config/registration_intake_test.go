package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLoadRegistrationIntakeDefaults(t *testing.T) {
	t.Parallel()

	got, err := Load(mapLookup(validProcessValues(nil)))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Enrollment == nil {
		t.Fatal("Enrollment = nil for all role")
	}
	want := RegistrationIntakeConfig{
		MaxAttempts:     defaultRegistrationIntakeMaxAttempts,
		RollbackTimeout: defaultRegistrationIntakeRollbackTimeout,
		PendingTTL:      defaultRegistrationIntakePendingTTL,
		Database: RegistrationIntakeDatabaseConfig{
			StatementTimeout: defaultRegistrationIntakeStatementTimeout,
			LockTimeout:      defaultRegistrationIntakeLockTimeout,
			IdleTimeout:      defaultRegistrationIntakeIdleTimeout,
		},
		Retry: RegistrationIntakeRetryConfig{
			Initial: defaultRegistrationIntakeRetryInitial,
			Maximum: defaultRegistrationIntakeRetryMaximum,
		},
	}
	if got.Enrollment.RegistrationIntake != want {
		t.Fatalf("registration intake config = %+v, want %+v", got.Enrollment.RegistrationIntake, want)
	}
}

func TestLoadRegistrationIntakeExplicitValues(t *testing.T) {
	t.Parallel()

	got, err := Load(mapLookup(validProcessValues(map[string]string{
		envShutdownTimeout:                    "3s",
		envRegistrationIntakeMaxAttempts:      "4",
		envRegistrationIntakeRollbackTimeout:  "2s",
		envRegistrationIntakePendingTTL:       "30m",
		envRegistrationIntakeStatementTimeout: "7s",
		envRegistrationIntakeLockTimeout:      "2s",
		envRegistrationIntakeIdleTimeout:      "12s",
		envRegistrationIntakeRetryInitial:     "20ms",
		envRegistrationIntakeRetryMaximum:     "400ms",
	})))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := RegistrationIntakeConfig{
		MaxAttempts:     4,
		RollbackTimeout: 2 * time.Second,
		PendingTTL:      30 * time.Minute,
		Database: RegistrationIntakeDatabaseConfig{
			StatementTimeout: 7 * time.Second,
			LockTimeout:      2 * time.Second,
			IdleTimeout:      12 * time.Second,
		},
		Retry: RegistrationIntakeRetryConfig{
			Initial: 20 * time.Millisecond,
			Maximum: 400 * time.Millisecond,
		},
	}
	if got.Enrollment == nil || got.Enrollment.RegistrationIntake != want {
		t.Fatalf("registration intake config = %+v, want %+v", got.Enrollment, want)
	}
}

func TestLoadRegistrationIntakeRejectsUnsafeBoundsWithoutEchoingValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		setting    string
		value      string
		additional map[string]string
	}{
		{
			name:    "zero attempts",
			setting: envRegistrationIntakeMaxAttempts,
			value:   "0",
		},
		{
			name:    "too many attempts",
			setting: envRegistrationIntakeMaxAttempts,
			value:   "6",
		},
		{
			name:    "zero rollback",
			setting: envRegistrationIntakeRollbackTimeout,
			value:   "0s",
		},
		{
			name:    "long rollback",
			setting: envRegistrationIntakeRollbackTimeout,
			value:   "6s",
		},
		{
			name:       "rollback exceeds shutdown",
			setting:    envRegistrationIntakeRollbackTimeout,
			value:      "2s",
			additional: map[string]string{envShutdownTimeout: "1s"},
		},
		{
			name:    "short pending ttl",
			setting: envRegistrationIntakePendingTTL,
			value:   "999ms",
		},
		{
			name:    "long pending ttl",
			setting: envRegistrationIntakePendingTTL,
			value:   "25h",
		},
		{
			name:    "zero statement timeout",
			setting: envRegistrationIntakeStatementTimeout,
			value:   "0s",
		},
		{
			name:    "long statement timeout",
			setting: envRegistrationIntakeStatementTimeout,
			value:   "61s",
		},
		{
			name:    "zero lock timeout",
			setting: envRegistrationIntakeLockTimeout,
			value:   "0s",
		},
		{
			name:    "lock exceeds statement",
			setting: envRegistrationIntakeLockTimeout,
			value:   "6s",
		},
		{
			name:    "zero idle timeout",
			setting: envRegistrationIntakeIdleTimeout,
			value:   "0s",
		},
		{
			name:    "long idle timeout",
			setting: envRegistrationIntakeIdleTimeout,
			value:   "61s",
		},
		{
			name:    "zero retry initial",
			setting: envRegistrationIntakeRetryInitial,
			value:   "0s",
		},
		{
			name:    "retry maximum below initial",
			setting: envRegistrationIntakeRetryMaximum,
			value:   "9ms",
		},
		{
			name:    "long retry maximum",
			setting: envRegistrationIntakeRetryMaximum,
			value:   "61s",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			overrides := map[string]string{test.setting: test.value}
			for key, value := range test.additional {
				overrides[key] = value
			}
			_, err := Load(mapLookup(validProcessValues(overrides)))
			if !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), test.setting) {
				t.Fatalf("Load() error = %v, want ErrInvalid naming %s", err, test.setting)
			}
			if strings.Contains(err.Error(), test.value) {
				t.Fatalf("Load() error exposed rejected value %q: %v", test.value, err)
			}
		})
	}
}
