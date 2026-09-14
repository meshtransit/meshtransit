package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLoadRegistrationDefaults(t *testing.T) {
	t.Parallel()

	got, err := Load(mapLookup(validProcessValues(nil)))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Enrollment == nil {
		t.Fatal("Enrollment = nil for all role")
	}
	want := RegistrationConfig{
		MaxAttempts:           defaultRegistrationMaxAttempts,
		RollbackTimeout:       defaultRegistrationRollbackTimeout,
		PendingTTL:            defaultRegistrationPendingTTL,
		AddressCandidateLimit: defaultRegistrationAddressCandidateLimit,
		Database: RegistrationDatabaseConfig{
			StatementTimeout: defaultRegistrationStatementTimeout,
			LockTimeout:      defaultRegistrationLockTimeout,
			IdleTimeout:      defaultRegistrationIdleTimeout,
		},
		Retry: RegistrationRetryConfig{
			Initial: defaultRegistrationRetryInitial,
			Maximum: defaultRegistrationRetryMaximum,
		},
	}
	if got.Enrollment.Registration != want {
		t.Fatalf("registration config = %+v, want %+v", got.Enrollment.Registration, want)
	}
}

func TestLoadRegistrationExplicitValues(t *testing.T) {
	t.Parallel()

	got, err := Load(mapLookup(validProcessValues(map[string]string{
		envShutdownTimeout:                   "3s",
		envRegistrationMaxAttempts:           "4",
		envRegistrationRollbackTimeout:       "2s",
		envRegistrationPendingTTL:            "30m",
		envRegistrationAddressCandidateLimit: "512",
		envRegistrationStatementTimeout:      "7s",
		envRegistrationLockTimeout:           "2s",
		envRegistrationIdleTimeout:           "12s",
		envRegistrationRetryInitial:          "20ms",
		envRegistrationRetryMaximum:          "400ms",
	})))
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	want := RegistrationConfig{
		MaxAttempts:           4,
		RollbackTimeout:       2 * time.Second,
		PendingTTL:            30 * time.Minute,
		AddressCandidateLimit: 512,
		Database: RegistrationDatabaseConfig{
			StatementTimeout: 7 * time.Second,
			LockTimeout:      2 * time.Second,
			IdleTimeout:      12 * time.Second,
		},
		Retry: RegistrationRetryConfig{
			Initial: 20 * time.Millisecond,
			Maximum: 400 * time.Millisecond,
		},
	}
	if got.Enrollment == nil || got.Enrollment.Registration != want {
		t.Fatalf("registration config = %+v, want %+v", got.Enrollment, want)
	}
}

func TestLoadRegistrationRejectsUnsafeBoundsWithoutEchoingValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		setting    string
		value      string
		additional map[string]string
	}{
		{
			name:    "zero attempts",
			setting: envRegistrationMaxAttempts,
			value:   "0",
		},
		{
			name:    "too many attempts",
			setting: envRegistrationMaxAttempts,
			value:   "6",
		},
		{
			name:    "zero rollback",
			setting: envRegistrationRollbackTimeout,
			value:   "0s",
		},
		{
			name:    "long rollback",
			setting: envRegistrationRollbackTimeout,
			value:   "6s",
		},
		{
			name:       "rollback exceeds shutdown",
			setting:    envRegistrationRollbackTimeout,
			value:      "2s",
			additional: map[string]string{envShutdownTimeout: "1s"},
		},
		{
			name:    "short pending ttl",
			setting: envRegistrationPendingTTL,
			value:   "999ms",
		},
		{
			name:    "long pending ttl",
			setting: envRegistrationPendingTTL,
			value:   "25h",
		},
		{
			name:    "zero address candidates",
			setting: envRegistrationAddressCandidateLimit,
			value:   "0",
		},
		{
			name:    "too many address candidates",
			setting: envRegistrationAddressCandidateLimit,
			value:   "65537",
		},
		{
			name:    "zero statement timeout",
			setting: envRegistrationStatementTimeout,
			value:   "0s",
		},
		{
			name:    "long statement timeout",
			setting: envRegistrationStatementTimeout,
			value:   "61s",
		},
		{
			name:    "zero lock timeout",
			setting: envRegistrationLockTimeout,
			value:   "0s",
		},
		{
			name:    "lock exceeds statement",
			setting: envRegistrationLockTimeout,
			value:   "6s",
		},
		{
			name:    "zero idle timeout",
			setting: envRegistrationIdleTimeout,
			value:   "0s",
		},
		{
			name:    "long idle timeout",
			setting: envRegistrationIdleTimeout,
			value:   "61s",
		},
		{
			name:    "zero retry initial",
			setting: envRegistrationRetryInitial,
			value:   "0s",
		},
		{
			name:    "retry maximum below initial",
			setting: envRegistrationRetryMaximum,
			value:   "9ms",
		},
		{
			name:    "long retry maximum",
			setting: envRegistrationRetryMaximum,
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
