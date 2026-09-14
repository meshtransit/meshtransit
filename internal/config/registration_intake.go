package config

import (
	"strconv"
	"time"
)

const (
	envRegistrationIntakeMaxAttempts      = "MESHTRANSIT_REGISTRATION_INTAKE_MAX_ATTEMPTS"
	envRegistrationIntakeRollbackTimeout  = "MESHTRANSIT_REGISTRATION_INTAKE_ROLLBACK_TIMEOUT"
	envRegistrationIntakePendingTTL       = "MESHTRANSIT_REGISTRATION_INTAKE_PENDING_TTL"
	envRegistrationIntakeStatementTimeout = "MESHTRANSIT_REGISTRATION_INTAKE_STATEMENT_TIMEOUT"
	envRegistrationIntakeLockTimeout      = "MESHTRANSIT_REGISTRATION_INTAKE_LOCK_TIMEOUT"
	envRegistrationIntakeIdleTimeout      = "MESHTRANSIT_REGISTRATION_INTAKE_IDLE_TIMEOUT"
	envRegistrationIntakeRetryInitial     = "MESHTRANSIT_REGISTRATION_INTAKE_RETRY_INITIAL"
	envRegistrationIntakeRetryMaximum     = "MESHTRANSIT_REGISTRATION_INTAKE_RETRY_MAXIMUM"

	defaultRegistrationIntakeMaxAttempts      = 3
	defaultRegistrationIntakeRollbackTimeout  = time.Second
	defaultRegistrationIntakePendingTTL       = 10 * time.Minute
	defaultRegistrationIntakeStatementTimeout = 5 * time.Second
	defaultRegistrationIntakeLockTimeout      = time.Second
	defaultRegistrationIntakeIdleTimeout      = 10 * time.Second
	defaultRegistrationIntakeRetryInitial     = 10 * time.Millisecond
	defaultRegistrationIntakeRetryMaximum     = 250 * time.Millisecond

	minRegistrationIntakeTimeout = time.Millisecond
	maxRegistrationIntakeTimeout = time.Minute
	maxRegistrationLockTimeout   = 30 * time.Second
	maxRegistrationRollback      = 5 * time.Second
	minRegistrationPendingTTL    = time.Second
	maxRegistrationPendingTTL    = 24 * time.Hour
	maxRegistrationAttempts      = 5
)

// RegistrationIntakeConfig bounds authentication retries, durable intent
// lifetime, and every PostgreSQL wait owned by registration intake.
type RegistrationIntakeConfig struct {
	MaxAttempts     int
	RollbackTimeout time.Duration
	PendingTTL      time.Duration
	Database        RegistrationIntakeDatabaseConfig
	Retry           RegistrationIntakeRetryConfig
}

// RegistrationIntakeDatabaseConfig bounds waits inside one intake transaction.
type RegistrationIntakeDatabaseConfig struct {
	StatementTimeout time.Duration
	LockTimeout      time.Duration
	IdleTimeout      time.Duration
}

// RegistrationIntakeRetryConfig bounds exponential retry delay and jitter.
type RegistrationIntakeRetryConfig struct {
	Initial time.Duration
	Maximum time.Duration
}

type registrationIntakeDurationSetting struct {
	name     string
	fallback time.Duration
	minimum  time.Duration
	maximum  time.Duration
}

func loadRegistrationIntakeConfig(
	lookup LookupFunc,
	shutdownTimeout time.Duration,
) (RegistrationIntakeConfig, error) {
	maxAttempts, err := parseIntInRange(
		valueOrDefault(
			lookup,
			envRegistrationIntakeMaxAttempts,
			strconv.Itoa(defaultRegistrationIntakeMaxAttempts),
		),
		1,
		maxRegistrationAttempts,
	)
	if err != nil {
		return RegistrationIntakeConfig{}, settingError(envRegistrationIntakeMaxAttempts)
	}
	rollbackTimeout, err := registrationIntakeDuration(
		lookup,
		registrationIntakeDurationSetting{
			name:     envRegistrationIntakeRollbackTimeout,
			fallback: defaultRegistrationIntakeRollbackTimeout,
			minimum:  minRegistrationIntakeTimeout,
			maximum:  maxRegistrationRollback,
		},
	)
	if err != nil || rollbackTimeout > shutdownTimeout {
		return RegistrationIntakeConfig{}, settingError(envRegistrationIntakeRollbackTimeout)
	}
	pendingTTL, err := registrationIntakeDuration(
		lookup,
		registrationIntakeDurationSetting{
			name:     envRegistrationIntakePendingTTL,
			fallback: defaultRegistrationIntakePendingTTL,
			minimum:  minRegistrationPendingTTL,
			maximum:  maxRegistrationPendingTTL,
		},
	)
	if err != nil {
		return RegistrationIntakeConfig{}, settingError(envRegistrationIntakePendingTTL)
	}
	database, err := loadRegistrationIntakeDatabaseConfig(lookup)
	if err != nil {
		return RegistrationIntakeConfig{}, err
	}
	retry, err := loadRegistrationIntakeRetryConfig(lookup)
	if err != nil {
		return RegistrationIntakeConfig{}, err
	}

	return RegistrationIntakeConfig{
		MaxAttempts:     maxAttempts,
		RollbackTimeout: rollbackTimeout,
		PendingTTL:      pendingTTL,
		Database:        database,
		Retry:           retry,
	}, nil
}

func loadRegistrationIntakeDatabaseConfig(lookup LookupFunc) (RegistrationIntakeDatabaseConfig, error) {
	statementTimeout, err := registrationIntakeDuration(
		lookup,
		registrationIntakeDurationSetting{
			name:     envRegistrationIntakeStatementTimeout,
			fallback: defaultRegistrationIntakeStatementTimeout,
			minimum:  minRegistrationIntakeTimeout,
			maximum:  maxRegistrationIntakeTimeout,
		},
	)
	if err != nil {
		return RegistrationIntakeDatabaseConfig{}, settingError(envRegistrationIntakeStatementTimeout)
	}
	lockTimeout, err := registrationIntakeDuration(
		lookup,
		registrationIntakeDurationSetting{
			name:     envRegistrationIntakeLockTimeout,
			fallback: defaultRegistrationIntakeLockTimeout,
			minimum:  minRegistrationIntakeTimeout,
			maximum:  maxRegistrationLockTimeout,
		},
	)
	if err != nil || lockTimeout > statementTimeout {
		return RegistrationIntakeDatabaseConfig{}, settingError(envRegistrationIntakeLockTimeout)
	}
	idleTimeout, err := registrationIntakeDuration(
		lookup,
		registrationIntakeDurationSetting{
			name:     envRegistrationIntakeIdleTimeout,
			fallback: defaultRegistrationIntakeIdleTimeout,
			minimum:  minRegistrationIntakeTimeout,
			maximum:  maxRegistrationIntakeTimeout,
		},
	)
	if err != nil {
		return RegistrationIntakeDatabaseConfig{}, settingError(envRegistrationIntakeIdleTimeout)
	}
	return RegistrationIntakeDatabaseConfig{
		StatementTimeout: statementTimeout,
		LockTimeout:      lockTimeout,
		IdleTimeout:      idleTimeout,
	}, nil
}

func loadRegistrationIntakeRetryConfig(lookup LookupFunc) (RegistrationIntakeRetryConfig, error) {
	retryInitial, err := registrationIntakeDuration(
		lookup,
		registrationIntakeDurationSetting{
			name:     envRegistrationIntakeRetryInitial,
			fallback: defaultRegistrationIntakeRetryInitial,
			minimum:  minRegistrationIntakeTimeout,
			maximum:  maxRegistrationIntakeTimeout,
		},
	)
	if err != nil {
		return RegistrationIntakeRetryConfig{}, settingError(envRegistrationIntakeRetryInitial)
	}
	retryMaximum, err := registrationIntakeDuration(
		lookup,
		registrationIntakeDurationSetting{
			name:     envRegistrationIntakeRetryMaximum,
			fallback: defaultRegistrationIntakeRetryMaximum,
			minimum:  retryInitial,
			maximum:  maxRegistrationIntakeTimeout,
		},
	)
	if err != nil {
		return RegistrationIntakeRetryConfig{}, settingError(envRegistrationIntakeRetryMaximum)
	}
	return RegistrationIntakeRetryConfig{
		Initial: retryInitial,
		Maximum: retryMaximum,
	}, nil
}

func registrationIntakeDuration(
	lookup LookupFunc,
	setting registrationIntakeDurationSetting,
) (time.Duration, error) {
	return parseDurationInRange(
		valueOrDefault(lookup, setting.name, setting.fallback.String()),
		setting.minimum,
		setting.maximum,
	)
}
