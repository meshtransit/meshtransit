package config

import (
	"strconv"
	"time"

	"meshtransit.net/core/internal/domain/ipam"
)

const (
	envRegistrationMaxAttempts           = "MESHTRANSIT_REGISTRATION_MAX_ATTEMPTS"
	envRegistrationRollbackTimeout       = "MESHTRANSIT_REGISTRATION_ROLLBACK_TIMEOUT"
	envRegistrationPendingTTL            = "MESHTRANSIT_REGISTRATION_PENDING_TTL"
	envRegistrationStatementTimeout      = "MESHTRANSIT_REGISTRATION_STATEMENT_TIMEOUT"
	envRegistrationLockTimeout           = "MESHTRANSIT_REGISTRATION_LOCK_TIMEOUT"
	envRegistrationIdleTimeout           = "MESHTRANSIT_REGISTRATION_IDLE_TIMEOUT"
	envRegistrationRetryInitial          = "MESHTRANSIT_REGISTRATION_RETRY_INITIAL"
	envRegistrationRetryMaximum          = "MESHTRANSIT_REGISTRATION_RETRY_MAXIMUM"
	envRegistrationAddressCandidateLimit = "MESHTRANSIT_REGISTRATION_ADDRESS_CANDIDATE_LIMIT"

	defaultRegistrationMaxAttempts           = 3
	defaultRegistrationRollbackTimeout       = time.Second
	defaultRegistrationPendingTTL            = 10 * time.Minute
	defaultRegistrationStatementTimeout      = 5 * time.Second
	defaultRegistrationLockTimeout           = time.Second
	defaultRegistrationIdleTimeout           = 10 * time.Second
	defaultRegistrationRetryInitial          = 10 * time.Millisecond
	defaultRegistrationRetryMaximum          = 250 * time.Millisecond
	defaultRegistrationAddressCandidateLimit = 256

	minRegistrationTimeout     = time.Millisecond
	maxRegistrationTimeout     = time.Minute
	maxRegistrationLockTimeout = 30 * time.Second
	maxRegistrationRollback    = 5 * time.Second
	minRegistrationPendingTTL  = time.Second
	maxRegistrationPendingTTL  = 24 * time.Hour
	maxRegistrationAttempts    = 5
)

// RegistrationConfig bounds authentication, durable intent, the authoritative
// mutation, and every PostgreSQL wait owned by credential registration.
type RegistrationConfig struct {
	MaxAttempts           int
	RollbackTimeout       time.Duration
	PendingTTL            time.Duration
	AddressCandidateLimit int
	Database              RegistrationDatabaseConfig
	Retry                 RegistrationRetryConfig
}

// RegistrationDatabaseConfig bounds waits inside each registration transaction.
type RegistrationDatabaseConfig struct {
	StatementTimeout time.Duration
	LockTimeout      time.Duration
	IdleTimeout      time.Duration
}

// RegistrationRetryConfig bounds exponential retry delay and jitter.
type RegistrationRetryConfig struct {
	Initial time.Duration
	Maximum time.Duration
}

type registrationDurationSetting struct {
	name     string
	fallback time.Duration
	minimum  time.Duration
	maximum  time.Duration
}

func loadRegistrationConfig(
	lookup LookupFunc,
	shutdownTimeout time.Duration,
) (RegistrationConfig, error) {
	maxAttempts, err := parseIntInRange(
		valueOrDefault(
			lookup,
			envRegistrationMaxAttempts,
			strconv.Itoa(defaultRegistrationMaxAttempts),
		),
		1,
		maxRegistrationAttempts,
	)
	if err != nil {
		return RegistrationConfig{}, settingError(envRegistrationMaxAttempts)
	}
	rollbackTimeout, err := registrationDuration(
		lookup,
		registrationDurationSetting{
			name:     envRegistrationRollbackTimeout,
			fallback: defaultRegistrationRollbackTimeout,
			minimum:  minRegistrationTimeout,
			maximum:  maxRegistrationRollback,
		},
	)
	if err != nil || rollbackTimeout > shutdownTimeout {
		return RegistrationConfig{}, settingError(envRegistrationRollbackTimeout)
	}
	pendingTTL, err := registrationDuration(
		lookup,
		registrationDurationSetting{
			name:     envRegistrationPendingTTL,
			fallback: defaultRegistrationPendingTTL,
			minimum:  minRegistrationPendingTTL,
			maximum:  maxRegistrationPendingTTL,
		},
	)
	if err != nil {
		return RegistrationConfig{}, settingError(envRegistrationPendingTTL)
	}
	addressCandidateLimit, err := parseIntInRange(
		valueOrDefault(
			lookup,
			envRegistrationAddressCandidateLimit,
			strconv.Itoa(defaultRegistrationAddressCandidateLimit),
		),
		1,
		ipam.MaxCandidateLimit,
	)
	if err != nil {
		return RegistrationConfig{}, settingError(envRegistrationAddressCandidateLimit)
	}
	database, err := loadRegistrationDatabaseConfig(lookup)
	if err != nil {
		return RegistrationConfig{}, err
	}
	retry, err := loadRegistrationRetryConfig(lookup)
	if err != nil {
		return RegistrationConfig{}, err
	}

	return RegistrationConfig{
		MaxAttempts:           maxAttempts,
		RollbackTimeout:       rollbackTimeout,
		PendingTTL:            pendingTTL,
		AddressCandidateLimit: addressCandidateLimit,
		Database:              database,
		Retry:                 retry,
	}, nil
}

func loadRegistrationDatabaseConfig(lookup LookupFunc) (RegistrationDatabaseConfig, error) {
	statementTimeout, err := registrationDuration(
		lookup,
		registrationDurationSetting{
			name:     envRegistrationStatementTimeout,
			fallback: defaultRegistrationStatementTimeout,
			minimum:  minRegistrationTimeout,
			maximum:  maxRegistrationTimeout,
		},
	)
	if err != nil {
		return RegistrationDatabaseConfig{}, settingError(envRegistrationStatementTimeout)
	}
	lockTimeout, err := registrationDuration(
		lookup,
		registrationDurationSetting{
			name:     envRegistrationLockTimeout,
			fallback: defaultRegistrationLockTimeout,
			minimum:  minRegistrationTimeout,
			maximum:  maxRegistrationLockTimeout,
		},
	)
	if err != nil || lockTimeout > statementTimeout {
		return RegistrationDatabaseConfig{}, settingError(envRegistrationLockTimeout)
	}
	idleTimeout, err := registrationDuration(
		lookup,
		registrationDurationSetting{
			name:     envRegistrationIdleTimeout,
			fallback: defaultRegistrationIdleTimeout,
			minimum:  minRegistrationTimeout,
			maximum:  maxRegistrationTimeout,
		},
	)
	if err != nil {
		return RegistrationDatabaseConfig{}, settingError(envRegistrationIdleTimeout)
	}
	return RegistrationDatabaseConfig{
		StatementTimeout: statementTimeout,
		LockTimeout:      lockTimeout,
		IdleTimeout:      idleTimeout,
	}, nil
}

func loadRegistrationRetryConfig(lookup LookupFunc) (RegistrationRetryConfig, error) {
	retryInitial, err := registrationDuration(
		lookup,
		registrationDurationSetting{
			name:     envRegistrationRetryInitial,
			fallback: defaultRegistrationRetryInitial,
			minimum:  minRegistrationTimeout,
			maximum:  maxRegistrationTimeout,
		},
	)
	if err != nil {
		return RegistrationRetryConfig{}, settingError(envRegistrationRetryInitial)
	}
	retryMaximum, err := registrationDuration(
		lookup,
		registrationDurationSetting{
			name:     envRegistrationRetryMaximum,
			fallback: defaultRegistrationRetryMaximum,
			minimum:  retryInitial,
			maximum:  maxRegistrationTimeout,
		},
	)
	if err != nil {
		return RegistrationRetryConfig{}, settingError(envRegistrationRetryMaximum)
	}
	return RegistrationRetryConfig{
		Initial: retryInitial,
		Maximum: retryMaximum,
	}, nil
}

func registrationDuration(
	lookup LookupFunc,
	setting registrationDurationSetting,
) (time.Duration, error) {
	return parseDurationInRange(
		valueOrDefault(lookup, setting.name, setting.fallback.String()),
		setting.minimum,
		setting.maximum,
	)
}
