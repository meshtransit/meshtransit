package config

import (
	"fmt"
	"time"
)

const (
	envMigrationPostgreSQLAddress  = "MESHTRANSIT_MIGRATION_POSTGRES_ADDRESS"
	envMigrationPostgreSQLDatabase = "MESHTRANSIT_MIGRATION_POSTGRES_DATABASE"
	envMigrationPostgreSQLUser     = "MESHTRANSIT_MIGRATION_POSTGRES_USER"
	// The value is an environment variable name, never credential material.
	envMigrationPostgreSQLPasswordFile = "MESHTRANSIT_MIGRATION_POSTGRES_PASSWORD_FILE" //nolint:gosec // G101 false positive.
	envMigrationPostgreSQLCAFile       = "MESHTRANSIT_MIGRATION_POSTGRES_CA_FILE"
	envMigrationActor                  = "MESHTRANSIT_MIGRATION_ACTOR"
	envMigrationConnectTimeout         = "MESHTRANSIT_MIGRATION_CONNECT_TIMEOUT"
	envMigrationLockTimeout            = "MESHTRANSIT_MIGRATION_LOCK_TIMEOUT"
	envMigrationStatementTimeout       = "MESHTRANSIT_MIGRATION_STATEMENT_TIMEOUT"

	defaultMigrationConnectTimeout   = 5 * time.Second
	defaultMigrationLockTimeout      = 5 * time.Second
	defaultMigrationStatementTimeout = 30 * time.Second
	minMigrationConnectionTimeout    = 100 * time.Millisecond
	maxMigrationConnectionTimeout    = 30 * time.Second
	minMigrationStatementTimeout     = time.Second
	maxMigrationStatementTimeout     = 10 * time.Minute
)

// MigrationConfig contains the separately supplied one-shot migration
// identity and bounded database-operation timeouts.
type MigrationConfig struct {
	PostgreSQL       MigrationPostgreSQLConfig
	Actor            string
	ConnectTimeout   time.Duration
	LockTimeout      time.Duration
	StatementTimeout time.Duration
}

// MigrationPostgreSQLConfig contains the direct migrator connection metadata
// and opaque file references. It is intentionally separate from runtime
// storage credentials.
type MigrationPostgreSQLConfig struct {
	Address      string
	Database     string
	User         string
	PasswordFile SecretFile
	CAFile       TrustFile
}

// LoadMigration reads only the configuration needed by an explicit one-shot
// migration command. It never falls back to serving-process credentials.
func LoadMigration(lookup LookupFunc) (MigrationConfig, error) {
	if lookup == nil {
		return MigrationConfig{}, fmt.Errorf("%w: environment lookup is required", ErrInvalid)
	}

	address, err := requiredValue(lookup, envMigrationPostgreSQLAddress, validateDependencyAddress)
	if err != nil {
		return MigrationConfig{}, err
	}
	database, err := requiredValue(lookup, envMigrationPostgreSQLDatabase, validateIdentifier)
	if err != nil {
		return MigrationConfig{}, err
	}
	user, err := requiredValue(lookup, envMigrationPostgreSQLUser, validateIdentifier)
	if err != nil {
		return MigrationConfig{}, err
	}
	passwordFile, err := requiredFile(lookup, envMigrationPostgreSQLPasswordFile)
	if err != nil {
		return MigrationConfig{}, err
	}
	caFile, err := requiredFile(lookup, envMigrationPostgreSQLCAFile)
	if err != nil {
		return MigrationConfig{}, err
	}
	actor, err := requiredValue(lookup, envMigrationActor, validateIdentifier)
	if err != nil {
		return MigrationConfig{}, err
	}
	connectTimeout, err := parseDurationInRange(
		valueOrDefault(lookup, envMigrationConnectTimeout, defaultMigrationConnectTimeout.String()),
		minMigrationConnectionTimeout,
		maxMigrationConnectionTimeout,
	)
	if err != nil {
		return MigrationConfig{}, settingError(envMigrationConnectTimeout)
	}
	lockTimeout, err := parseDurationInRange(
		valueOrDefault(lookup, envMigrationLockTimeout, defaultMigrationLockTimeout.String()),
		minMigrationConnectionTimeout,
		maxMigrationConnectionTimeout,
	)
	if err != nil {
		return MigrationConfig{}, settingError(envMigrationLockTimeout)
	}
	statementTimeout, err := parseDurationInRange(
		valueOrDefault(lookup, envMigrationStatementTimeout, defaultMigrationStatementTimeout.String()),
		minMigrationStatementTimeout,
		maxMigrationStatementTimeout,
	)
	if err != nil {
		return MigrationConfig{}, settingError(envMigrationStatementTimeout)
	}
	if lockTimeout >= statementTimeout {
		return MigrationConfig{}, settingError(envMigrationLockTimeout)
	}

	return MigrationConfig{
		PostgreSQL: MigrationPostgreSQLConfig{
			Address:      address,
			Database:     database,
			User:         user,
			PasswordFile: SecretFile{path: passwordFile},
			CAFile:       TrustFile{path: caFile},
		},
		Actor:            actor,
		ConnectTimeout:   connectTimeout,
		LockTimeout:      lockTimeout,
		StatementTimeout: statementTimeout,
	}, nil
}
