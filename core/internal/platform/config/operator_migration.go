package config

import (
	"fmt"
	"time"
)

const (
	envOperatorPostgreSQLAddress  = "MESHTRANSIT_OPERATOR_POSTGRES_ADDRESS"
	envOperatorPostgreSQLDatabase = "MESHTRANSIT_OPERATOR_POSTGRES_DATABASE"
	envOperatorPostgreSQLUser     = "MESHTRANSIT_OPERATOR_POSTGRES_USER"
	// The value is an environment variable name, never credential material.
	envOperatorPostgreSQLPasswordFile = "MESHTRANSIT_OPERATOR_POSTGRES_PASSWORD_FILE" //nolint:gosec // G101 false positive.
	envOperatorPostgreSQLCAFile       = "MESHTRANSIT_OPERATOR_POSTGRES_CA_FILE"
	envOperatorConnectTimeout         = "MESHTRANSIT_OPERATOR_CONNECT_TIMEOUT"
	envOperatorLockTimeout            = "MESHTRANSIT_OPERATOR_LOCK_TIMEOUT"
	envOperatorStatementTimeout       = "MESHTRANSIT_OPERATOR_STATEMENT_TIMEOUT"
)

// OperatorMigrationConfig contains the privileged database operator identity
// that runs the operator SQL steps. It is separate from the migrator and the
// serving roles, and never falls back to their settings.
type OperatorMigrationConfig struct {
	PostgreSQL       MigrationPostgreSQLConfig
	ConnectTimeout   time.Duration
	LockTimeout      time.Duration
	StatementTimeout time.Duration
}

// LoadOperatorMigration reads only the MESHTRANSIT_OPERATOR_* settings of the
// explicit operator command.
func LoadOperatorMigration(lookup LookupFunc) (OperatorMigrationConfig, error) {
	if lookup == nil {
		return OperatorMigrationConfig{}, fmt.Errorf("%w: environment lookup is required", ErrInvalid)
	}
	address, err := requiredValue(lookup, envOperatorPostgreSQLAddress, validateDependencyAddress)
	if err != nil {
		return OperatorMigrationConfig{}, err
	}
	database, err := requiredValue(lookup, envOperatorPostgreSQLDatabase, validateIdentifier)
	if err != nil {
		return OperatorMigrationConfig{}, err
	}
	user, err := requiredValue(lookup, envOperatorPostgreSQLUser, validateIdentifier)
	if err != nil {
		return OperatorMigrationConfig{}, err
	}
	passwordFile, err := requiredFile(lookup, envOperatorPostgreSQLPasswordFile)
	if err != nil {
		return OperatorMigrationConfig{}, err
	}
	caFile, err := requiredFile(lookup, envOperatorPostgreSQLCAFile)
	if err != nil {
		return OperatorMigrationConfig{}, err
	}
	connectTimeout, err := parseDurationInRange(
		valueOrDefault(lookup, envOperatorConnectTimeout, defaultMigrationConnectTimeout.String()),
		minMigrationConnectionTimeout, maxMigrationConnectionTimeout)
	if err != nil {
		return OperatorMigrationConfig{}, settingError(envOperatorConnectTimeout)
	}
	lockTimeout, err := parseDurationInRange(
		valueOrDefault(lookup, envOperatorLockTimeout, defaultMigrationLockTimeout.String()),
		minMigrationConnectionTimeout, maxMigrationConnectionTimeout)
	if err != nil {
		return OperatorMigrationConfig{}, settingError(envOperatorLockTimeout)
	}
	statementTimeout, err := parseDurationInRange(
		valueOrDefault(lookup, envOperatorStatementTimeout, defaultMigrationStatementTimeout.String()),
		minMigrationStatementTimeout, maxMigrationStatementTimeout)
	if err != nil {
		return OperatorMigrationConfig{}, settingError(envOperatorStatementTimeout)
	}
	if lockTimeout >= statementTimeout {
		return OperatorMigrationConfig{}, settingError(envOperatorLockTimeout)
	}
	return OperatorMigrationConfig{
		PostgreSQL: MigrationPostgreSQLConfig{
			Address:      address,
			Database:     database,
			User:         user,
			PasswordFile: SecretFile{path: passwordFile},
			CAFile:       TrustFile{path: caFile},
		},
		ConnectTimeout:   connectTimeout,
		LockTimeout:      lockTimeout,
		StatementTimeout: statementTimeout,
	}, nil
}
