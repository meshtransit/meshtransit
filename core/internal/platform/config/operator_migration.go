package config

import (
	"fmt"
	"regexp"
	"strings"
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
	// envOperatorLoginPasswordFiles lists login=file pairs, comma-separated:
	// the passwords of the operator logins the apply keeps (TD-SEC-90 S1).
	envOperatorLoginPasswordFiles = "MESHTRANSIT_OPERATOR_LOGIN_PASSWORD_FILES" //nolint:gosec // G101 false positive.
	maxOperatorLogins             = 8
	// envOperatorLoginRotate ("true"/"false") lets an apply replace a login
	// password that differs from the stored one.
	envOperatorLoginRotate = "MESHTRANSIT_OPERATOR_LOGIN_ROTATE"
)

// OperatorMigrationConfig contains the privileged database operator identity
// that runs the operator SQL steps. It is separate from the migrator and the
// serving roles, and never falls back to their settings.
type OperatorMigrationConfig struct {
	PostgreSQL       MigrationPostgreSQLConfig
	ConnectTimeout   time.Duration
	LockTimeout      time.Duration
	StatementTimeout time.Duration
	// LoginPasswordFiles holds, by login name, the file with that login's
	// password; empty when no login is kept.
	LoginPasswordFiles map[string]SecretFile
	// RotateLoginPasswords lets the apply replace a differing stored login
	// password.
	RotateLoginPasswords bool
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
	loginPasswordFiles, err := loadOperatorLoginPasswordFiles(lookup)
	if err != nil {
		return OperatorMigrationConfig{}, err
	}
	rotate, present := lookup(envOperatorLoginRotate)
	if present && rotate != "true" && rotate != "false" {
		return OperatorMigrationConfig{}, settingError(envOperatorLoginRotate)
	}
	return OperatorMigrationConfig{
		LoginPasswordFiles:   loginPasswordFiles,
		RotateLoginPasswords: rotate == "true",
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

// operatorLoginName is a lower-case PostgreSQL role name.
var operatorLoginName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// loadOperatorLoginPasswordFiles reads login=file pairs. A login appears at
// most once; names are identifiers and files absolute paths.
func loadOperatorLoginPasswordFiles(lookup LookupFunc) (map[string]SecretFile, error) {
	value, present := lookup(envOperatorLoginPasswordFiles)
	files := map[string]SecretFile{}
	if !present || value == "" {
		return files, nil
	}
	pairs := strings.Split(value, ",")
	if len(pairs) > maxOperatorLogins {
		return nil, settingError(envOperatorLoginPasswordFiles)
	}
	for _, pair := range pairs {
		name, path, found := strings.Cut(strings.TrimSpace(pair), "=")
		if !found || !operatorLoginName.MatchString(name) {
			return nil, settingError(envOperatorLoginPasswordFiles)
		}
		if _, duplicate := files[name]; duplicate {
			return nil, settingError(envOperatorLoginPasswordFiles)
		}
		file, err := NewSecretFile(path)
		if err != nil {
			return nil, settingError(envOperatorLoginPasswordFiles)
		}
		files[name] = file
	}
	return files, nil
}
