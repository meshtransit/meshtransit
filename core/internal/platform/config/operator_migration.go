package config

import (
	"fmt"
	"regexp"
	"strconv"
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
	// envOperatorConnectionLimits lists role=limit pairs, comma-separated:
	// the most connections PostgreSQL lets each serving login hold
	// (TD-CORE-139, V1-03); -1 removes the limit. A login not listed keeps
	// its limit.
	envOperatorConnectionLimits = "MESHTRANSIT_OPERATOR_CONNECTION_LIMITS"
	maxOperatorConnectionLimit  = 10000
)

// operatorConnectionLimitRoles are the serving logins a connection limit may
// name: the api, control, worker and self-host logins.
var operatorConnectionLimitRoles = map[string]bool{
	"mesh_runtime": true, "mesh_control": true, "mesh_worker": true, "mesh_all": true,
}

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
	// ConnectionLimits holds, by serving login, the most connections it may
	// hold; empty when the apply sets none.
	ConnectionLimits map[string]int
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
	connectionLimits, err := loadOperatorConnectionLimits(lookup)
	if err != nil {
		return OperatorMigrationConfig{}, err
	}
	return OperatorMigrationConfig{
		LoginPasswordFiles:   loginPasswordFiles,
		RotateLoginPasswords: rotate == "true",
		ConnectionLimits:     connectionLimits,
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

// loadOperatorConnectionLimits reads role=limit pairs: a serving login at
// most once, each limit between 1 and maxOperatorConnectionLimit, or -1 for
// none.
func loadOperatorConnectionLimits(lookup LookupFunc) (map[string]int, error) {
	value, present := lookup(envOperatorConnectionLimits)
	limits := map[string]int{}
	if !present || value == "" {
		return limits, nil
	}
	for _, pair := range strings.Split(value, ",") {
		name, text, found := strings.Cut(strings.TrimSpace(pair), "=")
		if !found || !operatorConnectionLimitRoles[name] {
			return nil, settingError(envOperatorConnectionLimits)
		}
		if _, duplicate := limits[name]; duplicate {
			return nil, settingError(envOperatorConnectionLimits)
		}
		limit, err := strconv.Atoi(text)
		if err != nil || (limit < 1 && limit != -1) || limit > maxOperatorConnectionLimit {
			return nil, settingError(envOperatorConnectionLimits)
		}
		limits[name] = limit
	}
	return limits, nil
}
