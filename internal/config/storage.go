package config

import (
	"strconv"

	"github.com/meshtransit/meshtransit/internal/app"
)

const (
	envPostgreSQLAddress  = "MESHTRANSIT_POSTGRES_ADDRESS"
	envPostgreSQLDatabase = "MESHTRANSIT_POSTGRES_DATABASE"
	envPostgreSQLCAFile   = "MESHTRANSIT_POSTGRES_CA_FILE"

	envPostgreSQLRuntimeUser           = "MESHTRANSIT_POSTGRES_RUNTIME_USER"
	envPostgreSQLRuntimePasswordFile   = "MESHTRANSIT_POSTGRES_RUNTIME_PASSWORD_FILE"
	envPostgreSQLRuntimeMaxConnections = "MESHTRANSIT_POSTGRES_RUNTIME_MAX_CONNECTIONS"

	envPostgreSQLWorkerUser           = "MESHTRANSIT_POSTGRES_WORKER_USER"
	envPostgreSQLWorkerPasswordFile   = "MESHTRANSIT_POSTGRES_WORKER_PASSWORD_FILE"
	envPostgreSQLWorkerMaxConnections = "MESHTRANSIT_POSTGRES_WORKER_MAX_CONNECTIONS"

	envRedisAddress      = "MESHTRANSIT_REDIS_ADDRESS"
	envRedisUsername     = "MESHTRANSIT_REDIS_USERNAME"
	envRedisPasswordFile = "MESHTRANSIT_REDIS_PASSWORD_FILE"
	envRedisCAFile       = "MESHTRANSIT_REDIS_CA_FILE"
	envRedisPoolSize     = "MESHTRANSIT_REDIS_POOL_SIZE"

	defaultPostgreSQLMaxConnections = 10
	defaultRedisPoolSize            = 10
	minPoolSize                     = 1
	maxPoolSize                     = 50
)

// StorageConfig contains the validated durable and ephemeral dependency
// settings required by non-relay roles.
type StorageConfig struct {
	PostgreSQL PostgreSQLConfig
	Redis      RedisConfig
}

// PostgreSQLConfig contains validated connection metadata and file references.
type PostgreSQLConfig struct {
	Address  string
	Database string
	CAFile   TrustFile
	Runtime  *PostgreSQLRoleConfig
	Worker   *PostgreSQLRoleConfig
}

// PostgreSQLRoleConfig contains one least-privilege role credential and pool
// budget. Runtime and worker credentials are never interchangeable.
type PostgreSQLRoleConfig struct {
	User           string
	PasswordFile   SecretFile
	MaxConnections int32
}

// RedisConfig contains validated connection metadata and file references.
type RedisConfig struct {
	Address      string
	Username     string
	PasswordFile SecretFile
	CAFile       TrustFile
	PoolSize     int
}

func loadStorageConfig(lookup LookupFunc, role app.Role) (StorageConfig, error) {
	postgresAddress, err := requiredValue(lookup, envPostgreSQLAddress, validateDependencyAddress)
	if err != nil {
		return StorageConfig{}, err
	}
	postgresDatabase, err := requiredValue(lookup, envPostgreSQLDatabase, validateIdentifier)
	if err != nil {
		return StorageConfig{}, err
	}
	postgresCAFile, err := requiredFile(lookup, envPostgreSQLCAFile)
	if err != nil {
		return StorageConfig{}, err
	}

	var runtimeConfig *PostgreSQLRoleConfig
	if role == app.RoleAll || role == app.RoleAPI || role == app.RoleControl {
		loaded, loadErr := loadPostgreSQLRoleConfig(
			lookup,
			envPostgreSQLRuntimeUser,
			envPostgreSQLRuntimePasswordFile,
			envPostgreSQLRuntimeMaxConnections,
		)
		if loadErr != nil {
			return StorageConfig{}, loadErr
		}
		runtimeConfig = &loaded
	}
	var workerConfig *PostgreSQLRoleConfig
	if role == app.RoleAll || role == app.RoleWorker {
		loaded, loadErr := loadPostgreSQLRoleConfig(
			lookup,
			envPostgreSQLWorkerUser,
			envPostgreSQLWorkerPasswordFile,
			envPostgreSQLWorkerMaxConnections,
		)
		if loadErr != nil {
			return StorageConfig{}, loadErr
		}
		workerConfig = &loaded
	}

	redisAddress, err := requiredValue(lookup, envRedisAddress, validateDependencyAddress)
	if err != nil {
		return StorageConfig{}, err
	}
	redisUsername, err := requiredValue(lookup, envRedisUsername, validateIdentifier)
	if err != nil {
		return StorageConfig{}, err
	}
	redisPasswordFile, err := requiredFile(lookup, envRedisPasswordFile)
	if err != nil {
		return StorageConfig{}, err
	}
	redisCAFile, err := requiredFile(lookup, envRedisCAFile)
	if err != nil {
		return StorageConfig{}, err
	}
	redisPoolSize, err := parsePoolSize(valueOrDefault(lookup, envRedisPoolSize, strconv.Itoa(defaultRedisPoolSize)))
	if err != nil {
		return StorageConfig{}, settingError(envRedisPoolSize)
	}

	return StorageConfig{
		PostgreSQL: PostgreSQLConfig{
			Address:  postgresAddress,
			Database: postgresDatabase,
			CAFile:   TrustFile{path: postgresCAFile},
			Runtime:  runtimeConfig,
			Worker:   workerConfig,
		},
		Redis: RedisConfig{
			Address:      redisAddress,
			Username:     redisUsername,
			PasswordFile: SecretFile{path: redisPasswordFile},
			CAFile:       TrustFile{path: redisCAFile},
			PoolSize:     redisPoolSize,
		},
	}, nil
}

func loadPostgreSQLRoleConfig(
	lookup LookupFunc,
	userSetting string,
	passwordSetting string,
	maxConnectionsSetting string,
) (PostgreSQLRoleConfig, error) {
	user, err := requiredValue(lookup, userSetting, validateIdentifier)
	if err != nil {
		return PostgreSQLRoleConfig{}, err
	}
	passwordFile, err := requiredFile(lookup, passwordSetting)
	if err != nil {
		return PostgreSQLRoleConfig{}, err
	}
	maxConnections, err := parsePostgreSQLMaxConnections(
		valueOrDefault(lookup, maxConnectionsSetting, strconv.Itoa(defaultPostgreSQLMaxConnections)),
	)
	if err != nil {
		return PostgreSQLRoleConfig{}, settingError(maxConnectionsSetting)
	}
	return PostgreSQLRoleConfig{
		User:           user,
		PasswordFile:   SecretFile{path: passwordFile},
		MaxConnections: maxConnections,
	}, nil
}
