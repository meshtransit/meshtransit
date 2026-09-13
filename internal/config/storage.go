package config

import "strconv"

const (
	envPostgreSQLAddress        = "MESHTRANSIT_POSTGRES_ADDRESS"
	envPostgreSQLDatabase       = "MESHTRANSIT_POSTGRES_DATABASE"
	envPostgreSQLUser           = "MESHTRANSIT_POSTGRES_USER"
	envPostgreSQLPasswordFile   = "MESHTRANSIT_POSTGRES_PASSWORD_FILE"
	envPostgreSQLCAFile         = "MESHTRANSIT_POSTGRES_CA_FILE"
	envPostgreSQLMaxConnections = "MESHTRANSIT_POSTGRES_MAX_CONNECTIONS"

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
	Address        string
	Database       string
	User           string
	PasswordFile   SecretFile
	CAFile         TrustFile
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

func loadStorageConfig(lookup LookupFunc) (StorageConfig, error) {
	postgresAddress, err := requiredValue(lookup, envPostgreSQLAddress, validateDependencyAddress)
	if err != nil {
		return StorageConfig{}, err
	}
	postgresDatabase, err := requiredValue(lookup, envPostgreSQLDatabase, validateIdentifier)
	if err != nil {
		return StorageConfig{}, err
	}
	postgresUser, err := requiredValue(lookup, envPostgreSQLUser, validateIdentifier)
	if err != nil {
		return StorageConfig{}, err
	}
	postgresPasswordFile, err := requiredFile(lookup, envPostgreSQLPasswordFile)
	if err != nil {
		return StorageConfig{}, err
	}
	postgresCAFile, err := requiredFile(lookup, envPostgreSQLCAFile)
	if err != nil {
		return StorageConfig{}, err
	}
	postgresMaxConnections, err := parsePostgreSQLMaxConnections(
		valueOrDefault(lookup, envPostgreSQLMaxConnections, strconv.Itoa(defaultPostgreSQLMaxConnections)),
	)
	if err != nil {
		return StorageConfig{}, settingError(envPostgreSQLMaxConnections)
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
			Address:        postgresAddress,
			Database:       postgresDatabase,
			User:           postgresUser,
			PasswordFile:   SecretFile{path: postgresPasswordFile},
			CAFile:         TrustFile{path: postgresCAFile},
			MaxConnections: postgresMaxConnections,
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
