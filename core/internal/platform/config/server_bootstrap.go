package config

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Settings of "meshcore install bootstrap postgres" (V1-11 step 2): the
// database administrator, the logins with their password files, and the
// databases. Read only by that command.
const (
	envBootstrapPostgreSQLAddress      = "MESHTRANSIT_BOOTSTRAP_POSTGRES_ADDRESS"
	envBootstrapMaintenanceDatabase    = "MESHTRANSIT_BOOTSTRAP_POSTGRES_MAINTENANCE_DATABASE"
	envBootstrapPostgreSQLUser         = "MESHTRANSIT_BOOTSTRAP_POSTGRES_USER"
	envBootstrapPostgreSQLPasswordFile = "MESHTRANSIT_BOOTSTRAP_POSTGRES_PASSWORD_FILE"
	envBootstrapPostgreSQLCAFile       = "MESHTRANSIT_BOOTSTRAP_POSTGRES_CA_FILE"
	envBootstrapConnectTimeout         = "MESHTRANSIT_BOOTSTRAP_CONNECT_TIMEOUT"
	envBootstrapStatementTimeout       = "MESHTRANSIT_BOOTSTRAP_STATEMENT_TIMEOUT"
	envBootstrapCoreDatabase           = "MESHTRANSIT_BOOTSTRAP_CORE_DATABASE"
	envBootstrapIdentityDatabase       = "MESHTRANSIT_BOOTSTRAP_IDENTITY_DATABASE"
	envBootstrapMarker                 = "MESHTRANSIT_BOOTSTRAP_MARKER"
	envBootstrapLoginPasswordFiles     = "MESHTRANSIT_BOOTSTRAP_LOGIN_PASSWORD_FILES"
	envBootstrapRotateLogins           = "MESHTRANSIT_BOOTSTRAP_ROTATE_LOGINS"
	maxBootstrapLogins                 = 10
)

var bootstrapMarker = regexp.MustCompile(`^meshtransit:[A-Za-z0-9._-]{1,64}$`)

// ServerBootstrapConfig is what the database bootstrap needs.
type ServerBootstrapConfig struct {
	Address             string
	MaintenanceDatabase string
	Admin               string
	AdminPasswordFile   SecretFile
	CAFile              TrustFile
	ConnectTimeout      time.Duration
	StatementTimeout    time.Duration
	CoreDatabase        string
	// IdentityDatabase is empty when the identity broker is not used.
	IdentityDatabase string
	Marker           string
	// LoginPasswordFiles maps a login to its password file; mesh_migrator
	// is required.
	LoginPasswordFiles map[string]SecretFile
	RotateLogins       bool
}

// LoadServerBootstrap reads and checks the bootstrap's settings.
func LoadServerBootstrap(lookup LookupFunc) (ServerBootstrapConfig, error) {
	if lookup == nil {
		return ServerBootstrapConfig{}, fmt.Errorf("%w: environment lookup is required", ErrInvalid)
	}
	address, err := requiredValue(lookup, envBootstrapPostgreSQLAddress, validateDependencyAddress)
	if err != nil {
		return ServerBootstrapConfig{}, err
	}
	user, err := requiredValue(lookup, envBootstrapPostgreSQLUser, validatePostgreSQLName)
	if err != nil {
		return ServerBootstrapConfig{}, err
	}
	passwordFile, err := requiredFile(lookup, envBootstrapPostgreSQLPasswordFile)
	if err != nil {
		return ServerBootstrapConfig{}, err
	}
	caFile, err := requiredFile(lookup, envBootstrapPostgreSQLCAFile)
	if err != nil {
		return ServerBootstrapConfig{}, err
	}
	maintenance := valueOrDefault(lookup, envBootstrapMaintenanceDatabase, "postgres")
	core := valueOrDefault(lookup, envBootstrapCoreDatabase, "meshtransit")
	identity := valueOrDefault(lookup, envBootstrapIdentityDatabase, "")
	for setting, value := range map[string]string{envBootstrapMaintenanceDatabase: maintenance, envBootstrapCoreDatabase: core} {
		if validatePostgreSQLName(value) != nil {
			return ServerBootstrapConfig{}, settingError(setting)
		}
	}
	if identity != "" && (validatePostgreSQLName(identity) != nil || identity == core) {
		return ServerBootstrapConfig{}, settingError(envBootstrapIdentityDatabase)
	}
	marker, err := requiredValue(lookup, envBootstrapMarker, func(value string) error {
		if !bootstrapMarker.MatchString(value) {
			return ErrInvalid
		}
		return nil
	})
	if err != nil {
		return ServerBootstrapConfig{}, err
	}
	connectTimeout, err := parseDurationInRange(
		valueOrDefault(lookup, envBootstrapConnectTimeout, defaultMigrationConnectTimeout.String()),
		minMigrationConnectionTimeout, maxMigrationConnectionTimeout)
	if err != nil {
		return ServerBootstrapConfig{}, settingError(envBootstrapConnectTimeout)
	}
	statementTimeout, err := parseDurationInRange(
		valueOrDefault(lookup, envBootstrapStatementTimeout, defaultMigrationStatementTimeout.String()),
		minMigrationStatementTimeout, maxMigrationStatementTimeout)
	if err != nil {
		return ServerBootstrapConfig{}, settingError(envBootstrapStatementTimeout)
	}
	logins, err := loadBootstrapLoginPasswordFiles(lookup)
	if err != nil {
		return ServerBootstrapConfig{}, err
	}
	if _, ok := logins["mesh_migrator"]; !ok {
		return ServerBootstrapConfig{}, settingError(envBootstrapLoginPasswordFiles)
	}
	for _, login := range []string{"identity_migrator", "identity_runtime"} {
		// Both with an identity database, neither without one.
		if _, ok := logins[login]; ok != (identity != "") {
			return ServerBootstrapConfig{}, settingError(envBootstrapLoginPasswordFiles)
		}
	}
	rotate, present := lookup(envBootstrapRotateLogins)
	if present && rotate != "true" && rotate != "false" {
		return ServerBootstrapConfig{}, settingError(envBootstrapRotateLogins)
	}
	return ServerBootstrapConfig{
		Address: address, MaintenanceDatabase: maintenance, Admin: user,
		AdminPasswordFile: SecretFile{path: passwordFile}, CAFile: TrustFile{path: caFile},
		ConnectTimeout: connectTimeout, StatementTimeout: statementTimeout,
		CoreDatabase: core, IdentityDatabase: identity, Marker: marker,
		LoginPasswordFiles: logins, RotateLogins: rotate == "true",
	}, nil
}

func loadBootstrapLoginPasswordFiles(lookup LookupFunc) (map[string]SecretFile, error) {
	value, present := lookup(envBootstrapLoginPasswordFiles)
	if !present || value == "" {
		return nil, settingError(envBootstrapLoginPasswordFiles)
	}
	pairs := strings.Split(value, ",")
	if len(pairs) > maxBootstrapLogins {
		return nil, settingError(envBootstrapLoginPasswordFiles)
	}
	files := map[string]SecretFile{}
	for _, pair := range pairs {
		name, path, found := strings.Cut(strings.TrimSpace(pair), "=")
		if !found || !operatorLoginName.MatchString(name) {
			return nil, settingError(envBootstrapLoginPasswordFiles)
		}
		if _, duplicate := files[name]; duplicate {
			return nil, settingError(envBootstrapLoginPasswordFiles)
		}
		file, err := NewSecretFile(path)
		if err != nil {
			return nil, settingError(envBootstrapLoginPasswordFiles)
		}
		files[name] = file
	}
	return files, nil
}

// validatePostgreSQLName accepts the names the bootstrap writes unquoted-safe:
// lower case, digits and underscores, as PostgreSQL folds them.
func validatePostgreSQLName(value string) error {
	if !operatorLoginName.MatchString(value) {
		return ErrInvalid
	}
	return nil
}
