package config

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// Settings of "meshcore redis acl apply" (role isolation design §6 and
// §10.3, TD-SEC-90 step S6). The command connects as a Redis administrator,
// which no serving role ever gets.
const (
	envRedisACLAdminUsername     = "MESHTRANSIT_REDIS_ADMIN_USERNAME"
	envRedisACLAdminPasswordFile = "MESHTRANSIT_REDIS_ADMIN_PASSWORD_FILE"
	// envRedisACLPasswordFiles lists role=path pairs, for example
	// "api=/run/a,control=/run/c": each named role's user is kept with the
	// password in its file.
	envRedisACLPasswordFiles = "MESHTRANSIT_REDIS_ACL_PASSWORD_FILES"
	// envRedisACLRotate allows replacing a user's stored password; without
	// it a differing password is refused, since running pods still use the
	// stored one.
	envRedisACLRotate         = "MESHTRANSIT_REDIS_ACL_ROTATE"
	envRedisACLRequestTimeout = "MESHTRANSIT_REDIS_ACL_REQUEST_TIMEOUT"

	defaultRedisACLRequestTimeout = 10 * time.Second
	minRedisACLRequestTimeout     = time.Second
	maxRedisACLRequestTimeout     = 2 * time.Minute
)

// redisACLRoles are the roles that may have a Redis user; the adapter owns
// what each may do.
var redisACLRoles = []string{"api", "control", "worker", "all"}

// RedisACLConfig is the configuration of "meshcore redis acl apply".
type RedisACLConfig struct {
	Address           string
	CAFile            TrustFile
	AdminUsername     string
	AdminPasswordFile SecretFile
	// PasswordFiles is keyed by role (api, control, worker, all).
	PasswordFiles  map[string]SecretFile
	Rotate         bool
	RequestTimeout time.Duration
}

// LoadRedisACL reads the settings of "meshcore redis acl apply". At least
// one role password is required: the command has nothing else to do.
func LoadRedisACL(lookup LookupFunc) (RedisACLConfig, error) {
	if lookup == nil {
		return RedisACLConfig{}, fmt.Errorf("%w: environment lookup is required", ErrInvalid)
	}
	address, err := requiredValue(lookup, envRedisAddress, validateDependencyAddress)
	if err != nil {
		return RedisACLConfig{}, err
	}
	caFile, err := requiredFile(lookup, envRedisCAFile)
	if err != nil {
		return RedisACLConfig{}, err
	}
	adminUsername, err := requiredValue(lookup, envRedisACLAdminUsername, validateIdentifier)
	if err != nil {
		return RedisACLConfig{}, err
	}
	adminPasswordFile, err := requiredFile(lookup, envRedisACLAdminPasswordFile)
	if err != nil {
		return RedisACLConfig{}, err
	}
	passwordFiles, err := loadRedisACLPasswordFiles(lookup, adminPasswordFile)
	if err != nil {
		return RedisACLConfig{}, err
	}
	rotate, present := lookup(envRedisACLRotate)
	if present && rotate != "true" && rotate != "false" {
		return RedisACLConfig{}, settingError(envRedisACLRotate)
	}
	requestTimeout, err := parseDurationInRange(
		valueOrDefault(lookup, envRedisACLRequestTimeout, defaultRedisACLRequestTimeout.String()),
		minRedisACLRequestTimeout, maxRedisACLRequestTimeout)
	if err != nil {
		return RedisACLConfig{}, settingError(envRedisACLRequestTimeout)
	}
	return RedisACLConfig{
		Address:           address,
		CAFile:            TrustFile{path: caFile},
		AdminUsername:     adminUsername,
		AdminPasswordFile: SecretFile{path: adminPasswordFile},
		PasswordFiles:     passwordFiles,
		Rotate:            rotate == "true",
		RequestTimeout:    requestTimeout,
	}, nil
}

func loadRedisACLPasswordFiles(lookup LookupFunc, adminPasswordFile string) (map[string]SecretFile, error) {
	value, present := lookup(envRedisACLPasswordFiles)
	if !present || value == "" {
		return nil, settingError(envRedisACLPasswordFiles)
	}
	pairs := strings.Split(value, ",")
	if len(pairs) > len(redisACLRoles) {
		return nil, settingError(envRedisACLPasswordFiles)
	}
	files := map[string]SecretFile{}
	paths := map[string]bool{adminPasswordFile: true}
	for _, pair := range pairs {
		role, path, found := strings.Cut(strings.TrimSpace(pair), "=")
		if !found || !slices.Contains(redisACLRoles, role) {
			return nil, settingError(envRedisACLPasswordFiles)
		}
		if _, duplicate := files[role]; duplicate {
			return nil, settingError(envRedisACLPasswordFiles)
		}
		file, err := NewSecretFile(path)
		if err != nil || paths[file.path] {
			// Two roles, or a role and the administrator, never share a
			// password file.
			return nil, settingError(envRedisACLPasswordFiles)
		}
		paths[file.path] = true
		files[role] = file
	}
	return files, nil
}
