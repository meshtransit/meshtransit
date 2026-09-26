package config

import (
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/netip"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
	envIdentityIssuer                   = "MESHTRANSIT_IDENTITY_ISSUER"
	envIdentityConfigurationFingerprint = "MESHTRANSIT_IDENTITY_CONFIGURATION_FINGERPRINT"
	envIdentityAddress                  = "MESHTRANSIT_IDENTITY_ADDRESS"
	envIdentityTLSCertificateFile       = "MESHTRANSIT_IDENTITY_TLS_CERTIFICATE_FILE"
	envIdentityTLSPrivateKeyFile        = "MESHTRANSIT_IDENTITY_TLS_PRIVATE_KEY_FILE"
	envIdentityRequestTimeout           = "MESHTRANSIT_IDENTITY_REQUEST_TIMEOUT"
	envIdentityMaxConnections           = "MESHTRANSIT_IDENTITY_MAX_CONNECTIONS"
	envIdentityMaxConcurrentRequests    = "MESHTRANSIT_IDENTITY_MAX_CONCURRENT_REQUESTS"

	envIdentityOIDCConnectorID               = "MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_ID"
	envIdentityOIDCConnectorDisplayName      = "MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_DISPLAY_NAME"
	envIdentityOIDCConnectorGeneration       = "MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_GENERATION"
	envIdentityOIDCConnectorIssuer           = "MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_ISSUER"
	envIdentityOIDCConnectorClientID         = "MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_CLIENT_ID"
	envIdentityOIDCConnectorClientSecretFile = "MESHTRANSIT_IDENTITY_OIDC_CONNECTOR_CLIENT_SECRET_FILE" //nolint:gosec // G101: environment name, not a credential.

	envIdentityCoreClientID          = "MESHTRANSIT_IDENTITY_CORE_CLIENT_ID"
	envIdentityCoreClientDisplayName = "MESHTRANSIT_IDENTITY_CORE_CLIENT_DISPLAY_NAME"
	envIdentityCoreClientGeneration  = "MESHTRANSIT_IDENTITY_CORE_CLIENT_GENERATION"
	envIdentityCoreClientSecretFile  = "MESHTRANSIT_IDENTITY_CORE_CLIENT_SECRET_FILE" //nolint:gosec // G101: environment name, not a credential.
	envIdentityCoreClientRedirectURI = "MESHTRANSIT_IDENTITY_CORE_CLIENT_REDIRECT_URI"

	envIdentityPostgreSQLAddress             = "MESHTRANSIT_IDENTITY_POSTGRES_ADDRESS"
	envIdentityPostgreSQLDatabase            = "MESHTRANSIT_IDENTITY_POSTGRES_DATABASE"
	envIdentityPostgreSQLRuntimeUser         = "MESHTRANSIT_IDENTITY_POSTGRES_RUNTIME_USER"
	envIdentityPostgreSQLRuntimePasswordFile = "MESHTRANSIT_IDENTITY_POSTGRES_RUNTIME_PASSWORD_FILE" //nolint:gosec // G101: environment name, not a credential.
	envIdentityPostgreSQLCAFile              = "MESHTRANSIT_IDENTITY_POSTGRES_CA_FILE"
	envIdentityPostgreSQLMaxOpenConnections  = "MESHTRANSIT_IDENTITY_POSTGRES_MAX_OPEN_CONNECTIONS"
	envIdentityPostgreSQLMaxIdleConnections  = "MESHTRANSIT_IDENTITY_POSTGRES_MAX_IDLE_CONNECTIONS"
	envIdentityPostgreSQLConnectTimeout      = "MESHTRANSIT_IDENTITY_POSTGRES_CONNECT_TIMEOUT"
	envIdentityPostgreSQLConnectionLifetime  = "MESHTRANSIT_IDENTITY_POSTGRES_CONNECTION_LIFETIME"

	envIdentityIDTokenLifetime     = "MESHTRANSIT_IDENTITY_ID_TOKEN_LIFETIME" //nolint:gosec // G101: lifetime setting, not a token.
	envIdentityAuthRequestLifetime = "MESHTRANSIT_IDENTITY_AUTH_REQUEST_LIFETIME"
	envIdentitySigningKeyRotation  = "MESHTRANSIT_IDENTITY_SIGNING_KEY_ROTATION"
	envIdentityGarbageCollection   = "MESHTRANSIT_IDENTITY_GARBAGE_COLLECTION_INTERVAL"

	defaultIdentityPostgreSQLMaxOpenConnections = 10
	defaultIdentityPostgreSQLMaxIdleConnections = 5
	defaultIdentityPostgreSQLConnectTimeout     = time.Second
	defaultIdentityPostgreSQLConnectionLifetime = 30 * time.Minute

	defaultIdentityIDTokenLifetime     = 5 * time.Minute
	defaultIdentityAuthRequestLifetime = 5 * time.Minute
	defaultIdentitySigningKeyRotation  = 6 * time.Hour
	defaultIdentityGarbageCollection   = 5 * time.Minute
	defaultIdentityRequestTimeout      = 15 * time.Second
	defaultIdentityMaxConnections      = 256
	defaultIdentityMaxConcurrent       = 128
	minimumIdentityRequestTimeout      = time.Second
	maximumIdentityRequestTimeout      = 30 * time.Second
	maximumIdentityConnections         = 4096

	identityConfigurationFingerprintPrefix = "sha256-v2:"
	identityConfigurationFingerprintSize   = 32
	identityGoogleIssuer                   = "https://accounts.google.com"
)

// IdentityConfig contains the isolated broker runtime configuration. It has no
// Core database, Redis, migration credential, connector, client, or listener
// fallback.
type IdentityConfig struct {
	Issuer                    string
	Listener                  IdentityListenerConfig
	PostgreSQL                IdentityPostgreSQLConfig
	OIDCConnectors            []IdentityOIDCConnectorConfig
	Clients                   []IdentityClientConfig
	ExpectedFingerprint       IdentityConfigurationFingerprint
	IDTokenLifetime           time.Duration
	AuthRequestLifetime       time.Duration
	SigningKeyRotation        time.Duration
	GarbageCollectionInterval time.Duration
}

// IdentityListenerConfig contains the private, direct-TLS broker listener
// contract. Unspecified binds support container networking; DNS, public, and
// link-local addresses remain invalid.
type IdentityListenerConfig struct {
	Address               string
	TLSCertificateFile    TrustFile
	TLSPrivateKeyFile     PrivateKeyFile
	RequestTimeout        time.Duration
	MaxConnections        int
	MaxConcurrentRequests int
}

// IdentityOIDCConnectorConfig is one immutable generic-OIDC connector intent.
// Generation advances whenever trust-relevant identity mapping changes.
type IdentityOIDCConnectorConfig struct {
	ID               string
	DisplayName      string
	Generation       uint64
	Issuer           string
	ClientID         string
	ClientSecretFile SecretFile
}

// IdentityClientConfig is one immutable confidential broker client intent.
type IdentityClientConfig struct {
	ID          string
	DisplayName string
	Generation  uint64
	SecretFile  SecretFile
	RedirectURI string
}

// IdentityConfigurationFingerprint is the approved digest of immutable broker
// configuration and secret contents. Its formatting is always redacted.
type IdentityConfigurationFingerprint [identityConfigurationFingerprintSize]byte

// IdentityPostgreSQLConfig contains one DML-only runtime credential and its
// explicit per-replica pool budget. Migration credentials use a separate
// command contract and are never accepted here.
type IdentityPostgreSQLConfig struct {
	Address               string
	Database              string
	RuntimeUser           string
	RuntimePasswordFile   SecretFile
	CAFile                TrustFile
	MaxOpenConnections    int
	MaxIdleConnections    int
	ConnectTimeout        time.Duration
	MaxConnectionLifetime time.Duration
}

func loadIdentityConfig(
	lookup LookupFunc,
	checkTimeout time.Duration,
	requireFingerprint bool,
) (IdentityConfig, error) {
	issuer, err := requiredValue(lookup, envIdentityIssuer, validateIdentityIssuer)
	if err != nil {
		return IdentityConfig{}, err
	}
	connectorID, err := requiredValue(lookup, envIdentityOIDCConnectorID, validateIdentityObjectID)
	if err != nil {
		return IdentityConfig{}, err
	}
	connectorDisplayName, err := requiredValue(
		lookup,
		envIdentityOIDCConnectorDisplayName,
		validateIdentityDisplayName,
	)
	if err != nil {
		return IdentityConfig{}, err
	}
	connectorGeneration, err := requiredIdentityGeneration(lookup, envIdentityOIDCConnectorGeneration)
	if err != nil {
		return IdentityConfig{}, err
	}
	connectorIssuer, err := requiredValue(lookup, envIdentityOIDCConnectorIssuer, validateGoogleConnectorIssuer)
	if err != nil {
		return IdentityConfig{}, err
	}
	connectorClientID, err := requiredValue(lookup, envIdentityOIDCConnectorClientID, validateIdentityClientID)
	if err != nil {
		return IdentityConfig{}, err
	}
	connectorClientSecretFile, err := requiredFile(lookup, envIdentityOIDCConnectorClientSecretFile)
	if err != nil {
		return IdentityConfig{}, err
	}
	coreClientID, err := requiredValue(lookup, envIdentityCoreClientID, validateIdentityObjectID)
	if err != nil {
		return IdentityConfig{}, err
	}
	coreClientDisplayName, err := requiredValue(
		lookup,
		envIdentityCoreClientDisplayName,
		validateIdentityDisplayName,
	)
	if err != nil {
		return IdentityConfig{}, err
	}
	coreClientGeneration, err := requiredIdentityGeneration(lookup, envIdentityCoreClientGeneration)
	if err != nil {
		return IdentityConfig{}, err
	}
	coreClientSecretFile, err := requiredFile(lookup, envIdentityCoreClientSecretFile)
	if err != nil {
		return IdentityConfig{}, err
	}
	coreClientRedirectURI, err := requiredValue(
		lookup,
		envIdentityCoreClientRedirectURI,
		validateIdentityRedirectURI,
	)
	if err != nil {
		return IdentityConfig{}, err
	}
	expectedFingerprint, err := loadIdentityConfigurationFingerprint(lookup, requireFingerprint)
	if err != nil {
		return IdentityConfig{}, err
	}
	listener, err := loadIdentityListenerConfig(lookup)
	if err != nil {
		return IdentityConfig{}, err
	}
	address, err := requiredValue(lookup, envIdentityPostgreSQLAddress, validateDependencyAddress)
	if err != nil {
		return IdentityConfig{}, err
	}
	database, err := requiredValue(lookup, envIdentityPostgreSQLDatabase, validateIdentifier)
	if err != nil {
		return IdentityConfig{}, err
	}
	runtimeUser, err := requiredValue(lookup, envIdentityPostgreSQLRuntimeUser, validateIdentifier)
	if err != nil {
		return IdentityConfig{}, err
	}
	runtimePasswordFile, err := requiredFile(lookup, envIdentityPostgreSQLRuntimePasswordFile)
	if err != nil {
		return IdentityConfig{}, err
	}
	caFile, err := requiredFile(lookup, envIdentityPostgreSQLCAFile)
	if err != nil {
		return IdentityConfig{}, err
	}
	maxOpen, err := parsePoolSize(valueOrDefault(
		lookup,
		envIdentityPostgreSQLMaxOpenConnections,
		strconv.Itoa(defaultIdentityPostgreSQLMaxOpenConnections),
	))
	if err != nil {
		return IdentityConfig{}, settingError(envIdentityPostgreSQLMaxOpenConnections)
	}
	maxIdle, err := parsePoolSize(valueOrDefault(
		lookup,
		envIdentityPostgreSQLMaxIdleConnections,
		strconv.Itoa(defaultIdentityPostgreSQLMaxIdleConnections),
	))
	if err != nil || maxIdle > maxOpen {
		return IdentityConfig{}, settingError(envIdentityPostgreSQLMaxIdleConnections)
	}
	connectTimeout, err := parseWholeSecondDuration(
		valueOrDefault(
			lookup,
			envIdentityPostgreSQLConnectTimeout,
			defaultIdentityPostgreSQLConnectTimeout.String(),
		),
		time.Second,
		30*time.Second,
	)
	if err != nil || connectTimeout > checkTimeout {
		return IdentityConfig{}, settingError(envIdentityPostgreSQLConnectTimeout)
	}
	connectionLifetime, err := parseWholeSecondDuration(
		valueOrDefault(
			lookup,
			envIdentityPostgreSQLConnectionLifetime,
			defaultIdentityPostgreSQLConnectionLifetime.String(),
		),
		time.Minute,
		24*time.Hour,
	)
	if err != nil {
		return IdentityConfig{}, settingError(envIdentityPostgreSQLConnectionLifetime)
	}

	idTokenLifetime, err := parseDurationInRange(
		valueOrDefault(lookup, envIdentityIDTokenLifetime, defaultIdentityIDTokenLifetime.String()),
		time.Minute,
		time.Hour,
	)
	if err != nil {
		return IdentityConfig{}, settingError(envIdentityIDTokenLifetime)
	}
	authRequestLifetime, err := parseDurationInRange(
		valueOrDefault(lookup, envIdentityAuthRequestLifetime, defaultIdentityAuthRequestLifetime.String()),
		time.Minute,
		30*time.Minute,
	)
	if err != nil {
		return IdentityConfig{}, settingError(envIdentityAuthRequestLifetime)
	}
	signingKeyRotation, err := parseDurationInRange(
		valueOrDefault(lookup, envIdentitySigningKeyRotation, defaultIdentitySigningKeyRotation.String()),
		time.Hour,
		30*24*time.Hour,
	)
	if err != nil {
		return IdentityConfig{}, settingError(envIdentitySigningKeyRotation)
	}
	garbageCollection, err := parseDurationInRange(
		valueOrDefault(lookup, envIdentityGarbageCollection, defaultIdentityGarbageCollection.String()),
		time.Minute,
		time.Hour,
	)
	if err != nil {
		return IdentityConfig{}, settingError(envIdentityGarbageCollection)
	}

	result := IdentityConfig{
		Issuer:   issuer,
		Listener: listener,
		PostgreSQL: IdentityPostgreSQLConfig{
			Address: address, Database: database, RuntimeUser: runtimeUser,
			RuntimePasswordFile: SecretFile{path: runtimePasswordFile},
			CAFile:              TrustFile{path: caFile}, MaxOpenConnections: maxOpen,
			MaxIdleConnections: maxIdle, ConnectTimeout: connectTimeout,
			MaxConnectionLifetime: connectionLifetime,
		},
		OIDCConnectors: []IdentityOIDCConnectorConfig{{
			ID: connectorID, DisplayName: connectorDisplayName, Generation: connectorGeneration,
			Issuer: connectorIssuer, ClientID: connectorClientID,
			ClientSecretFile: SecretFile{path: connectorClientSecretFile},
		}},
		Clients: []IdentityClientConfig{{
			ID: coreClientID, DisplayName: coreClientDisplayName, Generation: coreClientGeneration,
			SecretFile: SecretFile{path: coreClientSecretFile}, RedirectURI: coreClientRedirectURI,
		}},
		ExpectedFingerprint: expectedFingerprint,
		IDTokenLifetime:     idTokenLifetime, AuthRequestLifetime: authRequestLifetime,
		SigningKeyRotation: signingKeyRotation, GarbageCollectionInterval: garbageCollection,
	}
	if err := validateIdentitySecretOwnership(result); err != nil {
		return IdentityConfig{}, err
	}
	return result, nil
}

func loadIdentityListenerConfig(lookup LookupFunc) (IdentityListenerConfig, error) {
	address, err := requiredValue(lookup, envIdentityAddress, validateIdentityListenerAddress)
	if err != nil {
		return IdentityListenerConfig{}, err
	}
	certificatePath, err := requiredFile(lookup, envIdentityTLSCertificateFile)
	if err != nil {
		return IdentityListenerConfig{}, err
	}
	privateKeyPath, err := requiredFile(lookup, envIdentityTLSPrivateKeyFile)
	if err != nil {
		return IdentityListenerConfig{}, err
	}
	if certificatePath == privateKeyPath {
		return IdentityListenerConfig{}, settingError(envIdentityTLSPrivateKeyFile)
	}
	requestTimeout, err := parseWholeSecondDuration(
		valueOrDefault(lookup, envIdentityRequestTimeout, defaultIdentityRequestTimeout.String()),
		minimumIdentityRequestTimeout,
		maximumIdentityRequestTimeout,
	)
	if err != nil {
		return IdentityListenerConfig{}, settingError(envIdentityRequestTimeout)
	}
	maxConnections, err := parseIntInRange(
		valueOrDefault(lookup, envIdentityMaxConnections, strconv.Itoa(defaultIdentityMaxConnections)),
		1,
		maximumIdentityConnections,
	)
	if err != nil {
		return IdentityListenerConfig{}, settingError(envIdentityMaxConnections)
	}
	maxConcurrentRequests, err := parseIntInRange(
		valueOrDefault(
			lookup,
			envIdentityMaxConcurrentRequests,
			strconv.Itoa(defaultIdentityMaxConcurrent),
		),
		1,
		maxConnections,
	)
	if err != nil {
		return IdentityListenerConfig{}, settingError(envIdentityMaxConcurrentRequests)
	}
	return IdentityListenerConfig{
		Address: address, TLSCertificateFile: TrustFile{path: certificatePath},
		TLSPrivateKeyFile: PrivateKeyFile{path: privateKeyPath}, RequestTimeout: requestTimeout,
		MaxConnections: maxConnections, MaxConcurrentRequests: maxConcurrentRequests,
	}, nil
}

func validateIdentityListenerAddress(value string) error {
	address, err := netip.ParseAddrPort(value)
	if err != nil || address.String() != value || address.Port() == 0 || address.Addr().Is4In6() ||
		address.Addr().Zone() != "" ||
		(!address.Addr().IsPrivate() && !address.Addr().IsLoopback() && !address.Addr().IsUnspecified()) {
		return ErrInvalid
	}
	return nil
}

func validateIdentitySecretOwnership(identity IdentityConfig) error {
	paths := []struct {
		setting string
		path    string
	}{
		{setting: envIdentityTLSPrivateKeyFile, path: identity.Listener.TLSPrivateKeyFile.path},
		{setting: envIdentityPostgreSQLRuntimePasswordFile, path: identity.PostgreSQL.RuntimePasswordFile.path},
	}
	for _, connector := range identity.OIDCConnectors {
		paths = append(paths, struct {
			setting string
			path    string
		}{setting: envIdentityOIDCConnectorClientSecretFile, path: connector.ClientSecretFile.path})
	}
	for _, client := range identity.Clients {
		paths = append(paths, struct {
			setting string
			path    string
		}{setting: envIdentityCoreClientSecretFile, path: client.SecretFile.path})
	}
	seen := make(map[string]struct{}, len(paths))
	for _, candidate := range paths {
		if _, exists := seen[candidate.path]; exists {
			return settingError(candidate.setting)
		}
		seen[candidate.path] = struct{}{}
	}
	return nil
}

// LoadIdentityFingerprintInput loads the identity-only configuration used to
// derive an approved fingerprint. It intentionally does not require the digest
// that is being calculated and performs no network or database I/O.
func LoadIdentityFingerprintInput(lookup LookupFunc) (IdentityConfig, error) {
	if lookup == nil {
		return IdentityConfig{}, ErrInvalid
	}
	dependencies, err := loadDependencyConfig(lookup)
	if err != nil {
		return IdentityConfig{}, err
	}
	return loadIdentityConfig(lookup, dependencies.CheckTimeout, false)
}

func requiredIdentityGeneration(lookup LookupFunc, setting string) (uint64, error) {
	value, err := requiredValue(lookup, setting, func(value string) error {
		generation, parseErr := strconv.ParseUint(value, 10, 63)
		if parseErr != nil || generation == 0 {
			return ErrInvalid
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	generation, _ := strconv.ParseUint(value, 10, 63)
	return generation, nil
}

func loadIdentityConfigurationFingerprint(
	lookup LookupFunc,
	required bool,
) (IdentityConfigurationFingerprint, error) {
	value, exists := lookup(envIdentityConfigurationFingerprint)
	if !exists && !required {
		return IdentityConfigurationFingerprint{}, nil
	}
	if !exists {
		return IdentityConfigurationFingerprint{}, settingError(envIdentityConfigurationFingerprint)
	}
	fingerprint, err := parseIdentityConfigurationFingerprint(value)
	if err != nil {
		return IdentityConfigurationFingerprint{}, settingError(envIdentityConfigurationFingerprint)
	}
	return fingerprint, nil
}

func parseIdentityConfigurationFingerprint(value string) (IdentityConfigurationFingerprint, error) {
	var fingerprint IdentityConfigurationFingerprint
	encoded, validPrefix := strings.CutPrefix(value, identityConfigurationFingerprintPrefix)
	if !validPrefix || len(encoded) != hex.EncodedLen(len(fingerprint)) || strings.ToLower(encoded) != encoded {
		return fingerprint, ErrInvalid
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		return fingerprint, ErrInvalid
	}
	copy(fingerprint[:], decoded)
	if fingerprint == (IdentityConfigurationFingerprint{}) {
		return IdentityConfigurationFingerprint{}, ErrInvalid
	}
	return fingerprint, nil
}

func validateIdentityObjectID(value string) error {
	if len(value) == 0 || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
		return ErrInvalid
	}
	for _, character := range value {
		isLower := character >= 'a' && character <= 'z'
		isDigit := character >= '0' && character <= '9'
		if !isLower && !isDigit && character != '-' && character != '_' && character != '.' {
			return ErrInvalid
		}
	}
	return nil
}

func validateIdentityDisplayName(value string) error {
	if len(value) == 0 || len(value) > 80 || strings.TrimSpace(value) != value {
		return ErrInvalid
	}
	for _, character := range value {
		if character < ' ' || character == 127 {
			return ErrInvalid
		}
	}
	return nil
}

func validateIdentityClientID(value string) error {
	if len(value) == 0 || len(value) > 256 || strings.TrimSpace(value) != value {
		return ErrInvalid
	}
	for _, character := range value {
		if character <= ' ' || character == 127 {
			return ErrInvalid
		}
	}
	return nil
}

func validateGoogleConnectorIssuer(value string) error {
	if value != identityGoogleIssuer {
		return ErrInvalid
	}
	return nil
}

func validateIdentityRedirectURI(value string) error {
	redirect, err := url.Parse(value)
	if err != nil || redirect.Scheme != "https" || redirect.Host == "" || redirect.Hostname() == "" {
		return ErrInvalid
	}
	if redirect.Opaque != "" || redirect.User != nil || redirect.RawQuery != "" ||
		redirect.Fragment != "" || redirect.RawPath != "" || redirect.Path == "" ||
		redirect.Path == "/" || strings.HasSuffix(redirect.Path, "/") {
		return ErrInvalid
	}
	if path.Clean(redirect.Path) != redirect.Path {
		return ErrInvalid
	}
	return nil
}

func parseWholeSecondDuration(value string, minimum, maximum time.Duration) (time.Duration, error) {
	duration, err := parseDurationInRange(value, minimum, maximum)
	if err != nil || duration%time.Second != 0 {
		return 0, ErrInvalid
	}
	return duration, nil
}

func validateIdentityIssuer(value string) error {
	issuer, err := url.Parse(value)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.Hostname() == "" {
		return ErrInvalid
	}
	if issuer.Opaque != "" || issuer.User != nil || issuer.RawQuery != "" ||
		issuer.Fragment != "" || issuer.RawPath != "" || issuer.Path == "/" ||
		strings.HasSuffix(issuer.Path, "/") {
		return ErrInvalid
	}
	if issuer.Path != "" && path.Clean(issuer.Path) != issuer.Path {
		return ErrInvalid
	}
	return nil
}

// String redacts all identity runtime metadata.
func (IdentityConfig) String() string { return redactedValue }

// GoString redacts detailed identity runtime formatting.
func (IdentityConfig) GoString() string { return redactedValue }

// LogValue redacts identity runtime metadata from structured logs.
func (IdentityConfig) LogValue() slog.Value { return slog.StringValue(redactedValue) }

// MarshalJSON refuses accidental publication of identity runtime metadata.
func (IdentityConfig) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// String redacts private listener topology and key references.
func (IdentityListenerConfig) String() string { return redactedValue }

// GoString redacts detailed private listener formatting.
func (IdentityListenerConfig) GoString() string { return redactedValue }

// LogValue redacts private listener metadata from structured logs.
func (IdentityListenerConfig) LogValue() slog.Value { return slog.StringValue(redactedValue) }

// MarshalJSON refuses accidental private listener publication.
func (IdentityListenerConfig) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// String redacts all broker database metadata.
func (IdentityPostgreSQLConfig) String() string { return redactedValue }

// GoString redacts detailed broker database formatting.
func (IdentityPostgreSQLConfig) GoString() string { return redactedValue }

// LogValue redacts broker database metadata from structured logs.
func (IdentityPostgreSQLConfig) LogValue() slog.Value { return slog.StringValue(redactedValue) }

// MarshalJSON refuses accidental publication of broker database metadata.
func (IdentityPostgreSQLConfig) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// String redacts connector metadata and secret references.
func (IdentityOIDCConnectorConfig) String() string { return redactedValue }

// GoString redacts detailed connector formatting.
func (IdentityOIDCConnectorConfig) GoString() string { return redactedValue }

// LogValue redacts connector metadata from structured logs.
func (IdentityOIDCConnectorConfig) LogValue() slog.Value { return slog.StringValue(redactedValue) }

// MarshalJSON refuses accidental connector publication.
func (IdentityOIDCConnectorConfig) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// String redacts confidential client metadata and secret references.
func (IdentityClientConfig) String() string { return redactedValue }

// GoString redacts detailed confidential client formatting.
func (IdentityClientConfig) GoString() string { return redactedValue }

// LogValue redacts confidential client metadata from structured logs.
func (IdentityClientConfig) LogValue() slog.Value { return slog.StringValue(redactedValue) }

// MarshalJSON refuses accidental client publication.
func (IdentityClientConfig) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

// String redacts the approved configuration fingerprint.
func (IdentityConfigurationFingerprint) String() string { return redactedValue }

// GoString redacts detailed fingerprint formatting.
func (IdentityConfigurationFingerprint) GoString() string { return redactedValue }

// LogValue redacts the fingerprint from structured logs.
func (IdentityConfigurationFingerprint) LogValue() slog.Value { return slog.StringValue(redactedValue) }

// MarshalJSON refuses accidental fingerprint publication.
func (IdentityConfigurationFingerprint) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }

var _ json.Marshaler = IdentityConfig{}
var _ json.Marshaler = IdentityListenerConfig{}
var _ json.Marshaler = IdentityPostgreSQLConfig{}
var _ json.Marshaler = IdentityOIDCConnectorConfig{}
var _ json.Marshaler = IdentityClientConfig{}
var _ json.Marshaler = IdentityConfigurationFingerprint{}
