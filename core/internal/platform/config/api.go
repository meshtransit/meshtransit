package config

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/platform/idempotency"
	"meshtransit.net/core/internal/platform/ratelimit"
)

const (
	envAPIAddress                             = "MESHTRANSIT_API_ADDRESS"
	envAPITLSCertificateFile                  = "MESHTRANSIT_API_TLS_CERTIFICATE_FILE"
	envAPITLSPrivateKeyFile                   = "MESHTRANSIT_API_TLS_PRIVATE_KEY_FILE"
	envAPIAccountSessionDigestActiveKeyID     = "MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_ACTIVE_KEY_ID"
	envAPIAccountSessionDigestActiveKeyFile   = "MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_ACTIVE_KEY_FILE"
	envAPIAccountSessionDigestPreviousKeyID   = "MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_PREVIOUS_KEY_ID"
	envAPIAccountSessionDigestPreviousKeyFile = "MESHTRANSIT_API_ACCOUNT_SESSION_DIGEST_PREVIOUS_KEY_FILE"
	envAPIIdempotencyDigestKeyID              = "MESHTRANSIT_API_IDEMPOTENCY_DIGEST_KEY_ID"
	envAPIIdempotencyDigestKeyFile            = "MESHTRANSIT_API_IDEMPOTENCY_DIGEST_KEY_FILE"
	envAPIRateLimitDigestKeyID                = "MESHTRANSIT_API_RATE_LIMIT_DIGEST_KEY_ID"
	envAPIRateLimitDigestKeyFile              = "MESHTRANSIT_API_RATE_LIMIT_DIGEST_KEY_FILE"
	envAPITrustedProxyCIDRs                   = "MESHTRANSIT_API_TRUSTED_PROXY_CIDRS"
	envAPISourceRateLimitCapacity             = "MESHTRANSIT_API_SOURCE_RATE_LIMIT_CAPACITY"
	envAPISourceRateLimitRefillInterval       = "MESHTRANSIT_API_SOURCE_RATE_LIMIT_REFILL_INTERVAL"
	envAPISessionRateLimitCapacity            = "MESHTRANSIT_API_SESSION_RATE_LIMIT_CAPACITY"
	envAPISessionRateLimitRefillInterval      = "MESHTRANSIT_API_SESSION_RATE_LIMIT_REFILL_INTERVAL"
	envAPIRequestTimeout                      = "MESHTRANSIT_API_REQUEST_TIMEOUT"
	envAPIMaxConnections                      = "MESHTRANSIT_API_MAX_CONNECTIONS"
	envAPIMaxConcurrentRequests               = "MESHTRANSIT_API_MAX_CONCURRENT_REQUESTS"
	defaultAPIAddress                         = "0.0.0.0:8444"
	defaultAPIRequestTimeout                  = 10 * time.Second
	defaultAPIMaxConnections                  = 256
	defaultAPIMaxConcurrentRequests           = 128
	defaultAPISourceRateLimitCapacity         = 30
	defaultAPISourceRateLimitRefillInterval   = time.Second
	defaultAPISessionRateLimitCapacity        = 60
	defaultAPISessionRateLimitRefillInterval  = 500 * time.Millisecond
	minimumAPIRequestTimeout                  = 100 * time.Millisecond
	maximumAPIRequestTimeout                  = 30 * time.Second
	minimumAPIConnections                     = 1
	maximumAPIConnections                     = 4096
	minimumAPIRateLimitCapacity               = 1
	maximumAPIRateLimitCapacity               = 100_000
	minimumAPIRateLimitRefillInterval         = 10 * time.Millisecond
	maximumAPIRateLimitRefillInterval         = time.Hour
	maximumAPITrustedProxyPrefixes            = 16
)

// APIConfig contains the public management API listener and verifier contract.
type APIConfig struct {
	Address               string
	TLSCertificateFile    TrustFile
	TLSPrivateKeyFile     PrivateKeyFile
	AccountSessionDigest  AccountSessionDigestConfig
	IdempotencyDigest     IdempotencyDigestConfig
	RateLimitDigest       RateLimitDigestConfig
	TrustedProxyPrefixes  []netip.Prefix
	SourceRateLimit       ratelimit.Policy
	SessionRateLimit      ratelimit.Policy
	RequestTimeout        time.Duration
	MaxConnections        int
	MaxConcurrentRequests int
}

// AccountSessionDigestConfig defines an active key and bounded previous-key window.
type AccountSessionDigestConfig struct {
	Active   AccountSessionDigestKeyConfig
	Previous *AccountSessionDigestKeyConfig
}

// AccountSessionDigestKeyConfig references one versioned Account Session HMAC key.
type AccountSessionDigestKeyConfig struct {
	ID           accountsession.DigestKeyID
	MaterialFile SecretFile
}

// IdempotencyDigestConfig references the HMAC key used to destroy raw request keys.
type IdempotencyDigestConfig struct {
	ID           idempotency.DigestKeyID
	MaterialFile SecretFile
}

// RateLimitDigestConfig references the HMAC key used to pseudonymize counter subjects.
type RateLimitDigestConfig struct {
	ID           ratelimit.DigestKeyID
	MaterialFile SecretFile
}

func loadAPIConfig(lookup LookupFunc) (APIConfig, error) {
	address := valueOrDefault(lookup, envAPIAddress, defaultAPIAddress)
	if err := validateAddress(address); err != nil {
		return APIConfig{}, settingError(envAPIAddress)
	}
	certificatePath, err := requiredFile(lookup, envAPITLSCertificateFile)
	if err != nil {
		return APIConfig{}, err
	}
	privateKeyPath, err := requiredFile(lookup, envAPITLSPrivateKeyFile)
	if err != nil {
		return APIConfig{}, err
	}
	if certificatePath == privateKeyPath {
		return APIConfig{}, settingError(envAPITLSPrivateKeyFile)
	}

	active, err := loadAccountSessionDigestKey(
		lookup,
		envAPIAccountSessionDigestActiveKeyID,
		envAPIAccountSessionDigestActiveKeyFile,
	)
	if err != nil {
		return APIConfig{}, err
	}
	previous, err := loadPreviousAccountSessionDigestKey(lookup)
	if err != nil {
		return APIConfig{}, err
	}
	if previous != nil && previous.ID == active.ID {
		return APIConfig{}, settingError(envAPIAccountSessionDigestPreviousKeyID)
	}
	if previous != nil && previous.MaterialFile.path == active.MaterialFile.path {
		return APIConfig{}, settingError(envAPIAccountSessionDigestPreviousKeyFile)
	}

	idempotencyKeyIDValue, err := requiredValue(
		lookup,
		envAPIIdempotencyDigestKeyID,
		func(value string) error {
			_, keyErr := idempotency.NewDigestKeyID(value)
			return keyErr
		},
	)
	if err != nil {
		return APIConfig{}, err
	}
	idempotencyKeyID, err := idempotency.NewDigestKeyID(idempotencyKeyIDValue)
	if err != nil {
		return APIConfig{}, settingError(envAPIIdempotencyDigestKeyID)
	}
	idempotencyKeyPath, err := requiredFile(lookup, envAPIIdempotencyDigestKeyFile)
	if err != nil {
		return APIConfig{}, err
	}
	rateLimitDigest, err := loadRateLimitDigestConfig(lookup)
	if err != nil {
		return APIConfig{}, err
	}
	trustedProxyPrefixes, err := parseTrustedProxyPrefixes(
		valueOrDefault(lookup, envAPITrustedProxyCIDRs, ""),
	)
	if err != nil {
		return APIConfig{}, settingError(envAPITrustedProxyCIDRs)
	}
	sourceRateLimit, err := loadAPIRateLimitPolicy(
		lookup,
		envAPISourceRateLimitCapacity,
		envAPISourceRateLimitRefillInterval,
		defaultAPISourceRateLimitCapacity,
		defaultAPISourceRateLimitRefillInterval,
	)
	if err != nil {
		return APIConfig{}, err
	}
	sessionRateLimit, err := loadAPIRateLimitPolicy(
		lookup,
		envAPISessionRateLimitCapacity,
		envAPISessionRateLimitRefillInterval,
		defaultAPISessionRateLimitCapacity,
		defaultAPISessionRateLimitRefillInterval,
	)
	if err != nil {
		return APIConfig{}, err
	}

	requestTimeout, err := parseDurationInRange(
		valueOrDefault(lookup, envAPIRequestTimeout, defaultAPIRequestTimeout.String()),
		minimumAPIRequestTimeout,
		maximumAPIRequestTimeout,
	)
	if err != nil {
		return APIConfig{}, settingError(envAPIRequestTimeout)
	}
	maxConnections, err := parseIntInRange(
		valueOrDefault(lookup, envAPIMaxConnections, "256"),
		minimumAPIConnections,
		maximumAPIConnections,
	)
	if err != nil {
		return APIConfig{}, settingError(envAPIMaxConnections)
	}
	maxConcurrentRequests, err := parseIntInRange(
		valueOrDefault(lookup, envAPIMaxConcurrentRequests, "128"),
		minimumAPIConnections,
		maxConnections,
	)
	if err != nil {
		return APIConfig{}, settingError(envAPIMaxConcurrentRequests)
	}

	config := APIConfig{
		Address:              address,
		TLSCertificateFile:   TrustFile{path: certificatePath},
		TLSPrivateKeyFile:    PrivateKeyFile{path: privateKeyPath},
		AccountSessionDigest: AccountSessionDigestConfig{Active: active, Previous: previous},
		IdempotencyDigest: IdempotencyDigestConfig{
			ID: idempotencyKeyID, MaterialFile: SecretFile{path: idempotencyKeyPath},
		},
		RateLimitDigest:       rateLimitDigest,
		TrustedProxyPrefixes:  trustedProxyPrefixes,
		SourceRateLimit:       sourceRateLimit,
		SessionRateLimit:      sessionRateLimit,
		RequestTimeout:        requestTimeout,
		MaxConnections:        maxConnections,
		MaxConcurrentRequests: maxConcurrentRequests,
	}
	if err := validateAPISecretOwnership(config); err != nil {
		return APIConfig{}, err
	}
	return config, nil
}

func loadRateLimitDigestConfig(lookup LookupFunc) (RateLimitDigestConfig, error) {
	keyIDValue, err := requiredValue(lookup, envAPIRateLimitDigestKeyID, func(value string) error {
		_, keyErr := ratelimit.NewDigestKeyID(value)
		return keyErr
	})
	if err != nil {
		return RateLimitDigestConfig{}, err
	}
	keyID, err := ratelimit.NewDigestKeyID(keyIDValue)
	if err != nil {
		return RateLimitDigestConfig{}, settingError(envAPIRateLimitDigestKeyID)
	}
	keyPath, err := requiredFile(lookup, envAPIRateLimitDigestKeyFile)
	if err != nil {
		return RateLimitDigestConfig{}, err
	}
	return RateLimitDigestConfig{ID: keyID, MaterialFile: SecretFile{path: keyPath}}, nil
}

func loadAPIRateLimitPolicy(
	lookup LookupFunc,
	capacitySetting string,
	intervalSetting string,
	defaultCapacity int,
	defaultInterval time.Duration,
) (ratelimit.Policy, error) {
	capacity, err := parseIntInRange(
		valueOrDefault(lookup, capacitySetting, strconv.Itoa(defaultCapacity)),
		minimumAPIRateLimitCapacity,
		maximumAPIRateLimitCapacity,
	)
	if err != nil {
		return ratelimit.Policy{}, settingError(capacitySetting)
	}
	interval, err := parseDurationInRange(
		valueOrDefault(lookup, intervalSetting, defaultInterval.String()),
		minimumAPIRateLimitRefillInterval,
		maximumAPIRateLimitRefillInterval,
	)
	if err != nil {
		return ratelimit.Policy{}, settingError(intervalSetting)
	}
	policy, err := ratelimit.NewPolicy(capacity, interval)
	if err != nil {
		return ratelimit.Policy{}, settingError(intervalSetting)
	}
	return policy, nil
}

func parseTrustedProxyPrefixes(value string) ([]netip.Prefix, error) {
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	if len(parts) > maximumAPITrustedProxyPrefixes {
		return nil, errors.New("too many trusted proxy prefixes")
	}
	prefixes := make([]netip.Prefix, len(parts))
	seen := make(map[netip.Prefix]struct{}, len(parts))
	for index, part := range parts {
		if strings.TrimSpace(part) != part {
			return nil, errors.New("non-canonical trusted proxy prefix")
		}
		prefix, err := netip.ParsePrefix(part)
		if err != nil || prefix != prefix.Masked() {
			return nil, errors.New("invalid trusted proxy prefix")
		}
		if _, exists := seen[prefix]; exists {
			return nil, errors.New("duplicate trusted proxy prefix")
		}
		seen[prefix] = struct{}{}
		prefixes[index] = prefix
	}
	return prefixes, nil
}

func loadAccountSessionDigestKey(
	lookup LookupFunc,
	idSetting string,
	fileSetting string,
) (AccountSessionDigestKeyConfig, error) {
	idValue, err := requiredValue(lookup, idSetting, func(value string) error {
		_, keyErr := accountsession.NewDigestKeyID(value)
		return keyErr
	})
	if err != nil {
		return AccountSessionDigestKeyConfig{}, err
	}
	id, err := accountsession.NewDigestKeyID(idValue)
	if err != nil {
		return AccountSessionDigestKeyConfig{}, settingError(idSetting)
	}
	path, err := requiredFile(lookup, fileSetting)
	if err != nil {
		return AccountSessionDigestKeyConfig{}, err
	}
	return AccountSessionDigestKeyConfig{ID: id, MaterialFile: SecretFile{path: path}}, nil
}

func loadPreviousAccountSessionDigestKey(lookup LookupFunc) (*AccountSessionDigestKeyConfig, error) {
	_, hasID := lookup(envAPIAccountSessionDigestPreviousKeyID)
	_, hasFile := lookup(envAPIAccountSessionDigestPreviousKeyFile)
	if !hasID && !hasFile {
		return nil, nil
	}
	if !hasID {
		return nil, settingError(envAPIAccountSessionDigestPreviousKeyID)
	}
	if !hasFile {
		return nil, settingError(envAPIAccountSessionDigestPreviousKeyFile)
	}
	key, err := loadAccountSessionDigestKey(
		lookup,
		envAPIAccountSessionDigestPreviousKeyID,
		envAPIAccountSessionDigestPreviousKeyFile,
	)
	if err != nil {
		return nil, err
	}
	return &key, nil
}

func validateAPISecretOwnership(config APIConfig) error {
	paths := []struct {
		setting string
		path    string
	}{
		{setting: envAPITLSPrivateKeyFile, path: config.TLSPrivateKeyFile.path},
		{setting: envAPIAccountSessionDigestActiveKeyFile, path: config.AccountSessionDigest.Active.MaterialFile.path},
		{setting: envAPIIdempotencyDigestKeyFile, path: config.IdempotencyDigest.MaterialFile.path},
		{setting: envAPIRateLimitDigestKeyFile, path: config.RateLimitDigest.MaterialFile.path},
	}
	if config.AccountSessionDigest.Previous != nil {
		paths = append(paths, struct {
			setting string
			path    string
		}{setting: envAPIAccountSessionDigestPreviousKeyFile, path: config.AccountSessionDigest.Previous.MaterialFile.path})
	}
	seen := make(map[string]string, len(paths))
	for _, candidate := range paths {
		if _, exists := seen[candidate.path]; exists {
			return settingError(candidate.setting)
		}
		seen[candidate.path] = candidate.setting
	}
	return nil
}

func validateAPIExternalSecretOwnership(
	api APIConfig,
	control *ControlConfig,
	enrollment *EnrollmentConfig,
) error {
	apiSecrets := []struct {
		setting string
		path    string
	}{
		{setting: envAPIAccountSessionDigestActiveKeyFile, path: api.AccountSessionDigest.Active.MaterialFile.path},
		{setting: envAPIIdempotencyDigestKeyFile, path: api.IdempotencyDigest.MaterialFile.path},
		{setting: envAPIRateLimitDigestKeyFile, path: api.RateLimitDigest.MaterialFile.path},
	}
	if api.AccountSessionDigest.Previous != nil {
		apiSecrets = append(apiSecrets, struct {
			setting string
			path    string
		}{setting: envAPIAccountSessionDigestPreviousKeyFile, path: api.AccountSessionDigest.Previous.MaterialFile.path})
	}
	externalSecrets := make([]string, 0, 4)
	if control != nil {
		externalSecrets = append(externalSecrets, control.TLSPrivateKeyFile.path, control.NoisePrivateKeyFile.path)
		if control.NextNoisePrivateKeyFile != nil {
			externalSecrets = append(externalSecrets, control.NextNoisePrivateKeyFile.path)
		}
		if api.TLSPrivateKeyFile.path == control.NoisePrivateKeyFile.path {
			return settingError(envAPITLSPrivateKeyFile)
		}
	}
	if enrollment != nil {
		externalSecrets = append(externalSecrets, enrollment.CredentialDigest.Active.MaterialFile.path)
		if api.TLSPrivateKeyFile.path == enrollment.CredentialDigest.Active.MaterialFile.path {
			return settingError(envAPITLSPrivateKeyFile)
		}
		if enrollment.CredentialDigest.Previous != nil {
			externalSecrets = append(externalSecrets, enrollment.CredentialDigest.Previous.MaterialFile.path)
			if api.TLSPrivateKeyFile.path == enrollment.CredentialDigest.Previous.MaterialFile.path {
				return settingError(envAPITLSPrivateKeyFile)
			}
		}
	}
	for _, apiSecret := range apiSecrets {
		for _, externalSecret := range externalSecrets {
			if apiSecret.path == externalSecret {
				return settingError(apiSecret.setting)
			}
		}
	}
	return nil
}
