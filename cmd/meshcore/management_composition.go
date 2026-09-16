package main

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/meshtransit/meshtransit/internal/adapter/httpapi"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/idempotency"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/node/revocation"
	policypublication "github.com/meshtransit/meshtransit/internal/policy/publication"
	"github.com/meshtransit/meshtransit/internal/ratelimit"
)

const (
	managementStatementTimeout = 5 * time.Second
	managementLockTimeout      = 2 * time.Second
	managementTransactionIdle  = 10 * time.Second
	managementRollbackTimeout  = 2 * time.Second
	managementIdempotencyTTL   = time.Hour
	managementRetryInitial     = 25 * time.Millisecond
	managementRetryMaximum     = 250 * time.Millisecond
)

var errInvalidManagementComposition = errors.New("invalid management API composition")

func composeManagementAPI(
	apiConfig config.APIConfig,
	runtimePool *postgresadapter.Pool,
	rateLimiter httpapi.ManagementRateLimiter,
	logger *slog.Logger,
) (*httpapi.ManagementServer, prometheus.Collector, error) {
	if runtimePool == nil || rateLimiter == nil || logger == nil {
		return nil, nil, errInvalidManagementComposition
	}
	certificate, err := loadManagementTLSCertificate(apiConfig)
	if err != nil {
		return nil, nil, err
	}
	keyring, err := composeAccountSessionKeyring(apiConfig.AccountSessionDigest)
	if err != nil {
		return nil, nil, err
	}
	idempotencyDigester, err := composeIdempotencyDigester(apiConfig.IdempotencyDigest)
	if err != nil {
		return nil, nil, err
	}
	rateLimitDigester, err := composeRateLimitDigester(apiConfig.RateLimitDigest)
	if err != nil {
		return nil, nil, err
	}
	accountSessionStore, err := postgresadapter.NewAccountSessionStore(
		runtimePool,
		postgresadapter.AccountSessionOptions{
			StatementTimeout: managementStatementTimeout,
			IdleTimeout:      managementTransactionIdle,
		},
	)
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	sessions, err := accountsession.NewService(keyring, accountSessionStore, accountsession.SystemClock{})
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	revocationStore, err := postgresadapter.NewDeviceRevocationStore(
		runtimePool,
		postgresadapter.DeviceRevocationOptions{
			StatementTimeout: managementStatementTimeout,
			LockTimeout:      managementLockTimeout,
			IdleTimeout:      managementTransactionIdle,
		},
	)
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	backoff, err := revocation.NewExponentialBackoff(managementRetryInitial, managementRetryMaximum)
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	revocations, err := revocation.NewService(
		revocation.Options{
			MaxAttempts: 3, RollbackTimeout: managementRollbackTimeout,
			IdempotencyTTL: managementIdempotencyTTL,
		},
		revocation.Dependencies{
			Transactions: revocationStore, CommittedResults: revocationStore,
			MutationIDs: revocation.PublicMutationIDGenerator{}, Clock: revocation.SystemClock{},
			Retry: backoff,
		},
	)
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	policyStore, err := postgresadapter.NewPolicyPublicationStore(
		runtimePool,
		postgresadapter.PolicyPublicationOptions{
			StatementTimeout: managementStatementTimeout,
			LockTimeout:      managementLockTimeout,
			IdleTimeout:      managementTransactionIdle,
		},
	)
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	policyBackoff, err := policypublication.NewExponentialBackoff(
		managementRetryInitial,
		managementRetryMaximum,
	)
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	policyPublications, err := policypublication.NewService(
		policypublication.Options{
			MaxAttempts: 3, RollbackTimeout: managementRollbackTimeout,
		},
		policypublication.Dependencies{
			Transactions: policyStore, CommittedResults: policyStore,
			MutationIDs: policypublication.PublicMutationIDGenerator{},
			Clock:       policypublication.SystemClock{}, Retry: policyBackoff,
		},
	)
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	handler, err := httpapi.NewManagementHandler(httpapi.ManagementHandlerOptions{
		Sessions: sessions, Revocations: revocations, PolicyPublications: policyPublications,
		Idempotency:       idempotencyDigester,
		RateLimitSubjects: rateLimitDigester, RateLimiter: rateLimiter,
		TrustedProxyPrefixes: apiConfig.TrustedProxyPrefixes,
		SourceRateLimit:      apiConfig.SourceRateLimit, SessionRateLimit: apiConfig.SessionRateLimit,
		CorrelationIDs: httpapi.PublicCorrelationIDGenerator{}, Logger: logger,
		RequestTimeout:        apiConfig.RequestTimeout,
		MaxConcurrentRequests: apiConfig.MaxConcurrentRequests,
	})
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	server, err := httpapi.NewManagementServer(httpapi.ManagementServerOptions{
		Address: apiConfig.Address, Certificate: certificate, Handler: handler,
		MaxConnections: apiConfig.MaxConnections,
	})
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	return server, handler.MetricsCollector(), nil
}

func composeRateLimitDigester(
	digestConfig config.RateLimitDigestConfig,
) (*ratelimit.Digester, error) {
	material, err := readManagementKeyMaterial(digestConfig.MaterialFile)
	if err != nil {
		return nil, errors.Join(errInvalidManagementComposition, errors.New("rate limit key rejected"))
	}
	defer clear(material)
	digester, err := ratelimit.NewDigester(digestConfig.ID, material)
	if err != nil {
		return nil, errors.Join(errInvalidManagementComposition, errors.New("rate limit key rejected"))
	}
	return digester, nil
}

func composeAccountSessionKeyring(
	digestConfig config.AccountSessionDigestConfig,
) (*accountsession.Keyring, error) {
	active, err := loadAccountSessionDigestKey(digestConfig.Active)
	if err != nil {
		return nil, errors.Join(errInvalidManagementComposition, errors.New("active session key rejected"))
	}
	if digestConfig.Previous == nil {
		keyring, keyringErr := accountsession.NewKeyring(active)
		if keyringErr != nil {
			return nil, errors.Join(errInvalidManagementComposition, keyringErr)
		}
		return keyring, nil
	}
	previous, err := loadAccountSessionDigestKey(*digestConfig.Previous)
	if err != nil {
		return nil, errors.Join(errInvalidManagementComposition, errors.New("previous session key rejected"))
	}
	keyring, err := accountsession.NewKeyring(active, previous)
	if err != nil {
		return nil, errors.Join(errInvalidManagementComposition, err)
	}
	return keyring, nil
}

func loadAccountSessionDigestKey(
	keyConfig config.AccountSessionDigestKeyConfig,
) (accountsession.DigestKey, error) {
	material, err := readManagementKeyMaterial(keyConfig.MaterialFile)
	if err != nil {
		return accountsession.DigestKey{}, err
	}
	defer clear(material)
	return accountsession.NewDigestKey(keyConfig.ID, material)
}

func composeIdempotencyDigester(
	digestConfig config.IdempotencyDigestConfig,
) (*idempotency.Digester, error) {
	material, err := readManagementKeyMaterial(digestConfig.MaterialFile)
	if err != nil {
		return nil, errors.Join(errInvalidManagementComposition, errors.New("idempotency key rejected"))
	}
	defer clear(material)
	digester, err := idempotency.NewDigester(digestConfig.ID, material)
	if err != nil {
		return nil, errors.Join(errInvalidManagementComposition, errors.New("idempotency key rejected"))
	}
	return digester, nil
}

func readManagementKeyMaterial(file config.SecretFile) ([]byte, error) {
	encoded, err := file.Read()
	if err != nil {
		return nil, errInvalidManagementComposition
	}
	material, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(material) != encoded {
		clear(material)
		return nil, errInvalidManagementComposition
	}
	return material, nil
}

func loadManagementTLSCertificate(apiConfig config.APIConfig) (tls.Certificate, error) {
	certificatePEM, err := apiConfig.TLSCertificateFile.Read()
	if err != nil {
		return tls.Certificate{}, errors.Join(errInvalidManagementComposition, errors.New("tls identity rejected"))
	}
	defer clear(certificatePEM)
	privateKeyPEM, err := apiConfig.TLSPrivateKeyFile.Read()
	if err != nil {
		return tls.Certificate{}, errors.Join(errInvalidManagementComposition, errors.New("tls identity rejected"))
	}
	defer clear(privateKeyPEM)
	certificate, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return tls.Certificate{}, errors.Join(errInvalidManagementComposition, errors.New("tls identity rejected"))
	}
	return certificate, nil
}
