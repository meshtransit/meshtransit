package main

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"meshtransit.net/core/internal/adapter/httpapi"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/accessgraph"
	"meshtransit.net/core/internal/domain/accessgraph/simulation"
	"meshtransit.net/core/internal/domain/dnsname"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/node/revocation"
	policyapproval "meshtransit.net/core/internal/domain/policy/approval"
	"meshtransit.net/core/internal/domain/policy/compilation"
	policypublication "meshtransit.net/core/internal/domain/policy/publication"
	authority "meshtransit.net/core/internal/domain/resource/authority"
	"meshtransit.net/core/internal/domain/resource/catalog"
	"meshtransit.net/core/internal/domain/sharing"
	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/core/internal/platform/idempotency"
	"meshtransit.net/core/internal/platform/ratelimit"
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

// The simulator prepares the compiler (making Kubernetes cluster groups)
// before it reads the baseline; a wrapper must keep that.
var _ simulation.Preparer = (*compilation.Service)(nil)

type managementCompositionKeys struct {
	sessions    *accountsession.Keyring
	idempotency *idempotency.Digester
	rateLimit   *ratelimit.Digester
}

type managementCompositionOptions struct {
	API  config.APIConfig
	Keys managementCompositionKeys
	// DNSSuffix presents share names (MESHTRANSIT_DNS_SUFFIX); zero: the default.
	DNSSuffix dnsname.Suffix
	// EnrollmentKeys issues enrollment keys; nil reports them unavailable.
	EnrollmentKeys httpapi.EnrollmentKeyManager
	// KubernetesClusters manages Kubernetes clusters; nil reports them
	// unavailable.
	KubernetesClusters httpapi.KubernetesClusterManager
	// SubnetRoutes lets Access Rules name Sites
	// (MESHTRANSIT_SUBNET_ROUTES_ENABLED).
	SubnetRoutes bool
	// ExitNodes lets Access Rules name Exit Pools
	// (MESHTRANSIT_EXIT_NODES_ENABLED).
	ExitNodes bool
}

func composeManagementAPI(
	apiConfig config.APIConfig,
	dnsSuffix dnsname.Suffix,
	enrollmentKeys httpapi.EnrollmentKeyManager,
	kubernetesClusters httpapi.KubernetesClusterManager,
	subnetRoutes, exitNodes bool,
	runtimePool *postgresadapter.Pool,
	rateLimiter httpapi.ManagementRateLimiter,
	logger *slog.Logger,
) (*httpapi.ManagementServer, prometheus.Collector, error) {
	if runtimePool == nil || rateLimiter == nil || logger == nil {
		return nil, nil, errInvalidManagementComposition
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
	return composeManagementAPIWithKeys(managementCompositionOptions{
		API: apiConfig, Keys: managementCompositionKeys{
			sessions: keyring, idempotency: idempotencyDigester, rateLimit: rateLimitDigester,
		},
		DNSSuffix: dnsSuffix, EnrollmentKeys: enrollmentKeys, KubernetesClusters: kubernetesClusters,
		SubnetRoutes: subnetRoutes, ExitNodes: exitNodes,
	}, runtimePool, rateLimiter, logger)
}

// The private process shares the exact resident owners, not a second file read
// that could rotate between API and BFF construction under the same key ID.
func composeManagementAPIWithKeys(
	options managementCompositionOptions,
	runtimePool *postgresadapter.Pool,
	rateLimiter httpapi.ManagementRateLimiter,
	logger *slog.Logger,
) (*httpapi.ManagementServer, prometheus.Collector, error) {
	keys := options.Keys
	completeKeys := keys.sessions != nil && keys.idempotency != nil && keys.rateLimit != nil
	if runtimePool == nil || rateLimiter == nil || logger == nil || !completeKeys {
		return nil, nil, errInvalidManagementComposition
	}
	apiConfig := options.API
	certificate, err := loadManagementTLSCertificate(apiConfig)
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
	sessions, err := accountsession.NewService(keys.sessions, accountSessionStore, accountsession.SystemClock{})
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
			MutationIDs: revocation.PublicMutationIDGenerator{},
			Retry:       backoff,
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
			ApprovalMode:     postgresadapter.PolicyPublicationApprovalModePublisherAuthorized,
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
			Retry:       policyBackoff,
		},
	)
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	resourceAuthorityStore, err := postgresadapter.NewResourceAuthorityStore(
		runtimePool,
		postgresadapter.ResourceAuthorityOptions{
			StatementTimeout: managementStatementTimeout,
			LockTimeout:      managementLockTimeout,
			IdleTimeout:      managementTransactionIdle,
		},
	)
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	resourceBackoff, err := authority.NewExponentialBackoff(
		managementRetryInitial,
		managementRetryMaximum,
	)
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	resourceCreations, err := authority.NewService(
		authority.Options{
			MaxAttempts: 3, RollbackTimeout: managementRollbackTimeout,
			IdempotencyWindow: managementIdempotencyTTL,
		},
		authority.Dependencies{
			Transactions: resourceAuthorityStore, CommittedResults: resourceAuthorityStore,
			MutationIDs: authority.PublicMutationIDGenerator{},
			Retry:       resourceBackoff,
		},
	)
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	resourceLifecycles, err := authority.NewLifecycleService(
		authority.Options{
			MaxAttempts: 3, RollbackTimeout: managementRollbackTimeout,
			IdempotencyWindow: managementIdempotencyTTL,
		},
		authority.LifecycleDependencies{
			Transactions: resourceAuthorityStore, CommittedResults: resourceAuthorityStore,
			MutationIDs: authority.PublicLifecycleMutationIDGenerator{},
			Retry:       resourceBackoff,
		},
	)
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	resourceRebindings, err := authority.NewRebindService(
		authority.Options{
			MaxAttempts: 3, RollbackTimeout: managementRollbackTimeout,
			IdempotencyWindow: managementIdempotencyTTL,
		},
		authority.RebindDependencies{
			Impacts: resourceAuthorityStore, Transactions: resourceAuthorityStore,
			CommittedResults: resourceAuthorityStore,
			MutationIDs:      authority.PublicRebindMutationIDGenerator{},
			Retry:            resourceBackoff,
		},
	)
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	resourceGroupReplacements, err := authority.NewGroupReplaceService(
		authority.Options{
			MaxAttempts: 3, RollbackTimeout: managementRollbackTimeout,
			IdempotencyWindow: managementIdempotencyTTL,
		},
		authority.GroupReplaceDependencies{
			Impacts: resourceAuthorityStore, Transactions: resourceAuthorityStore,
			CommittedResults: resourceAuthorityStore,
			MutationIDs:      authority.PublicGroupReplaceMutationIDGenerator{}, Retry: resourceBackoff,
		},
	)
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	resourceAuthorityChanges, err := authority.NewAuthorityChangeService(
		authority.Options{
			MaxAttempts: 3, RollbackTimeout: managementRollbackTimeout,
			IdempotencyWindow: managementIdempotencyTTL,
		},
		authority.ChangeDependencies{
			Impacts:                  resourceAuthorityStore,
			RequestTransactions:      resourceAuthorityStore,
			CommittedRequests:        resourceAuthorityStore,
			ConfirmationTransactions: resourceAuthorityStore,
			CommittedConfirmations:   resourceAuthorityStore,
			MutationIDs:              authority.PublicAuthorityChangeMutationIDGenerator{}, Retry: resourceBackoff,
		},
	)
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	resourceCatalogStore, err := postgresadapter.NewResourceCatalogStore(
		runtimePool,
		postgresadapter.ResourceCatalogOptions{
			StatementTimeout: managementStatementTimeout,
			LockTimeout:      managementLockTimeout,
			IdleTimeout:      managementTransactionIdle,
		},
	)
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	resourceCatalog, err := catalog.NewService(catalog.Dependencies{
		Transactions: resourceCatalogStore,
	})
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	resourceSharingStore, err := postgresadapter.NewResourceSharingStore(
		runtimePool,
		postgresadapter.ResourceSharingOptions{
			StatementTimeout: managementStatementTimeout,
			LockTimeout:      managementLockTimeout,
			IdleTimeout:      managementTransactionIdle,
			IdempotencyTTL:   managementIdempotencyTTL,
		},
	)
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	policyCompiler, err := compilation.NewService(resourceCatalog, resourceSharingStore)
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	if options.SubnetRoutes {
		siteStore, siteErr := postgresadapter.NewSiteStore(runtimePool, postgresadapter.AccountSessionOptions{
			StatementTimeout: managementStatementTimeout, IdleTimeout: managementTransactionIdle,
		})
		if siteErr != nil {
			return nil, nil, errors.Join(errInvalidManagementComposition, siteErr)
		}
		if policyCompiler, err = policyCompiler.WithSites(siteStore); err != nil {
			return nil, nil, errors.Join(errInvalidManagementComposition, err)
		}
	}
	clusterGroups, err := postgresadapter.NewKubernetesClusterPolicyGroupStore(runtimePool,
		postgresadapter.AccountSessionOptions{
			StatementTimeout: managementStatementTimeout, IdleTimeout: managementTransactionIdle,
		})
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	if policyCompiler, err = policyCompiler.WithKubernetesClusters(clusterGroups); err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	if options.ExitNodes {
		exitPoolStore, poolErr := postgresadapter.NewExitPoolStore(runtimePool, postgresadapter.AccountSessionOptions{
			StatementTimeout: managementStatementTimeout, IdleTimeout: managementTransactionIdle,
		})
		if poolErr != nil {
			return nil, nil, errors.Join(errInvalidManagementComposition, poolErr)
		}
		if policyCompiler, err = policyCompiler.WithExitPools(exitPoolStore); err != nil {
			return nil, nil, errors.Join(errInvalidManagementComposition, err)
		}
	}
	accessGraphStore, err := postgresadapter.NewAccessGraphStore(
		runtimePool,
		postgresadapter.AccessGraphOptions{
			StatementTimeout: managementStatementTimeout,
			LockTimeout:      managementLockTimeout,
			IdleTimeout:      managementTransactionIdle,
		},
	)
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	policyExplainer, err := accessgraph.NewService(accessgraph.Dependencies{
		Reader: accessGraphStore, GraphReader: accessGraphStore,
	})
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	policySimulationStore, err := postgresadapter.NewPolicySimulationStore(
		runtimePool,
		postgresadapter.PolicySimulationOptions{
			StatementTimeout: managementStatementTimeout,
			LockTimeout:      managementLockTimeout,
			IdleTimeout:      managementTransactionIdle,
		},
	)
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	activePolicies, err := postgresadapter.NewActivePolicyStore(runtimePool, postgresadapter.PolicySimulationOptions{
		StatementTimeout: managementStatementTimeout, LockTimeout: managementLockTimeout, IdleTimeout: managementTransactionIdle,
	})
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	policySimulator, err := simulation.NewService(simulation.Dependencies{
		Baselines: policySimulationStore, Compiler: policyCompiler,
	})
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	policyApprovalStore, err := postgresadapter.NewPolicyApprovalStore(
		runtimePool,
		postgresadapter.PolicyApprovalOptions{
			StatementTimeout: managementStatementTimeout,
			LockTimeout:      managementLockTimeout,
			IdleTimeout:      managementTransactionIdle,
		},
	)
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	policyApprovals, err := policyapproval.NewService(
		policyapproval.Options{
			MaxAttempts: 3, RollbackTimeout: managementRollbackTimeout,
			IdempotencyWindow: managementIdempotencyTTL,
		},
		policyapproval.Dependencies{
			Simulator:           policySimulator,
			RequestTransactions: policyApprovalStore, CommittedRequests: policyApprovalStore,
			ApprovalTransactions: policyApprovalStore, CommittedApprovals: policyApprovalStore,
			MutationIDs: policyapproval.PublicMutationIDGenerator{},
			Retry:       policyBackoff,
		},
	)
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	policyApprovalCatalog, err := policyapproval.NewCatalogService(
		policyApprovalStore,
	)
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	resourceSharing, err := sharing.NewService(resourceSharingStore)
	if err != nil {
		return nil, nil, errors.Join(errInvalidManagementComposition, err)
	}
	handler, err := httpapi.NewManagementHandler(httpapi.ManagementHandlerOptions{
		Sessions: sessions, Revocations: revocations, PolicyPublications: policyPublications,
		PolicyCompilations:    policyCompiler,
		PolicyExplanations:    policyExplainer,
		AccessGraphs:          policyExplainer,
		PolicySimulations:     policySimulator,
		PolicyApprovals:       policyApprovals,
		PolicyApprovalCatalog: policyApprovalCatalog,
		ActivePolicies:        activePolicies,
		ResourceCreations:     resourceCreations, ResourceLifecycles: resourceLifecycles,
		ResourceRebindings: resourceRebindings, ResourceCatalog: resourceCatalog,
		ResourceGroupReplacements: resourceGroupReplacements,
		ResourceAuthorityChanges:  resourceAuthorityChanges,
		ResourceSharing:           resourceSharing,
		Idempotency:               keys.idempotency,
		RateLimitSubjects:         keys.rateLimit, RateLimiter: rateLimiter,
		TrustedProxyPrefixes: apiConfig.TrustedProxyPrefixes,
		SourceRateLimit:      apiConfig.SourceRateLimit, SessionRateLimit: apiConfig.SessionRateLimit,
		CorrelationIDs: httpapi.PublicCorrelationIDGenerator{}, Logger: logger,
		RequestTimeout:        apiConfig.RequestTimeout,
		MaxConcurrentRequests: apiConfig.MaxConcurrentRequests,
		DNSSuffix:             options.DNSSuffix,
		EnrollmentKeys:        options.EnrollmentKeys,
		KubernetesClusters:    options.KubernetesClusters,
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
