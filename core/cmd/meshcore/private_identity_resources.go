package main

import (
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/resource/authority"
	"meshtransit.net/core/internal/domain/resource/catalog"
	"meshtransit.net/core/internal/domain/sharing"
)

type privateIdentityResourceServices struct {
	creations *authority.Service
	catalog   *catalog.Service
	sharing   *sharing.Service
	imports   *postgresadapter.ResourceSharingStore
	// sites resolves Site destinations; nil when subnet routes are off, so
	// rules naming a Site are refused.
	sites compilation.SiteResolver
	// exitPools resolves Exit Pool destinations.
	exitPools compilation.ExitPoolResolver
}

func newPrivateIdentityResourceServices(pool *postgresadapter.Pool, options postgresadapter.AuthTransactionOptions) (privateIdentityResourceServices, error) {
	invalid := privateIdentityResourceServices{}
	authorityStore, err := postgresadapter.NewResourceAuthorityStore(pool, postgresadapter.ResourceAuthorityOptions(options))
	if err != nil {
		return invalid, errInvalidPrivateIdentityComposition
	}
	backoff, err := authority.NewExponentialBackoff(managementRetryInitial, managementRetryMaximum)
	if err != nil {
		return invalid, errInvalidPrivateIdentityComposition
	}
	creations, err := authority.NewService(authority.Options{
		MaxAttempts: 3, RollbackTimeout: managementRollbackTimeout, IdempotencyWindow: managementIdempotencyTTL,
	}, authority.Dependencies{
		Transactions: authorityStore, CommittedResults: authorityStore,
		MutationIDs: authority.PublicMutationIDGenerator{}, Retry: backoff,
	})
	if err != nil {
		return invalid, errInvalidPrivateIdentityComposition
	}
	catalogStore, err := postgresadapter.NewResourceCatalogStore(pool, postgresadapter.ResourceCatalogOptions(options))
	if err != nil {
		return invalid, errInvalidPrivateIdentityComposition
	}
	resourceCatalog, err := catalog.NewService(catalog.Dependencies{Transactions: catalogStore})
	if err != nil {
		return invalid, errInvalidPrivateIdentityComposition
	}
	imports, err := postgresadapter.NewResourceSharingStore(pool, postgresadapter.ResourceSharingOptions{
		StatementTimeout: options.StatementTimeout, LockTimeout: options.LockTimeout, IdleTimeout: options.IdleTimeout,
		IdempotencyTTL: managementIdempotencyTTL,
	})
	if err != nil {
		return invalid, errInvalidPrivateIdentityComposition
	}
	resourceSharing, err := sharing.NewService(imports)
	if err != nil {
		return invalid, errInvalidPrivateIdentityComposition
	}
	return privateIdentityResourceServices{creations: creations, catalog: resourceCatalog, sharing: resourceSharing, imports: imports}, nil
}
