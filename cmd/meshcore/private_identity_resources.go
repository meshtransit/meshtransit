package main

import (
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/resource/authority"
	"github.com/meshtransit/meshtransit/internal/resource/catalog"
	"github.com/meshtransit/meshtransit/internal/sharing"
)

type privateIdentityResourceServices struct {
	creations *authority.Service
	catalog   *catalog.Service
	sharing   *sharing.Service
	imports   *postgresadapter.ResourceSharingStore
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
		MutationIDs: authority.PublicMutationIDGenerator{}, Clock: authority.SystemClock{}, Retry: backoff,
	})
	if err != nil {
		return invalid, errInvalidPrivateIdentityComposition
	}
	catalogStore, err := postgresadapter.NewResourceCatalogStore(pool, postgresadapter.ResourceCatalogOptions(options))
	if err != nil {
		return invalid, errInvalidPrivateIdentityComposition
	}
	resourceCatalog, err := catalog.NewService(catalog.Dependencies{Transactions: catalogStore, Clock: catalog.SystemClock{}})
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
	resourceSharing, err := sharing.NewService(imports, sharing.SystemClock{})
	if err != nil {
		return invalid, errInvalidPrivateIdentityComposition
	}
	return privateIdentityResourceServices{creations: creations, catalog: resourceCatalog, sharing: resourceSharing, imports: imports}, nil
}
