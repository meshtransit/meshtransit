package main

import (
	"errors"

	"meshtransit.net/core/internal/adapter/httpapi"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/enrollment/enrollmentkey"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/platform/config"
)

var errInvalidEnrollmentKeyComposition = errors.New("invalid enrollment key composition")

// composeEnrollmentKeys builds the enrollment key service when the process
// has the enrollment digest keys; without them it returns nil and the API
// reports enrollment keys unavailable.
func composeEnrollmentKeys(
	runtimePool *postgresadapter.Pool,
	digest *config.CredentialDigestConfig,
) (httpapi.EnrollmentKeyManager, error) {
	if digest == nil {
		return nil, nil
	}
	if runtimePool == nil {
		return nil, errInvalidEnrollmentKeyComposition
	}
	keyring, err := composeCredentialVerifier(*digest)
	if err != nil {
		return nil, errors.Join(errInvalidEnrollmentKeyComposition, err)
	}
	store, err := postgresadapter.NewEnrollmentKeyStore(runtimePool, postgresadapter.AccountSessionOptions{
		StatementTimeout: managementStatementTimeout, IdleTimeout: managementTransactionIdle,
	}, keyring)
	if err != nil {
		return nil, errors.Join(errInvalidEnrollmentKeyComposition, err)
	}
	service, err := enrollmentkey.NewService(store, accountsession.SystemClock{})
	if err != nil {
		return nil, errors.Join(errInvalidEnrollmentKeyComposition, err)
	}
	return service, nil
}
