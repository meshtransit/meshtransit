package main

import (
	"errors"

	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	postgresintake "github.com/meshtransit/meshtransit/internal/adapter/postgres/registrationintake"
	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/control"
	"github.com/meshtransit/meshtransit/internal/enrollment/registration"
	"github.com/meshtransit/meshtransit/internal/enrollment/registration/intake"
)

var errInvalidRegistrationComposition = errors.New("invalid registration composition")

type registrationIntakeStore interface {
	intake.Transactions
	intake.PreparedIntentResolver
}

func composeRegistration(
	enrollmentConfig config.EnrollmentConfig,
	runtimePool *postgresadapter.Pool,
) (*control.RegistrationService, error) {
	if runtimePool == nil {
		return nil, errInvalidRegistrationComposition
	}
	verifier, err := composeCredentialVerifier(enrollmentConfig.CredentialDigest)
	if err != nil {
		return nil, errors.Join(errInvalidRegistrationComposition, err)
	}
	registrationConfig := enrollmentConfig.Registration
	intakeStore, err := postgresadapter.NewRegistrationIntakeTransactions(
		runtimePool,
		postgresintake.Options{
			StatementTimeout: registrationConfig.Database.StatementTimeout,
			LockTimeout:      registrationConfig.Database.LockTimeout,
			IdleTimeout:      registrationConfig.Database.IdleTimeout,
		},
	)
	if err != nil {
		return nil, errors.Join(errInvalidRegistrationComposition, err)
	}
	preparer, err := newRegistrationIntakeService(registrationConfig, intakeStore, verifier)
	if err != nil {
		return nil, err
	}

	transactions, err := postgresadapter.NewRegistrationTransactions(
		runtimePool,
		postgresadapter.RegistrationTransactionOptions{
			StatementTimeout:      registrationConfig.Database.StatementTimeout,
			LockTimeout:           registrationConfig.Database.LockTimeout,
			IdleTimeout:           registrationConfig.Database.IdleTimeout,
			AddressCandidateLimit: registrationConfig.AddressCandidateLimit,
		},
	)
	if err != nil {
		return nil, errors.Join(errInvalidRegistrationComposition, err)
	}
	committedResults, err := postgresadapter.NewRegistrationReplayStore(runtimePool)
	if err != nil {
		return nil, errors.Join(errInvalidRegistrationComposition, err)
	}
	executor, err := newRegistrationMutationService(
		registrationConfig,
		transactions,
		committedResults,
	)
	if err != nil {
		return nil, err
	}
	service, err := control.NewRegistrationService(preparer, executor)
	if err != nil {
		return nil, errors.Join(errInvalidRegistrationComposition, err)
	}
	return service, nil
}

func newRegistrationIntakeService(
	registrationConfig config.RegistrationConfig,
	store registrationIntakeStore,
	verifier intake.CredentialVerifier,
) (*intake.Service, error) {
	if store == nil || verifier == nil {
		return nil, errInvalidRegistrationComposition
	}
	retry, err := registration.NewExponentialBackoff(
		registrationConfig.Retry.Initial,
		registrationConfig.Retry.Maximum,
	)
	if err != nil {
		return nil, errors.Join(errInvalidRegistrationComposition, err)
	}
	service, err := intake.NewService(
		intake.Options{
			MaxAttempts:     registrationConfig.MaxAttempts,
			RollbackTimeout: registrationConfig.RollbackTimeout,
			PendingTTL:      registrationConfig.PendingTTL,
		},
		intake.Dependencies{
			Transactions:     store,
			PreparedIntents:  store,
			CredentialProofs: verifier,
			EvidenceIDs:      intake.PublicEvidenceIDGenerator{},
			Clock:            registration.SystemClock{},
			Retry:            retry,
		},
	)
	if err != nil {
		return nil, errors.Join(errInvalidRegistrationComposition, err)
	}
	return service, nil
}

func newRegistrationMutationService(
	registrationConfig config.RegistrationConfig,
	transactions registration.Transactions,
	committedResults registration.CommittedResultResolver,
) (*registration.Service, error) {
	if transactions == nil || committedResults == nil {
		return nil, errInvalidRegistrationComposition
	}
	retry, err := registration.NewExponentialBackoff(
		registrationConfig.Retry.Initial,
		registrationConfig.Retry.Maximum,
	)
	if err != nil {
		return nil, errors.Join(errInvalidRegistrationComposition, err)
	}
	service, err := registration.NewService(
		registration.Options{
			MaxAttempts:     registrationConfig.MaxAttempts,
			RollbackTimeout: registrationConfig.RollbackTimeout,
		},
		registration.Dependencies{
			Transactions:     transactions,
			CommittedResults: committedResults,
			NodeIDs:          registration.PublicNodeIDGenerator{},
			MutationIDs:      registration.PublicMutationIDGenerator{},
			Clock:            registration.SystemClock{},
			Retry:            retry,
		},
	)
	if err != nil {
		return nil, errors.Join(errInvalidRegistrationComposition, err)
	}
	return service, nil
}

var _ registrationIntakeStore = (*postgresintake.Transactions)(nil)
