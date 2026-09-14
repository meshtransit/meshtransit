package main

import (
	"errors"

	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	postgresintake "github.com/meshtransit/meshtransit/internal/adapter/postgres/registrationintake"
	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/enrollment/registration"
	"github.com/meshtransit/meshtransit/internal/enrollment/registration/intake"
)

var errInvalidRegistrationIntakeComposition = errors.New("invalid registration intake composition")

type registrationIntakeStore interface {
	intake.Transactions
	intake.PreparedIntentResolver
}

func composeRegistrationIntake(
	enrollmentConfig config.EnrollmentConfig,
	runtimePool *postgresadapter.Pool,
) (*intake.Service, error) {
	if runtimePool == nil {
		return nil, errInvalidRegistrationIntakeComposition
	}
	verifier, err := composeCredentialVerifier(enrollmentConfig.CredentialDigest)
	if err != nil {
		return nil, errors.Join(errInvalidRegistrationIntakeComposition, err)
	}
	intakeConfig := enrollmentConfig.RegistrationIntake
	store, err := postgresadapter.NewRegistrationIntakeTransactions(
		runtimePool,
		postgresintake.Options{
			StatementTimeout: intakeConfig.Database.StatementTimeout,
			LockTimeout:      intakeConfig.Database.LockTimeout,
			IdleTimeout:      intakeConfig.Database.IdleTimeout,
		},
	)
	if err != nil {
		return nil, errors.Join(errInvalidRegistrationIntakeComposition, err)
	}
	return newRegistrationIntakeService(intakeConfig, store, verifier)
}

func newRegistrationIntakeService(
	intakeConfig config.RegistrationIntakeConfig,
	store registrationIntakeStore,
	verifier intake.CredentialVerifier,
) (*intake.Service, error) {
	if store == nil || verifier == nil {
		return nil, errInvalidRegistrationIntakeComposition
	}
	retry, err := registration.NewExponentialBackoff(
		intakeConfig.Retry.Initial,
		intakeConfig.Retry.Maximum,
	)
	if err != nil {
		return nil, errors.Join(errInvalidRegistrationIntakeComposition, err)
	}
	service, err := intake.NewService(
		intake.Options{
			MaxAttempts:     intakeConfig.MaxAttempts,
			RollbackTimeout: intakeConfig.RollbackTimeout,
			PendingTTL:      intakeConfig.PendingTTL,
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
		return nil, errors.Join(errInvalidRegistrationIntakeComposition, err)
	}
	return service, nil
}

var _ registrationIntakeStore = (*postgresintake.Transactions)(nil)
