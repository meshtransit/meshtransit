package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/deployment"
	"github.com/meshtransit/meshtransit/internal/enrollment"
	"github.com/meshtransit/meshtransit/internal/enrollment/registration"
	"github.com/meshtransit/meshtransit/internal/enrollment/registration/intake"
	"github.com/meshtransit/meshtransit/internal/network"
)

func TestNewRegistrationIntakeServiceComposesRuntimeDependencies(t *testing.T) {
	t.Parallel()

	service, err := newRegistrationIntakeService(
		validRegistrationConfig(),
		registrationIntakeCompositionStore{},
		registrationIntakeCompositionVerifier{},
	)
	if err != nil {
		t.Fatalf("newRegistrationIntakeService() error = %v", err)
	}
	if service == nil {
		t.Fatal("newRegistrationIntakeService() returned nil service")
	}
}

func TestNewRegistrationIntakeServiceRejectsInvalidComposition(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		config   config.RegistrationConfig
		store    registrationIntakeStore
		verifier intake.CredentialVerifier
	}{
		{
			name:     "missing store",
			config:   validRegistrationConfig(),
			verifier: registrationIntakeCompositionVerifier{},
		},
		{
			name:   "missing verifier",
			config: validRegistrationConfig(),
			store:  registrationIntakeCompositionStore{},
		},
		{
			name:     "unsafe options",
			config:   config.RegistrationConfig{},
			store:    registrationIntakeCompositionStore{},
			verifier: registrationIntakeCompositionVerifier{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := newRegistrationIntakeService(test.config, test.store, test.verifier)
			if !errors.Is(err, errInvalidRegistrationComposition) {
				t.Fatalf("newRegistrationIntakeService() error = %v, want composition error", err)
			}
		})
	}
}

func TestNewRegistrationMutationServiceComposesRuntimeDependencies(t *testing.T) {
	t.Parallel()

	store := registrationMutationCompositionStore{}
	service, err := newRegistrationMutationService(validRegistrationConfig(), store, store)
	if err != nil {
		t.Fatalf("newRegistrationMutationService() error = %v", err)
	}
	if service == nil {
		t.Fatal("newRegistrationMutationService() returned nil service")
	}
}

func TestNewRegistrationMutationServiceRejectsInvalidComposition(t *testing.T) {
	t.Parallel()

	store := registrationMutationCompositionStore{}
	tests := []struct {
		name             string
		config           config.RegistrationConfig
		transactions     registration.Transactions
		committedResults registration.CommittedResultResolver
	}{
		{
			name:             "missing transactions",
			config:           validRegistrationConfig(),
			committedResults: store,
		},
		{
			name:         "missing committed result resolver",
			config:       validRegistrationConfig(),
			transactions: store,
		},
		{
			name:             "unsafe options",
			config:           config.RegistrationConfig{},
			transactions:     store,
			committedResults: store,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := newRegistrationMutationService(
				test.config,
				test.transactions,
				test.committedResults,
			)
			if !errors.Is(err, errInvalidRegistrationComposition) {
				t.Fatalf("newRegistrationMutationService() error = %v, want composition error", err)
			}
		})
	}
}

func TestComposeRegistrationRejectsMissingRuntimePool(t *testing.T) {
	t.Parallel()

	_, err := composeRegistration(config.EnrollmentConfig{}, nil)
	if !errors.Is(err, errInvalidRegistrationComposition) {
		t.Fatalf("composeRegistration() error = %v, want composition error", err)
	}
}

func validRegistrationConfig() config.RegistrationConfig {
	return config.RegistrationConfig{
		MaxAttempts:           3,
		RollbackTimeout:       time.Second,
		PendingTTL:            10 * time.Minute,
		AddressCandidateLimit: 256,
		Database: config.RegistrationDatabaseConfig{
			StatementTimeout: 5 * time.Second,
			LockTimeout:      time.Second,
			IdleTimeout:      10 * time.Second,
		},
		Retry: config.RegistrationRetryConfig{
			Initial: 10 * time.Millisecond,
			Maximum: 250 * time.Millisecond,
		},
	}
}

type registrationIntakeCompositionStore struct{}

func (registrationIntakeCompositionStore) Begin(
	context.Context,
	intake.Lookup,
) (intake.Transaction, error) {
	return nil, errors.New("composition fixture must not be called")
}

func (registrationIntakeCompositionStore) ResolvePrepared(
	context.Context,
	registration.Command,
) (registration.RequestHash, bool, error) {
	return registration.RequestHash{}, false, errors.New("composition fixture must not be called")
}

type registrationIntakeCompositionVerifier struct{}

func (registrationIntakeCompositionVerifier) Verify(
	deployment.ID,
	int64,
	enrollment.CredentialToken,
	enrollment.CredentialDigest,
) bool {
	return false
}

type registrationMutationCompositionStore struct{}

func (registrationMutationCompositionStore) Begin(
	context.Context,
	network.Scope,
) (registration.Transaction, error) {
	return nil, errors.New("composition fixture must not be called")
}

func (registrationMutationCompositionStore) ResolveCommitted(
	context.Context,
	registration.Command,
) (registration.Result, bool, error) {
	return registration.Result{}, false, errors.New("composition fixture must not be called")
}
