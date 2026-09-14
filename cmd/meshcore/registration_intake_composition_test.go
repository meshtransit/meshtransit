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
)

func TestNewRegistrationIntakeServiceComposesRuntimeDependencies(t *testing.T) {
	t.Parallel()

	service, err := newRegistrationIntakeService(
		validRegistrationIntakeConfig(),
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
		config   config.RegistrationIntakeConfig
		store    registrationIntakeStore
		verifier intake.CredentialVerifier
	}{
		{
			name:     "missing store",
			config:   validRegistrationIntakeConfig(),
			verifier: registrationIntakeCompositionVerifier{},
		},
		{
			name:   "missing verifier",
			config: validRegistrationIntakeConfig(),
			store:  registrationIntakeCompositionStore{},
		},
		{
			name:     "unsafe options",
			config:   config.RegistrationIntakeConfig{},
			store:    registrationIntakeCompositionStore{},
			verifier: registrationIntakeCompositionVerifier{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := newRegistrationIntakeService(test.config, test.store, test.verifier)
			if !errors.Is(err, errInvalidRegistrationIntakeComposition) {
				t.Fatalf("newRegistrationIntakeService() error = %v, want composition error", err)
			}
		})
	}
}

func TestComposeRegistrationIntakeRejectsMissingRuntimePool(t *testing.T) {
	t.Parallel()

	_, err := composeRegistrationIntake(config.EnrollmentConfig{}, nil)
	if !errors.Is(err, errInvalidRegistrationIntakeComposition) {
		t.Fatalf("composeRegistrationIntake() error = %v, want composition error", err)
	}
}

func validRegistrationIntakeConfig() config.RegistrationIntakeConfig {
	return config.RegistrationIntakeConfig{
		MaxAttempts:     3,
		RollbackTimeout: time.Second,
		PendingTTL:      10 * time.Minute,
		Database: config.RegistrationIntakeDatabaseConfig{
			StatementTimeout: 5 * time.Second,
			LockTimeout:      time.Second,
			IdleTimeout:      10 * time.Second,
		},
		Retry: config.RegistrationIntakeRetryConfig{
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
