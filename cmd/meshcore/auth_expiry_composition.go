package main

import (
	"errors"
	"log/slog"

	oidcadapter "github.com/meshtransit/meshtransit/internal/adapter/oidc"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/app"
	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/identity/authexpiry"
	"github.com/meshtransit/meshtransit/internal/identity/oidcauth"
)

var errInvalidAuthExpiryComposition = errors.New("invalid browser expiry composition")

func composeAuthExpiry(
	settings config.AuthExpiryConfig,
	pool *postgresadapter.Pool,
	telemetry *oidcadapter.ExpiryTelemetry,
	logger *slog.Logger,
) (*authexpiry.Worker, error) {
	missingDependencies := pool == nil || telemetry == nil || logger == nil
	if missingDependencies || settings.UnitTimeout > settings.PassTimeout {
		return nil, errInvalidAuthExpiryComposition
	}
	store, err := postgresadapter.NewAuthExpiryStore(pool, postgresadapter.AuthTransactionOptions{
		StatementTimeout: settings.UnitTimeout, LockTimeout: settings.UnitTimeout / 2, IdleTimeout: settings.UnitTimeout,
	})
	if err != nil {
		return nil, errInvalidAuthExpiryComposition
	}
	engine, err := oidcauth.NewExpiryService(oidcauth.ExpiryOptions{
		BatchSize: settings.BatchSize, PassTimeout: settings.PassTimeout,
		UnitTimeout: settings.UnitTimeout, RollbackTimeout: settings.RollbackTimeout,
	}, oidcauth.ExpiryDependencies{
		Candidates: store, Transactions: store, IDs: oidcauth.SystemClaimIDs{}, Clock: oidcauth.SystemStartClock{},
	})
	if err != nil {
		return nil, errInvalidAuthExpiryComposition
	}
	return authexpiry.New(authexpiry.Options{
		DeploymentID: settings.DeploymentID, BatchSize: settings.BatchSize,
		PollInterval: settings.PollInterval, PassTimeout: settings.PassTimeout,
	}, authexpiry.Dependencies{Sweeper: engine, Observer: telemetry, Logger: logger})
}

var _ app.Service = (*authexpiry.Worker)(nil)
