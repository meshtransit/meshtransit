package main

import (
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	oidcadapter "meshtransit.net/core/internal/adapter/oidc"
	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/domain/deployment"
	"meshtransit.net/core/internal/platform/config"
)

func TestAuthExpiryCompositionRejectsMissingOwnershipBeforeEffects(t *testing.T) {
	t.Parallel()
	assignment, err := deployment.ParseID("01958000-0000-7000-8000-000000000001")
	if err != nil {
		t.Fatal(err)
	}
	settings := config.AuthExpiryConfig{
		DeploymentID: assignment, BatchSize: 8, PollInterval: time.Second,
		PassTimeout: 10 * time.Second, UnitTimeout: time.Second, RollbackTimeout: time.Second,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, test := range []struct {
		name      string
		pool      *postgresadapter.Pool
		telemetry *oidcadapter.ExpiryTelemetry
		logger    *slog.Logger
	}{
		{name: "missing pool", telemetry: oidcadapter.NewExpiryTelemetry(), logger: logger},
		{name: "missing telemetry", pool: &postgresadapter.Pool{}, logger: logger},
		{name: "missing logger", pool: &postgresadapter.Pool{}, telemetry: oidcadapter.NewExpiryTelemetry()},
		{name: "uninitialized pool", pool: &postgresadapter.Pool{},
			telemetry: oidcadapter.NewExpiryTelemetry(), logger: logger},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			worker, err := composeAuthExpiry(
				settings,
				test.pool,
				test.telemetry,
				test.logger,
			)
			if !errors.Is(err, errInvalidAuthExpiryComposition) || worker != nil {
				t.Fatal("composition accepted missing/unowned dependency")
			}
		})
	}
}
