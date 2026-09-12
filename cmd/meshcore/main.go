// Command meshcore runs the MeshTransit Core process.
package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/meshtransit/meshtransit/internal/adapter/httpapi"
	"github.com/meshtransit/meshtransit/internal/app"
	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/observability"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	os.Exit(run(ctx, os.LookupEnv, os.Stderr))
}

func run(ctx context.Context, lookup config.LookupFunc, errorOutput io.Writer) int {
	logger, err := observability.NewLogger(errorOutput, slog.LevelInfo)
	if err != nil {
		return 1
	}

	processConfig, err := config.Load(lookup)
	if err != nil {
		logger.ErrorContext(ctx, "startup failed", "error_code", "invalid_configuration", "error", err)
		return 1
	}
	logger, err = observability.NewLogger(errorOutput, processConfig.LogLevel)
	if err != nil {
		return 1
	}

	roles, err := app.ExpandRole(processConfig.Role)
	if err != nil {
		logger.ErrorContext(ctx, "startup failed", "error_code", "invalid_role_selection", "error", err)
		return 1
	}
	readiness, err := app.NewRuntimeState(roles)
	if err != nil {
		logger.ErrorContext(ctx, "startup failed", "error_code", "invalid_runtime_state", "error", err)
		return 1
	}
	healthServer, err := httpapi.NewHealthServer(processConfig.HealthAddress, readiness, logger)
	if err != nil {
		logger.ErrorContext(ctx, "startup failed", "error_code", "invalid_health_server", "error", err)
		return 1
	}
	application, err := app.New(
		app.Options{
			Roles:           roles,
			ShutdownTimeout: processConfig.ShutdownTimeout,
		},
		readiness,
		healthServer,
		logger,
	)
	if err != nil {
		logger.ErrorContext(ctx, "startup failed", "error_code", "invalid_application", "error", err)
		return 1
	}

	if err := application.Run(ctx); err != nil {
		logger.ErrorContext(
			context.WithoutCancel(ctx),
			"runtime failed",
			"error_code", "runtime_failure",
			"error", err,
		)
		return 1
	}
	return 0
}
