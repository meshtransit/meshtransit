package main

import (
	"context"
	"io"
	"log/slog"

	"github.com/meshtransit/meshtransit/internal/adapter/httpapi"
	redisadapter "github.com/meshtransit/meshtransit/internal/adapter/redis"
	"github.com/meshtransit/meshtransit/internal/app"
	"github.com/meshtransit/meshtransit/internal/buildinfo"
	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/network/revisionworker"
	"github.com/meshtransit/meshtransit/internal/observability"
)

func run(ctx context.Context, lookup config.LookupFunc, errorOutput io.Writer) (exitCode int) {
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

	resources := &resourceOwner{}
	defer func() {
		if closeErr := resources.Close(); closeErr != nil {
			logger.ErrorContext(
				context.WithoutCancel(ctx),
				"resource cleanup failed",
				"error_code", "resource_cleanup_failure",
				"error", closeErr,
			)
			exitCode = 1
		}
	}()

	checkers := make([]app.DependencyChecker, 0, len(readiness.RequiredComponents()))
	var storagePools postgresPools
	var redisClient *redisadapter.Client
	if processConfig.Storage != nil {
		storagePools, err = openPostgresPools(
			ctx,
			processConfig.Storage.PostgreSQL,
			processConfig.Dependencies.CheckTimeout,
			resources,
		)
		if err != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "postgres_open_failure", "error", err)
			return 1
		}
		postgresChecker, checkerErr := storagePools.healthChecker()
		if checkerErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "postgres_checker_failure", "error", checkerErr)
			return 1
		}
		checkers = append(checkers, postgresChecker)

		redisClient, err = redisadapter.Open(ctx, redisadapter.Options{
			Address:        processConfig.Storage.Redis.Address,
			Username:       processConfig.Storage.Redis.Username,
			PasswordFile:   processConfig.Storage.Redis.PasswordFile,
			CAFile:         processConfig.Storage.Redis.CAFile,
			PoolSize:       processConfig.Storage.Redis.PoolSize,
			RequestTimeout: processConfig.Dependencies.CheckTimeout,
		})
		if err != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "redis_open_failure", "error", err)
			return 1
		}
		resources.Add("redis", redisClient.Close)
		checkers = append(checkers, redisClient)
	}

	monitor, err := app.NewDependencyMonitor(
		app.MonitorOptions{
			CheckTimeout:  processConfig.Dependencies.CheckTimeout,
			CheckInterval: processConfig.Dependencies.CheckInterval,
		},
		readiness,
		checkers...,
	)
	if err != nil {
		logger.ErrorContext(ctx, "startup failed", "error_code", "invalid_dependency_monitor", "error", err)
		return 1
	}
	build := buildinfo.Current()
	var revisionWorkerTelemetry *revisionworker.Telemetry
	if processConfig.RevisionWorker != nil {
		revisionWorkerTelemetry = revisionworker.NewTelemetry()
	}
	healthServer, err := httpapi.NewHealthServer(httpapi.HealthServerOptions{
		Address: processConfig.HealthAddress,
		State:   readiness,
		Logger:  logger,
		Build: httpapi.BuildInfo{
			Version:             build.Version,
			Revision:            build.Revision,
			GoVersion:           build.GoVersion,
			ConfigSchemaVersion: config.SchemaVersion,
		},
		RevisionWorkerTelemetry: revisionWorkerTelemetry,
	})
	if err != nil {
		logger.ErrorContext(ctx, "startup failed", "error_code", "invalid_health_server", "error", err)
		return 1
	}
	services := []app.OwnedService{{Name: "health", Service: healthServer}}
	if processConfig.RevisionWorker != nil {
		workerService, composeErr := composeRevisionWorker(
			*processConfig.RevisionWorker,
			storagePools.worker,
			redisClient,
			revisionWorkerTelemetry,
			logger,
		)
		if composeErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "worker_composition_failure", "error", composeErr)
			return 1
		}
		services = append(services, app.OwnedService{Name: "network-revision-worker", Service: workerService})
	}
	application, err := app.New(
		app.Options{
			Roles:           roles,
			ShutdownTimeout: processConfig.ShutdownTimeout,
		},
		readiness,
		monitor,
		logger,
		services...,
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
