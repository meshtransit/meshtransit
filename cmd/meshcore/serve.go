package main

import (
	"context"
	"errors"
	"io"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"

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
	resourcesOwnedByApplication := false
	defer func() {
		if resourcesOwnedByApplication {
			return
		}
		cleanupCtx, cancel := context.WithTimeout(
			context.WithoutCancel(ctx),
			processConfig.ShutdownTimeout,
		)
		defer cancel()
		if closeErr := resources.Close(cleanupCtx); closeErr != nil {
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
	additionalMetrics := make([]prometheus.Collector, 0, 4)
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
		postgresMetrics, metricsErr := storagePools.metricsCollector()
		if metricsErr != nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "postgres_metrics_failure", "error", metricsErr)
			return 1
		}
		additionalMetrics = append(additionalMetrics, postgresMetrics)

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
		if ownErr := resources.Add("redis", redisClient.Shutdown); ownErr != nil {
			logger.ErrorContext(
				ctx,
				"startup failed",
				"error_code", "redis_ownership_failure",
				"error", errors.Join(ownErr, redisClient.Shutdown(ctx)),
			)
			return 1
		}
		checkers = append(checkers, redisClient)
		additionalMetrics = append(additionalMetrics, redisClient.MetricsCollector())
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
	var revisionWorkerTelemetry *revisionworker.Telemetry
	roleServices := make([]app.OwnedService, 0, 3)
	if processConfig.RevisionWorker != nil {
		revisionWorkerTelemetry = revisionworker.NewTelemetry()
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
		roleServices = append(
			roleServices,
			app.OwnedService{Name: "network-revision-worker", Service: workerService},
		)
	}
	if processConfig.Control != nil {
		if processConfig.Enrollment == nil {
			logger.ErrorContext(ctx, "startup failed", "error_code", "control_configuration_failure")
			return 1
		}
		revisionFeed, revisionFeedTelemetry, composeErr := composeRevisionFeed(
			*processConfig.Control,
			redisClient,
		)
		if composeErr != nil {
			logger.ErrorContext(
				ctx,
				"startup failed",
				"error_code", "revision_feed_composition_failure",
				"error", composeErr,
			)
			return 1
		}
		revisionFeedMetrics, metricsErr := httpapi.NewRevisionFeedMetricsCollector(
			revisionFeedTelemetry,
		)
		if metricsErr != nil {
			logger.ErrorContext(
				ctx,
				"startup failed",
				"error_code", "revision_feed_metrics_failure",
				"error", metricsErr,
			)
			return 1
		}
		additionalMetrics = append(additionalMetrics, revisionFeedMetrics)
		roleServices = append(
			roleServices,
			app.OwnedService{Name: "network-revision-feed", Service: revisionFeed},
		)
		registrationService, composeErr := composeRegistration(
			*processConfig.Enrollment,
			storagePools.runtime,
		)
		if composeErr != nil {
			logger.ErrorContext(
				ctx,
				"startup failed",
				"error_code", "registration_composition_failure",
				"error", composeErr,
			)
			return 1
		}
		mapSessionService, composeErr := composeMapSession(
			processConfig.Control.Map,
			storagePools.runtime,
		)
		if composeErr != nil {
			logger.ErrorContext(
				ctx,
				"startup failed",
				"error_code", "map_session_composition_failure",
				"error", composeErr,
			)
			return 1
		}
		mapStreamService, composeErr := composeMapStream(
			processConfig.Control.Map,
			mapSessionService,
			redisClient,
			revisionFeed,
		)
		if composeErr != nil {
			logger.ErrorContext(
				ctx,
				"startup failed",
				"error_code", "map_stream_composition_failure",
				"error", composeErr,
			)
			return 1
		}
		controlListener, composeErr := composeControlListener(
			*processConfig.Control,
			registrationService,
			mapSessionService,
			mapStreamService,
			logger,
		)
		if composeErr != nil {
			logger.ErrorContext(
				ctx,
				"startup failed",
				"error_code", "control_composition_failure",
				"error", composeErr,
			)
			return 1
		}
		additionalMetrics = append(additionalMetrics, controlListener.MetricsCollector())
		roleServices = append(roleServices, app.OwnedService{Name: "control", Service: controlListener})
	}

	build := buildinfo.Current()
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
		AdditionalMetrics:       additionalMetrics,
	})
	if err != nil {
		logger.ErrorContext(ctx, "startup failed", "error_code", "invalid_health_server", "error", err)
		return 1
	}
	services := make([]app.OwnedService, 0, len(roleServices)+1)
	services = append(services, app.OwnedService{Name: "health", Service: healthServer})
	services = append(services, roleServices...)
	application, err := app.New(
		app.Options{
			Roles:           roles,
			ShutdownTimeout: processConfig.ShutdownTimeout,
		},
		readiness,
		monitor,
		resources,
		logger,
		services...,
	)
	if err != nil {
		logger.ErrorContext(ctx, "startup failed", "error_code", "invalid_application", "error", err)
		return 1
	}
	resourcesOwnedByApplication = true

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
