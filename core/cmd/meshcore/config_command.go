package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	redisadapter "github.com/meshtransit/meshtransit/core/internal/adapter/redis"
	"github.com/meshtransit/meshtransit/core/internal/platform/config"
	"github.com/meshtransit/meshtransit/core/internal/platform/observability"
)

type configValidationOutput struct {
	Status        string `json:"status"`
	SchemaVersion int    `json:"schema_version"`
	Role          string `json:"role"`
}

func runConfigValidate(
	ctx context.Context,
	lookup config.LookupFunc,
	output io.Writer,
	errorOutput io.Writer,
) int {
	logger, err := observability.NewLogger(errorOutput, slog.LevelInfo)
	if err != nil {
		return 1
	}
	processConfig, err := config.Load(lookup)
	if err != nil {
		logger.ErrorContext(ctx, "configuration validation failed", "error_code", "invalid_configuration", "error", err)
		return 1
	}
	if err := validateDependencyConfiguration(ctx, processConfig); err != nil {
		logger.ErrorContext(
			ctx,
			"configuration validation failed",
			"error_code", "invalid_dependency_configuration",
			"error", err,
		)
		return 1
	}
	result := configValidationOutput{
		Status:        "valid",
		SchemaVersion: config.SchemaVersion,
		Role:          processConfig.Role.String(),
	}
	if err := json.NewEncoder(output).Encode(result); err != nil {
		logger.ErrorContext(ctx, "configuration validation failed", "error_code", "output_failure")
		return 1
	}
	return 0
}

func validateDependencyConfiguration(ctx context.Context, processConfig config.Config) (returnErr error) {
	var privateProfile *config.PrivateLoginConfig
	if processConfig.PrivateLogin != nil {
		var err error
		privateProfile, err = processConfig.PrivateLogin.Load(ctx, processConfig)
		if err != nil {
			return errInvalidPrivateIdentityComposition
		}
	}
	if processConfig.Storage == nil && processConfig.Identity == nil {
		if privateProfile != nil {
			return errInvalidPrivateIdentityComposition
		}
		return nil
	}

	resources := &resourceOwner{}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(
			context.WithoutCancel(ctx),
			processConfig.ShutdownTimeout,
		)
		defer cancel()
		returnErr = errors.Join(returnErr, resources.Close(cleanupCtx))
	}()
	if processConfig.Identity != nil {
		logger, err := observability.NewLogger(io.Discard, slog.LevelInfo)
		if err != nil {
			return errInvalidIdentityBrokerComposition
		}
		broker, err := composeIdentityBroker(ctx, *processConfig.Identity, resources, logger)
		if err != nil {
			return err
		}
		for _, checker := range broker.checkers {
			checkCtx, cancel := context.WithTimeout(ctx, processConfig.Dependencies.CheckTimeout)
			checkErr := checker.Check(checkCtx)
			cancel()
			if checkErr != nil {
				return checkErr
			}
		}
	}
	if _, err := composeInvitationMailer(processConfig.Mail); err != nil {
		return fmt.Errorf("validate mail settings: %w", err)
	}
	if processConfig.Storage == nil {
		return nil
	}

	pools, err := openPostgresPools(
		ctx,
		processConfig.Storage.PostgreSQL,
		processConfig.Dependencies.CheckTimeout,
		resources,
	)
	if err != nil {
		return fmt.Errorf("validate postgresql settings: %w", err)
	}

	redisClient, err := redisadapter.Open(ctx, redisadapter.Options{
		Address:        processConfig.Storage.Redis.Address,
		Username:       processConfig.Storage.Redis.Username,
		PasswordFile:   processConfig.Storage.Redis.PasswordFile,
		CAFile:         processConfig.Storage.Redis.CAFile,
		PoolSize:       processConfig.Storage.Redis.PoolSize,
		RequestTimeout: processConfig.Dependencies.CheckTimeout,
	})
	if err != nil {
		return fmt.Errorf("validate redis settings: %w", err)
	}
	if err := resources.Add("redis", redisClient.Shutdown); err != nil {
		return errors.Join(err, redisClient.Shutdown(ctx))
	}
	if privateProfile != nil {
		logger, err := observability.NewLogger(io.Discard, slog.LevelInfo)
		if err != nil {
			return errInvalidPrivateIdentityComposition
		}
		factory, _, err := composePrivateIdentityRuntime(
			ctx,
			privateProfile,
			privateIdentityFactoryDependencies{Runtime: pools.runtime, Redis: redisClient, Logger: logger},
		)
		if err != nil {
			return errInvalidPrivateIdentityComposition
		}
		// No worker, readiness request or listener was started. Only idle clients
		// are owned here; borrowed pools remain owned by resources.
		factory.Close()
	}
	return nil
}
