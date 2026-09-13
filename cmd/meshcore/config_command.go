package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	redisadapter "github.com/meshtransit/meshtransit/internal/adapter/redis"
	"github.com/meshtransit/meshtransit/internal/config"
	"github.com/meshtransit/meshtransit/internal/observability"
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
	if processConfig.Storage == nil {
		return nil
	}

	resources := &resourceOwner{}
	defer func() {
		returnErr = errors.Join(returnErr, resources.Close())
	}()

	postgresPool, err := postgresadapter.Open(ctx, postgresadapter.Options{
		Address:        processConfig.Storage.PostgreSQL.Address,
		Database:       processConfig.Storage.PostgreSQL.Database,
		User:           processConfig.Storage.PostgreSQL.User,
		PasswordFile:   processConfig.Storage.PostgreSQL.PasswordFile,
		CAFile:         processConfig.Storage.PostgreSQL.CAFile,
		MaxConnections: processConfig.Storage.PostgreSQL.MaxConnections,
		ConnectTimeout: processConfig.Dependencies.CheckTimeout,
	})
	if err != nil {
		return fmt.Errorf("validate postgresql settings: %w", err)
	}
	resources.Add("postgresql", postgresPool.Close)

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
	resources.Add("redis", redisClient.Close)
	return nil
}
