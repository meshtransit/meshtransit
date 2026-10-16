package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	postgresadapter "meshtransit.net/core/internal/adapter/postgres"
	"meshtransit.net/core/internal/platform/config"
)

type postgresPools struct {
	runtime *postgresadapter.Pool
	worker  *postgresadapter.Pool
}

func openPostgresPools(
	ctx context.Context,
	postgresConfig config.PostgreSQLConfig,
	connectTimeout time.Duration,
	resources *resourceOwner,
	logger *slog.Logger,
) (postgresPools, error) {
	if ctx == nil || connectTimeout <= 0 || resources == nil {
		return postgresPools{}, errors.New("invalid postgres pool composition")
	}
	var pools postgresPools
	if postgresConfig.Runtime != nil {
		pool, err := openLoggedPostgresRolePool(
			ctx,
			postgresadapter.PoolRoleRuntime,
			postgresConfig,
			*postgresConfig.Runtime,
			connectTimeout,
			logger,
		)
		if err != nil {
			return postgresPools{}, fmt.Errorf("open runtime postgres pool: %w", err)
		}
		pools.runtime = pool
		if err := resources.Add("postgresql-runtime", pool.Shutdown); err != nil {
			return postgresPools{}, errors.Join(
				fmt.Errorf("own runtime postgres pool: %w", err),
				pool.Shutdown(ctx),
			)
		}
	}
	if postgresConfig.Worker != nil {
		pool, err := openLoggedPostgresRolePool(
			ctx,
			postgresadapter.PoolRoleWorker,
			postgresConfig,
			*postgresConfig.Worker,
			connectTimeout,
			logger,
		)
		if err != nil {
			return postgresPools{}, fmt.Errorf("open worker postgres pool: %w", err)
		}
		pools.worker = pool
		if err := resources.Add("postgresql-worker", pool.Shutdown); err != nil {
			return postgresPools{}, errors.Join(
				fmt.Errorf("own worker postgres pool: %w", err),
				pool.Shutdown(ctx),
			)
		}
	}
	if pools.runtime == nil && pools.worker == nil {
		return postgresPools{}, errors.New("postgres role pool is required")
	}
	return pools, nil
}

func openPostgresRolePool(
	ctx context.Context,
	poolRole postgresadapter.PoolRole,
	postgresConfig config.PostgreSQLConfig,
	roleConfig config.PostgreSQLRoleConfig,
	connectTimeout time.Duration,
) (*postgresadapter.Pool, error) {
	return openLoggedPostgresRolePool(ctx, poolRole, postgresConfig, roleConfig, connectTimeout, nil)
}

// openLoggedPostgresRolePool opens a pool whose logger reports the function
// versions its paths select and the pending operator steps.
func openLoggedPostgresRolePool(
	ctx context.Context,
	poolRole postgresadapter.PoolRole,
	postgresConfig config.PostgreSQLConfig,
	roleConfig config.PostgreSQLRoleConfig,
	connectTimeout time.Duration,
	logger *slog.Logger,
) (*postgresadapter.Pool, error) {
	return postgresadapter.Open(ctx, postgresadapter.Options{
		Role:           poolRole,
		Address:        postgresConfig.Address,
		Database:       postgresConfig.Database,
		User:           roleConfig.User,
		PasswordFile:   roleConfig.PasswordFile,
		CAFile:         postgresConfig.CAFile,
		MaxConnections: roleConfig.MaxConnections,
		ConnectTimeout: connectTimeout,
		Logger:         logger,
	})
}

func (pools postgresPools) healthChecker() (*postgresadapter.HealthChecker, error) {
	return postgresadapter.NewHealthChecker(pools.runtime, pools.worker)
}

func (pools postgresPools) metricsCollector() (prometheus.Collector, error) {
	configured := make([]*postgresadapter.Pool, 0, 2)
	if pools.runtime != nil {
		configured = append(configured, pools.runtime)
	}
	if pools.worker != nil {
		configured = append(configured, pools.worker)
	}
	return postgresadapter.NewMetricsCollector(configured...)
}
