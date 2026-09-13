package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/config"
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
) (postgresPools, error) {
	if ctx == nil || connectTimeout <= 0 || resources == nil {
		return postgresPools{}, errors.New("invalid postgres pool composition")
	}
	var pools postgresPools
	if postgresConfig.Runtime != nil {
		pool, err := openPostgresRolePool(ctx, postgresConfig, *postgresConfig.Runtime, connectTimeout)
		if err != nil {
			return postgresPools{}, fmt.Errorf("open runtime postgres pool: %w", err)
		}
		pools.runtime = pool
		resources.Add("postgresql-runtime", pool.Close)
	}
	if postgresConfig.Worker != nil {
		pool, err := openPostgresRolePool(ctx, postgresConfig, *postgresConfig.Worker, connectTimeout)
		if err != nil {
			return postgresPools{}, fmt.Errorf("open worker postgres pool: %w", err)
		}
		pools.worker = pool
		resources.Add("postgresql-worker", pool.Close)
	}
	if pools.runtime == nil && pools.worker == nil {
		return postgresPools{}, errors.New("postgres role pool is required")
	}
	return pools, nil
}

func openPostgresRolePool(
	ctx context.Context,
	postgresConfig config.PostgreSQLConfig,
	roleConfig config.PostgreSQLRoleConfig,
	connectTimeout time.Duration,
) (*postgresadapter.Pool, error) {
	return postgresadapter.Open(ctx, postgresadapter.Options{
		Address:        postgresConfig.Address,
		Database:       postgresConfig.Database,
		User:           roleConfig.User,
		PasswordFile:   roleConfig.PasswordFile,
		CAFile:         postgresConfig.CAFile,
		MaxConnections: roleConfig.MaxConnections,
		ConnectTimeout: connectTimeout,
	})
}

func (pools postgresPools) healthChecker() (*postgresadapter.HealthChecker, error) {
	return postgresadapter.NewHealthChecker(pools.runtime, pools.worker)
}
