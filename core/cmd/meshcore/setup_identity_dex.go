//go:build dexbroker

package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"meshtransit.net/core/internal/adapter/dexbroker"
	"meshtransit.net/core/internal/platform/config"
	"meshtransit.net/core/internal/platform/selfhost"
)

// migrateIdentityStorage brings the broker's database to the pinned
// broker's schema with its migration identity (meshcore setup migrate).
func migrateIdentityStorage(ctx context.Context, migration config.MigrationConfig, logger *slog.Logger) error {
	if migration.PostgreSQL.User == selfhost.IdentityRuntimeRole {
		return errors.New("the broker's runtime identity never migrates its schema")
	}
	return dexbroker.MigratePostgreSQLSchema(ctx, dexbroker.PostgreSQLResourceOptions{
		Address: migration.PostgreSQL.Address, Database: migration.PostgreSQL.Database,
		User: migration.PostgreSQL.User, PasswordFile: migration.PostgreSQL.PasswordFile,
		CAFile: migration.PostgreSQL.CAFile, MaxOpenConnections: 1, MaxIdleConnections: 1,
		ConnectTimeout: migration.ConnectTimeout, MaxConnectionLifetime: time.Minute,
	}, logger)
}
