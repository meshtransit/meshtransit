//go:build !dexbroker

package main

import (
	"context"
	"log/slog"

	"meshtransit.net/core/internal/platform/config"
)

// migrateIdentityStorage needs the dexbroker build, where meshcore setup
// runs.
func migrateIdentityStorage(context.Context, config.MigrationConfig, *slog.Logger) error {
	return errIdentityBrokerUnavailable
}
