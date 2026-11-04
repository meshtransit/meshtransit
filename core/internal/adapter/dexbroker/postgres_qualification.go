//go:build dexbroker && qualification

package dexbroker

import (
	"context"
	"log/slog"
)

// PreparePostgreSQLSchemaForQualification runs the dependency-owned schema
// migrations with an explicitly supplied migration identity, for the offline
// qualification tooling (the same migration "meshcore setup migrate" runs).
func PreparePostgreSQLSchemaForQualification(
	ctx context.Context,
	options PostgreSQLResourceOptions,
	logger *slog.Logger,
) error {
	return MigratePostgreSQLSchema(ctx, options, logger)
}
