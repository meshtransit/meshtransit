//go:build dexbroker && qualification

package dexbroker

import (
	"context"
	"log/slog"

	dexsql "github.com/dexidp/dex/storage/sql"
)

// PreparePostgreSQLSchemaForQualification runs the dependency-owned schema
// migrations with an explicitly supplied migration identity. It is available
// only to offline qualification tooling; runtime composition cannot link it.
func PreparePostgreSQLSchemaForQualification(
	ctx context.Context,
	options PostgreSQLResourceOptions,
	logger *slog.Logger,
) error {
	return preparePostgreSQLSchemaForQualification(ctx, options, logger, func(
		postgres *dexsql.Postgres,
		logger *slog.Logger,
	) (interface{ Close() error }, error) {
		return postgres.Open(logger)
	})
}

func preparePostgreSQLSchemaForQualification(
	ctx context.Context,
	options PostgreSQLResourceOptions,
	logger *slog.Logger,
	opener func(*dexsql.Postgres, *slog.Logger) (interface{ Close() error }, error),
) error {
	if opener == nil {
		return ErrInvalidPostgreSQLResource
	}
	host, port, valid := validatePostgreSQLResourceOptions(ctx, options, logger)
	if !valid {
		return ErrInvalidPostgreSQLResource
	}
	postgres, err := newPostgreSQLStorageConfiguration(options, host, port)
	if err != nil {
		return err
	}
	storage, err := opener(postgres, logger)
	if err != nil || storage == nil {
		if storage != nil {
			_ = storage.Close()
		}
		return ErrOpenPostgreSQLResource
	}
	if err := storage.Close(); err != nil {
		return ErrClosePostgreSQLResource
	}
	return nil
}
