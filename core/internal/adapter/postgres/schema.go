package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"meshtransit.net/core/migrations"
)

const runtimeSchemaCompatibilitySQL = `SELECT
    compatibility.current_schema_version,
    compatibility.minimum_reader_generation,
    compatibility.maximum_reader_generation,
    compatibility.minimum_writer_generation,
    compatibility.maximum_writer_generation,
    compatibility.migration_state,
    migration.checksum,
    migration.result,
    (
        (
            SELECT
                pg_catalog.count(*) = compatibility.current_schema_version
                AND COALESCE(pg_catalog.bool_and(history.result = 'succeeded'), FALSE)
            FROM mesh_ops.schema_migration AS history
            WHERE history.version <= compatibility.current_schema_version
        )
        AND NOT EXISTS (
            SELECT 1
            FROM mesh_ops.schema_migration AS future
            WHERE future.version > compatibility.current_schema_version
        )
        AND NOT EXISTS (
            SELECT 1
            FROM pg_catalog.unnest($1::text[]) WITH ORDINALITY AS expected(checksum, version)
            LEFT JOIN mesh_ops.schema_migration AS known
                ON known.version = expected.version
            WHERE expected.version <= compatibility.current_schema_version
              AND (
                  known.version IS NULL
                  OR known.checksum <> expected.checksum
                  OR known.result <> 'succeeded'
              )
        )
    ) AS known_history_valid,
    runtime_role.rolname,
    (
        runtime_role.rolcanlogin
        AND NOT runtime_role.rolsuper
        AND NOT runtime_role.rolcreatedb
        AND NOT runtime_role.rolcreaterole
        AND NOT runtime_role.rolreplication
        AND NOT runtime_role.rolbypassrls
        AND NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_auth_members AS membership
            WHERE membership.member = runtime_role.oid
        )
        AND NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_database AS database
            WHERE database.datdba = runtime_role.oid
        )
        AND NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_namespace AS namespace
            WHERE namespace.nspowner = runtime_role.oid
              AND namespace.nspname IN ('mesh', 'mesh_ops', 'mesh_audit')
        )
        AND NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_class AS relation
            JOIN pg_catalog.pg_namespace AS namespace
                ON namespace.oid = relation.relnamespace
            WHERE relation.relowner = runtime_role.oid
              AND namespace.nspname IN ('mesh', 'mesh_ops', 'mesh_audit')
        )
        AND NOT EXISTS (
            SELECT 1
            FROM pg_catalog.pg_proc AS routine
            JOIN pg_catalog.pg_namespace AS namespace
                ON namespace.oid = routine.pronamespace
            WHERE routine.proowner = runtime_role.oid
              AND namespace.nspname IN ('mesh', 'mesh_ops', 'mesh_audit')
        )
    ) AS runtime_role_safe
FROM mesh_ops.schema_compatibility AS compatibility
JOIN mesh_ops.schema_migration AS migration
    ON migration.version = compatibility.current_schema_version
JOIN pg_catalog.pg_roles AS runtime_role
    ON runtime_role.rolname = CURRENT_USER
WHERE compatibility.singleton = TRUE`

var (
	// ErrSchemaIncompatible indicates that runtime authority must remain closed
	// because the durable schema cannot safely serve this binary generation.
	ErrSchemaIncompatible = errors.New("postgres schema is incompatible")
)

type runtimeSchemaQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type runtimeSchemaCompatibility struct {
	currentVersion          int64
	minimumReaderGeneration int64
	maximumReaderGeneration int64
	minimumWriterGeneration int64
	maximumWriterGeneration int64
	migrationState          string
	currentChecksum         string
	migrationResult         string
	knownHistoryValid       bool
	currentUser             string
	runtimeRoleSafe         bool
}

func checkRuntimeSchemaCompatibility(
	ctx context.Context,
	querier runtimeSchemaQuerier,
	expectedUser string,
) error {
	if ctx == nil || querier == nil || expectedUser == "" {
		return ErrSchemaIncompatible
	}
	catalog := migrations.Catalog()
	checksums := make([]string, len(catalog))
	for index, migration := range catalog {
		checksums[index] = migration.Checksum
	}

	var compatibility runtimeSchemaCompatibility
	if err := querier.QueryRow(ctx, runtimeSchemaCompatibilitySQL, checksums).Scan(
		&compatibility.currentVersion,
		&compatibility.minimumReaderGeneration,
		&compatibility.maximumReaderGeneration,
		&compatibility.minimumWriterGeneration,
		&compatibility.maximumWriterGeneration,
		&compatibility.migrationState,
		&compatibility.currentChecksum,
		&compatibility.migrationResult,
		&compatibility.knownHistoryValid,
		&compatibility.currentUser,
		&compatibility.runtimeRoleSafe,
	); err != nil {
		return errors.Join(ErrSchemaIncompatible, err)
	}
	return validateRuntimeSchemaCompatibility(
		catalog,
		migrations.ApplicationGeneration,
		expectedUser,
		compatibility,
	)
}

func validateRuntimeSchemaCompatibility(
	catalog []migrations.Migration,
	applicationGeneration int64,
	expectedUser string,
	compatibility runtimeSchemaCompatibility,
) error {
	if !validMigrationCatalog(catalog) || compatibility.currentVersion <= 0 ||
		compatibility.migrationState != "clean" || compatibility.migrationResult != "succeeded" ||
		!compatibility.knownHistoryValid || compatibility.currentUser != expectedUser ||
		!compatibility.runtimeRoleSafe ||
		!withinGeneration(
			applicationGeneration,
			compatibility.minimumReaderGeneration,
			compatibility.maximumReaderGeneration,
		) ||
		!withinGeneration(
			applicationGeneration,
			compatibility.minimumWriterGeneration,
			compatibility.maximumWriterGeneration,
		) {
		return ErrSchemaIncompatible
	}
	// The binary calls objects up to its newest migration, so an older schema
	// must stay closed. A newer schema stays open: expand-only migrations keep
	// the previous binary working during a rollback.
	latestVersion := int64(len(catalog))
	if compatibility.currentVersion < latestVersion {
		return fmt.Errorf(
			"%w: schema version %d is older than binary version %d",
			ErrSchemaIncompatible,
			compatibility.currentVersion,
			latestVersion,
		)
	}
	if compatibility.currentVersion == latestVersion &&
		compatibility.currentChecksum != catalog[latestVersion-1].Checksum {
		return ErrSchemaIncompatible
	}
	return nil
}
