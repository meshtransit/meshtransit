package postgres

import (
	"strconv"
	"time"
)

const (
	migrationLockKey int64 = 0x4d54524d49475231

	migrationTimeoutsSQL = `SELECT
    pg_catalog.set_config('statement_timeout', $1, true),
    pg_catalog.set_config('lock_timeout', $2, true),
    pg_catalog.set_config('idle_in_transaction_session_timeout', $1, true)`
	migrationLockSQL      = `SELECT pg_catalog.pg_advisory_xact_lock($1)`
	migrationPreflightSQL = `SELECT
    pg_catalog.current_setting('server_version_num')::integer,
    COALESCE((SELECT extension.extversion FROM pg_catalog.pg_extension AS extension WHERE extension.extname = 'btree_gist'), ''),
    CURRENT_USER::text,
    role.rolsuper,
    role.rolcreatedb,
    role.rolcreaterole,
    role.rolreplication,
    role.rolbypassrls,
    EXISTS (
        SELECT 1
        FROM pg_catalog.pg_database AS database
        WHERE database.datname = pg_catalog.current_database()
          AND database.datdba = role.oid
    ),
    (
        SELECT
            pg_catalog.count(*) = pg_catalog.cardinality($1::text[])
            AND COALESCE(
                pg_catalog.bool_and(
                    NOT support.rolsuper
                    AND NOT support.rolcreatedb
                    AND NOT support.rolcreaterole
                    AND NOT support.rolreplication
                    AND NOT support.rolbypassrls
                    AND support.rolcanlogin = (
                        support.rolname IN ('mesh_runtime', 'mesh_worker', 'mesh_observer')
                    )
                ),
                FALSE
            )
        FROM pg_catalog.pg_roles AS support
        WHERE support.rolname = ANY($1::text[])
    ),
    NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_auth_members AS membership
        JOIN pg_catalog.pg_roles AS granted_role ON granted_role.oid = membership.roleid
        JOIN pg_catalog.pg_roles AS member_role ON member_role.oid = membership.member
        WHERE member_role.rolname = CURRENT_USER
           OR granted_role.rolname = CURRENT_USER
           OR member_role.rolname = ANY($1::text[])
           OR granted_role.rolname = ANY($1::text[])
    )
FROM pg_catalog.pg_roles AS role
WHERE role.rolname = CURRENT_USER`
	migrationObjectsSQL = `SELECT
    pg_catalog.to_regclass('mesh_ops.schema_migration') IS NOT NULL,
    pg_catalog.to_regclass('mesh_ops.schema_compatibility') IS NOT NULL,
    pg_catalog.to_regclass('mesh_ops.data_backfill') IS NOT NULL`
	appliedMigrationsSQL = `SELECT version, checksum, result
FROM mesh_ops.schema_migration
ORDER BY version`
	migrationCompatibilitySQL = `SELECT
    current_schema_version,
    minimum_reader_generation,
    maximum_reader_generation,
    minimum_writer_generation,
    maximum_writer_generation,
    migration_state
FROM mesh_ops.schema_compatibility
WHERE singleton = TRUE`
	recordMigrationSQL = `INSERT INTO mesh_ops.schema_migration (
    version,
    checksum,
    description,
    code_release,
    actor,
    started_at,
    finished_at,
    result,
    failure_class
) VALUES (
    $1,
    $2,
    $3,
    $4,
    $5,
    pg_catalog.transaction_timestamp(),
    pg_catalog.clock_timestamp(),
    'succeeded',
    NULL
)`
	markCompatibilityDirtySQL = `UPDATE mesh_ops.schema_compatibility
SET migration_state = 'dirty', last_verified_at = pg_catalog.clock_timestamp()
WHERE singleton = TRUE`
	upsertCompatibilitySQL = `INSERT INTO mesh_ops.schema_compatibility (
    singleton,
    current_schema_version,
    minimum_reader_generation,
    maximum_reader_generation,
    minimum_writer_generation,
    maximum_writer_generation,
    migration_state,
    last_verified_at
) VALUES (TRUE, $1, $2, $3, $4, $5, 'clean', pg_catalog.clock_timestamp())
ON CONFLICT (singleton) DO UPDATE SET
    current_schema_version = EXCLUDED.current_schema_version,
    minimum_reader_generation = EXCLUDED.minimum_reader_generation,
    maximum_reader_generation = EXCLUDED.maximum_reader_generation,
    minimum_writer_generation = EXCLUDED.minimum_writer_generation,
    maximum_writer_generation = EXCLUDED.maximum_writer_generation,
    migration_state = EXCLUDED.migration_state,
    last_verified_at = EXCLUDED.last_verified_at`
)

func postgresTimeoutValue(duration time.Duration) string {
	return strconv.FormatInt(duration.Milliseconds(), 10) + "ms"
}
