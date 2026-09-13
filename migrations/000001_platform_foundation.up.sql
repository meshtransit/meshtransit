CREATE SCHEMA mesh;
CREATE SCHEMA mesh_ops;
CREATE SCHEMA mesh_audit;

DO $database_privileges$
BEGIN
    EXECUTE pg_catalog.format(
        'REVOKE ALL ON DATABASE %I FROM PUBLIC',
        pg_catalog.current_database()
    );
    EXECUTE pg_catalog.format(
        'GRANT CONNECT ON DATABASE %I TO mesh_runtime, mesh_worker',
        pg_catalog.current_database()
    );
END;
$database_privileges$;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA mesh FROM PUBLIC;
REVOKE ALL ON SCHEMA mesh_ops FROM PUBLIC;
REVOKE ALL ON SCHEMA mesh_audit FROM PUBLIC;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_audit REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_audit REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_audit REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE TABLE mesh_ops.schema_migration (
    version BIGINT PRIMARY KEY CHECK (version > 0),
    checksum TEXT NOT NULL CHECK (checksum ~ '^[0-9a-f]{64}$'),
    description TEXT NOT NULL CHECK (
        char_length(description) BETWEEN 1 AND 128
        AND description = btrim(description)
    ),
    code_release TEXT NOT NULL CHECK (
        char_length(code_release) BETWEEN 1 AND 128
        AND code_release = btrim(code_release)
    ),
    actor TEXT NOT NULL CHECK (
        char_length(actor) BETWEEN 1 AND 128
        AND actor = btrim(actor)
    ),
    started_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ NOT NULL,
    result TEXT NOT NULL CHECK (result IN ('succeeded', 'failed')),
    failure_class TEXT CHECK (
        failure_class IS NULL
        OR char_length(failure_class) BETWEEN 1 AND 64
    ),
    CHECK (finished_at >= started_at),
    CHECK (
        (result = 'succeeded' AND failure_class IS NULL)
        OR (result = 'failed' AND failure_class IS NOT NULL)
    )
);

CREATE TABLE mesh_ops.schema_compatibility (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    current_schema_version BIGINT NOT NULL CHECK (current_schema_version > 0),
    minimum_reader_generation BIGINT NOT NULL CHECK (minimum_reader_generation > 0),
    maximum_reader_generation BIGINT NOT NULL CHECK (maximum_reader_generation > 0),
    minimum_writer_generation BIGINT NOT NULL CHECK (minimum_writer_generation > 0),
    maximum_writer_generation BIGINT NOT NULL CHECK (maximum_writer_generation > 0),
    migration_state TEXT NOT NULL CHECK (migration_state IN ('clean', 'dirty')),
    last_verified_at TIMESTAMPTZ NOT NULL,
    CHECK (minimum_reader_generation <= maximum_reader_generation),
    CHECK (minimum_writer_generation <= maximum_writer_generation)
);

CREATE TABLE mesh_ops.data_backfill (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name TEXT NOT NULL CHECK (
        char_length(name) BETWEEN 1 AND 128
        AND name = btrim(name)
    ),
    version BIGINT NOT NULL CHECK (version > 0),
    keyset_cursor BIGINT CHECK (keyset_cursor >= 0),
    processed_count BIGINT NOT NULL DEFAULT 0 CHECK (processed_count >= 0),
    semantic_checksum TEXT CHECK (
        semantic_checksum IS NULL
        OR semantic_checksum ~ '^[0-9a-f]{64}$'
    ),
    state TEXT NOT NULL CHECK (state IN ('pending', 'running', 'succeeded', 'failed')),
    error_class TEXT CHECK (
        error_class IS NULL
        OR char_length(error_class) BETWEEN 1 AND 64
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (name, version),
    CHECK (updated_at >= created_at),
    CHECK (state = 'failed' OR error_class IS NULL)
);

REVOKE ALL ON ALL TABLES IN SCHEMA mesh_ops FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA mesh_ops FROM PUBLIC;
