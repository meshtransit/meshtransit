ALTER TABLE mesh.pending_registration
    ADD COLUMN intent_format_version SMALLINT NOT NULL DEFAULT 1,
    ADD COLUMN requested_node_key BYTEA,
    ADD COLUMN completed_hostname TEXT,
    ADD COLUMN completed_disposition TEXT,
    ADD COLUMN completed_network_revision BIGINT;

ALTER TABLE mesh.pending_registration
    ALTER COLUMN intent_format_version SET DEFAULT 2;

ALTER TABLE mesh.pending_registration
    ADD CONSTRAINT pending_registration_intent_format_check CHECK (
        intent_format_version IN (1, 2)
    ),
    ADD CONSTRAINT pending_registration_requested_node_key_check CHECK (
        intent_format_version = 1
        OR (
            requested_node_key IS NOT NULL
            AND pg_catalog.octet_length(requested_node_key) = 32
        )
    ),
    ADD CONSTRAINT pending_registration_completion_replay_check CHECK (
        intent_format_version = 1
        OR (
            state = 'completed'
            AND completed_hostname IS NOT NULL
            AND pg_catalog.char_length(completed_hostname) BETWEEN 1 AND 253
            AND completed_hostname = pg_catalog.btrim(completed_hostname)
            AND completed_disposition IS NOT NULL
            AND completed_disposition IN ('created', 'resumed')
            AND completed_network_revision IS NOT NULL
            AND completed_network_revision > 0
        )
        OR (
            state <> 'completed'
            AND completed_hostname IS NULL
            AND completed_disposition IS NULL
            AND completed_network_revision IS NULL
        )
    );

GRANT UPDATE (
    completed_hostname,
    completed_disposition,
    completed_network_revision
) ON mesh.pending_registration TO mesh_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE ALL ON TABLES FROM PUBLIC;
