CREATE FUNCTION mesh_ops.int4multirange_count(p_value INT4MULTIRANGE)
RETURNS INTEGER
LANGUAGE SQL
IMMUTABLE
PARALLEL SAFE
STRICT
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.count(*)::INTEGER
    FROM pg_catalog.unnest(p_value)
$function$;

CREATE TABLE mesh.policy_release (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    policy_revision BIGINT NOT NULL CHECK (policy_revision > 0),
    semantic_hash BYTEA NOT NULL,
    compiler_format_version INTEGER NOT NULL CHECK (compiler_format_version > 0),
    state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    activated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    superseded_at TIMESTAMPTZ,
    CONSTRAINT policy_release_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT policy_release_semantic_hash_check CHECK (
        pg_catalog.octet_length(semantic_hash) = 32
    ),
    CONSTRAINT policy_release_state_check CHECK (state IN ('active', 'superseded')),
    CONSTRAINT policy_release_state_shape_check CHECK (
        (state = 'active' AND superseded_at IS NULL)
        OR (
            state = 'superseded'
            AND superseded_at IS NOT NULL
            AND superseded_at >= activated_at
        )
    ),
    CONSTRAINT policy_release_timestamps_check CHECK (activated_at >= created_at),
    CONSTRAINT policy_release_network_scope_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    UNIQUE (workspace_id, network_id, policy_revision),
    UNIQUE (workspace_id, network_id, id, policy_revision)
);

CREATE UNIQUE INDEX policy_release_active_uidx
    ON mesh.policy_release (workspace_id, network_id)
    WHERE state = 'active';

CREATE TABLE mesh.compiled_policy_rule (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    access_rule_public_id UUID NOT NULL,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    policy_release_id BIGINT NOT NULL,
    policy_revision BIGINT NOT NULL CHECK (policy_revision > 0),
    source_device_id BIGINT NOT NULL,
    destination_device_id BIGINT NOT NULL,
    protocol TEXT NOT NULL,
    destination_ports INT4MULTIRANGE NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT compiled_policy_rule_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT compiled_policy_rule_access_rule_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(access_rule_public_id), 6) >> 4 = 7
    ),
    CONSTRAINT compiled_policy_rule_distinct_devices_check CHECK (
        source_device_id <> destination_device_id
    ),
    CONSTRAINT compiled_policy_rule_protocol_check CHECK (
        protocol IN ('tcp', 'udp', 'icmp')
    ),
    CONSTRAINT compiled_policy_rule_port_shape_check CHECK (
        (
            protocol = 'icmp'
            AND destination_ports = '{}'::INT4MULTIRANGE
        )
        OR (
            protocol IN ('tcp', 'udp')
            AND NOT pg_catalog.isempty(destination_ports)
            AND destination_ports <@ '{[1,65536)}'::INT4MULTIRANGE
            AND mesh_ops.int4multirange_count(destination_ports) BETWEEN 1 AND 64
        )
    ),
    CONSTRAINT compiled_policy_rule_release_scope_fk FOREIGN KEY (
        workspace_id,
        network_id,
        policy_release_id,
        policy_revision
    ) REFERENCES mesh.policy_release (
        workspace_id,
        network_id,
        id,
        policy_revision
    ) ON DELETE RESTRICT,
    CONSTRAINT compiled_policy_rule_source_device_scope_fk FOREIGN KEY (
        workspace_id,
        network_id,
        source_device_id
    ) REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT compiled_policy_rule_destination_device_scope_fk FOREIGN KEY (
        workspace_id,
        network_id,
        destination_device_id
    ) REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT compiled_policy_rule_edge_unique UNIQUE (
        workspace_id,
        network_id,
        policy_release_id,
        access_rule_public_id,
        source_device_id,
        destination_device_id,
        protocol
    )
);

CREATE INDEX compiled_policy_rule_source_projection_idx
    ON mesh.compiled_policy_rule (
        workspace_id,
        network_id,
        policy_revision,
        source_device_id,
        access_rule_public_id,
        id
    );
CREATE INDEX compiled_policy_rule_destination_projection_idx
    ON mesh.compiled_policy_rule (
        workspace_id,
        network_id,
        policy_revision,
        destination_device_id,
        access_rule_public_id,
        id
    );

ALTER TABLE mesh.policy_release ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.policy_release FORCE ROW LEVEL SECURITY;
CREATE POLICY policy_release_migrator_policy ON mesh.policy_release
    TO mesh_migrator
    USING (TRUE)
    WITH CHECK (TRUE);
CREATE POLICY policy_release_exact_scope_policy ON mesh.policy_release
    TO mesh_runtime
    USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    )
    WITH CHECK (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    );

ALTER TABLE mesh.compiled_policy_rule ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.compiled_policy_rule FORCE ROW LEVEL SECURITY;
CREATE POLICY compiled_policy_rule_migrator_policy ON mesh.compiled_policy_rule
    TO mesh_migrator
    USING (TRUE)
    WITH CHECK (TRUE);
CREATE POLICY compiled_policy_rule_exact_scope_policy ON mesh.compiled_policy_rule
    TO mesh_runtime
    USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    )
    WITH CHECK (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    );

CREATE TRIGGER policy_release_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.policy_release
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('policy_release', 'public_id');
CREATE TRIGGER compiled_policy_rule_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.compiled_policy_rule
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('compiled_policy_rule', 'public_id');
CREATE TRIGGER compiled_policy_rule_immutable
BEFORE UPDATE OR DELETE ON mesh.compiled_policy_rule
FOR EACH ROW EXECUTE FUNCTION mesh_audit.reject_immutable_change();

CREATE FUNCTION mesh_ops.advance_network_policy_revision()
RETURNS TABLE (
    network_revision BIGINT,
    policy_revision BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
    advanced_network_revision BIGINT;
    advanced_policy_revision BIGINT;
BEGIN
    BEGIN
        scoped_workspace_id := NULLIF(
            pg_catalog.current_setting('mesh.workspace_id', TRUE),
            ''
        )::BIGINT;
        scoped_network_id := NULLIF(
            pg_catalog.current_setting('mesh.network_id', TRUE),
            ''
        )::BIGINT;
    EXCEPTION
        WHEN invalid_text_representation OR numeric_value_out_of_range THEN
            RAISE EXCEPTION USING
                ERRCODE = '42501',
                MESSAGE = 'transaction Network scope is unavailable';
    END;

    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'transaction Network scope is unavailable';
    END IF;

    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        policy_revision = revision.policy_revision + 1,
        updated_at = pg_catalog.clock_timestamp()
    WHERE revision.workspace_id = scoped_workspace_id
      AND revision.network_id = scoped_network_id
    RETURNING revision.network_revision, revision.policy_revision
    INTO advanced_network_revision, advanced_policy_revision;

    IF advanced_network_revision IS NULL OR advanced_policy_revision IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'Network revision is unavailable';
    END IF;

    network_revision := advanced_network_revision;
    policy_revision := advanced_policy_revision;
    RETURN NEXT;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.int4multirange_count(INT4MULTIRANGE) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.advance_network_policy_revision() FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.advance_network_policy_revision()
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.advance_network_policy_revision() TO mesh_runtime;

REVOKE ALL ON
    mesh.policy_release,
    mesh.compiled_policy_rule
    FROM mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT SELECT ON
    mesh.policy_release,
    mesh.compiled_policy_rule
    TO mesh_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
