CREATE POLICY workspace_scope_resolution_policy ON mesh.workspace
    FOR SELECT
    TO mesh_migrator
    USING (
        public_id = NULLIF(
            pg_catalog.current_setting('mesh.requested_workspace_public_id', TRUE),
            ''
        )::UUID
    );

CREATE POLICY network_scope_resolution_policy ON mesh.network
    FOR SELECT
    TO mesh_migrator
    USING (
        public_id = NULLIF(
            pg_catalog.current_setting('mesh.requested_network_public_id', TRUE),
            ''
        )::UUID
    );

CREATE FUNCTION mesh_ops.set_network_scope(
    p_workspace_public_id UUID,
    p_network_public_id UUID
)
RETURNS TABLE (
    workspace_internal_id BIGINT,
    network_internal_id BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    resolved_workspace_id BIGINT;
    resolved_network_id BIGINT;
    current_workspace_setting TEXT;
    current_network_setting TEXT;
    current_workspace_id BIGINT;
    current_network_id BIGINT;
BEGIN
    IF p_workspace_public_id IS NULL
        OR p_network_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_workspace_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_network_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'network scope is unavailable';
    END IF;

    PERFORM pg_catalog.set_config(
        'mesh.requested_workspace_public_id',
        p_workspace_public_id::TEXT,
        TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.requested_network_public_id',
        p_network_public_id::TEXT,
        TRUE
    );

    SELECT workspace.id, network.id
    INTO resolved_workspace_id, resolved_network_id
    FROM mesh.workspace AS workspace
    JOIN mesh.network AS network
      ON network.workspace_id = workspace.id
    WHERE workspace.public_id = p_workspace_public_id
      AND network.public_id = p_network_public_id;

    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.requested_network_public_id', '', TRUE);

    IF resolved_workspace_id IS NULL OR resolved_network_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'network scope is unavailable';
    END IF;

    current_workspace_setting := pg_catalog.current_setting('mesh.workspace_id', TRUE);
    current_network_setting := pg_catalog.current_setting('mesh.network_id', TRUE);
    IF COALESCE(current_workspace_setting, '') <> ''
        OR COALESCE(current_network_setting, '') <> '' THEN
        BEGIN
            current_workspace_id := current_workspace_setting::BIGINT;
            current_network_id := current_network_setting::BIGINT;
        EXCEPTION
            WHEN invalid_text_representation OR numeric_value_out_of_range THEN
                RAISE EXCEPTION USING
                    ERRCODE = '42501',
                    MESSAGE = 'transaction Network scope cannot be replaced';
        END;
        IF current_workspace_id IS NULL
            OR current_network_id IS NULL
            OR current_workspace_id <> resolved_workspace_id
            OR current_network_id <> resolved_network_id THEN
            RAISE EXCEPTION USING
                ERRCODE = '42501',
                MESSAGE = 'transaction Network scope cannot be replaced';
        END IF;
    ELSE
        PERFORM pg_catalog.set_config(
            'mesh.workspace_id',
            resolved_workspace_id::TEXT,
            TRUE
        );
        PERFORM pg_catalog.set_config(
            'mesh.network_id',
            resolved_network_id::TEXT,
            TRUE
        );
    END IF;

    workspace_internal_id := resolved_workspace_id;
    network_internal_id := resolved_network_id;
    RETURN NEXT;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.set_network_scope(UUID, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.set_network_scope(UUID, UUID)
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.set_network_scope(UUID, UUID) TO mesh_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
