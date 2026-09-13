CREATE FUNCTION mesh_audit.lock_network_stream_head()
RETURNS TABLE (
    stream_internal_id BIGINT,
    next_sequence BIGINT,
    latest_event_hash BYTEA
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh_audit, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
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

    RETURN QUERY
    SELECT
        stream.id,
        stream.next_sequence,
        stream.latest_event_hash
    FROM mesh_audit.audit_stream AS stream
    WHERE stream.scope_kind = 'network'
      AND stream.workspace_id = scoped_workspace_id
      AND stream.network_id = scoped_network_id
    FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'Network audit stream is unavailable';
    END IF;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_audit.lock_network_stream_head() FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_audit.lock_network_stream_head()
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

GRANT USAGE ON SCHEMA mesh_audit TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_audit.lock_network_stream_head() TO mesh_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_audit REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
