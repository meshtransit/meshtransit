CREATE POLICY network_revision_scoped_read_policy ON mesh_ops.network_revision
    FOR SELECT
    TO mesh_migrator
    USING (
        workspace_id = NULLIF(
            pg_catalog.current_setting('mesh.workspace_id', TRUE),
            ''
        )::BIGINT
        AND network_id = NULLIF(
            pg_catalog.current_setting('mesh.network_id', TRUE),
            ''
        )::BIGINT
    );

CREATE POLICY network_revision_scoped_mutation_policy ON mesh_ops.network_revision
    FOR UPDATE
    TO mesh_migrator
    USING (
        workspace_id = NULLIF(
            pg_catalog.current_setting('mesh.workspace_id', TRUE),
            ''
        )::BIGINT
        AND network_id = NULLIF(
            pg_catalog.current_setting('mesh.network_id', TRUE),
            ''
        )::BIGINT
    )
    WITH CHECK (
        workspace_id = NULLIF(
            pg_catalog.current_setting('mesh.workspace_id', TRUE),
            ''
        )::BIGINT
        AND network_id = NULLIF(
            pg_catalog.current_setting('mesh.network_id', TRUE),
            ''
        )::BIGINT
    );

CREATE FUNCTION mesh_ops.advance_network_inventory_revision()
RETURNS TABLE (
    network_revision BIGINT,
    inventory_revision BIGINT
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
    advanced_inventory_revision BIGINT;
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
        inventory_revision = revision.inventory_revision + 1,
        updated_at = pg_catalog.clock_timestamp()
    WHERE revision.workspace_id = scoped_workspace_id
      AND revision.network_id = scoped_network_id
    RETURNING revision.network_revision, revision.inventory_revision
    INTO advanced_network_revision, advanced_inventory_revision;

    IF advanced_network_revision IS NULL OR advanced_inventory_revision IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'Network revision is unavailable';
    END IF;

    network_revision := advanced_network_revision;
    inventory_revision := advanced_inventory_revision;
    RETURN NEXT;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.advance_network_inventory_revision() FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.advance_network_inventory_revision()
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.advance_network_inventory_revision() TO mesh_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
