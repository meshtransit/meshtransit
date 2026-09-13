CREATE FUNCTION mesh_ops.lock_registration_credential(
    p_credential_public_id UUID
)
RETURNS TABLE (
    credential_internal_id BIGINT,
    profile_internal_id BIGINT,
    issuer_internal_id BIGINT,
    issuer_public_id TEXT,
    credential_state TEXT,
    use_limit_kind TEXT,
    max_uses BIGINT,
    used_count BIGINT,
    issued_recovery_epoch BIGINT,
    valid_from TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    credential_version BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
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
        credential.id,
        credential.enrollment_profile_id,
        credential.issuer_principal_id,
        principal.public_id::TEXT,
        credential.state,
        credential.use_limit_kind,
        credential.max_uses,
        credential.used_count,
        credential.issued_recovery_epoch,
        credential.valid_from,
        credential.expires_at,
        credential.version
    FROM mesh.enrollment_credential AS credential
    JOIN mesh.principal AS principal ON principal.id = credential.issuer_principal_id
    WHERE credential.workspace_id = scoped_workspace_id
      AND credential.network_id = scoped_network_id
      AND credential.public_id = p_credential_public_id
    FOR UPDATE OF credential;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'scoped enrollment credential is unavailable';
    END IF;
END;
$function$;

CREATE FUNCTION mesh_ops.lock_registration_prefixes(
    p_limit BIGINT
)
RETURNS TABLE (
    prefix_internal_id BIGINT,
    address_realm_internal_id BIGINT,
    address_pool_internal_id BIGINT,
    prefix_value TEXT,
    address_family INTEGER
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY INVOKER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
    allocator RECORD;
BEGIN
    IF p_limit <= 0 OR p_limit > 9 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'registration prefix lock limit is invalid';
    END IF;

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

    FOR allocator IN
        SELECT DISTINCT
            candidate.address_realm_id,
            candidate.address_pool_id
        FROM (
            SELECT
                prefix.id,
                prefix.family,
                prefix.address_realm_id,
                prefix.address_pool_id
            FROM mesh.network_prefix AS prefix
            JOIN mesh.address_pool AS pool
              ON pool.workspace_id = prefix.workspace_id
             AND pool.address_realm_id = prefix.address_realm_id
             AND pool.id = prefix.address_pool_id
            JOIN mesh.address_realm AS realm
              ON realm.workspace_id = prefix.workspace_id
             AND realm.id = prefix.address_realm_id
            WHERE prefix.workspace_id = scoped_workspace_id
              AND prefix.network_id = scoped_network_id
              AND prefix.state = 'active'
              AND pool.state = 'active'
              AND pool.purpose = 'node_overlay'
              AND realm.state = 'active'
            ORDER BY prefix.family, prefix.id
            LIMIT p_limit
        ) AS candidate
        ORDER BY candidate.address_realm_id, candidate.address_pool_id
    LOOP
        PERFORM pg_catalog.pg_advisory_xact_lock(
            pg_catalog.hashtextextended(
                'meshtransit:registration_allocator:'
                    || allocator.address_realm_id::TEXT
                    || ':'
                    || allocator.address_pool_id::TEXT,
                0
            )
        );
    END LOOP;

    RETURN QUERY
    SELECT
        prefix.id,
        prefix.address_realm_id,
        prefix.address_pool_id,
        prefix.prefix::TEXT,
        prefix.family
    FROM mesh.network_prefix AS prefix
    JOIN mesh.address_pool AS pool
      ON pool.workspace_id = prefix.workspace_id
     AND pool.address_realm_id = prefix.address_realm_id
     AND pool.id = prefix.address_pool_id
    JOIN mesh.address_realm AS realm
      ON realm.workspace_id = prefix.workspace_id
     AND realm.id = prefix.address_realm_id
    WHERE prefix.workspace_id = scoped_workspace_id
      AND prefix.network_id = scoped_network_id
      AND prefix.state = 'active'
      AND pool.state = 'active'
      AND pool.purpose = 'node_overlay'
      AND realm.state = 'active'
    ORDER BY prefix.family, prefix.id
    LIMIT p_limit;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.lock_registration_credential(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.lock_registration_prefixes(BIGINT) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.lock_registration_credential(UUID)
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.lock_registration_prefixes(BIGINT)
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.lock_registration_credential(UUID) TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.lock_registration_prefixes(BIGINT) TO mesh_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
