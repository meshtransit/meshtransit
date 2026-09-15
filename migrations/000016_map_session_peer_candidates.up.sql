CREATE POLICY workspace_map_peer_candidate_scope_policy ON mesh.workspace
    FOR SELECT
    TO mesh_migrator
    USING (
        id = NULLIF(
            pg_catalog.current_setting('mesh.workspace_id', TRUE),
            ''
        )::BIGINT
    );

CREATE POLICY network_map_peer_candidate_scope_policy ON mesh.network
    FOR SELECT
    TO mesh_migrator
    USING (
        workspace_id = NULLIF(
            pg_catalog.current_setting('mesh.workspace_id', TRUE),
            ''
        )::BIGINT
        AND id = NULLIF(
            pg_catalog.current_setting('mesh.network_id', TRUE),
            ''
        )::BIGINT
    );

CREATE FUNCTION mesh_ops.load_map_peer_candidates(
    p_machine_key_fingerprint BYTEA,
    p_node_key BYTEA,
    p_limit INTEGER
)
RETURNS TABLE (
    node_public_id UUID,
    owner_public_id UUID,
    hostname TEXT,
    machine_key BYTEA,
    node_key BYTEA,
    session_generation BIGINT,
    created_at TIMESTAMPTZ,
    key_expiry TIMESTAMPTZ,
    addresses TEXT[]
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
    authenticated_device_id BIGINT;
BEGIN
    IF p_machine_key_fingerprint IS NULL
        OR pg_catalog.octet_length(p_machine_key_fingerprint) <> 32
        OR p_node_key IS NULL
        OR pg_catalog.octet_length(p_node_key) <> 32
        OR p_limit IS NULL
        OR p_limit < 1
        OR p_limit > 10001 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'map peer candidate request is invalid';
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
                MESSAGE = 'map peer candidate scope is unavailable';
    END;
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'map peer candidate scope is unavailable';
    END IF;

    SELECT device.id
    INTO authenticated_device_id
    FROM mesh.device AS device
    JOIN mesh.device_machine_key_epoch AS machine
      ON machine.workspace_id = device.workspace_id
     AND machine.network_id = device.network_id
     AND machine.device_id = device.id
    JOIN mesh.device_node_key_epoch AS current_node_key
      ON current_node_key.workspace_id = device.workspace_id
     AND current_node_key.network_id = device.network_id
     AND current_node_key.device_id = device.id
    JOIN mesh.workspace AS workspace
      ON workspace.id = device.workspace_id
    JOIN mesh.network AS network
      ON network.workspace_id = workspace.id
     AND network.id = device.network_id
    JOIN mesh.deployment AS deployment
      ON deployment.id = workspace.deployment_id
    JOIN mesh.principal AS owner
      ON owner.id = device.owner_principal_id
     AND owner.deployment_id = deployment.id
    WHERE device.workspace_id = scoped_workspace_id
      AND device.network_id = scoped_network_id
      AND machine.fingerprint = p_machine_key_fingerprint
      AND machine.state = 'active'
      AND machine.epoch = device.current_machine_key_epoch
      AND current_node_key.public_key = p_node_key
      AND current_node_key.state = 'active'
      AND current_node_key.epoch = device.current_node_key_epoch
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND deployment.deleted_at IS NULL
      AND workspace.state = 'active'
      AND workspace.deleted_at IS NULL
      AND network.state = 'active'
      AND network.deleted_at IS NULL
      AND owner.state = 'active'
      AND owner.deleted_at IS NULL
      AND device.state = 'active'
      AND device.deleted_at IS NULL
      AND device.expires_at > pg_catalog.transaction_timestamp();

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'map peer candidate authority is unavailable';
    END IF;

    RETURN QUERY
    SELECT
        candidate.public_id,
        owner.public_id,
        candidate.hostname,
        machine.public_key,
        current_node_key.public_key,
        candidate.session_generation,
        candidate.created_at,
        candidate.expires_at,
        ARRAY(
            SELECT lease.address::TEXT
            FROM mesh.node_address_lease AS lease
            WHERE lease.workspace_id = candidate.workspace_id
              AND lease.network_id = candidate.network_id
              AND lease.device_id = candidate.id
              AND lease.state = 'active'
              AND lease.lease_role = 'primary'
            ORDER BY lease.family, lease.address, lease.id
        )
    FROM mesh.device AS candidate
    JOIN mesh.device_machine_key_epoch AS machine
      ON machine.workspace_id = candidate.workspace_id
     AND machine.network_id = candidate.network_id
     AND machine.device_id = candidate.id
    JOIN mesh.device_node_key_epoch AS current_node_key
      ON current_node_key.workspace_id = candidate.workspace_id
     AND current_node_key.network_id = candidate.network_id
     AND current_node_key.device_id = candidate.id
    JOIN mesh.workspace AS workspace
      ON workspace.id = candidate.workspace_id
    JOIN mesh.network AS network
      ON network.workspace_id = workspace.id
     AND network.id = candidate.network_id
    JOIN mesh.deployment AS deployment
      ON deployment.id = workspace.deployment_id
    JOIN mesh.principal AS owner
      ON owner.id = candidate.owner_principal_id
     AND owner.deployment_id = deployment.id
    WHERE candidate.workspace_id = scoped_workspace_id
      AND candidate.network_id = scoped_network_id
      AND candidate.id <> authenticated_device_id
      AND candidate.state = 'active'
      AND candidate.deleted_at IS NULL
      AND candidate.expires_at > pg_catalog.transaction_timestamp()
      AND machine.state = 'active'
      AND machine.epoch = candidate.current_machine_key_epoch
      AND current_node_key.state = 'active'
      AND current_node_key.epoch = candidate.current_node_key_epoch
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND deployment.deleted_at IS NULL
      AND workspace.state = 'active'
      AND workspace.deleted_at IS NULL
      AND network.state = 'active'
      AND network.deleted_at IS NULL
      AND owner.state = 'active'
      AND owner.deleted_at IS NULL
      AND EXISTS (
          SELECT 1
          FROM mesh.node_address_lease AS lease
          WHERE lease.workspace_id = candidate.workspace_id
            AND lease.network_id = candidate.network_id
            AND lease.device_id = candidate.id
            AND lease.state = 'active'
            AND lease.lease_role = 'primary'
      )
    ORDER BY candidate.created_at DESC, candidate.id DESC
    LIMIT p_limit;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.load_map_peer_candidates(BYTEA, BYTEA, INTEGER)
    FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.load_map_peer_candidates(BYTEA, BYTEA, INTEGER)
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_peer_candidates(BYTEA, BYTEA, INTEGER)
    TO mesh_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
