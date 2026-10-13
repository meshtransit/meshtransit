-- Schema 152: the Network-wide map readers stay linear in the Network's
-- size whatever the planner believes about it.
--
-- The inventory read (schema 140) and the per-Device candidate read (schema
-- 16) joined every Device to its key epochs on (workspace, network, device)
-- in one statement. When the planner expects one Device (statistics behind a
-- Network that grew fast, or a generic plan costed for the average Network
-- of a database with many small ones), it chose to scan the whole Network's
-- epochs once per Device: 2,628 Devices filtered out 3.45 million rows and
-- took 2.1 s in a 3,000-Device load test, and 100,000 Devices would cost
-- 10^10.
--
-- The readers now check the Deployment, Workspace and Network once, then
-- look up each Device's key epochs, owner and leases by key, one LATERAL
-- lookup each (LIMIT 1 and OFFSET 0 keep the planner from folding them back
-- into joins), so every lookup is an index probe whatever the estimates. The
-- authenticated Device is found from its node key, which the active-key
-- unique index names directly. The results are those of the joins they
-- replace: an active epoch, a primary lease and an owner are unique per
-- Device, and a Device without a primary active lease is left out as
-- before.
--
-- Covering indexes let the per-Device lookups read the index alone: the
-- active epoch of a Device with its number and key, and a Device's primary
-- active addresses.

CREATE INDEX device_machine_key_epoch_device_active_key_idx
    ON mesh.device_machine_key_epoch (workspace_id, network_id, device_id, epoch)
    INCLUDE (public_key, fingerprint)
    WHERE state = 'active';
CREATE INDEX device_node_key_epoch_device_active_key_idx
    ON mesh.device_node_key_epoch (workspace_id, network_id, device_id, epoch)
    INCLUDE (public_key)
    WHERE state = 'active';
CREATE INDEX node_address_lease_device_primary_address_idx
    ON mesh.node_address_lease (workspace_id, network_id, device_id, family, address, id)
    WHERE state = 'active' AND lease_role = 'primary';

CREATE OR REPLACE FUNCTION mesh_ops.load_map_network_devices_v1(
    p_limit INTEGER
)
RETURNS TABLE (
    numeric_node_id BIGINT,
    numeric_owner_id BIGINT,
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
    scoped_deployment_id BIGINT;
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 200001 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'map network inventory request is invalid';
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
                MESSAGE = 'map network inventory scope is unavailable';
    END;
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'map network inventory scope is unavailable';
    END IF;

    -- The Deployment, Workspace and Network every listed Device shares.
    SELECT deployment.id
    INTO scoped_deployment_id
    FROM mesh.workspace AS workspace
    JOIN mesh.network AS network
      ON network.workspace_id = workspace.id
     AND network.id = scoped_network_id
    JOIN mesh.deployment AS deployment
      ON deployment.id = workspace.deployment_id
    WHERE workspace.id = scoped_workspace_id
      AND workspace.state = 'active'
      AND workspace.deleted_at IS NULL
      AND network.state = 'active'
      AND network.deleted_at IS NULL
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND deployment.deleted_at IS NULL;
    IF scoped_deployment_id IS NULL THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT
        candidate.id,
        owner.id,
        candidate.public_id,
        owner.public_id,
        candidate.hostname,
        machine.public_key,
        current_node_key.public_key,
        candidate.session_generation,
        candidate.created_at,
        candidate.expires_at,
        lease.addresses
    FROM mesh.device AS candidate
    CROSS JOIN LATERAL (
        SELECT key_epoch.public_key
        FROM mesh.device_machine_key_epoch AS key_epoch
        WHERE key_epoch.workspace_id = candidate.workspace_id
          AND key_epoch.network_id = candidate.network_id
          AND key_epoch.device_id = candidate.id
          AND key_epoch.epoch = candidate.current_machine_key_epoch
          AND key_epoch.state = 'active'
        LIMIT 1
    ) AS machine
    CROSS JOIN LATERAL (
        SELECT key_epoch.public_key
        FROM mesh.device_node_key_epoch AS key_epoch
        WHERE key_epoch.workspace_id = candidate.workspace_id
          AND key_epoch.network_id = candidate.network_id
          AND key_epoch.device_id = candidate.id
          AND key_epoch.epoch = candidate.current_node_key_epoch
          AND key_epoch.state = 'active'
        LIMIT 1
    ) AS current_node_key
    CROSS JOIN LATERAL (
        SELECT principal.id, principal.public_id
        FROM mesh.principal AS principal
        WHERE principal.id = candidate.owner_principal_id
          AND principal.deployment_id = scoped_deployment_id
          AND principal.state = 'active'
          AND principal.deleted_at IS NULL
        LIMIT 1
    ) AS owner
    CROSS JOIN LATERAL (
        SELECT ARRAY(
            SELECT primary_lease.address::TEXT
            FROM mesh.node_address_lease AS primary_lease
            WHERE primary_lease.workspace_id = candidate.workspace_id
              AND primary_lease.network_id = candidate.network_id
              AND primary_lease.device_id = candidate.id
              AND primary_lease.state = 'active'
              AND primary_lease.lease_role = 'primary'
            ORDER BY primary_lease.family, primary_lease.address, primary_lease.id
        ) AS addresses
        OFFSET 0
    ) AS lease
    WHERE candidate.workspace_id = scoped_workspace_id
      AND candidate.network_id = scoped_network_id
      AND candidate.state = 'active'
      AND candidate.deleted_at IS NULL
      AND candidate.expires_at > pg_catalog.transaction_timestamp()
      AND pg_catalog.cardinality(lease.addresses) > 0
    ORDER BY candidate.created_at DESC, candidate.id DESC
    LIMIT p_limit;
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.load_map_peer_candidates(
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
    scoped_deployment_id BIGINT;
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

    SELECT deployment.id
    INTO scoped_deployment_id
    FROM mesh.workspace AS workspace
    JOIN mesh.network AS network
      ON network.workspace_id = workspace.id
     AND network.id = scoped_network_id
    JOIN mesh.deployment AS deployment
      ON deployment.id = workspace.deployment_id
    WHERE workspace.id = scoped_workspace_id
      AND workspace.state = 'active'
      AND workspace.deleted_at IS NULL
      AND network.state = 'active'
      AND network.deleted_at IS NULL
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND deployment.deleted_at IS NULL;

    -- The authenticated Device, from its active node key (unique).
    SELECT device.id
    INTO authenticated_device_id
    FROM mesh.device_node_key_epoch AS current_node_key
    CROSS JOIN LATERAL (
        SELECT authenticated.id, authenticated.owner_principal_id,
            authenticated.current_machine_key_epoch
        FROM mesh.device AS authenticated
        WHERE authenticated.workspace_id = current_node_key.workspace_id
          AND authenticated.network_id = current_node_key.network_id
          AND authenticated.id = current_node_key.device_id
          AND authenticated.current_node_key_epoch = current_node_key.epoch
          AND authenticated.state = 'active'
          AND authenticated.deleted_at IS NULL
          AND authenticated.expires_at > pg_catalog.transaction_timestamp()
        LIMIT 1
    ) AS device
    CROSS JOIN LATERAL (
        SELECT 1
        FROM mesh.device_machine_key_epoch AS machine
        WHERE machine.workspace_id = current_node_key.workspace_id
          AND machine.network_id = current_node_key.network_id
          AND machine.device_id = device.id
          AND machine.epoch = device.current_machine_key_epoch
          AND machine.state = 'active'
          AND machine.fingerprint = p_machine_key_fingerprint
        LIMIT 1
    ) AS machine
    CROSS JOIN LATERAL (
        SELECT 1
        FROM mesh.principal AS owner
        WHERE owner.id = device.owner_principal_id
          AND owner.deployment_id = scoped_deployment_id
          AND owner.state = 'active'
          AND owner.deleted_at IS NULL
        LIMIT 1
    ) AS owner
    WHERE current_node_key.public_key = p_node_key
      AND current_node_key.state = 'active'
      AND current_node_key.workspace_id = scoped_workspace_id
      AND current_node_key.network_id = scoped_network_id
      AND scoped_deployment_id IS NOT NULL;

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
        lease.addresses
    FROM mesh.device AS candidate
    CROSS JOIN LATERAL (
        SELECT key_epoch.public_key
        FROM mesh.device_machine_key_epoch AS key_epoch
        WHERE key_epoch.workspace_id = candidate.workspace_id
          AND key_epoch.network_id = candidate.network_id
          AND key_epoch.device_id = candidate.id
          AND key_epoch.epoch = candidate.current_machine_key_epoch
          AND key_epoch.state = 'active'
        LIMIT 1
    ) AS machine
    CROSS JOIN LATERAL (
        SELECT key_epoch.public_key
        FROM mesh.device_node_key_epoch AS key_epoch
        WHERE key_epoch.workspace_id = candidate.workspace_id
          AND key_epoch.network_id = candidate.network_id
          AND key_epoch.device_id = candidate.id
          AND key_epoch.epoch = candidate.current_node_key_epoch
          AND key_epoch.state = 'active'
        LIMIT 1
    ) AS current_node_key
    CROSS JOIN LATERAL (
        SELECT principal.public_id
        FROM mesh.principal AS principal
        WHERE principal.id = candidate.owner_principal_id
          AND principal.deployment_id = scoped_deployment_id
          AND principal.state = 'active'
          AND principal.deleted_at IS NULL
        LIMIT 1
    ) AS owner
    CROSS JOIN LATERAL (
        SELECT ARRAY(
            SELECT primary_lease.address::TEXT
            FROM mesh.node_address_lease AS primary_lease
            WHERE primary_lease.workspace_id = candidate.workspace_id
              AND primary_lease.network_id = candidate.network_id
              AND primary_lease.device_id = candidate.id
              AND primary_lease.state = 'active'
              AND primary_lease.lease_role = 'primary'
            ORDER BY primary_lease.family, primary_lease.address, primary_lease.id
        ) AS addresses
        OFFSET 0
    ) AS lease
    WHERE candidate.workspace_id = scoped_workspace_id
      AND candidate.network_id = scoped_network_id
      AND candidate.id <> authenticated_device_id
      AND candidate.state = 'active'
      AND candidate.deleted_at IS NULL
      AND candidate.expires_at > pg_catalog.transaction_timestamp()
      AND pg_catalog.cardinality(lease.addresses) > 0
    ORDER BY candidate.created_at DESC, candidate.id DESC
    LIMIT p_limit;
END;
$function$;
