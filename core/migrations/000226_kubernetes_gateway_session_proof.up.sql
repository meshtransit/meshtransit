-- Schema 226 (K1a1.4a): a Kubernetes gateway proves its node key on every
-- session (mtcp-v1 §6.7). Every path that resolves a session to a gateway
-- Device needs the proof, which new Core marks in the transaction; older
-- Core never marks it, so it cannot serve, log out or rotate a gateway.
-- Gateway machine keys enter a history and are never used again.

CREATE TABLE mesh_ops.kubernetes_gateway_machine_key_history (
    fingerprint BYTEA PRIMARY KEY CHECK (pg_catalog.octet_length(fingerprint) = 32),
    device_id BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    retired_at TIMESTAMPTZ,
    CONSTRAINT kubernetes_gateway_machine_key_history_retired_check CHECK (
        retired_at IS NULL OR retired_at >= created_at
    )
);
CREATE INDEX kubernetes_gateway_machine_key_history_device_idx
    ON mesh_ops.kubernetes_gateway_machine_key_history (device_id);
ALTER TABLE mesh_ops.kubernetes_gateway_machine_key_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.kubernetes_gateway_machine_key_history FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_gateway_machine_key_history_migrator_policy
    ON mesh_ops.kubernetes_gateway_machine_key_history
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);

-- Gateways enrolled before this schema.
INSERT INTO mesh_ops.kubernetes_gateway_machine_key_history (fingerprint, device_id, created_at, retired_at)
SELECT machine.fingerprint, device.id, machine.valid_from,
    CASE WHEN machine.state = 'active' AND machine.epoch = device.current_machine_key_epoch THEN NULL
         ELSE GREATEST(machine.valid_from, COALESCE(machine.valid_until, machine.valid_from)) END
FROM mesh.device_machine_key_epoch AS machine
JOIN mesh.device AS device ON device.id = machine.device_id
WHERE device.kind = 'kubernetes_gateway'
ON CONFLICT (fingerprint) DO NOTHING;

-- Marks, for this transaction only, that the session of machine key
-- p_machine_fingerprint proved node key p_node_key. A marker of new Core,
-- not an authority: any runtime caller can set it, and older Core never
-- does.
CREATE FUNCTION mesh_ops.mark_session_proven_v1(p_machine_fingerprint BYTEA, p_node_key BYTEA)
RETURNS VOID
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF p_node_key IS NULL OR pg_catalog.octet_length(p_node_key) <> 32
        OR p_machine_fingerprint IS NULL OR pg_catalog.octet_length(p_machine_fingerprint) <> 32 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'proven node key is invalid';
    END IF;
    PERFORM pg_catalog.set_config('mesh.session_proven_node_key',
        pg_catalog.encode(p_machine_fingerprint, 'hex') || ':' || pg_catalog.encode(p_node_key, 'hex') || '@'
            || ((EXTRACT(EPOCH FROM pg_catalog.transaction_timestamp()) * 1000000)::BIGINT)::TEXT,
        TRUE);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.mark_session_proven_v1(BYTEA, BYTEA)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.mark_session_proven_v1(BYTEA, BYTEA) TO mesh_runtime;

-- Whether this transaction marked p_node_key proven for machine key
-- p_machine_fingerprint: unset, empty, other keys, or a value left from an
-- earlier transaction are all FALSE.
CREATE FUNCTION mesh_ops.session_proven_node_key_matches_v1(p_machine_fingerprint BYTEA, p_node_key BYTEA)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
    SELECT p_node_key IS NOT NULL AND pg_catalog.octet_length(p_node_key) = 32
        AND p_machine_fingerprint IS NOT NULL AND pg_catalog.octet_length(p_machine_fingerprint) = 32
        AND pg_catalog.current_setting('mesh.session_proven_node_key', TRUE) IS NOT DISTINCT FROM
            pg_catalog.encode(p_machine_fingerprint, 'hex') || ':' || pg_catalog.encode(p_node_key, 'hex') || '@'
            || ((EXTRACT(EPOCH FROM pg_catalog.transaction_timestamp()) * 1000000)::BIGINT)::TEXT
$function$;
REVOKE ALL ON FUNCTION mesh_ops.session_proven_node_key_matches_v1(BYTEA, BYTEA) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mesh_ops.session_proven_node_key_matches_v1(BYTEA, BYTEA) TO mesh_runtime, mesh_migrator;

-- What a handshake's machine key and node key are (mtcp-v1 §3, §6.7):
-- gateway when the machine key belongs, or belonged, to a gateway Device;
-- machine_state current, retired or unbound; node_current when the node key
-- is the current key of the Device the machine key currently holds.
-- Ordinary keys keep schema 137's replay protection and write it here; a
-- gateway's timestamp is only compared, and written after its proof
-- (commit_mtcp_gateway_timestamp_v1).
CREATE FUNCTION mesh_ops.accept_mtcp_timestamp_v2(
    p_machine_fingerprint BYTEA, p_node_key BYTEA, p_timestamp_ms BIGINT
)
RETURNS TABLE (accepted BOOLEAN, gateway BOOLEAN, machine_state TEXT, node_current BOOLEAN)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_device BIGINT;
    v_kind TEXT;
    v_current BOOLEAN := FALSE;
    v_gateway BOOLEAN;
    v_state TEXT := 'unbound';
    v_node BOOLEAN := FALSE;
    v_accepted BOOLEAN;
BEGIN
    IF p_machine_fingerprint IS NULL OR pg_catalog.octet_length(p_machine_fingerprint) <> 32
        OR p_timestamp_ms IS NULL OR p_timestamp_ms <= 0
        OR (p_node_key IS NOT NULL AND pg_catalog.octet_length(p_node_key) NOT IN (0, 32)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid MTCP timestamp input';
    END IF;
    -- The Device holding this machine key now, if any.
    SELECT device.id, device.kind INTO v_device, v_kind
    FROM mesh.device_machine_key_epoch AS machine
    JOIN mesh.device AS device
      ON device.workspace_id = machine.workspace_id AND device.network_id = machine.network_id
     AND device.id = machine.device_id AND device.current_machine_key_epoch = machine.epoch
    WHERE machine.fingerprint = p_machine_fingerprint AND machine.state = 'active'
      AND device.state = 'active' AND device.deleted_at IS NULL
      AND device.expires_at > pg_catalog.transaction_timestamp();
    IF v_device IS NOT NULL THEN
        v_state := 'current';
        IF p_node_key IS NOT NULL AND pg_catalog.octet_length(p_node_key) = 32 THEN
            SELECT TRUE INTO v_node FROM mesh.device_node_key_epoch AS node_key
            JOIN mesh.device AS device ON device.id = node_key.device_id
             AND device.current_node_key_epoch = node_key.epoch
            WHERE node_key.device_id = v_device AND node_key.state = 'active'
              AND node_key.public_key = p_node_key;
            v_node := COALESCE(v_node, FALSE);
        END IF;
    ELSIF EXISTS (SELECT 1 FROM mesh.device_machine_key_epoch AS machine
                  WHERE machine.fingerprint = p_machine_fingerprint) THEN
        v_state := 'retired';
    END IF;
    v_gateway := COALESCE(v_kind = 'kubernetes_gateway', FALSE)
        OR EXISTS (SELECT 1 FROM mesh_ops.kubernetes_gateway_machine_key_history AS history
                   WHERE history.fingerprint = p_machine_fingerprint)
        OR EXISTS (SELECT 1 FROM mesh.device_machine_key_epoch AS machine
                   JOIN mesh.device AS device ON device.id = machine.device_id
                   WHERE machine.fingerprint = p_machine_fingerprint AND device.kind = 'kubernetes_gateway');
    IF v_gateway THEN
        IF v_state = 'unbound' THEN
            v_state := 'retired';
        END IF;
        SELECT NOT EXISTS (
            SELECT 1 FROM mesh_ops.mtcp_machine_timestamp AS stored
            WHERE stored.machine_fingerprint = p_machine_fingerprint
              AND stored.last_timestamp_ms >= p_timestamp_ms
        ) INTO v_accepted;
        RETURN QUERY SELECT v_accepted, TRUE, v_state, v_node;
        RETURN;
    END IF;
    IF v_state <> 'current' OR NOT v_node THEN
        RETURN QUERY SELECT TRUE, FALSE, v_state, v_node; -- the replica's cache decides
        RETURN;
    END IF;
    INSERT INTO mesh_ops.mtcp_machine_timestamp AS stored (machine_fingerprint, last_timestamp_ms, updated_at)
    VALUES (p_machine_fingerprint, p_timestamp_ms, pg_catalog.clock_timestamp())
    ON CONFLICT (machine_fingerprint) DO UPDATE
    SET last_timestamp_ms = EXCLUDED.last_timestamp_ms, updated_at = EXCLUDED.updated_at
    WHERE stored.last_timestamp_ms < EXCLUDED.last_timestamp_ms
    RETURNING TRUE INTO v_accepted;
    RETURN QUERY SELECT COALESCE(v_accepted, FALSE), FALSE, v_state, v_node;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.accept_mtcp_timestamp_v2(BYTEA, BYTEA, BIGINT)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.accept_mtcp_timestamp_v2(BYTEA, BYTEA, BIGINT) TO mesh_runtime;

-- Records a gateway's handshake timestamp once its session proved the node
-- key: in one statement, only while the machine key and node key are the
-- gateway's current ones and the timestamp is newer. FALSE ends the
-- session.
CREATE FUNCTION mesh_ops.commit_mtcp_gateway_timestamp_v1(
    p_machine_fingerprint BYTEA, p_node_key BYTEA, p_timestamp_ms BIGINT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_accepted BOOLEAN;
BEGIN
    IF p_machine_fingerprint IS NULL OR pg_catalog.octet_length(p_machine_fingerprint) <> 32
        OR p_node_key IS NULL OR pg_catalog.octet_length(p_node_key) <> 32
        OR p_timestamp_ms IS NULL OR p_timestamp_ms <= 0 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid MTCP timestamp input';
    END IF;
    INSERT INTO mesh_ops.mtcp_machine_timestamp AS stored (machine_fingerprint, last_timestamp_ms, updated_at)
    SELECT p_machine_fingerprint, p_timestamp_ms, pg_catalog.clock_timestamp()
    WHERE EXISTS (
        SELECT 1
        FROM mesh.device_machine_key_epoch AS machine
        JOIN mesh.device AS device
          ON device.workspace_id = machine.workspace_id AND device.network_id = machine.network_id
         AND device.id = machine.device_id AND device.current_machine_key_epoch = machine.epoch
        JOIN mesh.device_node_key_epoch AS node_key
          ON node_key.device_id = device.id AND node_key.epoch = device.current_node_key_epoch
        WHERE machine.fingerprint = p_machine_fingerprint AND machine.state = 'active'
          AND node_key.public_key = p_node_key AND node_key.state = 'active'
          AND device.kind = 'kubernetes_gateway' AND device.state = 'active' AND device.deleted_at IS NULL
          AND device.expires_at > pg_catalog.transaction_timestamp()
    )
    ON CONFLICT (machine_fingerprint) DO UPDATE
    SET last_timestamp_ms = EXCLUDED.last_timestamp_ms, updated_at = EXCLUDED.updated_at
    WHERE stored.last_timestamp_ms < EXCLUDED.last_timestamp_ms
    RETURNING TRUE INTO v_accepted;
    RETURN COALESCE(v_accepted, FALSE);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.commit_mtcp_gateway_timestamp_v1(BYTEA, BYTEA, BIGINT)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.commit_mtcp_gateway_timestamp_v1(BYTEA, BYTEA, BIGINT) TO mesh_runtime;

CREATE OR REPLACE FUNCTION mesh_ops.resolve_map_session_scope(
    p_machine_key_fingerprint BYTEA,
    p_node_key BYTEA
)
RETURNS TABLE (
    workspace_public_id UUID,
    network_public_id UUID,
    recovery_epoch BIGINT
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    resolved_workspace_id BIGINT;
    resolved_network_id BIGINT;
    resolved_device_id BIGINT;
    previous_map_workspace_id TEXT;
    previous_map_network_id TEXT;
BEGIN
    previous_map_workspace_id := pg_catalog.current_setting(
        'mesh.map_session_workspace_id',
        TRUE
    );
    previous_map_network_id := pg_catalog.current_setting(
        'mesh.map_session_network_id',
        TRUE
    );

    IF p_machine_key_fingerprint IS NULL
        OR pg_catalog.octet_length(p_machine_key_fingerprint) <> 32
        OR p_node_key IS NULL
        OR pg_catalog.octet_length(p_node_key) <> 32 THEN
        RETURN;
    END IF;

    SELECT device.workspace_id, device.network_id, device.id
    INTO resolved_workspace_id, resolved_network_id, resolved_device_id
    FROM mesh.device_machine_key_epoch AS machine
    JOIN mesh.device AS device
      ON device.workspace_id = machine.workspace_id
     AND device.network_id = machine.network_id
     AND device.id = machine.device_id
    JOIN mesh.device_node_key_epoch AS node_key
      ON node_key.workspace_id = device.workspace_id
     AND node_key.network_id = device.network_id
     AND node_key.device_id = device.id
    WHERE machine.fingerprint = p_machine_key_fingerprint
      AND machine.state = 'active'
      AND machine.epoch = device.current_machine_key_epoch
      AND node_key.public_key = p_node_key
      AND node_key.state = 'active'
      AND node_key.epoch = device.current_node_key_epoch
      AND device.state = 'active'
      AND device.deleted_at IS NULL
      AND device.expires_at > pg_catalog.transaction_timestamp()
      -- Schema 226: a gateway only for a session that proved its node key.
      AND (device.kind <> 'kubernetes_gateway'
           OR mesh_ops.session_proven_node_key_matches_v1(p_machine_key_fingerprint, p_node_key));

    IF NOT FOUND THEN
        RETURN;
    END IF;

    PERFORM pg_catalog.set_config(
        'mesh.map_session_workspace_id',
        resolved_workspace_id::TEXT,
        TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.map_session_network_id',
        resolved_network_id::TEXT,
        TRUE
    );

    RETURN QUERY
    SELECT
        workspace.public_id,
        network.public_id,
        deployment.recovery_epoch
    FROM mesh.workspace AS workspace
    JOIN mesh.network AS network
      ON network.workspace_id = workspace.id
     AND network.id = resolved_network_id
    JOIN mesh.deployment AS deployment
      ON deployment.id = workspace.deployment_id
    JOIN mesh.device AS device
      ON device.workspace_id = workspace.id
     AND device.network_id = network.id
     AND device.id = resolved_device_id
    JOIN mesh.principal AS owner
      ON owner.id = device.owner_principal_id
     AND owner.deployment_id = deployment.id
    WHERE workspace.id = resolved_workspace_id
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND deployment.deleted_at IS NULL
      AND workspace.state = 'active'
      AND workspace.deleted_at IS NULL
      AND network.state = 'active'
      AND network.deleted_at IS NULL
      AND device.state = 'active'
      AND device.deleted_at IS NULL
      AND device.expires_at > pg_catalog.transaction_timestamp()
      AND owner.state = 'active'
      AND owner.deleted_at IS NULL;

    PERFORM pg_catalog.set_config(
        'mesh.map_session_workspace_id',
        COALESCE(previous_map_workspace_id, ''),
        TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.map_session_network_id',
        COALESCE(previous_map_network_id, ''),
        TRUE
    );
EXCEPTION
    WHEN OTHERS THEN
        PERFORM pg_catalog.set_config(
            'mesh.map_session_workspace_id',
            COALESCE(previous_map_workspace_id, ''),
            TRUE
        );
        PERFORM pg_catalog.set_config(
            'mesh.map_session_network_id',
            COALESCE(previous_map_network_id, ''),
            TRUE
        );
        RAISE;
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.resolve_node_key_rotation_scope(
    p_machine_key_fingerprint BYTEA,
    p_machine_key BYTEA,
    p_old_node_key BYTEA,
    p_new_node_key BYTEA
)
RETURNS TABLE (
    workspace_public_id UUID,
    network_public_id UUID
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    resolved_workspace_id BIGINT;
    resolved_network_id BIGINT;
    resolved_device_id BIGINT;
    previous_workspace_id TEXT;
    previous_network_id TEXT;
BEGIN
    previous_workspace_id := pg_catalog.current_setting(
        'mesh.node_key_rotation_workspace_id',
        TRUE
    );
    previous_network_id := pg_catalog.current_setting(
        'mesh.node_key_rotation_network_id',
        TRUE
    );

    IF p_machine_key_fingerprint IS NULL
        OR pg_catalog.octet_length(p_machine_key_fingerprint) <> 32
        OR p_machine_key IS NULL
        OR pg_catalog.octet_length(p_machine_key) <> 32
        OR p_old_node_key IS NULL
        OR pg_catalog.octet_length(p_old_node_key) <> 32
        OR p_new_node_key IS NULL
        OR pg_catalog.octet_length(p_new_node_key) <> 32
        OR p_old_node_key = p_new_node_key THEN
        RETURN;
    END IF;

    SELECT device.workspace_id, device.network_id, device.id
    INTO resolved_workspace_id, resolved_network_id, resolved_device_id
    FROM mesh.device_machine_key_epoch AS machine_key
    JOIN mesh.device AS device
      ON device.workspace_id = machine_key.workspace_id
     AND device.network_id = machine_key.network_id
     AND device.id = machine_key.device_id
     AND device.current_machine_key_epoch = machine_key.epoch
    JOIN mesh.device_node_key_epoch AS node_key
      ON node_key.workspace_id = device.workspace_id
     AND node_key.network_id = device.network_id
     AND node_key.device_id = device.id
     AND node_key.epoch = device.current_node_key_epoch
    WHERE machine_key.fingerprint = p_machine_key_fingerprint
      AND machine_key.public_key = p_machine_key
      AND machine_key.state = 'active'
      AND node_key.public_key IN (p_old_node_key, p_new_node_key)
      AND node_key.state = 'active'
      AND device.state = 'active'
      AND device.deleted_at IS NULL
      AND device.expires_at > pg_catalog.transaction_timestamp()
      -- Schema 226: a gateway only for a session that proved its current
      -- node key.
      AND (device.kind <> 'kubernetes_gateway'
           OR mesh_ops.session_proven_node_key_matches_v1(p_machine_key_fingerprint, node_key.public_key));

    IF NOT FOUND THEN
        RETURN;
    END IF;

    PERFORM pg_catalog.set_config(
        'mesh.node_key_rotation_workspace_id',
        resolved_workspace_id::TEXT,
        TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.node_key_rotation_network_id',
        resolved_network_id::TEXT,
        TRUE
    );

    RETURN QUERY
    SELECT workspace.public_id, network.public_id
    FROM mesh.workspace AS workspace
    JOIN mesh.network AS network
      ON network.workspace_id = workspace.id
     AND network.id = resolved_network_id
    JOIN mesh.deployment AS deployment
      ON deployment.id = workspace.deployment_id
    JOIN mesh.device AS device
      ON device.workspace_id = workspace.id
     AND device.network_id = network.id
     AND device.id = resolved_device_id
    WHERE workspace.id = resolved_workspace_id
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND deployment.deleted_at IS NULL
      AND workspace.state = 'active'
      AND workspace.deleted_at IS NULL
      AND network.state = 'active'
      AND network.deleted_at IS NULL
      AND device.state = 'active'
      AND device.deleted_at IS NULL
      AND device.expires_at > pg_catalog.transaction_timestamp();

    PERFORM pg_catalog.set_config(
        'mesh.node_key_rotation_workspace_id',
        COALESCE(previous_workspace_id, ''),
        TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.node_key_rotation_network_id',
        COALESCE(previous_network_id, ''),
        TRUE
    );
EXCEPTION
    WHEN OTHERS THEN
        PERFORM pg_catalog.set_config(
            'mesh.node_key_rotation_workspace_id',
            COALESCE(previous_workspace_id, ''),
            TRUE
        );
        PERFORM pg_catalog.set_config(
            'mesh.node_key_rotation_network_id',
            COALESCE(previous_network_id, ''),
            TRUE
        );
        RAISE;
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.logout_device_v1(p_machine_fingerprint bytea, p_node_key bytea, p_change_public_id uuid, p_evaluated_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_device mesh.device%ROWTYPE;
    v_before JSONB;
    v_actor UUID;
    v_network_revision BIGINT;
    v_inventory_revision BIGINT;
    v_group_revision BIGINT;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_machine_fingerprint IS NULL OR pg_catalog.octet_length(p_machine_fingerprint) <> 32
        OR p_node_key IS NULL OR pg_catalog.octet_length(p_node_key) <> 32
        OR p_change_public_id IS NULL OR p_evaluated_at IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Device logout is invalid';
    END IF;
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;

    -- Serializes with registration, publication and other map inputs.
    PERFORM 1 FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_workspace AND revision.network_id = v_network
    FOR UPDATE;
    SELECT device.* INTO v_device
    FROM mesh.device AS device
    JOIN mesh.device_machine_key_epoch AS machine
      ON machine.workspace_id = device.workspace_id AND machine.network_id = device.network_id
     AND machine.device_id = device.id AND machine.epoch = device.current_machine_key_epoch
     AND machine.state = 'active' AND machine.fingerprint = p_machine_fingerprint
    JOIN mesh.device_node_key_epoch AS node_key
      ON node_key.workspace_id = device.workspace_id AND node_key.network_id = device.network_id
     AND node_key.device_id = device.id AND node_key.epoch = device.current_node_key_epoch
     AND node_key.state = 'active' AND node_key.public_key = p_node_key
    WHERE device.workspace_id = v_workspace AND device.network_id = v_network
      AND device.state = 'active' AND device.deleted_at IS NULL
    FOR UPDATE OF device;
    IF v_device.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Device is unavailable';
    END IF;
    -- Schema 226: a gateway is removed by an administrator, never by itself.
    IF v_device.kind = 'kubernetes_gateway' THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK11', MESSAGE = 'a Kubernetes gateway cannot log out';
    END IF;
    SELECT principal.public_id INTO STRICT v_actor
    FROM mesh.principal AS principal WHERE principal.id = v_device.owner_principal_id;
    v_before := mesh_ops.device_lifecycle_document_internal_v1(v_device);
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    PERFORM mesh_ops.revoke_member_device_internal_v1(v_device.id, 'logged out', v_now);
    SELECT * INTO STRICT v_device FROM mesh.device AS device WHERE device.id = v_device.id;

    -- Peers lose the Device and groups their member: every projection moves.
    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        inventory_revision = revision.inventory_revision + 1,
        group_revision = revision.group_revision + 1,
        updated_at = pg_catalog.clock_timestamp()
    WHERE revision.workspace_id = v_workspace AND revision.network_id = v_network
    RETURNING revision.network_revision, revision.inventory_revision, revision.group_revision
    INTO v_network_revision, v_inventory_revision, v_group_revision;

    RETURN pg_catalog.jsonb_build_object(
        'before', v_before,
        'after', mesh_ops.device_lifecycle_document_internal_v1(v_device),
        'actor_principal_id', v_actor,
        'network_revision', v_network_revision,
        'inventory_revision', v_inventory_revision,
        'group_revision', v_group_revision
    );
END;
$function$
;

CREATE OR REPLACE FUNCTION mesh_ops.complete_kubernetes_replica_request_v1(
    p_request_internal_id BIGINT, p_device_internal_id BIGINT, p_credential_use_public_id UUID,
    p_network_revision BIGINT, p_occurred_at TIMESTAMPTZ
)
RETURNS BOOLEAN
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_request mesh.kubernetes_replica_request%ROWTYPE;
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_request_internal_id IS NULL OR p_device_internal_id IS NULL OR p_credential_use_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_credential_use_public_id), 6) >> 4 <> 7
        OR p_network_revision IS NULL OR p_network_revision <= 0 OR p_occurred_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'replica completion is invalid';
    END IF;
    UPDATE mesh.kubernetes_replica_request AS request
    SET state = 'completed', device_id = p_device_internal_id, completed_network_revision = p_network_revision,
        version = request.version + 1, updated_at = GREATEST(p_occurred_at, request.updated_at)
    FROM mesh.device AS device
    WHERE request.id = p_request_internal_id AND request.workspace_id = v_workspace
      AND request.network_id = v_network AND request.state = 'approved'
      AND device.workspace_id = v_workspace AND device.network_id = v_network
      AND device.id = p_device_internal_id AND device.kind = 'kubernetes_gateway'
      AND device.kubernetes_cluster_id = request.kubernetes_cluster_id
      AND device.kubernetes_ordinal = request.reserved_ordinal
    RETURNING request.* INTO v_request;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK10', MESSAGE = 'the replica request cannot complete';
    END IF;
    -- The Device holds exactly the keys the administrator's code bound.
    PERFORM 1 FROM mesh.device_machine_key_epoch AS epoch
    WHERE epoch.device_id = p_device_internal_id AND epoch.state = 'active'
      AND epoch.public_key = v_request.machine_key AND epoch.fingerprint = v_request.machine_key_fingerprint;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK10', MESSAGE = 'the Device does not hold the approved machine key';
    END IF;
    PERFORM 1 FROM mesh.device_node_key_epoch AS epoch
    WHERE epoch.device_id = p_device_internal_id AND epoch.state = 'active'
      AND epoch.public_key = v_request.node_key;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK10', MESSAGE = 'the Device does not hold the approved node key';
    END IF;
    -- Schema 226: a gateway's machine keys are never used again, by any
    -- gateway; its first one enters the history here.
    INSERT INTO mesh_ops.kubernetes_gateway_machine_key_history (fingerprint, device_id, created_at)
    VALUES (v_request.machine_key_fingerprint, p_device_internal_id, p_occurred_at)
    ON CONFLICT (fingerprint) DO NOTHING;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK10', MESSAGE = 'the machine key was used by a gateway before';
    END IF;
    INSERT INTO mesh.enrollment_credential_use (
        public_id, workspace_id, network_id, enrollment_credential_id, pending_registration_id,
        kubernetes_replica_request_id, device_id, machine_key_fingerprint, result, used_at, created_at
    ) VALUES (
        p_credential_use_public_id, v_workspace, v_network, v_request.enrollment_credential_id, NULL,
        v_request.id, p_device_internal_id, v_request.machine_key_fingerprint, 'created', p_occurred_at,
        p_occurred_at
    );
    RETURN TRUE;
END;
$function$;
