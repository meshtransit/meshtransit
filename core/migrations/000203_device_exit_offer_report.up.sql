-- A node reports whether its own configuration offers to be an exit node
-- (mtcp-v1 §8.2, exit_offered; exit node design §5.2, step E1c).
--
-- report_device_exit_offer_v2 resolves the session's Network and stores the
-- offer in one statement, like the route offer (schema 200). An unchanged
-- offer writes nothing. A change is serialized with Exit Pool and policy
-- changes on the Network's revision row; when the Device is an exit node of a
-- pool, the change decides whether it may serve, so it advances the Network
-- and route revisions and maps are rebuilt. The caller records the evidence
-- (device.exit_offer_changed). Offering grants nothing.

-- Each change of an offer is evidence of its Device: it carries the
-- Device's public ID and a version, and the authority mutation trigger
-- records it, as for route offers (schema 190). Schema 201 stored no offer
-- yet, so the new column needs no backfill.
ALTER TABLE mesh.device_exit_offer
    ADD COLUMN public_id UUID NOT NULL,
    ADD COLUMN version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0);
CREATE TRIGGER device_exit_offer_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.device_exit_offer
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('device_exit_offer', 'public_id');

CREATE FUNCTION mesh_ops.report_device_exit_offer_v1(
    p_machine_fingerprint BYTEA, p_node_key BYTEA, p_offered BOOLEAN, p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_device mesh.device%ROWTYPE;
    v_before BOOLEAN;
    v_exit_node BOOLEAN;
    v_version BIGINT;
    v_actor UUID;
    v_revisions RECORD;
BEGIN
    IF p_machine_fingerprint IS NULL OR pg_catalog.octet_length(p_machine_fingerprint) <> 32
        OR p_node_key IS NULL OR pg_catalog.octet_length(p_node_key) <> 32
        OR p_offered IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'exit offer is invalid';
    END IF;
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;

    FOR attempt IN 1..2 LOOP
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
          AND device.state = 'active' AND device.deleted_at IS NULL;
        IF v_device.id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Device is unavailable';
        END IF;
        SELECT offer.offered INTO v_before
        FROM mesh.device_exit_offer AS offer WHERE offer.device_id = v_device.id;
        v_before := COALESCE(v_before, FALSE);
        IF v_before = p_offered THEN
            RETURN pg_catalog.jsonb_build_object('changed', FALSE);
        END IF;
        EXIT WHEN attempt = 2;
        -- A change: serialize with Exit Pool, exit node and policy changes
        -- and with the Device's own lifecycle, then read again under the lock.
        PERFORM 1 FROM mesh_ops.network_revision AS revision
        WHERE revision.workspace_id = v_workspace AND revision.network_id = v_network
        FOR UPDATE;
    END LOOP;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    INSERT INTO mesh.device_exit_offer AS offer
        (device_id, workspace_id, network_id, public_id, offered, reported_at)
    VALUES (v_device.id, v_workspace, v_network, v_device.public_id, p_offered, pg_catalog.transaction_timestamp())
    ON CONFLICT (device_id) DO UPDATE
    SET offered = EXCLUDED.offered, reported_at = EXCLUDED.reported_at, version = offer.version + 1
    RETURNING offer.version INTO v_version;

    v_exit_node := EXISTS (
        SELECT 1 FROM mesh.network_exit_node AS exit_node
        JOIN mesh.network_exit_pool AS exit_pool ON exit_pool.id = exit_node.pool_id AND exit_pool.state = 'active'
        WHERE exit_node.device_id = v_device.id
    );
    IF v_exit_node THEN
        SELECT * INTO STRICT v_revisions FROM mesh_ops.advance_site_revisions_internal_v1(v_workspace, v_network);
    ELSE
        SELECT revision.network_revision, revision.route_revision INTO STRICT v_revisions
        FROM mesh_ops.network_revision AS revision
        WHERE revision.workspace_id = v_workspace AND revision.network_id = v_network;
    END IF;
    SELECT principal.public_id INTO STRICT v_actor
    FROM mesh.principal AS principal WHERE principal.id = v_device.owner_principal_id;
    RETURN pg_catalog.jsonb_build_object(
        'changed', TRUE, 'moves_maps', v_exit_node,
        'device_id', v_device.public_id, 'hostname', v_device.hostname, 'version', v_version,
        'actor_principal_id', v_actor, 'before', v_before, 'after', p_offered,
        'network_revision', v_revisions.network_revision, 'route_revision', v_revisions.route_revision
    );
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.report_device_exit_offer_v1(BYTEA, BYTEA, BOOLEAN, UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.report_device_exit_offer_v2(
    p_machine_fingerprint BYTEA, p_node_key BYTEA, p_offered BOOLEAN, p_change_public_id UUID
)
RETURNS TABLE (workspace_public_id UUID, network_public_id UUID, result JSONB)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace UUID;
    v_network UUID;
BEGIN
    SELECT scope.workspace_public_id, scope.network_public_id INTO v_workspace, v_network
    FROM mesh_ops.resolve_map_session_scope(p_machine_fingerprint, p_node_key) AS scope;
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'exit offer Device not found';
    END IF;
    PERFORM bound.workspace_internal_id FROM mesh_ops.set_network_scope(v_workspace, v_network) AS bound;
    RETURN QUERY SELECT v_workspace, v_network,
        mesh_ops.report_device_exit_offer_v1(p_machine_fingerprint, p_node_key, p_offered, p_change_public_id);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.report_device_exit_offer_v2(BYTEA, BYTEA, BOOLEAN, UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.report_device_exit_offer_v2(BYTEA, BYTEA, BOOLEAN, UUID) TO mesh_runtime;
