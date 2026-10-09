-- Compatibility observations are not packet or administrative authority.
-- There is one bounded row per Device; readers must match all current epochs.
CREATE TABLE mesh.device_alias_client_version (
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    device_id BIGINT NOT NULL,
    session_generation BIGINT NOT NULL CHECK (session_generation > 0),
    machine_key_epoch BIGINT NOT NULL CHECK (machine_key_epoch > 0),
    node_key_epoch BIGINT NOT NULL CHECK (node_key_epoch > 0),
    node_public_key BYTEA NOT NULL CHECK (
        pg_catalog.octet_length(node_public_key) = 32
        AND node_public_key <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')),
    alias_version INTEGER NOT NULL CHECK (alias_version IN (0, 1)),
    observed_at TIMESTAMPTZ NOT NULL CHECK (pg_catalog.isfinite(observed_at)),
    PRIMARY KEY (workspace_id, network_id, device_id),
    FOREIGN KEY (workspace_id, network_id, device_id)
        REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id, network_id, device_id, machine_key_epoch)
        REFERENCES mesh.device_machine_key_epoch (workspace_id, network_id, device_id, epoch) ON DELETE RESTRICT,
    FOREIGN KEY (workspace_id, network_id, device_id, node_key_epoch)
        REFERENCES mesh.device_node_key_epoch (workspace_id, network_id, device_id, epoch) ON DELETE RESTRICT
);
ALTER TABLE mesh.device_alias_client_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.device_alias_client_version FORCE ROW LEVEL SECURITY;
CREATE POLICY device_alias_client_version_migrator_policy ON mesh.device_alias_client_version
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY device_alias_client_version_observer_policy ON mesh.device_alias_client_version
    TO mesh_device_alias_observer USING (
        workspace_id = mesh_ops.current_workspace_id() AND network_id = mesh_ops.current_network_id())
    WITH CHECK (workspace_id = mesh_ops.current_workspace_id() AND network_id = mesh_ops.current_network_id());
REVOKE ALL ON mesh.device_alias_client_version FROM PUBLIC, mesh_runtime, mesh_worker,
    mesh_observer, mesh_share_writer, mesh_direct_map_reader;
GRANT SELECT, INSERT, UPDATE ON mesh.device_alias_client_version TO mesh_device_alias_observer;
GRANT USAGE ON SCHEMA mesh, mesh_ops TO mesh_device_alias_observer;
GRANT EXECUTE ON FUNCTION mesh_ops.current_workspace_id(), mesh_ops.current_network_id(),
    mesh_ops.resolve_map_session_scope(BYTEA, BYTEA), mesh_ops.set_network_scope(UUID, UUID)
    TO mesh_device_alias_observer;
CREATE POLICY device_alias_observer_device_read ON mesh.device FOR SELECT TO mesh_device_alias_observer
    USING (workspace_id = mesh_ops.current_workspace_id() AND network_id = mesh_ops.current_network_id());
CREATE POLICY device_alias_observer_machine_read ON mesh.device_machine_key_epoch FOR SELECT TO mesh_device_alias_observer
    USING (workspace_id = mesh_ops.current_workspace_id() AND network_id = mesh_ops.current_network_id());
CREATE POLICY device_alias_observer_node_read ON mesh.device_node_key_epoch FOR SELECT TO mesh_device_alias_observer
    USING (workspace_id = mesh_ops.current_workspace_id() AND network_id = mesh_ops.current_network_id());
CREATE POLICY device_alias_observer_device_lock ON mesh.device FOR UPDATE TO mesh_device_alias_observer
    USING (workspace_id = mesh_ops.current_workspace_id() AND network_id = mesh_ops.current_network_id())
    WITH CHECK (workspace_id = mesh_ops.current_workspace_id() AND network_id = mesh_ops.current_network_id());
CREATE POLICY device_alias_observer_machine_lock ON mesh.device_machine_key_epoch FOR UPDATE TO mesh_device_alias_observer
    USING (workspace_id = mesh_ops.current_workspace_id() AND network_id = mesh_ops.current_network_id())
    WITH CHECK (workspace_id = mesh_ops.current_workspace_id() AND network_id = mesh_ops.current_network_id());
CREATE POLICY device_alias_observer_node_lock ON mesh.device_node_key_epoch FOR UPDATE TO mesh_device_alias_observer
    USING (workspace_id = mesh_ops.current_workspace_id() AND network_id = mesh_ops.current_network_id())
    WITH CHECK (workspace_id = mesh_ops.current_workspace_id() AND network_id = mesh_ops.current_network_id());
-- PostgreSQL requires an UPDATE privilege for FOR SHARE. The function never
-- updates these identities, and this NOLOGIN role is not granted to a session.
GRANT SELECT, UPDATE (id) ON mesh.device, mesh.device_machine_key_epoch, mesh.device_node_key_epoch
    TO mesh_device_alias_observer;

CREATE FUNCTION mesh_ops.observe_device_alias_version_v1(
    p_machine_fingerprint BYTEA, p_node_key BYTEA, p_alias_version INTEGER
) RETURNS BOOLEAN
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    previous_workspace TEXT := pg_catalog.current_setting('mesh.workspace_id', TRUE);
    previous_network TEXT := pg_catalog.current_setting('mesh.network_id', TRUE);
    resolved_workspace UUID;
    resolved_network UUID;
    scoped_workspace BIGINT;
    scoped_network BIGINT;
    device_row mesh.device%ROWTYPE;
    decision_at TIMESTAMPTZ;
BEGIN
    IF p_alias_version IS NULL OR p_alias_version NOT IN (0, 1)
        OR p_machine_fingerprint IS NULL OR pg_catalog.octet_length(p_machine_fingerprint) <> 32
        OR p_node_key IS NULL OR pg_catalog.octet_length(p_node_key) <> 32 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid client compatibility declaration';
    END IF;
    SELECT scope.workspace_public_id, scope.network_public_id INTO resolved_workspace, resolved_network
    FROM mesh_ops.resolve_map_session_scope(p_machine_fingerprint, p_node_key) AS scope;
    IF resolved_workspace IS NULL OR resolved_network IS NULL THEN RETURN FALSE; END IF;
    -- Ignore caller ordinary scope; only the proven identity selects this observation.
    PERFORM pg_catalog.set_config('mesh.workspace_id', '', TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', '', TRUE);
    SELECT scope.workspace_internal_id, scope.network_internal_id INTO STRICT scoped_workspace, scoped_network
    FROM mesh_ops.set_network_scope(resolved_workspace, resolved_network) AS scope;
    SELECT device.* INTO device_row FROM mesh.device AS device
    JOIN mesh.device_machine_key_epoch AS machine ON machine.workspace_id = device.workspace_id
        AND machine.network_id = device.network_id AND machine.device_id = device.id
        AND machine.epoch = device.current_machine_key_epoch AND machine.state = 'active'
        AND machine.fingerprint = p_machine_fingerprint AND machine.valid_from <= pg_catalog.clock_timestamp()
    JOIN mesh.device_node_key_epoch AS node_key ON node_key.workspace_id = device.workspace_id
        AND node_key.network_id = device.network_id AND node_key.device_id = device.id
        AND node_key.epoch = device.current_node_key_epoch AND node_key.state = 'active'
        AND node_key.public_key = p_node_key AND node_key.valid_from <= pg_catalog.clock_timestamp()
    WHERE device.workspace_id = scoped_workspace AND device.network_id = scoped_network
        AND device.state = 'active' AND device.deleted_at IS NULL
    FOR SHARE OF device, machine, node_key;
    decision_at := pg_catalog.clock_timestamp();
    IF device_row.id IS NULL OR device_row.expires_at <= decision_at OR device_row.created_at > decision_at THEN
        PERFORM pg_catalog.set_config('mesh.workspace_id', COALESCE(previous_workspace, ''), TRUE);
        PERFORM pg_catalog.set_config('mesh.network_id', COALESCE(previous_network, ''), TRUE);
        RETURN FALSE;
    END IF;
    INSERT INTO mesh.device_alias_client_version (workspace_id, network_id, device_id,
        session_generation, machine_key_epoch, node_key_epoch, node_public_key, alias_version, observed_at)
    VALUES (scoped_workspace, scoped_network, device_row.id, device_row.session_generation,
        device_row.current_machine_key_epoch, device_row.current_node_key_epoch, p_node_key, p_alias_version, decision_at)
    ON CONFLICT (workspace_id, network_id, device_id) DO UPDATE SET
        session_generation = EXCLUDED.session_generation, machine_key_epoch = EXCLUDED.machine_key_epoch,
        node_key_epoch = EXCLUDED.node_key_epoch, node_public_key = EXCLUDED.node_public_key,
        alias_version = EXCLUDED.alias_version, observed_at = EXCLUDED.observed_at
    WHERE (mesh.device_alias_client_version.session_generation, mesh.device_alias_client_version.machine_key_epoch,
        mesh.device_alias_client_version.node_key_epoch, mesh.device_alias_client_version.node_public_key,
        mesh.device_alias_client_version.alias_version) IS DISTINCT FROM (EXCLUDED.session_generation,
        EXCLUDED.machine_key_epoch, EXCLUDED.node_key_epoch, EXCLUDED.node_public_key, EXCLUDED.alias_version);
    PERFORM pg_catalog.set_config('mesh.workspace_id', COALESCE(previous_workspace, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', COALESCE(previous_network, ''), TRUE);
    RETURN TRUE;
EXCEPTION WHEN OTHERS THEN
    PERFORM pg_catalog.set_config('mesh.workspace_id', COALESCE(previous_workspace, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', COALESCE(previous_network, ''), TRUE);
    RAISE;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.observe_device_alias_version_v1(BYTEA, BYTEA, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_share_writer, mesh_direct_map_reader;
-- Runtime EXECUTE is enabled only by the operator after assigning the owner.
