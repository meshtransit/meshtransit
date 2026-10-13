-- Schema 153: a Network's map inventory is kept up to date from the Devices
-- that changed instead of reading the whole Network again.
--
-- Core reads a Network's live Devices once per revision and shares them with
-- every map (schema 140). While Devices join, every revision costs a read of
-- the whole Network, O(N) each and O(N^2) while a Network fills. Each Network
-- now keeps a change counter (map_inventory_change_head) and each Device the
-- counter value of its last change (map_inventory_change): a reader that
-- holds the inventory as of counter C reads the Devices changed after C and
-- applies them.
--
-- The counter is taken when the changing transaction commits (deferred
-- constraint triggers), under the head row's lock, so counters follow commit
-- order: a snapshot that sees counter C sees every change numbered up to C,
-- and a change numbered after C is not visible to it yet. One transaction
-- takes one number per Network, recognised by its own transaction ID on the
-- head row (which only these functions write), not by session state. The triggers cover every column the
-- inventory reads: a Device's identity, owner, name, session generation,
-- creation, expiry, state and current key epochs; its key epochs; its
-- primary leases; and its owner's state, which marks every Device of the
-- owner. The update triggers fire on every update and compare those columns
-- (WHEN), so a column another trigger sets is not missed. A transaction that
-- changes several Networks takes their heads in the order of its changes;
-- writers that change Devices of several Networks at once must keep one
-- order (ascending, as Network revisions are taken) to avoid deadlocks. A Device that only expires changes no row, so the reader drops
-- Devices whose expiry passed itself. Deployment, Workspace and Network
-- state are read with every inventory, as before.

CREATE TABLE mesh_ops.map_inventory_change_head (
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    change_seq BIGINT NOT NULL CHECK (change_seq > 0),
    -- The transaction that took change_seq, which reuses it for its other
    -- changes of the Network.
    numbered_by XID8 NOT NULL,
    PRIMARY KEY (workspace_id, network_id),
    CONSTRAINT map_inventory_change_head_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT
);

-- One row per Device that changed since schema 153, with its last change.
CREATE TABLE mesh_ops.map_inventory_change (
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    device_id BIGINT NOT NULL,
    change_seq BIGINT NOT NULL CHECK (change_seq > 0),
    PRIMARY KEY (workspace_id, network_id, device_id)
);
-- A reader asks for one Network's changes after a counter, in order.
CREATE INDEX map_inventory_change_seq_idx
    ON mesh_ops.map_inventory_change (workspace_id, network_id, change_seq, device_id);

ALTER TABLE mesh_ops.map_inventory_change_head ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.map_inventory_change_head FORCE ROW LEVEL SECURITY;
CREATE POLICY map_inventory_change_head_migrator_policy ON mesh_ops.map_inventory_change_head
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
ALTER TABLE mesh_ops.map_inventory_change ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.map_inventory_change FORCE ROW LEVEL SECURITY;
CREATE POLICY map_inventory_change_migrator_policy ON mesh_ops.map_inventory_change
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);

-- Numbers this transaction's change of one Network (once per transaction,
-- holding the head row until commit) and records it for p_device_ids.
CREATE FUNCTION mesh_ops.stamp_map_inventory_change_internal_v1(
    p_workspace_id BIGINT, p_network_id BIGINT, p_device_ids BIGINT[]
)
RETURNS VOID
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
DECLARE
    v_seq BIGINT;
BEGIN
    IF p_workspace_id IS NULL OR p_network_id IS NULL OR p_device_ids IS NULL THEN
        RETURN;
    END IF;
    SELECT head.change_seq
    INTO v_seq
    FROM mesh_ops.map_inventory_change_head AS head
    WHERE head.workspace_id = p_workspace_id
      AND head.network_id = p_network_id
      AND head.numbered_by = pg_catalog.pg_current_xact_id();
    IF v_seq IS NULL THEN
        INSERT INTO mesh_ops.map_inventory_change_head AS head (workspace_id, network_id, change_seq, numbered_by)
        VALUES (p_workspace_id, p_network_id, 1, pg_catalog.pg_current_xact_id())
        ON CONFLICT (workspace_id, network_id)
        DO UPDATE SET change_seq = head.change_seq + 1, numbered_by = EXCLUDED.numbered_by
        RETURNING head.change_seq INTO v_seq;
    END IF;
    INSERT INTO mesh_ops.map_inventory_change AS change (workspace_id, network_id, device_id, change_seq)
    SELECT DISTINCT p_workspace_id, p_network_id, changed.device_id, v_seq
    FROM pg_catalog.unnest(p_device_ids) AS changed(device_id)
    WHERE changed.device_id IS NOT NULL
    ON CONFLICT (workspace_id, network_id, device_id)
    DO UPDATE SET change_seq = EXCLUDED.change_seq
    WHERE change.change_seq < EXCLUDED.change_seq;
END;
$function$;

-- A Device row, or a key epoch or lease row naming its Device, changed.
CREATE FUNCTION mesh_ops.record_map_inventory_change_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
DECLARE
    v_new BIGINT[];
    v_old BIGINT[];
BEGIN
    -- [workspace, network, Device] of the row after and before the change.
    IF TG_OP <> 'DELETE' THEN
        IF TG_TABLE_NAME = 'device' THEN
            v_new := ARRAY[NEW.workspace_id, NEW.network_id, NEW.id];
        ELSE
            v_new := ARRAY[NEW.workspace_id, NEW.network_id, NEW.device_id];
        END IF;
    END IF;
    IF TG_OP <> 'INSERT' THEN
        IF TG_TABLE_NAME = 'device' THEN
            v_old := ARRAY[OLD.workspace_id, OLD.network_id, OLD.id];
        ELSE
            v_old := ARRAY[OLD.workspace_id, OLD.network_id, OLD.device_id];
        END IF;
    END IF;
    IF v_new IS NOT NULL THEN
        PERFORM mesh_ops.stamp_map_inventory_change_internal_v1(v_new[1], v_new[2], ARRAY[v_new[3]]);
    END IF;
    IF v_old IS NOT NULL AND v_old IS DISTINCT FROM v_new THEN
        PERFORM mesh_ops.stamp_map_inventory_change_internal_v1(v_old[1], v_old[2], ARRAY[v_old[3]]);
    END IF;
    RETURN NULL;
END;
$function$;

-- A principal's state changed: every Device it owns, Network by Network in
-- order (so two such transactions lock heads in the same order).
CREATE FUNCTION mesh_ops.record_map_inventory_owner_change_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    owned RECORD;
BEGIN
    FOR owned IN
        SELECT device.workspace_id, device.network_id, pg_catalog.array_agg(device.id ORDER BY device.id) AS ids
        FROM mesh.device AS device
        WHERE device.owner_principal_id = NEW.id
        GROUP BY device.workspace_id, device.network_id
        ORDER BY device.workspace_id, device.network_id
    LOOP
        PERFORM mesh_ops.stamp_map_inventory_change_internal_v1(owned.workspace_id, owned.network_id, owned.ids);
    END LOOP;
    RETURN NULL;
END;
$function$;

CREATE CONSTRAINT TRIGGER device_map_inventory_change_write
AFTER INSERT OR DELETE ON mesh.device
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION mesh_ops.record_map_inventory_change_v1();
CREATE CONSTRAINT TRIGGER device_map_inventory_change_update
AFTER UPDATE ON mesh.device
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
WHEN ((OLD.workspace_id, OLD.network_id, OLD.id, OLD.public_id, OLD.owner_principal_id, OLD.hostname,
        OLD.session_generation, OLD.created_at, OLD.expires_at, OLD.state, OLD.deleted_at,
        OLD.current_machine_key_epoch, OLD.current_node_key_epoch)
    IS DISTINCT FROM (NEW.workspace_id, NEW.network_id, NEW.id, NEW.public_id, NEW.owner_principal_id,
        NEW.hostname, NEW.session_generation, NEW.created_at, NEW.expires_at, NEW.state, NEW.deleted_at,
        NEW.current_machine_key_epoch, NEW.current_node_key_epoch))
EXECUTE FUNCTION mesh_ops.record_map_inventory_change_v1();

CREATE CONSTRAINT TRIGGER device_machine_key_epoch_map_inventory_change_write
AFTER INSERT OR DELETE ON mesh.device_machine_key_epoch
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION mesh_ops.record_map_inventory_change_v1();
CREATE CONSTRAINT TRIGGER device_machine_key_epoch_map_inventory_change_update
AFTER UPDATE ON mesh.device_machine_key_epoch
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
WHEN ((OLD.workspace_id, OLD.network_id, OLD.device_id, OLD.epoch, OLD.state, OLD.public_key, OLD.fingerprint)
    IS DISTINCT FROM (NEW.workspace_id, NEW.network_id, NEW.device_id, NEW.epoch, NEW.state, NEW.public_key,
        NEW.fingerprint))
EXECUTE FUNCTION mesh_ops.record_map_inventory_change_v1();

CREATE CONSTRAINT TRIGGER device_node_key_epoch_map_inventory_change_write
AFTER INSERT OR DELETE ON mesh.device_node_key_epoch
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION mesh_ops.record_map_inventory_change_v1();
CREATE CONSTRAINT TRIGGER device_node_key_epoch_map_inventory_change_update
AFTER UPDATE ON mesh.device_node_key_epoch
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
WHEN ((OLD.workspace_id, OLD.network_id, OLD.device_id, OLD.epoch, OLD.state, OLD.public_key)
    IS DISTINCT FROM (NEW.workspace_id, NEW.network_id, NEW.device_id, NEW.epoch, NEW.state, NEW.public_key))
EXECUTE FUNCTION mesh_ops.record_map_inventory_change_v1();

CREATE CONSTRAINT TRIGGER node_address_lease_map_inventory_change_write
AFTER INSERT OR DELETE ON mesh.node_address_lease
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION mesh_ops.record_map_inventory_change_v1();
CREATE CONSTRAINT TRIGGER node_address_lease_map_inventory_change_update
AFTER UPDATE ON mesh.node_address_lease
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
WHEN ((OLD.workspace_id, OLD.network_id, OLD.device_id, OLD.address, OLD.family, OLD.lease_role, OLD.state)
    IS DISTINCT FROM (NEW.workspace_id, NEW.network_id, NEW.device_id, NEW.address, NEW.family, NEW.lease_role,
        NEW.state))
EXECUTE FUNCTION mesh_ops.record_map_inventory_change_v1();

CREATE CONSTRAINT TRIGGER principal_map_inventory_change_update
AFTER UPDATE ON mesh.principal
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
WHEN ((OLD.id, OLD.public_id, OLD.deployment_id, OLD.state, OLD.deleted_at)
    IS DISTINCT FROM (NEW.id, NEW.public_id, NEW.deployment_id, NEW.state, NEW.deleted_at))
EXECUTE FUNCTION mesh_ops.record_map_inventory_owner_change_v1();

-- The change counter of the installed exact scope (0 before its first
-- change), read in the inventory's own transaction.
CREATE FUNCTION mesh_ops.read_map_inventory_change_head_v1()
RETURNS BIGINT
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
    SELECT COALESCE((
        SELECT head.change_seq
        FROM mesh_ops.map_inventory_change_head AS head
        WHERE head.workspace_id = mesh_ops.current_workspace_id()
          AND head.network_id = mesh_ops.current_network_id()
    ), 0)
$function$;

-- The installed scope's Devices changed after p_since, in change order, each
-- as load_map_network_devices_v1 lists it, or listed = FALSE when it no
-- longer would (the reader removes it).
CREATE FUNCTION mesh_ops.load_map_network_device_changes_v1(
    p_since BIGINT,
    p_limit INTEGER
)
RETURNS TABLE (
    change_seq BIGINT,
    numeric_node_id BIGINT,
    listed BOOLEAN,
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
    IF p_since IS NULL OR p_since < 0 OR p_limit IS NULL OR p_limit < 1 OR p_limit > 200001 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'map network inventory change request is invalid';
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

    -- As load_map_network_devices_v1: no Device is listed unless the
    -- Deployment, Workspace and Network serve maps.
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

    RETURN QUERY
    SELECT
        change.change_seq,
        change.device_id,
        live.id IS NOT NULL,
        live.owner_id,
        live.public_id,
        live.owner_public_id,
        live.hostname,
        live.machine_key,
        live.node_key,
        live.session_generation,
        live.created_at,
        live.expires_at,
        live.addresses
    FROM mesh_ops.map_inventory_change AS change
    LEFT JOIN LATERAL (
        SELECT
            candidate.id,
            owner.id AS owner_id,
            candidate.public_id,
            owner.public_id AS owner_public_id,
            candidate.hostname,
            machine.public_key AS machine_key,
            current_node_key.public_key AS node_key,
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
        WHERE candidate.workspace_id = change.workspace_id
          AND candidate.network_id = change.network_id
          AND candidate.id = change.device_id
          AND scoped_deployment_id IS NOT NULL
          AND candidate.state = 'active'
          AND candidate.deleted_at IS NULL
          AND candidate.expires_at > pg_catalog.transaction_timestamp()
          AND pg_catalog.cardinality(lease.addresses) > 0
        LIMIT 1
    ) AS live ON TRUE
    WHERE change.workspace_id = scoped_workspace_id
      AND change.network_id = scoped_network_id
      AND change.change_seq > p_since
    ORDER BY change.change_seq, change.device_id
    LIMIT p_limit;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.stamp_map_inventory_change_internal_v1(BIGINT, BIGINT, BIGINT[])
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.record_map_inventory_change_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.record_map_inventory_owner_change_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.read_map_inventory_change_head_v1()
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_map_inventory_change_head_v1() TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.load_map_network_device_changes_v1(BIGINT, INTEGER)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_device_changes_v1(BIGINT, INTEGER) TO mesh_runtime;
