-- Maps read a Network's DNS zones of every kind and the names they hold
-- (DNS design D2b), in the inventory transaction, scoped like the other map
-- readers to the transaction's Workspace and Network; and DNS changes reach
-- maps together, at most 30 seconds after the first of them.
--
-- Zones come in domain order with what their other names get; their
-- resolvers come from schema 214's reader (only forward zones have any).
-- Names come in name order, each with its zone and target: a Device by its
-- internal reference (0 once it is gone) and public ID, fixed addresses, or
-- a CNAME. Go decides the rest per Device: the zone's distribution, the rule
-- to a target Device, liveness, the peer limit and the bounds of one map.
--
-- A DNS change wakes map sessions through its outbox events like any
-- change, but they become available only at the end of the Network's DNS
-- window: the first change of a quiet Network opens one 30 seconds long, and
-- every change before it ends shares it. The changes commit at once; a map
-- refreshed for any other reason carries them sooner.

CREATE FUNCTION mesh_ops.load_map_network_dns_zones_v2(p_limit INTEGER)
RETURNS TABLE (
    zone_id BIGINT,
    domain TEXT,
    other_names TEXT,
    failure_mode TEXT,
    group_ids BIGINT[],
    search_position INTEGER
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT := mesh_ops.current_workspace_id();
    scoped_network_id BIGINT := mesh_ops.current_network_id();
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 1025 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'map network DNS zone request is invalid';
    END IF;
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network DNS zone scope is unavailable';
    END IF;

    RETURN QUERY
    SELECT zone.id, zone.domain, zone.other_names, zone.failure_mode, zone.distribution_group_ids,
           COALESCE(zone.search_position, 0)
    FROM mesh.network_dns_zone AS zone
    WHERE zone.workspace_id = scoped_workspace_id
      AND zone.network_id = scoped_network_id
      AND zone.state = 'active'
    ORDER BY zone.domain COLLATE "C"
    LIMIT p_limit;
END;
$function$;

CREATE FUNCTION mesh_ops.load_map_network_dns_names_v1(p_limit INTEGER)
RETURNS TABLE (
    zone_id BIGINT,
    fqdn TEXT,
    kind TEXT,
    device_id BIGINT,
    device_public_id TEXT,
    addresses TEXT[],
    cname TEXT
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT := mesh_ops.current_workspace_id();
    scoped_network_id BIGINT := mesh_ops.current_network_id();
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 10001 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'map network DNS name request is invalid';
    END IF;
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network DNS name scope is unavailable';
    END IF;

    RETURN QUERY
    SELECT name.zone_id, name.fqdn::TEXT, name.kind, COALESCE(device.id, 0),
           COALESCE(name.device_public_id::TEXT, ''),
           COALESCE(ARRAY(SELECT pg_catalog.host(item.address)
                          FROM pg_catalog.unnest(name.addresses) WITH ORDINALITY AS item (address, ordinal)
                          ORDER BY item.ordinal), '{}'::TEXT[]),
           COALESCE(name.cname::TEXT, '')
    FROM mesh.network_dns_name AS name
    LEFT JOIN mesh.device AS device
      ON device.workspace_id = name.workspace_id AND device.network_id = name.network_id
     AND device.public_id = name.device_public_id AND device.deleted_at IS NULL
    WHERE name.workspace_id = scoped_workspace_id
      AND name.network_id = scoped_network_id
      AND name.state = 'active'
    ORDER BY name.fqdn
    LIMIT p_limit;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.load_map_network_dns_zones_v2(INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.load_map_network_dns_zones_v2(INTEGER)
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_dns_zones_v2(INTEGER) TO mesh_runtime;

REVOKE ALL ON FUNCTION mesh_ops.load_map_network_dns_names_v1(INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.load_map_network_dns_names_v1(INTEGER)
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_dns_names_v1(INTEGER) TO mesh_runtime;

-- Holds the outbox events of this transaction's DNS change (p_change_public_id)
-- until the Network's DNS window ends, and returns how many seconds from now
-- that is. Only events of DNS zones and names of the transaction's own
-- Network move; a window still open is shared, so changes coalesce.
CREATE FUNCTION mesh_ops.defer_dns_change_wakeup_v1(p_change_public_id UUID)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_transaction BIGINT := (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT;
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_due TIMESTAMPTZ;
BEGIN
    IF p_change_public_id IS NULL OR v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'DNS change wakeup is invalid';
    END IF;
    -- Every DNS writer holds the Network's revision row, so the window it
    -- reads cannot move under it.
    PERFORM 1 FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_workspace AND revision.network_id = v_network
    FOR UPDATE;
    -- A window is one a DNS change opened: an event the worker put back to
    -- retry later never sets it, and a window never ends past 30 seconds.
    SELECT pg_catalog.min(event.available_at) INTO v_due
    FROM mesh_ops.outbox_event AS event
    WHERE event.workspace_id = v_workspace AND event.network_id = v_network
      AND event.aggregate_kind IN ('network_dns_zone', 'network_dns_name')
      AND event.completed_at IS NULL AND event.state = 'pending' AND event.attempt_count = 0
      AND event.available_at > v_now;
    v_due := LEAST(COALESCE(v_due, v_now + INTERVAL '30 seconds'), v_now + INTERVAL '30 seconds');
    UPDATE mesh_ops.outbox_event AS event
    SET available_at = v_due
    WHERE event.change_public_id = p_change_public_id AND event.transaction_id = v_transaction
      AND event.workspace_id = v_workspace AND event.network_id = v_network
      AND event.aggregate_kind IN ('network_dns_zone', 'network_dns_name')
      AND event.state = 'pending';
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'DNS change has no wakeup to defer';
    END IF;
    RETURN GREATEST(pg_catalog.ceil(pg_catalog.date_part('epoch', v_due - v_now))::INTEGER, 1);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.defer_dns_change_wakeup_v1(UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.defer_dns_change_wakeup_v1(UUID) TO mesh_runtime;

-- The window read finds a Network's held DNS wakeups through its
-- undelivered DNS events. The predicate names only columns other indexes
-- already name or that never change, so claiming an event stays a HOT
-- update.
CREATE INDEX outbox_event_dns_window_idx
    ON mesh_ops.outbox_event (workspace_id, network_id, available_at)
    WHERE completed_at IS NULL AND aggregate_kind IN ('network_dns_zone', 'network_dns_name');
