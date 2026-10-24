-- DNS debt close-out (2026-10-24).
--
-- TD-CORE-41: two writers that give Devices of one Network a DNS label at
-- once could pick the same free label; the loser hit the unique index and
-- its whole Device write failed. Label allocation now holds a transaction
-- lock of its Network first, so writers of one Network take labels one
-- after the other. The lock is taken only when a label must be chosen: a
-- Device that keeps its label takes none. It needs READ COMMITTED callers,
-- which every Device writer is (registration, lifecycle, browser
-- completion); they also lock the Network revision first, so the order is
-- revision, Device, label lock.
--
-- TD-CLI-73: a resolver Device's consumers, counted when a zone is written
-- (MTZ06), no longer include the Devices of the Network's unmanaged Device
-- Groups (schema 221): they get no DNS, so they ask no resolver.

CREATE OR REPLACE FUNCTION mesh_ops.assign_device_dns_label_internal_v1(
    p_workspace_id BIGINT, p_network_id BIGINT, p_device_id BIGINT, p_hostname TEXT
)
RETURNS TEXT
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_base TEXT := mesh_ops.derive_device_dns_label_v1(p_hostname);
    v_current TEXT;
    v_ordinal INTEGER := 0;
    v_candidate TEXT;
BEGIN
    SELECT label.dns_label INTO v_current
    FROM mesh.device_dns_label AS label
    WHERE label.workspace_id = p_workspace_id AND label.network_id = p_network_id
      AND label.device_id = p_device_id;
    IF v_current = v_base OR (
        v_current ~ '-[0-9]{1,6}$'
        AND v_current = mesh_ops.device_dns_label_variant_v1(
            v_base, pg_catalog.substring(v_current, '-([0-9]{1,6})$')::INTEGER)
    ) THEN
        RETURN v_current;
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(
        pg_catalog.hashtextextended(
            'meshtransit:device_dns_label:' || p_workspace_id::TEXT || ':' || p_network_id::TEXT, 0));
    LOOP
        v_candidate := mesh_ops.device_dns_label_variant_v1(v_base, v_ordinal);
        EXIT WHEN NOT EXISTS (
            SELECT 1 FROM mesh.device_dns_label AS label
            WHERE label.workspace_id = p_workspace_id AND label.network_id = p_network_id
              AND label.dns_label = v_candidate AND label.device_id <> p_device_id
        );
        v_ordinal := v_ordinal + 1;
        IF v_ordinal > 200000 THEN
            RAISE EXCEPTION USING ERRCODE = '53000', MESSAGE = 'Device DNS label allocation unavailable';
        END IF;
    END LOOP;
    INSERT INTO mesh.device_dns_label AS label (workspace_id, network_id, device_id, dns_label)
    VALUES (p_workspace_id, p_network_id, p_device_id, v_candidate)
    ON CONFLICT (workspace_id, network_id, device_id)
    DO UPDATE SET dns_label = EXCLUDED.dns_label;
    RETURN v_candidate;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.assign_device_dns_label_internal_v1(BIGINT, BIGINT, BIGINT, TEXT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE OR REPLACE FUNCTION mesh_ops.dns_resolver_consumers_internal_v1(
    p_workspace_id BIGINT, p_network_id BIGINT, p_resolver_public_id TEXT, p_zone_id BIGINT,
    p_groups BIGINT[]
)
RETURNS BIGINT
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_groups BIGINT[] := p_groups;
    v_all BOOLEAN := pg_catalog.cardinality(p_groups) = 0;
    v_zone_groups BIGINT[];
    v_unmanaged BIGINT[];
BEGIN
    FOR v_zone_groups IN
        SELECT zone.distribution_group_ids
        FROM mesh.network_dns_zone AS zone
        WHERE zone.workspace_id = p_workspace_id AND zone.network_id = p_network_id
          AND zone.state = 'active' AND zone.id IS DISTINCT FROM p_zone_id
          AND zone.resolvers @> pg_catalog.jsonb_build_array(
              pg_catalog.jsonb_build_object('device_id', p_resolver_public_id))
    LOOP
        v_all := v_all OR pg_catalog.cardinality(v_zone_groups) = 0;
        v_groups := v_groups || v_zone_groups;
    END LOOP;
    SELECT setting.unmanaged_group_ids INTO v_unmanaged
    FROM mesh.network_dns_setting AS setting
    WHERE setting.workspace_id = p_workspace_id AND setting.network_id = p_network_id;
    v_unmanaged := COALESCE(v_unmanaged, '{}');
    -- A zone sent to every Device: count the Network's active Devices.
    IF v_all THEN
        RETURN (SELECT pg_catalog.count(*) FROM mesh.device AS device
                WHERE device.workspace_id = p_workspace_id AND device.network_id = p_network_id
                  AND device.deleted_at IS NULL AND device.state = 'active'
                  AND device.public_id <> p_resolver_public_id::UUID
                  AND (pg_catalog.cardinality(v_unmanaged) = 0 OR NOT EXISTS (
                      SELECT 1 FROM mesh.device_group_member AS unmanaged
                      WHERE unmanaged.workspace_id = p_workspace_id AND unmanaged.network_id = p_network_id
                        AND unmanaged.device_id = device.id
                        AND unmanaged.device_group_id = ANY (v_unmanaged))));
    END IF;
    RETURN (SELECT pg_catalog.count(DISTINCT member.device_id)
            FROM mesh.device_group_member AS member
            JOIN mesh.device AS device ON device.id = member.device_id
            WHERE member.device_group_id = ANY (v_groups)
              AND device.deleted_at IS NULL AND device.state = 'active'
              AND device.public_id <> p_resolver_public_id::UUID
              AND (pg_catalog.cardinality(v_unmanaged) = 0 OR NOT EXISTS (
                  SELECT 1 FROM mesh.device_group_member AS unmanaged
                  WHERE unmanaged.workspace_id = p_workspace_id AND unmanaged.network_id = p_network_id
                    AND unmanaged.device_id = device.id
                    AND unmanaged.device_group_id = ANY (v_unmanaged))));
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.dns_resolver_consumers_internal_v1(BIGINT, BIGINT, TEXT, BIGINT, BIGINT[])
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
