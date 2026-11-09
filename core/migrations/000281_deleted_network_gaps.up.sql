-- Schema 281: closing what a deleted Network still let through
-- (docs/network-delete-design.md §4.4, N1c). Registration, its intake and
-- node key rotation lock the revision with lock_active_network_revision_v1
-- and stop once the Network is deleted; the Site and Exit Pool elections
-- skip a deleted Network's Sites and pools (replaced in place, same
-- signatures, so the running Core keeps working during the rollout).

CREATE OR REPLACE FUNCTION mesh_ops.list_site_elections_v1(p_deployment UUID, p_after_site UUID, p_limit INTEGER)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_deployment_id BIGINT;
    v_site RECORD;
    v_items JSONB := '[]'::JSONB;
    v_count INTEGER := 0;
BEGIN
    IF p_deployment IS NULL OR p_limit IS NULL OR p_limit < 1 OR p_limit > 64 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Site election page';
    END IF;
    v_deployment_id := mesh_ops.site_election_deployment_internal_v1(p_deployment);
    FOR v_site IN
        SELECT network_site.id, network_site.public_id, network_site.workspace_id, network_site.network_id,
               network_site.failback, site_primary.device_id AS primary_id,
               COALESCE(site_primary.generation, 0) AS generation
        FROM mesh.network_site AS network_site
        LEFT JOIN mesh.site_primary AS site_primary ON site_primary.site_id = network_site.id
        WHERE network_site.deployment_id = v_deployment_id AND network_site.state = 'active'
          AND (p_after_site IS NULL OR network_site.public_id > p_after_site)
          AND EXISTS (SELECT 1 FROM mesh.network_site_router AS any_router WHERE any_router.site_id = network_site.id)
          -- Schema 281: a deleted Network's Sites elect nothing more.
          AND NOT EXISTS (SELECT 1 FROM mesh_ops.network_deletion AS deletion
                          WHERE deletion.workspace_id = network_site.workspace_id
                            AND deletion.network_id = network_site.network_id)
        ORDER BY network_site.public_id
        LIMIT p_limit + 1
    LOOP
        v_count := v_count + 1;
        EXIT WHEN v_count > p_limit;
        PERFORM pg_catalog.set_config('mesh.workspace_id', v_site.workspace_id::TEXT, TRUE);
        PERFORM pg_catalog.set_config('mesh.network_id', v_site.network_id::TEXT, TRUE);
        v_items := v_items || pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object(
            'site_id', v_site.public_id,
            'workspace_id', (SELECT workspace.public_id FROM mesh.workspace AS workspace
                             WHERE workspace.id = v_site.workspace_id),
            'network_id', (SELECT network.public_id FROM mesh.network AS network
                           WHERE network.workspace_id = v_site.workspace_id AND network.id = v_site.network_id),
            'failback', v_site.failback,
            'primary_device_id', (SELECT device.public_id FROM mesh.device AS device
                                  WHERE device.workspace_id = v_site.workspace_id
                                    AND device.network_id = v_site.network_id AND device.id = v_site.primary_id),
            'generation', v_site.generation,
            'routers', (
                SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                    'device_id', device.public_id,
                    'priority', router.priority,
                    'state', router.state,
                    'live', device.state = 'active' AND device.expires_at > pg_catalog.transaction_timestamp(),
                    'workspace_owned', device.ownership = 'workspace',
                    'covers', mesh_ops.offer_covers_internal_v1(COALESCE(offer.prefixes, '{}'::CIDR[]),
                        network_site.prefixes)
                ) ORDER BY router.priority, device.public_id)
                FROM mesh.network_site_router AS router
                JOIN mesh.network_site AS network_site ON network_site.id = router.site_id
                JOIN mesh.device AS device
                  ON device.workspace_id = router.workspace_id AND device.network_id = router.network_id
                 AND device.id = router.device_id
                LEFT JOIN mesh.device_route_advertisement AS offer ON offer.device_id = router.device_id
                WHERE router.site_id = v_site.id
            )
        ));
    END LOOP;
    RETURN pg_catalog.jsonb_build_object('items', v_items, 'done', v_count <= p_limit);
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.list_exit_pool_elections_v1(p_deployment UUID, p_after_pool UUID, p_limit INTEGER)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_deployment_id BIGINT;
    v_pool RECORD;
    v_items JSONB := '[]'::JSONB;
    v_count INTEGER := 0;
BEGIN
    IF p_deployment IS NULL OR p_limit IS NULL OR p_limit < 1 OR p_limit > 64 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Exit Pool election page';
    END IF;
    v_deployment_id := mesh_ops.site_election_deployment_internal_v1(p_deployment);
    FOR v_pool IN
        SELECT exit_pool.id, exit_pool.public_id, exit_pool.workspace_id, exit_pool.network_id,
               exit_pool.failback, pool_primary.device_id AS primary_id,
               COALESCE(pool_primary.generation, 0) AS generation
        FROM mesh.network_exit_pool AS exit_pool
        LEFT JOIN mesh.exit_pool_primary AS pool_primary ON pool_primary.pool_id = exit_pool.id
        WHERE exit_pool.deployment_id = v_deployment_id AND exit_pool.state = 'active'
          AND (p_after_pool IS NULL OR exit_pool.public_id > p_after_pool)
          AND EXISTS (SELECT 1 FROM mesh.network_exit_node AS any_node WHERE any_node.pool_id = exit_pool.id)
          -- Schema 281: a deleted Network's Exit Pools elect nothing more.
          AND NOT EXISTS (SELECT 1 FROM mesh_ops.network_deletion AS deletion
                          WHERE deletion.workspace_id = exit_pool.workspace_id
                            AND deletion.network_id = exit_pool.network_id)
        ORDER BY exit_pool.public_id
        LIMIT p_limit + 1
    LOOP
        v_count := v_count + 1;
        EXIT WHEN v_count > p_limit;
        PERFORM pg_catalog.set_config('mesh.workspace_id', v_pool.workspace_id::TEXT, TRUE);
        PERFORM pg_catalog.set_config('mesh.network_id', v_pool.network_id::TEXT, TRUE);
        v_items := v_items || pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object(
            'pool_id', v_pool.public_id,
            'workspace_id', (SELECT workspace.public_id FROM mesh.workspace AS workspace
                             WHERE workspace.id = v_pool.workspace_id),
            'network_id', (SELECT network.public_id FROM mesh.network AS network
                           WHERE network.workspace_id = v_pool.workspace_id AND network.id = v_pool.network_id),
            'failback', v_pool.failback,
            'primary_device_id', (SELECT device.public_id FROM mesh.device AS device
                                  WHERE device.workspace_id = v_pool.workspace_id
                                    AND device.network_id = v_pool.network_id AND device.id = v_pool.primary_id),
            'generation', v_pool.generation,
            'nodes', (
                SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                    'device_id', device.public_id,
                    'priority', exit_node.priority,
                    'state', exit_node.state,
                    'live', device.state = 'active' AND device.expires_at > pg_catalog.transaction_timestamp(),
                    'workspace_owned', device.ownership = 'workspace',
                    'offered', COALESCE(offer.offered, FALSE)
                ) ORDER BY exit_node.priority, device.public_id)
                FROM mesh.network_exit_node AS exit_node
                JOIN mesh.device AS device
                  ON device.workspace_id = exit_node.workspace_id AND device.network_id = exit_node.network_id
                 AND device.id = exit_node.device_id
                LEFT JOIN mesh.device_exit_offer AS offer ON offer.device_id = exit_node.device_id
                WHERE exit_node.pool_id = v_pool.id
            )
        ));
    END LOOP;
    RETURN pg_catalog.jsonb_build_object('items', v_items, 'done', v_count <= p_limit);
END;
$function$;

-- Schema 281: the revision lock of a write that must not reach a deleted
-- Network (registration, its intake, node key rotation). The same lock as
-- lock_network_revision(), then the Network must still be active: phase 1
-- of a deletion holds this lock while it marks the Network deleted, so a
-- write that waited behind it sees the deletion.
CREATE FUNCTION mesh_ops.lock_active_network_revision_v1()
RETURNS TABLE (
    network_revision BIGINT,
    inventory_revision BIGINT,
    group_revision BIGINT,
    policy_revision BIGINT,
    dns_revision BIGINT,
    route_revision BIGINT,
    sharing_revision BIGINT,
    isolation_generation BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
BEGIN
    RETURN QUERY SELECT * FROM mesh_ops.lock_network_revision();
    IF EXISTS (SELECT 1 FROM mesh_ops.network_deletion AS deletion
               WHERE deletion.workspace_id = mesh_ops.current_workspace_id()
                 AND deletion.network_id = mesh_ops.current_network_id()) THEN
        -- Its own code: the callers end the request for good, no retry.
        RAISE EXCEPTION USING ERRCODE = 'MTN02', MESSAGE = 'the Network was deleted';
    END IF;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.lock_active_network_revision_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.lock_active_network_revision_v1()
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.lock_active_network_revision_v1() TO mesh_runtime;
