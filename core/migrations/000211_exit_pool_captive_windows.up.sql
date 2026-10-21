-- Schema 211: an Exit Pool may turn captive portal windows off for its
-- consumers (exit node design §17.4, C5). Root on the host opens a window;
-- Core can only refuse them, never open one: maps carry the setting and the
-- host's helper refuses a window, or closes an open one, while the pool it
-- uses has them off. Earlier functions stay for older Cores during a rollout
-- or a rollback; their changes keep the stored setting.

ALTER TABLE mesh.network_exit_pool
    ADD COLUMN captive_windows TEXT NOT NULL DEFAULT 'allowed',
    ADD CONSTRAINT network_exit_pool_captive_windows_check CHECK (captive_windows IN ('allowed', 'off'));

-- Creates, changes or deletes a pool as change_exit_pool_v2 does, with its
-- captive portal windows setting; an update without one (NULL) keeps the
-- stored one. The result adds the setting before and after the change.
CREATE FUNCTION mesh_ops.change_exit_pool_v3(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_operation TEXT,
    p_pool_public_id UUID, p_expected_version BIGINT, p_name TEXT, p_failback BOOLEAN,
    p_smtp_allowed BOOLEAN, p_conntrack_per_consumer INTEGER, p_dns_upstreams INET[], p_probes JSONB,
    p_mode TEXT, p_spread_salt BYTEA, p_captive_windows TEXT, p_pool_limit INTEGER, p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_scope RECORD;
    v_pool mesh.network_exit_pool%ROWTYPE;
    v_before JSONB;
    v_previous_mode TEXT;
    v_mode TEXT;
    v_previous_captive TEXT;
    v_captive TEXT;
    v_revisions RECORD;
    v_constraint TEXT;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_operation NOT IN ('create', 'update', 'delete') OR p_pool_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_pool_public_id), 6) >> 4 <> 7
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR (p_operation <> 'create' AND (p_expected_version IS NULL OR p_expected_version < 1))
        OR (p_operation <> 'delete' AND (p_name IS NULL OR p_failback IS NULL OR p_smtp_allowed IS NULL
            OR p_conntrack_per_consumer IS NULL OR p_dns_upstreams IS NULL OR p_probes IS NULL
            OR p_mode NOT IN ('failover', 'spread')
            OR p_spread_salt IS NULL OR pg_catalog.octet_length(p_spread_salt) <> 16
            OR p_captive_windows NOT IN ('allowed', 'off')))
        OR (p_operation = 'create' AND (p_pool_limit IS NULL OR p_pool_limit NOT BETWEEN 1 AND 64
            OR p_mode IS NULL OR p_captive_windows IS NULL)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Exit Pool change is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_exit_pool_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id,
        CASE WHEN p_operation = 'delete' THEN 'route.withdraw' ELSE 'route.approve' END
    );
    PERFORM mesh_ops.lock_site_scope_internal_v1(v_scope.workspace_id, v_scope.network_id);
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    IF p_operation = 'create' THEN
        IF (SELECT pg_catalog.count(*) FROM mesh.network_exit_pool AS exit_pool
            WHERE exit_pool.workspace_id = v_scope.workspace_id
              AND exit_pool.network_id = v_scope.network_id
              AND exit_pool.state = 'active') >= p_pool_limit THEN
            RAISE EXCEPTION USING ERRCODE = 'MTX02', MESSAGE = 'Network already has the maximum Exit Pools';
        END IF;
        BEGIN
            INSERT INTO mesh.network_exit_pool (
                public_id, deployment_id, workspace_id, network_id, name, name_key, failback, smtp_allowed,
                conntrack_per_consumer, dns_upstreams, probes, mode, spread_salt, captive_windows,
                created_at, updated_at
            ) VALUES (
                p_pool_public_id, v_scope.deployment_id, v_scope.workspace_id, v_scope.network_id,
                p_name, pg_catalog.lower(p_name), p_failback, p_smtp_allowed, p_conntrack_per_consumer,
                p_dns_upstreams, p_probes, p_mode, CASE WHEN p_mode = 'spread' THEN p_spread_salt END,
                p_captive_windows, v_now, v_now
            ) RETURNING * INTO v_pool;
        EXCEPTION WHEN unique_violation THEN
            GET STACKED DIAGNOSTICS v_constraint = CONSTRAINT_NAME;
            IF v_constraint = 'network_exit_pool_active_name_uidx' THEN
                RAISE EXCEPTION USING ERRCODE = 'MTX01', MESSAGE = 'Exit Pool name is taken';
            END IF;
            RAISE;
        END;
    ELSE
        SELECT * INTO v_pool FROM mesh.network_exit_pool AS exit_pool
        WHERE exit_pool.workspace_id = v_scope.workspace_id AND exit_pool.network_id = v_scope.network_id
          AND exit_pool.public_id = p_pool_public_id AND exit_pool.state = 'active'
        FOR UPDATE;
        IF v_pool.id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Exit Pool is unavailable';
        END IF;
        IF v_pool.version <> p_expected_version THEN
            RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Exit Pool version changed';
        END IF;
        v_before := mesh_ops.exit_pool_document_internal_v1(v_pool);
        v_previous_mode := v_pool.mode;
        v_mode := COALESCE(p_mode, v_pool.mode);
        v_previous_captive := v_pool.captive_windows;
        v_captive := COALESCE(p_captive_windows, v_pool.captive_windows);
        IF p_operation = 'update' AND v_pool.name = p_name AND v_pool.failback = p_failback
            AND v_pool.smtp_allowed = p_smtp_allowed AND v_pool.conntrack_per_consumer = p_conntrack_per_consumer
            AND v_pool.dns_upstreams = p_dns_upstreams AND v_pool.probes = p_probes AND v_pool.mode = v_mode
            AND v_pool.captive_windows = v_captive THEN
            RETURN pg_catalog.jsonb_build_object(
                'pool', v_before, 'previous', v_before, 'changed', FALSE,
                'mode', v_pool.mode, 'previous_mode', v_pool.mode,
                'captive_windows', v_pool.captive_windows, 'previous_captive_windows', v_pool.captive_windows,
                'role_binding_id', v_scope.role_binding_public_id);
        END IF;
        IF p_operation = 'update' THEN
            IF v_pool.mode <> v_mode THEN
                -- A new mode starts from an empty set; its generation goes on.
                UPDATE mesh.exit_pool_serving
                SET previous_device_ids = device_ids, device_ids = '{}'::BIGINT[], generation = generation + 1,
                    reason = 'none', version = version + 1, changed_at = v_now
                WHERE pool_id = v_pool.id AND pg_catalog.cardinality(device_ids) > 0;
            END IF;
            BEGIN
                UPDATE mesh.network_exit_pool
                SET name = p_name, name_key = pg_catalog.lower(p_name), failback = p_failback,
                    smtp_allowed = p_smtp_allowed, conntrack_per_consumer = p_conntrack_per_consumer,
                    dns_upstreams = p_dns_upstreams, probes = p_probes, mode = v_mode,
                    captive_windows = v_captive,
                    spread_salt = CASE WHEN v_mode = 'spread' THEN COALESCE(spread_salt, p_spread_salt)
                                       ELSE spread_salt END,
                    version = version + 1, updated_at = GREATEST(v_now, updated_at)
                WHERE id = v_pool.id
                RETURNING * INTO v_pool;
            EXCEPTION WHEN unique_violation THEN
                GET STACKED DIAGNOSTICS v_constraint = CONSTRAINT_NAME;
                IF v_constraint = 'network_exit_pool_active_name_uidx' THEN
                    RAISE EXCEPTION USING ERRCODE = 'MTX01', MESSAGE = 'Exit Pool name is taken';
                END IF;
                RAISE;
            END;
        ELSE
            IF mesh_ops.exit_pool_rule_count_internal_v1(v_pool.id) > 0 THEN
                RAISE EXCEPTION USING ERRCODE = 'MTX06', MESSAGE = 'Exit Pool is named by active rules';
            END IF;
            DELETE FROM mesh.network_exit_node WHERE pool_id = v_pool.id;
            UPDATE mesh.network_exit_pool
            SET state = 'deleted', deleted_at = GREATEST(v_now, updated_at),
                version = version + 1, updated_at = GREATEST(v_now, updated_at)
            WHERE id = v_pool.id
            RETURNING * INTO v_pool;
        END IF;
    END IF;
    SELECT * INTO STRICT v_revisions FROM mesh_ops.advance_site_revisions_internal_v1(
        v_scope.workspace_id, v_scope.network_id);
    RETURN pg_catalog.jsonb_build_object(
        'pool', mesh_ops.exit_pool_document_internal_v1(v_pool), 'previous', v_before, 'changed', TRUE,
        'mode', v_pool.mode, 'previous_mode', v_previous_mode,
        'captive_windows', v_pool.captive_windows, 'previous_captive_windows', v_previous_captive,
        'network_revision', v_revisions.network_revision, 'route_revision', v_revisions.route_revision,
        'role_binding_id', v_scope.role_binding_public_id);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.change_exit_pool_v3(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    TEXT, UUID, BIGINT, TEXT, BOOLEAN, BOOLEAN, INTEGER, INET[], JSONB, TEXT, BYTEA, TEXT, INTEGER, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_exit_pool_v3(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    TEXT, UUID, BIGINT, TEXT, BOOLEAN, BOOLEAN, INTEGER, INET[], JSONB, TEXT, BYTEA, TEXT, INTEGER, UUID
) TO mesh_runtime;

-- Changes an exit node as change_exit_node_v2 does; the result adds the
-- pool's captive portal windows setting.
CREATE FUNCTION mesh_ops.change_exit_node_v3(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_operation TEXT,
    p_pool_public_id UUID, p_expected_version BIGINT, p_device_public_id UUID,
    p_priority INTEGER, p_state TEXT, p_node_limit INTEGER, p_node_public_id UUID,
    p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_result JSONB;
BEGIN
    v_result := mesh_ops.change_exit_node_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_operation, p_pool_public_id, p_expected_version,
        p_device_public_id, p_priority, p_state, p_node_limit, p_node_public_id, p_change_public_id);
    RETURN v_result || pg_catalog.jsonb_build_object('captive_windows', (
        SELECT exit_pool.captive_windows FROM mesh.network_exit_pool AS exit_pool
        WHERE exit_pool.workspace_id = mesh_ops.current_workspace_id()
          AND exit_pool.network_id = mesh_ops.current_network_id()
          AND exit_pool.public_id = p_pool_public_id));
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.change_exit_node_v3(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    TEXT, UUID, BIGINT, UUID, INTEGER, TEXT, INTEGER, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_exit_node_v3(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    TEXT, UUID, BIGINT, UUID, INTEGER, TEXT, INTEGER, UUID, UUID
) TO mesh_runtime;

-- One page of pools as list_exit_pools_v2, with each listed pool's captive
-- portal windows setting by pool ID.
CREATE FUNCTION mesh_ops.list_exit_pools_v3(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_after_pool_public_id UUID, p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_page JSONB;
BEGIN
    v_page := mesh_ops.list_exit_pools_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_after_pool_public_id, p_limit);
    RETURN v_page || pg_catalog.jsonb_build_object('captive_windows', COALESCE((
        SELECT pg_catalog.jsonb_object_agg(exit_pool.public_id::TEXT, exit_pool.captive_windows)
        FROM mesh.network_exit_pool AS exit_pool
        WHERE exit_pool.workspace_id = mesh_ops.current_workspace_id()
          AND exit_pool.network_id = mesh_ops.current_network_id()
          AND exit_pool.public_id IN (
              SELECT (listed.item ->> 'pool_id')::UUID
              FROM pg_catalog.jsonb_array_elements(v_page -> 'pools') AS listed(item))
    ), '{}'::JSONB));
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.list_exit_pools_v3(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_exit_pools_v3(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, INTEGER
) TO mesh_runtime;

-- One pool as read_exit_pool_v3, with its captive portal windows setting.
CREATE FUNCTION mesh_ops.read_exit_pool_v4(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_pool_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_reading JSONB;
BEGIN
    v_reading := mesh_ops.read_exit_pool_v3(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_pool_public_id);
    RETURN v_reading || pg_catalog.jsonb_build_object('captive_windows', (
        SELECT exit_pool.captive_windows FROM mesh.network_exit_pool AS exit_pool
        WHERE exit_pool.workspace_id = mesh_ops.current_workspace_id()
          AND exit_pool.network_id = mesh_ops.current_network_id()
          AND exit_pool.public_id = p_pool_public_id));
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_exit_pool_v4(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_exit_pool_v4(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) TO mesh_runtime;

-- The active pools of the map session's Network that turn captive portal
-- windows off, for maps; the same Network scope as
-- load_map_network_exit_pools_v1.
CREATE FUNCTION mesh_ops.load_map_network_exit_pool_captive_v1(p_limit INTEGER)
RETURNS TABLE (pool_id BIGINT)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
BEGIN
    RETURN QUERY
    SELECT loaded.pool_id
    FROM mesh_ops.load_map_network_exit_pools_v1(p_limit) AS loaded
    JOIN mesh.network_exit_pool AS exit_pool ON exit_pool.id = loaded.pool_id
    WHERE exit_pool.captive_windows = 'off'
    ORDER BY loaded.pool_id;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.load_map_network_exit_pool_captive_v1(INTEGER)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_exit_pool_captive_v1(INTEGER) TO mesh_runtime;
