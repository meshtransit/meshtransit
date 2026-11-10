-- Schema 285: the Console shows signed-out Devices (docs/device-logout-
-- design.md §8, S3). A Device's owner can sign it out and keep it (schema
-- 283); the Console lists it as "Signed out" with when, and can list only
-- those.
--
-- read_console_devices_v7 is v6 with each item's signed_out_at, set only
-- for a Device not removed (active, expired or suspended: revoked and
-- deleted Devices keep the column as history), and p_state 'signed_out'
-- keeping active or expired Devices their owner signed out: what a person
-- sees as signed out, after revoked and suspended and before expired
-- (§8's order). They are a subset of 'inactive' (signing out ends the
-- expiry). read_console_device_v5 is v4 with the same field. The v6 list
-- and v4 item stay for Core replicas that predate this schema.

-- The signed_out page in name order: a Network's signed-out Devices are few
-- (the worker removes them after 30 days), so this index stays small and the
-- page never walks the Network's whole name index. Its predicate is the
-- query's, word for word, so the planner matches it (the integration test
-- assertConsoleSignedOutPage checks a copy of that filter: keep them alike).
CREATE INDEX device_network_signed_out_name_idx
    ON mesh.device (workspace_id, network_id, (hostname COLLATE "C"), public_id)
    WHERE signed_out_at IS NOT NULL AND state IN ('active', 'expired');

CREATE FUNCTION mesh_ops.console_device_signed_out_internal_v1(p_device_public_id UUID)
RETURNS JSONB
LANGUAGE sql STABLE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object('signed_out_at', device.signed_out_at)
    FROM mesh.device AS device
    WHERE device.public_id = p_device_public_id AND device.signed_out_at IS NOT NULL
      AND device.state IN ('active', 'expired', 'suspended')
$function$;
REVOKE ALL ON FUNCTION mesh_ops.console_device_signed_out_internal_v1(UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.read_console_devices_v7(
    p_session_public_id UUID, p_deployment_public_id UUID,
    p_principal_public_id UUID, p_identity_subject_public_id UUID,
    p_session_version BIGINT, p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT, p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT, p_workspace_public_id UUID,
    p_network_public_id UUID, p_evaluated_at TIMESTAMPTZ,
    p_name_prefix TEXT, p_state TEXT, p_after_hostname TEXT, p_after_device_public_id UUID, p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
-- Each call plans with its own prefix and cursor, so both stay index ranges.
SET plan_cache_mode = force_custom_plan
AS $function$
DECLARE
    v_result JSONB;
    v_scope RECORD;
BEGIN
    IF p_state IS DISTINCT FROM 'signed_out' THEN
        -- v6 checks its own input, authority and the other filters.
        v_result := mesh_ops.read_console_devices_v6(
            p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
            p_session_version, p_principal_authority_generation, p_account_session_generation,
            p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
            p_evaluated_at, p_name_prefix, p_state, p_after_hostname, p_after_device_public_id, p_limit);
    ELSE
        IF p_limit IS NULL OR p_limit < 1 OR p_limit > 101 OR p_evaluated_at IS NULL
            OR (p_after_hostname IS NULL) <> (p_after_device_public_id IS NULL)
            OR (p_name_prefix IS NOT NULL AND p_name_prefix !~ '^[a-z0-9.-]{1,253}$') THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Device inventory input';
        END IF;
        SELECT * INTO v_scope FROM mesh_ops.authorize_console_device_read_internal_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
            p_session_version, p_principal_authority_generation, p_account_session_generation,
            p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
            p_evaluated_at);
        IF v_scope.scope_workspace IS NULL THEN
            RETURN NULL;
        END IF;
        v_result := pg_catalog.jsonb_build_object(
            'workspace_id', p_workspace_public_id, 'network_id', p_network_public_id,
            'inventory_revision', v_scope.scope_revision,
            'workspace_code', v_scope.scope_workspace_code, 'network_code', v_scope.scope_network_code,
            'devices', COALESCE((
                SELECT pg_catalog.jsonb_agg(mesh_ops.console_device_item_internal_v2(page, 16)
                    ORDER BY page.hostname COLLATE "C", page.public_id)
                FROM (
                    SELECT device.*
                    FROM mesh.device AS device
                    WHERE device.workspace_id = v_scope.scope_workspace
                      AND device.network_id = v_scope.scope_network
                      AND device.signed_out_at IS NOT NULL AND device.state IN ('active', 'expired')
                      AND (p_name_prefix IS NULL OR device.hostname COLLATE "C" LIKE p_name_prefix || '%')
                      AND (p_after_hostname IS NULL OR (device.hostname COLLATE "C", device.public_id)
                           > (p_after_hostname COLLATE "C", p_after_device_public_id))
                    ORDER BY device.hostname COLLATE "C", device.public_id
                    LIMIT p_limit
                ) AS page
            ), '[]'::JSONB));
    END IF;
    IF v_result IS NULL THEN
        RETURN NULL;
    END IF;
    -- v6 already joined each replica's cluster; the signed_out branch does
    -- it here so both answers have one shape (a gateway cannot sign out,
    -- MTK11, so it adds nothing today). Every item gains its sign-out, by
    -- its unique public ID.
    RETURN v_result || pg_catalog.jsonb_build_object('devices', COALESCE((
        SELECT pg_catalog.jsonb_agg(
            item.value
            || CASE WHEN p_state IS NOT DISTINCT FROM 'signed_out'
                    THEN COALESCE(mesh_ops.console_device_cluster_internal_v1((item.value ->> 'id')::UUID),
                                  '{}'::JSONB)
                    ELSE '{}'::JSONB END
            || COALESCE(mesh_ops.console_device_signed_out_internal_v1((item.value ->> 'id')::UUID), '{}'::JSONB)
            ORDER BY item.ordinal)
        FROM pg_catalog.jsonb_array_elements(v_result -> 'devices') WITH ORDINALITY AS item(value, ordinal)
    ), '[]'::JSONB));
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_console_devices_v7(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ,
    TEXT, TEXT, TEXT, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_console_devices_v7(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ,
    TEXT, TEXT, TEXT, UUID, INTEGER
) TO mesh_runtime;

-- read_console_device_v4 with the Device's sign-out.
CREATE FUNCTION mesh_ops.read_console_device_v5(
    p_session_public_id UUID, p_deployment_public_id UUID,
    p_principal_public_id UUID, p_identity_subject_public_id UUID,
    p_session_version BIGINT, p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT, p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT, p_workspace_public_id UUID,
    p_network_public_id UUID, p_evaluated_at TIMESTAMPTZ, p_device_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    v_result JSONB;
BEGIN
    v_result := mesh_ops.read_console_device_v4(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_evaluated_at, p_device_public_id);
    IF v_result IS NULL OR NOT v_result ? 'device' THEN
        RETURN v_result;
    END IF;
    RETURN v_result || pg_catalog.jsonb_build_object('device', (v_result -> 'device')
        || COALESCE(mesh_ops.console_device_signed_out_internal_v1(p_device_public_id), '{}'::JSONB));
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_console_device_v5(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_console_device_v5(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ, UUID
) TO mesh_runtime;
