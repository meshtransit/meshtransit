-- The Console shows what each Device offers to forward (subnet routes,
-- R1.8b), so an administrator picks a Site's router among the Devices that
-- offer its prefixes.
--
-- console_device_item_internal_v2 adds the stored offer to the inventory
-- item: advertised_prefixes in the order Go stored them (canonical, sorted),
-- at most p_offer_limit of them, and advertised_prefix_count, how many the
-- Device offers in all. A Device that never reported an offer offers none.
-- The offer is read by the advertisement table's primary key.
--
-- The list keeps a page of 101 Devices well inside the Console's response
-- bound with 16 prefixes each; one Device's page shows all 256 at most.
-- The v4 list and v1 item stay for Core replicas that predate this schema.

CREATE FUNCTION mesh_ops.console_device_item_internal_v2(p_device mesh.device, p_offer_limit INTEGER)
RETURNS JSONB
LANGUAGE sql STABLE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT mesh_ops.console_device_item_internal_v1(p_device) || COALESCE((
        SELECT pg_catalog.jsonb_build_object(
            'advertised_prefixes', pg_catalog.to_jsonb(offer.prefixes[1:p_offer_limit]::TEXT[]),
            'advertised_prefix_count', pg_catalog.cardinality(offer.prefixes))
        FROM mesh.device_route_advertisement AS offer
        WHERE offer.device_id = p_device.id
    ), '{"advertised_prefixes": [], "advertised_prefix_count": 0}'::JSONB);
$function$;
REVOKE ALL ON FUNCTION mesh_ops.console_device_item_internal_v2(mesh.device, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- A page of the scope's Devices in name order, each with at most 16 of the
-- prefixes it offers. p_name_prefix (lower-case
-- [a-z0-9.-]) keeps names that start with it; p_state 'active' keeps Devices
-- active and unexpired at p_evaluated_at, 'inactive' every other one, NULL
-- all. The page follows (p_after_hostname, p_after_device_public_id).
CREATE FUNCTION mesh_ops.read_console_devices_v5(
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
    v_scope RECORD;
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 101 OR p_evaluated_at IS NULL
        OR (p_after_hostname IS NULL) <> (p_after_device_public_id IS NULL)
        OR (p_name_prefix IS NOT NULL AND p_name_prefix !~ '^[a-z0-9.-]{1,253}$')
        OR (p_state IS NOT NULL AND p_state NOT IN ('active', 'inactive')) THEN
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
    RETURN pg_catalog.jsonb_build_object(
        'workspace_id', p_workspace_public_id, 'network_id', p_network_public_id,
        'inventory_revision', v_scope.scope_revision,
        'workspace_code', v_scope.scope_workspace_code, 'network_code', v_scope.scope_network_code,
        'devices', COALESCE((
            SELECT pg_catalog.jsonb_agg(mesh_ops.console_device_item_internal_v2(page, 16)
                ORDER BY page.hostname COLLATE "C", page.public_id)
            FROM (
                SELECT device.*
                FROM mesh.device AS device
                WHERE device.workspace_id = v_scope.scope_workspace AND device.network_id = v_scope.scope_network
                  AND (p_name_prefix IS NULL OR device.hostname COLLATE "C" LIKE p_name_prefix || '%')
                  AND (p_after_hostname IS NULL OR (device.hostname COLLATE "C", device.public_id)
                       > (p_after_hostname COLLATE "C", p_after_device_public_id))
                  AND (p_state IS NULL
                       OR (p_state = 'active') = (device.state = 'active' AND device.expires_at > p_evaluated_at))
                ORDER BY device.hostname COLLATE "C", device.public_id
                LIMIT p_limit
            ) AS page
        ), '[]'::JSONB)
    );
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_console_devices_v5(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ,
    TEXT, TEXT, TEXT, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_console_devices_v5(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ,
    TEXT, TEXT, TEXT, UUID, INTEGER
) TO mesh_runtime;

-- One Device of the scope with every prefix it offers, how it was enrolled (by a browser sign-in, or
-- by an enrollment key: its ID, description and creator) and its tags. NULL
-- without authority; no device member when the scope holds no such Device.
CREATE FUNCTION mesh_ops.read_console_device_v2(
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
    v_scope RECORD;
    v_device mesh.device%ROWTYPE;
    v_enrollment JSONB;
BEGIN
    IF p_evaluated_at IS NULL OR p_device_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_device_public_id), 6) >> 4 <> 7 THEN
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
    SELECT * INTO v_device FROM mesh.device AS device
    WHERE device.workspace_id = v_scope.scope_workspace AND device.network_id = v_scope.scope_network
      AND device.public_id = p_device_public_id;
    IF v_device.id IS NULL THEN
        RETURN pg_catalog.jsonb_build_object(
            'workspace_id', p_workspace_public_id, 'network_id', p_network_public_id,
            'workspace_code', v_scope.scope_workspace_code, 'network_code', v_scope.scope_network_code);
    END IF;
    IF v_device.registered_by_kind = 'credential' THEN
        SELECT pg_catalog.jsonb_build_object(
            'kind', 'key', 'key_id', credential.public_id,
            'description', COALESCE(credential.description, ''),
            'created_by', pg_catalog.jsonb_build_object(
                'principal_id', issuer.public_id, 'display_name', COALESCE(account.display_name, '')))
        INTO v_enrollment
        FROM mesh.enrollment_credential AS credential
        JOIN mesh.principal AS issuer ON issuer.id = credential.issuer_principal_id
        LEFT JOIN mesh.account AS account
          ON account.deployment_id = issuer.deployment_id AND account.principal_id = issuer.id
        WHERE credential.workspace_id = v_device.workspace_id AND credential.network_id = v_device.network_id
          AND credential.id = v_device.registered_by_credential_id;
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'workspace_id', p_workspace_public_id, 'network_id', p_network_public_id,
        'workspace_code', v_scope.scope_workspace_code, 'network_code', v_scope.scope_network_code,
        'device', mesh_ops.console_device_item_internal_v2(v_device, 256),
        'enrollment', COALESCE(v_enrollment, pg_catalog.jsonb_build_object('kind', 'browser')),
        'tags', COALESCE((
            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('id', held.public_id, 'name', held.name)
                ORDER BY held.name, held.public_id)
            FROM (
                SELECT tag.public_id, tag.name
                FROM mesh.device_tag_assignment AS assignment
                JOIN mesh.device_tag AS tag
                  ON tag.id = assignment.device_tag_id AND tag.workspace_id = assignment.workspace_id
                WHERE assignment.workspace_id = v_device.workspace_id AND assignment.network_id = v_device.network_id
                  AND assignment.device_id = v_device.id AND tag.state = 'active'
                ORDER BY tag.name, tag.public_id
                LIMIT 64
            ) AS held
        ), '[]'::JSONB));
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_console_device_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_console_device_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ, UUID
) TO mesh_runtime;
