-- The Console lists a Network's Devices by name, ten at a time, and opens one
-- Device on its own page. Both reads check device.read like the inventory
-- read before them (000125, 000169) and stay bounded: the list walks an index
-- in name order from a (hostname, public ID) cursor, and the item reads one
-- row.

-- Name order over every Device, removed ones included: hostname_key is
-- released on removal, so the order uses the hostname itself. Hostnames are
-- lower-case [a-z0-9.-], so a "C" collation orders them by byte and serves a
-- prefix search.
CREATE INDEX device_network_hostname_order_idx
    ON mesh.device (workspace_id, network_id, (hostname COLLATE "C"), public_id);

-- One Device of the scope as the inventory item, with its DNS label.
CREATE FUNCTION mesh_ops.console_device_item_internal_v1(p_device mesh.device)
RETURNS JSONB
LANGUAGE sql STABLE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'id', p_device.public_id, 'hostname', p_device.hostname,
        'state', p_device.state, 'is_ephemeral', p_device.is_ephemeral,
        'version', p_device.version, 'created_at', p_device.created_at,
        'updated_at', p_device.updated_at, 'expires_at', p_device.expires_at,
        'ownership', p_device.ownership,
        'owner', CASE WHEN p_device.ownership = 'member' THEN (
            SELECT pg_catalog.jsonb_build_object(
                'principal_id', owner.public_id, 'display_name', COALESCE(account.display_name, ''))
            FROM mesh.principal AS owner
            LEFT JOIN mesh.account AS account
              ON account.deployment_id = owner.deployment_id AND account.principal_id = owner.id
            WHERE owner.id = p_device.owner_principal_id) ELSE NULL END,
        'suspended_reason', p_device.suspended_reason,
        'handover_to', CASE WHEN p_device.handover_principal_id IS NOT NULL THEN (
            SELECT pg_catalog.jsonb_build_object(
                'principal_id', handover.public_id, 'display_name', COALESCE(account.display_name, ''))
            FROM mesh.principal AS handover
            LEFT JOIN mesh.account AS account
              ON account.deployment_id = handover.deployment_id AND account.principal_id = handover.id
            WHERE handover.id = p_device.handover_principal_id) ELSE NULL END,
        'dns_label', (
            SELECT label.dns_label FROM mesh.device_dns_label AS label
            WHERE label.workspace_id = p_device.workspace_id AND label.network_id = p_device.network_id
              AND label.device_id = p_device.id)
    );
$function$;
REVOKE ALL ON FUNCTION mesh_ops.console_device_item_internal_v1(mesh.device) FROM PUBLIC;

-- Installs the exact scope and checks device.read; returns the scope's
-- internal IDs, revision and display codes, or no row without authority.
CREATE FUNCTION mesh_ops.authorize_console_device_read_internal_v1(
    p_session_public_id UUID, p_deployment_public_id UUID,
    p_principal_public_id UUID, p_identity_subject_public_id UUID,
    p_session_version BIGINT, p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT, p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT, p_workspace_public_id UUID,
    p_network_public_id UUID, p_evaluated_at TIMESTAMPTZ
)
RETURNS TABLE (
    scope_workspace BIGINT, scope_network BIGINT, scope_revision BIGINT, scope_workspace_code TEXT,
    scope_network_code TEXT
)
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    v_workspace BIGINT;
    v_network BIGINT;
    v_revision BIGINT;
    v_codes RECORD;
BEGIN
    BEGIN
        SELECT workspace_internal_id, network_internal_id INTO v_workspace, v_network
        FROM mesh_ops.set_network_scope(p_workspace_public_id, p_network_public_id);
    EXCEPTION WHEN foreign_key_violation OR insufficient_privilege THEN
        RETURN;
    END;
    IF NOT EXISTS (
        SELECT 1 FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version,
            p_principal_authority_generation, p_account_session_generation,
            p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, 'device.read', p_evaluated_at
        )
    ) THEN
        RETURN;
    END IF;
    SELECT revision_row.inventory_revision INTO v_revision
    FROM mesh_ops.network_revision AS revision_row
    WHERE revision_row.workspace_id = v_workspace AND revision_row.network_id = v_network
    FOR SHARE;
    SELECT * INTO v_codes FROM mesh_ops.read_scope_display_codes_v1();
    IF v_revision IS NULL OR v_codes.workspace_code IS NULL OR v_codes.network_code IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'Device inventory unavailable';
    END IF;
    RETURN QUERY SELECT v_workspace, v_network, v_revision, v_codes.workspace_code, v_codes.network_code;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.authorize_console_device_read_internal_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) FROM PUBLIC;

-- A page of the scope's Devices in name order. p_name_prefix (lower-case
-- [a-z0-9.-]) keeps names that start with it; p_state 'active' keeps Devices
-- active and unexpired at p_evaluated_at, 'inactive' every other one, NULL
-- all. The page follows (p_after_hostname, p_after_device_public_id).
CREATE FUNCTION mesh_ops.read_console_devices_v4(
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
            SELECT pg_catalog.jsonb_agg(mesh_ops.console_device_item_internal_v1(page)
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
REVOKE ALL ON FUNCTION mesh_ops.read_console_devices_v4(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ,
    TEXT, TEXT, TEXT, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_console_devices_v4(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ,
    TEXT, TEXT, TEXT, UUID, INTEGER
) TO mesh_runtime;

-- One Device of the scope with how it was enrolled (by a browser sign-in, or
-- by an enrollment key: its ID, description and creator) and its tags. NULL
-- without authority; no device member when the scope holds no such Device.
CREATE FUNCTION mesh_ops.read_console_device_v1(
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
        'device', mesh_ops.console_device_item_internal_v1(v_device),
        'enrollment', COALESCE(v_enrollment, pg_catalog.jsonb_build_object('kind', 'browser')),
        'tags', COALESCE((
            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('id', tag.public_id, 'name', tag.name)
                ORDER BY tag.name, tag.public_id)
            FROM mesh.device_tag_assignment AS assignment
            JOIN mesh.device_tag AS tag
              ON tag.id = assignment.device_tag_id AND tag.workspace_id = assignment.workspace_id
            WHERE assignment.workspace_id = v_device.workspace_id AND assignment.network_id = v_device.network_id
              AND assignment.device_id = v_device.id AND tag.state = 'active'
        ), '[]'::JSONB));
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_console_device_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_console_device_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ, UUID
) TO mesh_runtime;

-- The Network's current revisions and one of its connectable Devices, for
-- that Device's delivery status. NULL without authority; no device member
-- when the scope holds no active or suspended Device of that ID.
CREATE FUNCTION mesh_ops.read_device_distribution_target_v1(
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
    v_network_revision BIGINT;
    v_policy_revision BIGINT;
    v_device JSONB;
BEGIN
    IF p_evaluated_at IS NULL OR p_device_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_device_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Device distribution input';
    END IF;
    SELECT * INTO v_scope FROM mesh_ops.authorize_console_device_read_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_evaluated_at);
    IF v_scope.scope_workspace IS NULL THEN
        RETURN NULL;
    END IF;
    SELECT revision.network_revision, revision.policy_revision INTO v_network_revision, v_policy_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_scope.scope_workspace AND revision.network_id = v_scope.scope_network;
    SELECT pg_catalog.jsonb_build_object('id', device.public_id, 'hostname', device.hostname, 'state', device.state)
    INTO v_device
    FROM mesh.device AS device
    WHERE device.workspace_id = v_scope.scope_workspace AND device.network_id = v_scope.scope_network
      AND device.public_id = p_device_public_id AND device.deleted_at IS NULL
      AND device.state IN ('active', 'suspended');
    RETURN pg_catalog.jsonb_build_object(
        'workspace_id', p_workspace_public_id, 'network_id', p_network_public_id,
        'network_revision', v_network_revision, 'policy_revision', v_policy_revision,
        'devices', CASE WHEN v_device IS NULL THEN '[]'::JSONB ELSE pg_catalog.jsonb_build_array(v_device) END);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_device_distribution_target_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_device_distribution_target_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ, UUID
) TO mesh_runtime;

-- The hostnames of up to 100 Devices of the scope, by public ID, to name the
-- peers a Device reports. IDs of other Networks are left out. NULL without
-- authority.
CREATE FUNCTION mesh_ops.read_console_device_names_v1(
    p_session_public_id UUID, p_deployment_public_id UUID,
    p_principal_public_id UUID, p_identity_subject_public_id UUID,
    p_session_version BIGINT, p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT, p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT, p_workspace_public_id UUID,
    p_network_public_id UUID, p_evaluated_at TIMESTAMPTZ, p_device_public_ids UUID[]
)
RETURNS JSONB
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    v_scope RECORD;
BEGIN
    IF p_evaluated_at IS NULL OR p_device_public_ids IS NULL
        OR pg_catalog.cardinality(p_device_public_ids) > 100 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Device name input';
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
        'names', COALESCE((
            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('id', device.public_id,
                'hostname', device.hostname) ORDER BY device.public_id)
            FROM mesh.device AS device
            WHERE device.workspace_id = v_scope.scope_workspace AND device.network_id = v_scope.scope_network
              AND device.public_id = ANY (p_device_public_ids)
        ), '[]'::JSONB));
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_console_device_names_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ, UUID[]
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_console_device_names_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ, UUID[]
) TO mesh_runtime;
