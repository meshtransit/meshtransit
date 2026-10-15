-- Schema 169: every Device has a DNS name in its Network.
--
-- A Device is named <dns label>.<workspace code>.<network code>.<suffix>. The
-- label is derived from the hostname (its first label, lowercased, other
-- characters replaced by hyphens, trimmed to 63 bytes; "device" when nothing
-- is left, "device-" before an all-digit result) and is unique among the
-- live Devices of one Network: a Device whose hostname derives a taken label
-- gets the first free numbered variant (<label>-1, <label>-2, ...); existing
-- Devices are labeled Network by Network in Device order.
--
-- Labels live beside the Device row (mesh.device_dns_label), not in it: a
-- label is derived discovery metadata, never authority, and labeling an
-- existing Device must neither version it nor need audit evidence (every
-- Device row change does). A trigger keeps labels current on every write
-- path: a Device that is inserted, renamed or reactivated gets one; one that
-- is revoked or deleted releases it at once. Writers that change Devices
-- hold the Network revision, which serializes the allocation; the unique
-- constraint is the final arbiter.
--
-- Renaming a Device (change_device_lifecycle_v1) refuses a hostname whose
-- label another live Device holds, with MTL03 as for a taken hostname, so a
-- rename never yields a numbered variant the administrator did not choose.
--
-- Maps read the labels of the Devices they list (the runtime may read the
-- labels of its exact scope) and the scope's display codes through
-- read_scope_display_codes_v1. The Console inventory v3 adds both to v2.

CREATE TABLE mesh.device_dns_label (
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    device_id BIGINT NOT NULL,
    dns_label TEXT COLLATE "C" NOT NULL,
    CONSTRAINT device_dns_label_pkey PRIMARY KEY (workspace_id, network_id, device_id),
    CONSTRAINT device_dns_label_network_label_key UNIQUE (workspace_id, network_id, dns_label),
    CONSTRAINT device_dns_label_check CHECK (
        pg_catalog.octet_length(dns_label) BETWEEN 1 AND 63
        AND dns_label ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
        AND dns_label !~ '^[0-9]+$'
    ),
    CONSTRAINT device_dns_label_device_fk FOREIGN KEY (workspace_id, network_id, device_id)
        REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE CASCADE
);

ALTER TABLE mesh.device_dns_label ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.device_dns_label FORCE ROW LEVEL SECURITY;
CREATE POLICY device_dns_label_migrator_policy ON mesh.device_dns_label
    TO mesh_migrator
    USING (TRUE)
    WITH CHECK (TRUE);
CREATE POLICY device_dns_label_exact_scope_policy ON mesh.device_dns_label
    FOR SELECT
    TO mesh_runtime
    USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    );
REVOKE ALL ON mesh.device_dns_label
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT SELECT ON mesh.device_dns_label TO mesh_runtime;

-- The label a hostname derives, before deduplication.
CREATE FUNCTION mesh_ops.derive_device_dns_label_v1(p_hostname TEXT)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT CASE
        WHEN bounded.label = '' THEN 'device'
        WHEN bounded.label ~ '^[0-9]+$' THEN pg_catalog.rtrim(pg_catalog.left('device-' || bounded.label, 63), '-')
        ELSE bounded.label
    END
    FROM (
        SELECT pg_catalog.rtrim(pg_catalog.left(pg_catalog.btrim(pg_catalog.regexp_replace(
            pg_catalog.lower(pg_catalog.split_part(pg_catalog.btrim(COALESCE(p_hostname, '')), '.', 1)),
            '[^a-z0-9]+', '-', 'g'), '-'), 63), '-') AS label
    ) AS bounded
$function$;

-- Numbered variant p_ordinal of a derived label (0: the label itself).
CREATE FUNCTION mesh_ops.device_dns_label_variant_v1(p_label TEXT, p_ordinal INTEGER)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT CASE
        WHEN p_ordinal = 0 THEN p_label
        ELSE pg_catalog.rtrim(pg_catalog.left(p_label, 63 - pg_catalog.length('-' || p_ordinal::TEXT)), '-')
            || '-' || p_ordinal::TEXT
    END
$function$;

-- Gives the Device the label its hostname derives, or the first free
-- numbered variant. A Device keeps its label while the hostname still
-- derives it (or one of its variants), so a client login that sends the
-- same hostname never renames it.
CREATE FUNCTION mesh_ops.assign_device_dns_label_internal_v1(
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

-- A live Device (active, expired or suspended) holds a label; a revoked or
-- deleted one releases it.
CREATE FUNCTION mesh_ops.maintain_device_dns_label_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF NEW.state IN ('revoked', 'deleted') OR NEW.deleted_at IS NOT NULL THEN
        DELETE FROM mesh.device_dns_label AS label
        WHERE label.workspace_id = NEW.workspace_id AND label.network_id = NEW.network_id
          AND label.device_id = NEW.id;
    ELSE
        PERFORM mesh_ops.assign_device_dns_label_internal_v1(NEW.workspace_id, NEW.network_id, NEW.id, NEW.hostname);
    END IF;
    RETURN NULL;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.derive_device_dns_label_v1(TEXT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.device_dns_label_variant_v1(TEXT, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.assign_device_dns_label_internal_v1(BIGINT, BIGINT, BIGINT, TEXT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.maintain_device_dns_label_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE TRIGGER device_dns_label_insert
AFTER INSERT ON mesh.device
FOR EACH ROW EXECUTE FUNCTION mesh_ops.maintain_device_dns_label_v1();
CREATE TRIGGER device_dns_label_update
AFTER UPDATE ON mesh.device
FOR EACH ROW
WHEN ((OLD.hostname, OLD.state, OLD.deleted_at) IS DISTINCT FROM (NEW.hostname, NEW.state, NEW.deleted_at))
EXECUTE FUNCTION mesh_ops.maintain_device_dns_label_v1();

-- Existing live Devices, Network by Network in Device order.
DO $backfill$
DECLARE
    v_device RECORD;
BEGIN
    FOR v_device IN
        SELECT device.workspace_id, device.network_id, device.id, device.hostname
        FROM mesh.device AS device
        WHERE device.state NOT IN ('revoked', 'deleted') AND device.deleted_at IS NULL
        ORDER BY device.workspace_id, device.network_id, device.id
    LOOP
        PERFORM mesh_ops.assign_device_dns_label_internal_v1(
            v_device.workspace_id, v_device.network_id, v_device.id, v_device.hostname);
    END LOOP;
END;
$backfill$;

-- The Workspace and Network display codes of the installed exact scope
-- (immutable; no row without a scope).
CREATE FUNCTION mesh_ops.read_scope_display_codes_v1()
RETURNS TABLE (workspace_code TEXT, network_code TEXT)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT workspace_identity.display_code, network_identity.display_code
    FROM mesh.workspace AS workspace
    JOIN mesh.network AS network
      ON network.workspace_id = workspace.id
     AND network.id = mesh_ops.current_network_id()
    JOIN mesh_ops.tenant_display_identity AS workspace_identity
      ON workspace_identity.workspace_public_id = workspace.public_id
    JOIN mesh_ops.tenant_display_identity AS network_identity
      ON network_identity.network_public_id = network.public_id
    WHERE workspace.id = mesh_ops.current_workspace_id()
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_scope_display_codes_v1()
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_scope_display_codes_v1() TO mesh_runtime;

-- The Console inventory v2 with each Device's DNS label (null when it holds
-- none) and the scope's display codes.
CREATE FUNCTION mesh_ops.read_console_devices_v3(
    p_session_public_id UUID, p_deployment_public_id UUID,
    p_principal_public_id UUID, p_identity_subject_public_id UUID,
    p_session_version BIGINT, p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT, p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT, p_workspace_public_id UUID,
    p_network_public_id UUID, p_evaluated_at TIMESTAMPTZ,
    p_after_device_public_id UUID, p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_page JSONB;
    v_codes RECORD;
BEGIN
    v_page := mesh_ops.read_console_devices_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_evaluated_at, p_after_device_public_id, p_limit);
    IF v_page IS NULL THEN
        RETURN NULL;
    END IF;
    -- v2 installed and authorized the exact scope.
    SELECT * INTO v_codes FROM mesh_ops.read_scope_display_codes_v1();
    IF v_codes.workspace_code IS NULL OR v_codes.network_code IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'Device inventory unavailable';
    END IF;
    RETURN v_page || pg_catalog.jsonb_build_object(
        'workspace_code', v_codes.workspace_code,
        'network_code', v_codes.network_code,
        'devices', COALESCE((
            SELECT pg_catalog.jsonb_agg(
                item.device || pg_catalog.jsonb_build_object('dns_label', label.dns_label) ORDER BY item.ordinal)
            FROM pg_catalog.jsonb_array_elements(v_page -> 'devices') WITH ORDINALITY AS item(device, ordinal)
            LEFT JOIN mesh.device AS device
              ON device.workspace_id = mesh_ops.current_workspace_id()
             AND device.network_id = mesh_ops.current_network_id()
             AND device.public_id = (item.device ->> 'id')::UUID
            LEFT JOIN mesh.device_dns_label AS label
              ON label.workspace_id = device.workspace_id
             AND label.network_id = device.network_id
             AND label.device_id = device.id
        ), '[]'::JSONB)
    );
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_console_devices_v3(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_console_devices_v3(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ, UUID, INTEGER
) TO mesh_runtime;

-- Schema 127's function with the rename refusing a label another live Device
-- of the Network holds (MTL03).
CREATE OR REPLACE FUNCTION mesh_ops.change_device_lifecycle_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_device_public_id UUID,
    p_action TEXT, p_expected_version BIGINT, p_target_principal_public_id UUID, p_hostname TEXT,
    p_change_public_id UUID, p_evaluated_at TIMESTAMPTZ
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
    v_permission TEXT;
    v_grant RECORD;
    v_device mesh.device%ROWTYPE;
    v_before JSONB;
    v_target BIGINT;
    v_workspace_owner BIGINT;
    v_hostname TEXT;
    v_network_revision BIGINT;
    v_inventory_revision BIGINT;
    v_group_revision BIGINT;
    v_dns_revision BIGINT;
    v_owner_changes BOOLEAN := FALSE;
    v_now TIMESTAMPTZ := GREATEST(pg_catalog.clock_timestamp(), p_evaluated_at);
BEGIN
    v_permission := CASE p_action
        WHEN 'suspend' THEN 'device.quarantine'
        WHEN 'resume' THEN 'device.quarantine'
        WHEN 'transfer_workspace' THEN 'device.transfer'
        WHEN 'transfer_member' THEN 'device.transfer'
        WHEN 'rename' THEN 'device.manage'
    END;
    IF v_workspace IS NULL OR v_network IS NULL OR v_permission IS NULL
        OR p_device_public_id IS NULL OR p_expected_version IS NULL OR p_expected_version < 1
        OR p_change_public_id IS NULL OR p_evaluated_at IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR (p_action = 'transfer_member') <> (p_target_principal_public_id IS NOT NULL)
        OR (p_action = 'rename') <> (p_hostname IS NOT NULL) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Device lifecycle change is invalid';
    END IF;
    IF p_action = 'rename' THEN
        v_hostname := pg_catalog.lower(p_hostname);
        IF pg_catalog.octet_length(p_hostname) NOT BETWEEN 1 AND 253
            OR v_hostname !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$' THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Device hostname is invalid';
        END IF;
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, v_permission, p_evaluated_at
    ) LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Device lifecycle change is not authorized';
    END IF;

    -- Serializes with registration, publication and other map inputs.
    PERFORM 1 FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_workspace AND revision.network_id = v_network
    FOR UPDATE;
    SELECT * INTO v_device FROM mesh.device AS device
    WHERE device.workspace_id = v_workspace AND device.network_id = v_network
      AND device.public_id = p_device_public_id AND device.deleted_at IS NULL
    FOR UPDATE;
    IF v_device.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Device is unavailable';
    END IF;
    IF v_device.version <> p_expected_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Device changed';
    END IF;
    IF v_device.state NOT IN ('active', 'suspended') THEN
        RAISE EXCEPTION USING ERRCODE = 'MTL01', MESSAGE = 'Device is not active or suspended';
    END IF;
    v_before := mesh_ops.device_lifecycle_document_internal_v1(v_device);
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    CASE p_action
    WHEN 'suspend' THEN
        IF v_device.state <> 'active' THEN
            RAISE EXCEPTION USING ERRCODE = 'MTL01', MESSAGE = 'Device is not active';
        END IF;
        UPDATE mesh.device SET state = 'suspended', suspended_reason = 'admin',
            session_generation = session_generation + 1, version = version + 1, updated_at = v_now
        WHERE id = v_device.id RETURNING * INTO v_device;
    WHEN 'resume' THEN
        -- Resuming a Device that waits for handover cancels the handover.
        IF v_device.state <> 'suspended' THEN
            RAISE EXCEPTION USING ERRCODE = 'MTL01', MESSAGE = 'Device is not suspended';
        END IF;
        IF v_device.suspended_reason = 'member' THEN
            RAISE EXCEPTION USING ERRCODE = 'MTL01', MESSAGE = 'resume the member to resume this Device';
        END IF;
        UPDATE mesh.device SET state = 'active', suspended_reason = NULL, handover_principal_id = NULL,
            version = version + 1, updated_at = v_now
        WHERE id = v_device.id RETURNING * INTO v_device;
    WHEN 'transfer_workspace' THEN
        IF v_device.ownership = 'workspace' AND v_device.handover_principal_id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'MTL01', MESSAGE = 'Device is already owned by the Workspace';
        END IF;
        v_workspace_owner := mesh_ops.workspace_device_principal_internal_v1(v_workspace);
        -- An administrator's suspension stays; a pending handover ends, and so
        -- does the suspension of a suspended member, who no longer owns it.
        UPDATE mesh.device SET ownership = 'workspace',
            owner_principal_id = v_workspace_owner, custodian_principal_id = v_workspace_owner,
            expires_at = mesh_ops.device_never_expires_v1(),
            state = CASE WHEN suspended_reason IN ('handover', 'member') THEN 'active' ELSE state END,
            suspended_reason = CASE WHEN suspended_reason IN ('handover', 'member') THEN NULL
                                    ELSE suspended_reason END,
            handover_principal_id = NULL,
            session_generation = session_generation + 1, version = version + 1, updated_at = v_now
        WHERE id = v_device.id RETURNING * INTO v_device;
        v_owner_changes := TRUE;
    WHEN 'transfer_member' THEN
        SELECT principal.id INTO v_target
        FROM mesh.principal AS principal
        JOIN mesh.workspace_membership AS membership
          ON membership.workspace_id = v_workspace AND membership.principal_id = principal.id
         AND membership.state = 'active'
         AND (membership.expires_at IS NULL OR membership.expires_at > v_now)
        JOIN mesh.network_membership AS network_member
          ON network_member.workspace_id = v_workspace AND network_member.network_id = v_network
         AND network_member.principal_id = principal.id AND network_member.state = 'active'
         AND (network_member.expires_at IS NULL OR network_member.expires_at > v_now)
        WHERE principal.public_id = p_target_principal_public_id
          AND principal.state = 'active' AND principal.deleted_at IS NULL;
        IF v_target IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'MTL02', MESSAGE = 'new owner is not an active member of this Network';
        END IF;
        IF v_device.ownership = 'member' AND v_device.owner_principal_id = v_target THEN
            RAISE EXCEPTION USING ERRCODE = 'MTL01', MESSAGE = 'Device already belongs to this member';
        END IF;
        IF v_device.suspended_reason = 'admin' THEN
            RAISE EXCEPTION USING ERRCODE = 'MTL01', MESSAGE = 'resume the suspended Device before transferring it';
        END IF;
        UPDATE mesh.device SET state = 'suspended', suspended_reason = 'handover',
            handover_principal_id = v_target,
            session_generation = session_generation + 1, version = version + 1, updated_at = v_now
        WHERE id = v_device.id RETURNING * INTO v_device;
    WHEN 'rename' THEN
        IF v_hostname = v_device.hostname THEN
            RAISE EXCEPTION USING ERRCODE = 'MTL01', MESSAGE = 'Device already has this hostname';
        END IF;
        IF EXISTS (
            SELECT 1 FROM mesh.device AS other
            WHERE other.workspace_id = v_workspace AND other.network_id = v_network
              AND other.hostname_key = v_hostname AND other.deleted_at IS NULL AND other.id <> v_device.id
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'MTL03', MESSAGE = 'another Device has this hostname';
        END IF;
        IF EXISTS (
            SELECT 1 FROM mesh.device_dns_label AS other
            WHERE other.workspace_id = v_workspace AND other.network_id = v_network
              AND other.dns_label = mesh_ops.derive_device_dns_label_v1(v_hostname)
              AND other.device_id <> v_device.id
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'MTL03', MESSAGE = 'another Device has this DNS name';
        END IF;
        UPDATE mesh.device SET hostname = v_hostname, hostname_key = v_hostname, hostname_locked = TRUE,
            version = version + 1, updated_at = v_now
        WHERE id = v_device.id RETURNING * INTO v_device;
    END CASE;

    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        inventory_revision = revision.inventory_revision + 1,
        group_revision = revision.group_revision + CASE WHEN v_owner_changes THEN 1 ELSE 0 END,
        dns_revision = revision.dns_revision + CASE WHEN p_action = 'rename' THEN 1 ELSE 0 END,
        updated_at = pg_catalog.clock_timestamp()
    WHERE revision.workspace_id = v_workspace AND revision.network_id = v_network
    RETURNING revision.network_revision, revision.inventory_revision, revision.group_revision,
        revision.dns_revision
    INTO v_network_revision, v_inventory_revision, v_group_revision, v_dns_revision;

    RETURN pg_catalog.jsonb_build_object(
        'before', v_before,
        'after', mesh_ops.device_lifecycle_document_internal_v1(v_device),
        'network_revision', v_network_revision,
        'inventory_revision', v_inventory_revision,
        'group_revision', v_group_revision,
        'role_binding_id', v_grant.role_binding_public_id,
        'permission', v_permission
    );
END;
$function$;
