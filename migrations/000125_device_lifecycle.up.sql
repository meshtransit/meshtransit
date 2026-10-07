-- Schema 125: Device ownership, suspension, transfer and rename (L1 of
-- docs/device-lifecycle.md).
--
-- Ownership. A Device is owned by a member (laptops: the member's untagged
-- Devices join their Identity Groups, and the session expires per profile)
-- or by the Workspace (servers, shared machines: no member's departure
-- affects it and it never expires). Workspace Devices are owned by one
-- service principal per Workspace, so every reader that joins the owner
-- principal keeps working; device.ownership names the kind explicitly.
-- registered_by never changes.
--
-- Suspension. A suspended Device keeps its identity, keys, addresses, tags
-- and group memberships but is in no map (maps admit only active Devices),
-- and a new session generation cuts its open sessions. Reasons:
--   admin     an administrator suspended it (device.quarantine);
--   handover  it is being transferred to a member and waits until that
--             member signs in on the Device (browser registration resume).
--
-- Transfer (device.transfer): to the Workspace takes effect at once; to a
-- member suspends the Device for handover so that whoever holds it must
-- prove to be the new owner. The handover completes inside the browser
-- completion transaction, which grants mesh_runtime the columns below.
--
-- Rename (device.manage) sets the hostname and locks it, so a later client
-- login does not rename the Device back.
--
-- change_device_lifecycle_v1 authorizes, applies and returns the before and
-- after documents; the caller appends audit evidence and the revision wakeup
-- under the same change identity. Errors: 22023 invalid input, 42501 not
-- authorized, P0002 unknown Device, 40001 stale version, MTL01 the Device is
-- in a state the action does not accept, MTL02 the new owner is not an
-- active member of the Workspace and Network, MTL03 hostname taken.

ALTER TABLE mesh.device
    ADD COLUMN ownership TEXT NOT NULL DEFAULT 'member',
    ADD COLUMN suspended_reason TEXT,
    ADD COLUMN handover_principal_id BIGINT,
    ADD COLUMN hostname_locked BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE mesh.device DROP CONSTRAINT device_state_check;
ALTER TABLE mesh.device
    ADD CONSTRAINT device_state_check CHECK (
        state IN ('active', 'expired', 'suspended', 'revoked', 'deleted')
    ),
    ADD CONSTRAINT device_ownership_check CHECK (ownership IN ('member', 'workspace')),
    ADD CONSTRAINT device_suspension_check CHECK (
        (state = 'suspended') = (suspended_reason IS NOT NULL)
        AND (suspended_reason IS NULL OR suspended_reason IN ('admin', 'handover'))
        AND (handover_principal_id IS NOT NULL) = (suspended_reason IS NOT DISTINCT FROM 'handover')
    ),
    ADD CONSTRAINT device_handover_principal_fk FOREIGN KEY (handover_principal_id)
        REFERENCES mesh.principal (id) ON DELETE RESTRICT;

CREATE INDEX device_handover_principal_idx ON mesh.device (handover_principal_id)
    WHERE handover_principal_id IS NOT NULL;

GRANT UPDATE (ownership, suspended_reason, handover_principal_id, hostname_locked)
    ON mesh.device TO mesh_runtime;

-- A Workspace Device never expires; the sentinel matches share contracts.
CREATE FUNCTION mesh_ops.device_never_expires_v1()
RETURNS TIMESTAMPTZ
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$ SELECT TIMESTAMPTZ '2200-01-01 00:00:00+00' $function$;
GRANT EXECUTE ON FUNCTION mesh_ops.device_never_expires_v1() TO mesh_runtime;

-- The service principal that owns one Workspace's Devices.
CREATE TABLE mesh.workspace_device_principal (
    workspace_id BIGINT PRIMARY KEY,
    principal_id BIGINT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT workspace_device_principal_workspace_fk FOREIGN KEY (workspace_id)
        REFERENCES mesh.workspace (id) ON DELETE RESTRICT,
    CONSTRAINT workspace_device_principal_principal_fk FOREIGN KEY (principal_id)
        REFERENCES mesh.principal (id) ON DELETE RESTRICT
);
ALTER TABLE mesh.workspace_device_principal ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.workspace_device_principal FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_device_principal_migrator_policy ON mesh.workspace_device_principal
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.workspace_device_principal FROM PUBLIC;

CREATE FUNCTION mesh_ops.workspace_device_principal_internal_v1(p_workspace_id BIGINT)
RETURNS BIGINT
LANGUAGE plpgsql
VOLATILE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_principal BIGINT;
BEGIN
    SELECT owner.principal_id INTO v_principal
    FROM mesh.workspace_device_principal AS owner
    WHERE owner.workspace_id = p_workspace_id;
    IF v_principal IS NOT NULL THEN
        RETURN v_principal;
    END IF;
    INSERT INTO mesh.principal (public_id, deployment_id, kind, state)
    SELECT pg_catalog.uuidv7(), workspace.deployment_id, 'service', 'active'
    FROM mesh.workspace AS workspace
    WHERE workspace.id = p_workspace_id
    RETURNING id INTO v_principal;
    IF v_principal IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Workspace is unavailable';
    END IF;
    INSERT INTO mesh.workspace_device_principal (workspace_id, principal_id)
    VALUES (p_workspace_id, v_principal);
    RETURN v_principal;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.workspace_device_principal_internal_v1(BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The lifecycle document of one Device; principals by public identity.
CREATE FUNCTION mesh_ops.device_lifecycle_document_internal_v1(p_device mesh.device)
RETURNS JSONB
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'device_id', p_device.public_id,
        'hostname', p_device.hostname,
        'state', p_device.state,
        'ownership', p_device.ownership,
        'owner_principal_id', CASE WHEN p_device.ownership = 'member' THEN
            (SELECT principal.public_id FROM mesh.principal AS principal
             WHERE principal.id = p_device.owner_principal_id) END,
        'suspended_reason', p_device.suspended_reason,
        'handover_principal_id', (SELECT principal.public_id FROM mesh.principal AS principal
                                  WHERE principal.id = p_device.handover_principal_id),
        'hostname_locked', p_device.hostname_locked,
        'expires_at', p_device.expires_at,
        'version', p_device.version
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.device_lifecycle_document_internal_v1(mesh.device)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.change_device_lifecycle_v1(
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
        UPDATE mesh.device SET state = 'active', suspended_reason = NULL, handover_principal_id = NULL,
            version = version + 1, updated_at = v_now
        WHERE id = v_device.id RETURNING * INTO v_device;
    WHEN 'transfer_workspace' THEN
        IF v_device.ownership = 'workspace' AND v_device.handover_principal_id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'MTL01', MESSAGE = 'Device is already owned by the Workspace';
        END IF;
        v_workspace_owner := mesh_ops.workspace_device_principal_internal_v1(v_workspace);
        -- An administrator's suspension stays; a pending handover ends.
        UPDATE mesh.device SET ownership = 'workspace',
            owner_principal_id = v_workspace_owner, custodian_principal_id = v_workspace_owner,
            expires_at = mesh_ops.device_never_expires_v1(),
            state = CASE WHEN suspended_reason = 'handover' THEN 'active' ELSE state END,
            suspended_reason = CASE WHEN suspended_reason = 'handover' THEN NULL ELSE suspended_reason END,
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

REVOKE ALL ON FUNCTION mesh_ops.change_device_lifecycle_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID,
    TEXT, BIGINT, UUID, TEXT, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_device_lifecycle_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID,
    TEXT, BIGINT, UUID, TEXT, UUID, TIMESTAMPTZ
) TO mesh_runtime;

-- The Console inventory (schema 76's v1) with ownership and suspension:
-- owner and handover member names come from the members' accounts.
CREATE FUNCTION mesh_ops.read_console_devices_v2(
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
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    resolved_workspace BIGINT;
    resolved_network BIGINT;
    revision BIGINT;
    result JSONB;
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 101 OR
       (p_after_device_public_id IS NOT NULL AND
        pg_catalog.get_byte(pg_catalog.uuid_send(p_after_device_public_id), 6) >> 4 <> 7) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Device inventory input';
    END IF;
    BEGIN
        SELECT workspace_internal_id, network_internal_id
        INTO resolved_workspace, resolved_network
        FROM mesh_ops.set_network_scope(p_workspace_public_id, p_network_public_id);
    EXCEPTION WHEN foreign_key_violation OR insufficient_privilege THEN
        RETURN NULL;
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
        RETURN NULL;
    END IF;
    SELECT inventory_revision INTO revision
    FROM mesh_ops.network_revision
    WHERE workspace_id = resolved_workspace AND network_id = resolved_network
    FOR SHARE;
    IF revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'Device inventory unavailable';
    END IF;
    SELECT pg_catalog.jsonb_build_object(
        'workspace_id', p_workspace_public_id, 'network_id', p_network_public_id,
        'inventory_revision', revision,
        'devices', COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
            'id', device.public_id, 'hostname', device.hostname,
            'state', device.state, 'is_ephemeral', device.is_ephemeral,
            'version', device.version, 'created_at', device.created_at,
            'updated_at', device.updated_at, 'expires_at', device.expires_at,
            'ownership', device.ownership,
            'owner', CASE WHEN device.ownership = 'member' THEN pg_catalog.jsonb_build_object(
                'principal_id', owner.public_id, 'display_name', COALESCE(owner_account.display_name, ''))
                ELSE NULL END,
            'suspended_reason', device.suspended_reason,
            'handover_to', CASE WHEN device.handover_principal_id IS NOT NULL THEN pg_catalog.jsonb_build_object(
                'principal_id', handover.public_id, 'display_name', COALESCE(handover_account.display_name, ''))
                ELSE NULL END
        ) ORDER BY device.public_id), '[]'::JSONB)
    ) INTO result
    FROM (
        SELECT public_id, hostname, state, is_ephemeral, version, created_at, updated_at, expires_at,
               ownership, owner_principal_id, suspended_reason, handover_principal_id
        FROM mesh.device
        WHERE workspace_id = resolved_workspace AND network_id = resolved_network
          AND (p_after_device_public_id IS NULL OR public_id > p_after_device_public_id)
        ORDER BY public_id LIMIT p_limit
    ) AS device
    LEFT JOIN mesh.principal AS owner ON owner.id = device.owner_principal_id
    LEFT JOIN mesh.account AS owner_account
      ON owner_account.deployment_id = owner.deployment_id AND owner_account.principal_id = owner.id
    LEFT JOIN mesh.principal AS handover ON handover.id = device.handover_principal_id
    LEFT JOIN mesh.account AS handover_account
      ON handover_account.deployment_id = handover.deployment_id
     AND handover_account.principal_id = handover.id;
    RETURN result;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.read_console_devices_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_console_devices_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ, UUID, INTEGER
) TO mesh_runtime;
