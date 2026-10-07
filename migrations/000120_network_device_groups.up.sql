-- Schema 120 (G1): Network Device Groups and Access Rules that select them.
--
-- A Device Group belongs to one Network and holds Devices of that Network
-- only, so no group reaches across Networks; crossing a Network still needs a
-- share and passes the Workspace guardrails. A Device may be in many groups;
-- an empty group grants nothing.
--
-- Rules name groups, not their members. A release stores group rules once
-- (mesh.compiled_policy_group_rule) and mesh_ops.resolve_group_policy_edges_v1
-- resolves them to Device pairs from the current membership, so a membership
-- change reaches maps without republishing policy. Every membership change
-- advances the Network and group revisions under the Network revision lock
-- and commits with audit evidence naming the member-set hashes before and
-- after, so the policy that applied at a Network revision can be rebuilt from
-- the release plus the membership history.
--
-- Tables are reachable only through the SECURITY DEFINER functions below;
-- each checks the caller's Session and the exact Network permission.

CREATE TABLE mesh.device_group (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    name TEXT NOT NULL,
    name_key TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    member_count INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'active',
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ,
    CONSTRAINT device_group_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT device_group_name_check CHECK (
        name = pg_catalog.btrim(name)
        AND pg_catalog.char_length(name) BETWEEN 1 AND 64
        AND name !~ '[[:cntrl:]]'
        AND name_key = pg_catalog.lower(name)
    ),
    CONSTRAINT device_group_description_check CHECK (
        pg_catalog.char_length(description) <= 280 AND description !~ '[[:cntrl:]]'
    ),
    CONSTRAINT device_group_member_count_check CHECK (member_count BETWEEN 0 AND 5000),
    CONSTRAINT device_group_state_check CHECK (
        (state = 'active' AND deleted_at IS NULL)
        OR (state = 'deleted' AND deleted_at IS NOT NULL AND member_count = 0)
    ),
    CONSTRAINT device_group_timestamps_check CHECK (updated_at >= created_at),
    CONSTRAINT device_group_workspace_fk FOREIGN KEY (deployment_id, workspace_id)
        REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT device_group_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    UNIQUE (workspace_id, network_id, id)
);

CREATE UNIQUE INDEX device_group_active_name_uidx
    ON mesh.device_group (workspace_id, network_id, name_key)
    WHERE state = 'active';

CREATE TABLE mesh.device_group_member (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    device_group_id BIGINT NOT NULL,
    device_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version = 1),
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT device_group_member_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT device_group_member_group_fk FOREIGN KEY (workspace_id, network_id, device_group_id)
        REFERENCES mesh.device_group (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT device_group_member_device_fk FOREIGN KEY (workspace_id, network_id, device_id)
        REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE RESTRICT,
    UNIQUE (device_group_id, device_id)
);

CREATE INDEX device_group_member_device_idx
    ON mesh.device_group_member (workspace_id, network_id, device_id, device_group_id);

-- Groups are never hard-deleted; scope and identity never change; every
-- update advances the version by one; deletion is terminal.
CREATE FUNCTION mesh_ops.enforce_device_group_transition_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Device Groups are never deleted';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.version <> 1 OR NEW.state <> 'active' OR NEW.member_count <> 0 THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Device Group must start active, empty, at version 1';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.public_id <> OLD.public_id OR NEW.deployment_id <> OLD.deployment_id
        OR NEW.workspace_id <> OLD.workspace_id OR NEW.network_id <> OLD.network_id
        OR NEW.created_at <> OLD.created_at OR NEW.version <> OLD.version + 1
        OR OLD.state = 'deleted' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Device Group transition';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER device_group_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.device_group
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_device_group_transition_v1();
CREATE TRIGGER device_group_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.device_group
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('device_group', 'public_id');

-- Membership rows are inserted or deleted, never rewritten.
CREATE TRIGGER device_group_member_immutable
BEFORE UPDATE ON mesh.device_group_member
FOR EACH ROW EXECUTE FUNCTION mesh_audit.reject_immutable_change();
CREATE TRIGGER device_group_member_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.device_group_member
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('device_group_member', 'public_id');

-- One Access Rule of a release whose source or destination is a Device
-- Group. Device-to-Device rules stay in mesh.compiled_policy_rule; an Access
-- Rule lives in exactly one of the two tables.
CREATE TABLE mesh.compiled_policy_group_rule (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    access_rule_public_id UUID NOT NULL,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    policy_release_id BIGINT NOT NULL,
    policy_revision BIGINT NOT NULL CHECK (policy_revision > 0),
    source_device_id BIGINT,
    source_device_group_id BIGINT,
    destination_device_id BIGINT,
    destination_device_group_id BIGINT,
    protocol TEXT NOT NULL,
    destination_ports INT4MULTIRANGE NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version = 1),
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT compiled_policy_group_rule_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT compiled_policy_group_rule_access_rule_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(access_rule_public_id), 6) >> 4 = 7
    ),
    CONSTRAINT compiled_policy_group_rule_selector_check CHECK (
        pg_catalog.num_nonnulls(source_device_id, source_device_group_id) = 1
        AND pg_catalog.num_nonnulls(destination_device_id, destination_device_group_id) = 1
        AND (source_device_group_id IS NOT NULL OR destination_device_group_id IS NOT NULL)
    ),
    CONSTRAINT compiled_policy_group_rule_protocol_check CHECK (protocol IN ('tcp', 'udp', 'icmp')),
    CONSTRAINT compiled_policy_group_rule_port_shape_check CHECK (
        (protocol = 'icmp' AND destination_ports = '{}'::INT4MULTIRANGE)
        OR (
            protocol IN ('tcp', 'udp')
            AND NOT pg_catalog.isempty(destination_ports)
            AND destination_ports <@ '{[1,65536)}'::INT4MULTIRANGE
            AND mesh_ops.int4multirange_count(destination_ports) BETWEEN 1 AND 64
        )
    ),
    CONSTRAINT compiled_policy_group_rule_release_fk FOREIGN KEY (
        workspace_id, network_id, policy_release_id, policy_revision
    ) REFERENCES mesh.policy_release (workspace_id, network_id, id, policy_revision) ON DELETE RESTRICT,
    CONSTRAINT compiled_policy_group_rule_source_device_fk FOREIGN KEY (workspace_id, network_id, source_device_id)
        REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT compiled_policy_group_rule_destination_device_fk FOREIGN KEY (
        workspace_id, network_id, destination_device_id
    ) REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT compiled_policy_group_rule_source_group_fk FOREIGN KEY (
        workspace_id, network_id, source_device_group_id
    ) REFERENCES mesh.device_group (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT compiled_policy_group_rule_destination_group_fk FOREIGN KEY (
        workspace_id, network_id, destination_device_group_id
    ) REFERENCES mesh.device_group (workspace_id, network_id, id) ON DELETE RESTRICT,
    UNIQUE (policy_release_id, access_rule_public_id)
);

CREATE INDEX compiled_policy_group_rule_release_idx
    ON mesh.compiled_policy_group_rule (workspace_id, network_id, policy_revision, access_rule_public_id);
CREATE INDEX compiled_policy_group_rule_source_group_idx
    ON mesh.compiled_policy_group_rule (source_device_group_id) WHERE source_device_group_id IS NOT NULL;
CREATE INDEX compiled_policy_group_rule_destination_group_idx
    ON mesh.compiled_policy_group_rule (destination_device_group_id)
    WHERE destination_device_group_id IS NOT NULL;

CREATE TRIGGER compiled_policy_group_rule_immutable
BEFORE UPDATE OR DELETE ON mesh.compiled_policy_group_rule
FOR EACH ROW EXECUTE FUNCTION mesh_audit.reject_immutable_change();
CREATE TRIGGER compiled_policy_group_rule_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.compiled_policy_group_rule
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('compiled_policy_group_rule', 'public_id');

ALTER TABLE mesh.device_group ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.device_group FORCE ROW LEVEL SECURITY;
CREATE POLICY device_group_migrator_policy ON mesh.device_group TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
ALTER TABLE mesh.device_group_member ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.device_group_member FORCE ROW LEVEL SECURITY;
CREATE POLICY device_group_member_migrator_policy ON mesh.device_group_member
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
ALTER TABLE mesh.compiled_policy_group_rule ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.compiled_policy_group_rule FORCE ROW LEVEL SECURITY;
CREATE POLICY compiled_policy_group_rule_migrator_policy ON mesh.compiled_policy_group_rule
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.device_group, mesh.device_group_member, mesh.compiled_policy_group_rule
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- network_admin gains Device Group management: it already writes rules to
-- every Device of its Networks, so grouping them adds no reach.
INSERT INTO mesh.builtin_role_permission (role_key, permission_id)
SELECT 'network_admin', permission.id
FROM mesh.permission AS permission
WHERE permission.permission_key IN ('device_group.manage', 'device_group.members.manage')
ON CONFLICT DO NOTHING;

-- The exact Network scope bound by the caller, after one permission check.
-- Runs as the invoking definer function, so every query names the scope.
CREATE FUNCTION mesh_ops.authorize_device_group_internal_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_permission TEXT,
    p_evaluated_at TIMESTAMPTZ
)
RETURNS TABLE (deployment_id BIGINT, workspace_id BIGINT, network_id BIGINT, role_binding_public_id UUID)
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_deployment BIGINT;
    v_binding UUID;
BEGIN
    IF p_workspace_public_id IS NULL OR p_network_public_id IS NULL OR p_evaluated_at IS NULL
        OR p_permission NOT IN ('device_group.read', 'device_group.manage', 'device_group.members.manage') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Device Group scope input is invalid';
    END IF;
    SELECT workspace.deployment_id INTO v_deployment
    FROM mesh.workspace AS workspace
    JOIN mesh.network AS network ON network.workspace_id = workspace.id
    WHERE workspace.id = v_workspace AND network.id = v_network
      AND workspace.public_id = p_workspace_public_id AND network.public_id = p_network_public_id
      AND workspace.state = 'active' AND workspace.deleted_at IS NULL
      AND network.state = 'active' AND network.deleted_at IS NULL;
    IF v_deployment IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Device Group scope is unavailable';
    END IF;
    SELECT permission.role_binding_public_id INTO v_binding
    FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version,
        p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_permission, p_evaluated_at
    ) AS permission;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Device Group action is not authorized';
    END IF;
    RETURN QUERY SELECT v_deployment, v_workspace, v_network, v_binding;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.authorize_device_group_internal_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TEXT, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Whether a Session holds a permission in the bound Network, without raising.
CREATE FUNCTION mesh_ops.holds_device_group_permission_internal_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_permission TEXT,
    p_evaluated_at TIMESTAMPTZ
)
RETURNS BOOLEAN
LANGUAGE sql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
    SELECT EXISTS (
        SELECT 1 FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version,
            p_principal_authority_generation, p_account_session_generation,
            p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, p_permission, p_evaluated_at
        )
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.holds_device_group_permission_internal_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TEXT, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Rules of the Network's active release that select a group.
CREATE FUNCTION mesh_ops.device_group_rule_count_internal_v1(p_device_group_id BIGINT)
RETURNS INTEGER
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.count(*)::INTEGER
    FROM mesh.compiled_policy_group_rule AS rule
    JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id
    WHERE release.state = 'active'
      AND (rule.source_device_group_id = p_device_group_id
           OR rule.destination_device_group_id = p_device_group_id)
$function$;
REVOKE ALL ON FUNCTION mesh_ops.device_group_rule_count_internal_v1(BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- SHA-256 over the sorted member Device public IDs, one per line. Empty
-- groups hash the empty string.
CREATE FUNCTION mesh_ops.device_group_member_hash_internal_v1(p_device_group_id BIGINT)
RETURNS BYTEA
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.sha256(pg_catalog.convert_to(COALESCE(
        pg_catalog.string_agg(device.public_id::TEXT, E'\n' ORDER BY device.public_id::TEXT), ''
    ), 'UTF8'))
    FROM mesh.device_group_member AS member
    JOIN mesh.device AS device ON device.id = member.device_id
    WHERE member.device_group_id = p_device_group_id
$function$;
REVOKE ALL ON FUNCTION mesh_ops.device_group_member_hash_internal_v1(BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.device_group_document_internal_v1(p_group mesh.device_group)
RETURNS JSONB
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'group_id', p_group.public_id,
        'name', p_group.name,
        'description', p_group.description,
        'member_count', p_group.member_count,
        'rule_count', mesh_ops.device_group_rule_count_internal_v1(p_group.id),
        'state', p_group.state,
        'version', p_group.version,
        'created_at', p_group.created_at,
        'updated_at', p_group.updated_at
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.device_group_document_internal_v1(mesh.device_group)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The Network's active groups (device_group.read) and whether the Session
-- may change them, so the Console offers only what Core would accept.
CREATE FUNCTION mesh_ops.list_device_groups_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_evaluated_at TIMESTAMPTZ
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
BEGIN
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_device_group_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'device_group.read', p_evaluated_at
    );
    RETURN pg_catalog.jsonb_build_object(
        'groups', COALESCE((
            SELECT pg_catalog.jsonb_agg(mesh_ops.device_group_document_internal_v1(device_group)
                ORDER BY device_group.name_key, device_group.public_id)
            FROM mesh.device_group AS device_group
            WHERE device_group.workspace_id = v_scope.workspace_id
              AND device_group.network_id = v_scope.network_id
              AND device_group.state = 'active'
        ), '[]'::JSONB),
        'can_manage', mesh_ops.holds_device_group_permission_internal_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, 'device_group.manage', p_evaluated_at),
        'can_manage_members', mesh_ops.holds_device_group_permission_internal_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, 'device_group.members.manage', p_evaluated_at)
    );
END;
$function$;

-- One page of a group's members, ordered by Device public ID, at most 500.
-- A member whose Device is no longer active shows as inactive and grants
-- nothing. P0002: unknown group.
CREATE FUNCTION mesh_ops.read_device_group_members_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_group_public_id UUID,
    p_after_device_public_id UUID, p_limit INTEGER, p_evaluated_at TIMESTAMPTZ
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
    v_group mesh.device_group%ROWTYPE;
    v_members JSONB;
    v_count INTEGER;
BEGIN
    IF p_group_public_id IS NULL OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 500 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Device Group member page input is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_device_group_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'device_group.read', p_evaluated_at
    );
    SELECT * INTO v_group FROM mesh.device_group AS device_group
    WHERE device_group.workspace_id = v_scope.workspace_id AND device_group.network_id = v_scope.network_id
      AND device_group.public_id = p_group_public_id AND device_group.state = 'active';
    IF v_group.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Device Group is unavailable';
    END IF;
    WITH page AS (
        SELECT device.public_id, device.hostname, device.state, device.deleted_at, device.expires_at,
               member.created_at
        FROM mesh.device_group_member AS member
        JOIN mesh.device AS device ON device.id = member.device_id
        WHERE member.device_group_id = v_group.id
          AND (p_after_device_public_id IS NULL OR device.public_id::TEXT > p_after_device_public_id::TEXT)
        ORDER BY device.public_id::TEXT
        LIMIT p_limit + 1
    )
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
               'device_id', page.public_id,
               'name', page.hostname,
               'active', page.state = 'active' AND page.deleted_at IS NULL
                         AND (page.expires_at IS NULL OR page.expires_at > p_evaluated_at),
               'added_at', page.created_at
           ) ORDER BY page.public_id::TEXT),
           pg_catalog.count(*)::INTEGER
    INTO v_members, v_count
    FROM page;
    RETURN pg_catalog.jsonb_build_object(
        'group', mesh_ops.device_group_document_internal_v1(v_group),
        'members', CASE WHEN v_count > p_limit
            THEN (SELECT pg_catalog.jsonb_agg(item.value ORDER BY item.ordinal)
                  FROM pg_catalog.jsonb_array_elements(v_members) WITH ORDINALITY AS item(value, ordinal)
                  WHERE item.ordinal <= p_limit)
            ELSE COALESCE(v_members, '[]'::JSONB) END,
        'has_more', COALESCE(v_count, 0) > p_limit
    );
END;
$function$;

-- Creates, renames or deletes a group (device_group.manage). A group that
-- the active release selects cannot be deleted. Errors: P0002 unknown group,
-- 40001 stale version, MTD02 more than 200 groups, MTD04 name taken,
-- MTD05 group in use.
CREATE FUNCTION mesh_ops.change_device_group_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID,
    p_operation TEXT, p_group_public_id UUID, p_expected_version BIGINT,
    p_name TEXT, p_description TEXT, p_change_public_id UUID, p_evaluated_at TIMESTAMPTZ
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
    v_group mesh.device_group%ROWTYPE;
    v_before JSONB;
    v_hash_before BYTEA;
    v_network_revision BIGINT;
    v_now TIMESTAMPTZ := GREATEST(pg_catalog.clock_timestamp(), p_evaluated_at);
BEGIN
    IF p_operation NOT IN ('create', 'update', 'delete') OR p_group_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_group_public_id), 6) >> 4 <> 7
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR (p_operation <> 'create' AND (p_expected_version IS NULL OR p_expected_version < 1))
        OR (p_operation <> 'delete' AND (p_name IS NULL OR p_description IS NULL)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Device Group change is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_device_group_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'device_group.manage', p_evaluated_at
    );
    -- Serializes group changes with publication and membership changes.
    SELECT revision.network_revision INTO v_network_revision FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id
    FOR UPDATE;
    IF v_network_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Device Group scope is unavailable';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    IF p_operation = 'create' THEN
        IF (SELECT pg_catalog.count(*) FROM mesh.device_group AS device_group
            WHERE device_group.workspace_id = v_scope.workspace_id
              AND device_group.network_id = v_scope.network_id
              AND device_group.state = 'active') >= 200 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTD02', MESSAGE = 'Network already has the maximum Device Groups';
        END IF;
        BEGIN
            INSERT INTO mesh.device_group (
                public_id, deployment_id, workspace_id, network_id, name, name_key, description,
                created_at, updated_at
            ) VALUES (
                p_group_public_id, v_scope.deployment_id, v_scope.workspace_id, v_scope.network_id,
                p_name, pg_catalog.lower(p_name), p_description, v_now, v_now
            ) RETURNING * INTO v_group;
        EXCEPTION WHEN unique_violation THEN
            RAISE EXCEPTION USING ERRCODE = 'MTD04', MESSAGE = 'Device Group name is taken';
        END;
        RETURN pg_catalog.jsonb_build_object(
            'group', mesh_ops.device_group_document_internal_v1(v_group),
            'previous', NULL,
            'member_hash_before', NULL,
            'member_hash_after', pg_catalog.encode(mesh_ops.device_group_member_hash_internal_v1(v_group.id), 'hex'),
            'network_revision', v_network_revision,
            'role_binding_id', v_scope.role_binding_public_id);
    END IF;

    SELECT * INTO v_group FROM mesh.device_group AS device_group
    WHERE device_group.workspace_id = v_scope.workspace_id AND device_group.network_id = v_scope.network_id
      AND device_group.public_id = p_group_public_id AND device_group.state = 'active'
    FOR UPDATE;
    IF v_group.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Device Group is unavailable';
    END IF;
    IF v_group.version <> p_expected_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Device Group version changed';
    END IF;
    v_before := mesh_ops.device_group_document_internal_v1(v_group);
    v_hash_before := mesh_ops.device_group_member_hash_internal_v1(v_group.id);

    IF p_operation = 'update' THEN
        BEGIN
            UPDATE mesh.device_group
            SET name = p_name, name_key = pg_catalog.lower(p_name), description = p_description,
                version = version + 1, updated_at = GREATEST(v_now, updated_at)
            WHERE id = v_group.id
            RETURNING * INTO v_group;
        EXCEPTION WHEN unique_violation THEN
            RAISE EXCEPTION USING ERRCODE = 'MTD04', MESSAGE = 'Device Group name is taken';
        END;
    ELSE
        IF mesh_ops.device_group_rule_count_internal_v1(v_group.id) > 0 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTD05', MESSAGE = 'Device Group is selected by active rules';
        END IF;
        DELETE FROM mesh.device_group_member WHERE device_group_id = v_group.id;
        UPDATE mesh.device_group
        SET state = 'deleted', member_count = 0, deleted_at = GREATEST(v_now, updated_at),
            version = version + 1, updated_at = GREATEST(v_now, updated_at)
        WHERE id = v_group.id
        RETURNING * INTO v_group;
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'group', mesh_ops.device_group_document_internal_v1(v_group),
        'previous', v_before,
        'member_hash_before', pg_catalog.encode(v_hash_before, 'hex'),
        'member_hash_after', pg_catalog.encode(mesh_ops.device_group_member_hash_internal_v1(v_group.id), 'hex'),
        'network_revision', v_network_revision,
        'role_binding_id', v_scope.role_binding_public_id);
END;
$function$;

-- Adds and removes members (device_group.members.manage), at most 150 of
-- each per call. Added Devices must be active Devices of this Network;
-- adding a member twice or removing a non-member is a no-op. When the set
-- changes, the Network and group revisions advance so maps rebuild.
-- Errors: P0002 unknown group, 40001 stale version, MTD01 Device not
-- eligible, MTD03 more than 5000 members.
CREATE FUNCTION mesh_ops.change_device_group_members_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID,
    p_group_public_id UUID, p_expected_version BIGINT,
    p_add JSONB, p_remove UUID[], p_change_public_id UUID, p_evaluated_at TIMESTAMPTZ
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
    v_group mesh.device_group%ROWTYPE;
    v_before JSONB;
    v_hash_before BYTEA;
    v_hash_after BYTEA;
    v_requested INTEGER;
    v_eligible INTEGER;
    v_added INTEGER := 0;
    v_removed INTEGER := 0;
    v_count INTEGER;
    v_network_revision BIGINT;
    v_group_revision BIGINT;
    v_now TIMESTAMPTZ := GREATEST(pg_catalog.clock_timestamp(), p_evaluated_at);
BEGIN
    IF p_group_public_id IS NULL OR p_expected_version IS NULL OR p_expected_version < 1
        OR p_add IS NULL OR pg_catalog.jsonb_typeof(p_add) <> 'array'
        OR pg_catalog.jsonb_array_length(p_add) > 150
        OR p_remove IS NULL OR pg_catalog.cardinality(p_remove) > 150
        OR pg_catalog.jsonb_array_length(p_add) + pg_catalog.cardinality(p_remove) = 0
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_array_elements(p_add) AS entry(value)
            WHERE pg_catalog.jsonb_typeof(entry.value) <> 'object'
               OR (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(entry.value)) <> 2
               OR NOT entry.value ? 'device_id' OR NOT entry.value ? 'member_id'
        ) OR EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_to_recordset(p_add) AS item(device_id UUID, member_id UUID)
            WHERE item.device_id IS NULL OR item.member_id IS NULL
               OR pg_catalog.get_byte(pg_catalog.uuid_send(item.member_id), 6) >> 4 <> 7
        ) OR (
            SELECT pg_catalog.count(DISTINCT item.device_id) <> pg_catalog.jsonb_array_length(p_add)
            FROM pg_catalog.jsonb_to_recordset(p_add) AS item(device_id UUID, member_id UUID)
        ) OR EXISTS (SELECT 1 FROM pg_catalog.unnest(p_remove) AS removed(id) WHERE removed.id IS NULL)
        OR EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_to_recordset(p_add) AS item(device_id UUID, member_id UUID)
            WHERE item.device_id = ANY (p_remove)
        ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Device Group membership change is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_device_group_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'device_group.members.manage', p_evaluated_at
    );
    SELECT revision.network_revision, revision.group_revision
    INTO v_network_revision, v_group_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id
    FOR UPDATE;
    IF v_network_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Device Group scope is unavailable';
    END IF;
    SELECT * INTO v_group FROM mesh.device_group AS device_group
    WHERE device_group.workspace_id = v_scope.workspace_id AND device_group.network_id = v_scope.network_id
      AND device_group.public_id = p_group_public_id AND device_group.state = 'active'
    FOR UPDATE;
    IF v_group.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Device Group is unavailable';
    END IF;
    IF v_group.version <> p_expected_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Device Group version changed';
    END IF;
    v_before := mesh_ops.device_group_document_internal_v1(v_group);
    v_hash_before := mesh_ops.device_group_member_hash_internal_v1(v_group.id);

    v_requested := pg_catalog.jsonb_array_length(p_add);
    IF v_requested > 0 THEN
        SELECT pg_catalog.count(*)::INTEGER INTO v_eligible
        FROM pg_catalog.jsonb_to_recordset(p_add) AS item(device_id UUID, member_id UUID)
        JOIN mesh.device AS device
          ON device.workspace_id = v_scope.workspace_id AND device.network_id = v_scope.network_id
         AND device.public_id = item.device_id
         AND device.state = 'active' AND device.deleted_at IS NULL;
        IF v_eligible <> v_requested THEN
            RAISE EXCEPTION USING ERRCODE = 'MTD01', MESSAGE = 'a Device is not an active Device of this Network';
        END IF;
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    IF pg_catalog.cardinality(p_remove) > 0 THEN
        DELETE FROM mesh.device_group_member AS member
        USING mesh.device AS device
        WHERE member.device_group_id = v_group.id AND device.id = member.device_id
          AND device.public_id = ANY (p_remove);
        GET DIAGNOSTICS v_removed = ROW_COUNT;
    END IF;
    IF v_requested > 0 THEN
        INSERT INTO mesh.device_group_member (
            public_id, workspace_id, network_id, device_group_id, device_id, created_at
        )
        SELECT item.member_id, v_scope.workspace_id, v_scope.network_id, v_group.id, device.id, v_now
        FROM pg_catalog.jsonb_to_recordset(p_add) AS item(device_id UUID, member_id UUID)
        JOIN mesh.device AS device
          ON device.workspace_id = v_scope.workspace_id AND device.network_id = v_scope.network_id
         AND device.public_id = item.device_id
        ORDER BY device.id
        ON CONFLICT (device_group_id, device_id) DO NOTHING;
        GET DIAGNOSTICS v_added = ROW_COUNT;
    END IF;

    IF v_added + v_removed > 0 THEN
        SELECT pg_catalog.count(*)::INTEGER INTO v_count
        FROM mesh.device_group_member AS member WHERE member.device_group_id = v_group.id;
        IF v_count > 5000 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTD03', MESSAGE = 'Device Group would exceed 5000 members';
        END IF;
        UPDATE mesh.device_group
        SET member_count = v_count, version = version + 1, updated_at = GREATEST(v_now, updated_at)
        WHERE id = v_group.id
        RETURNING * INTO v_group;
        UPDATE mesh_ops.network_revision AS revision
        SET network_revision = revision.network_revision + 1,
            group_revision = revision.group_revision + 1,
            updated_at = pg_catalog.clock_timestamp()
        WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id
        RETURNING revision.network_revision, revision.group_revision
        INTO v_network_revision, v_group_revision;
    END IF;
    v_hash_after := mesh_ops.device_group_member_hash_internal_v1(v_group.id);
    RETURN pg_catalog.jsonb_build_object(
        'group', mesh_ops.device_group_document_internal_v1(v_group),
        'previous', v_before,
        'added', v_added,
        'removed', v_removed,
        'changed', v_added + v_removed > 0,
        'member_hash_before', pg_catalog.encode(v_hash_before, 'hex'),
        'member_hash_after', pg_catalog.encode(v_hash_after, 'hex'),
        'network_revision', v_network_revision,
        'group_revision', v_group_revision,
        'role_binding_id', v_scope.role_binding_public_id
    );
END;
$function$;

-- Attaches the group rules of a release just published in this
-- transaction. Each rule: projection_public_id, access_rule_public_id,
-- exactly one of source_node_public_id / source_device_group_public_id,
-- exactly one of destination_node_public_id / destination_device_group_public_id
-- (at least one side a group), protocol, port_range_first, port_range_last.
-- Devices must be active and groups active, both in this Network; an Access
-- Rule may not also appear as a Device-to-Device rule of the release.
CREATE FUNCTION mesh_ops.attach_policy_group_rules_v1(
    p_release_public_id UUID, p_created_at TIMESTAMPTZ, p_rules JSONB
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_release mesh.policy_release%ROWTYPE;
    v_expected INTEGER;
    v_inserted INTEGER;
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_release_public_id IS NULL OR p_created_at IS NULL OR p_rules IS NULL
        OR pg_catalog.jsonb_typeof(p_rules) <> 'array'
        OR pg_catalog.jsonb_array_length(p_rules) NOT BETWEEN 1 AND 10000 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'policy group rule input is invalid';
    END IF;
    -- Only the release this transaction inserted, before anything else
    -- attached group rules to it.
    SELECT * INTO v_release FROM mesh.policy_release AS release
    WHERE release.workspace_id = v_workspace AND release.network_id = v_network
      AND release.public_id = p_release_public_id AND release.state = 'active'
      AND EXISTS (
          SELECT 1 FROM mesh_audit.authority_mutation AS mutation
          WHERE mutation.aggregate_kind = 'policy_release' AND mutation.operation = 'insert'
            AND mutation.row_public_id = p_release_public_id
            AND mutation.transaction_id = (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT
      )
      AND NOT EXISTS (
          SELECT 1 FROM mesh.compiled_policy_group_rule AS attached
          WHERE attached.policy_release_id = release.id
      );
    IF v_release.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'policy group rules need the release published now';
    END IF;
    v_expected := pg_catalog.jsonb_array_length(p_rules);

    WITH input_rule AS (
        SELECT rule.*
        FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
            projection_public_id UUID, access_rule_public_id UUID,
            source_node_public_id UUID, source_device_group_public_id UUID,
            destination_node_public_id UUID, destination_device_group_public_id UUID,
            protocol TEXT, port_range_first INTEGER[], port_range_last INTEGER[]
        )
    ),
    valid_rule AS (
        SELECT rule.* FROM input_rule AS rule
        WHERE rule.projection_public_id IS NOT NULL
          AND pg_catalog.get_byte(pg_catalog.uuid_send(rule.projection_public_id), 6) >> 4 = 7
          AND rule.access_rule_public_id IS NOT NULL
          AND pg_catalog.get_byte(pg_catalog.uuid_send(rule.access_rule_public_id), 6) >> 4 = 7
          AND pg_catalog.num_nonnulls(rule.source_node_public_id, rule.source_device_group_public_id) = 1
          AND pg_catalog.num_nonnulls(rule.destination_node_public_id, rule.destination_device_group_public_id) = 1
          AND (rule.source_device_group_public_id IS NOT NULL OR rule.destination_device_group_public_id IS NOT NULL)
          AND rule.protocol IN ('tcp', 'udp', 'icmp')
          AND rule.port_range_first IS NOT NULL AND rule.port_range_last IS NOT NULL
          AND pg_catalog.cardinality(rule.port_range_first) = pg_catalog.cardinality(rule.port_range_last)
          AND pg_catalog.cardinality(rule.port_range_first) <= 64
          AND ((rule.protocol = 'icmp' AND pg_catalog.cardinality(rule.port_range_first) = 0)
               OR (rule.protocol IN ('tcp', 'udp') AND pg_catalog.cardinality(rule.port_range_first) > 0))
          AND NOT EXISTS (
              SELECT 1 FROM ROWS FROM (
                  pg_catalog.unnest(rule.port_range_first), pg_catalog.unnest(rule.port_range_last)
              ) AS port_range(first_port, last_port)
              WHERE port_range.first_port < 1 OR port_range.last_port < port_range.first_port
                 OR port_range.last_port > 65535
          )
          AND NOT EXISTS (
              SELECT 1 FROM mesh.compiled_policy_rule AS device_rule
              WHERE device_rule.policy_release_id = v_release.id
                AND device_rule.access_rule_public_id = rule.access_rule_public_id
          )
    ),
    resolved_rule AS (
        SELECT rule.*, source_device.id AS source_device_id, source_group.id AS source_device_group_id,
               destination_device.id AS destination_device_id,
               destination_group.id AS destination_device_group_id
        FROM valid_rule AS rule
        LEFT JOIN mesh.device AS source_device
          ON source_device.workspace_id = v_workspace AND source_device.network_id = v_network
         AND source_device.public_id = rule.source_node_public_id AND source_device.state = 'active'
        LEFT JOIN mesh.device_group AS source_group
          ON source_group.workspace_id = v_workspace AND source_group.network_id = v_network
         AND source_group.public_id = rule.source_device_group_public_id AND source_group.state = 'active'
        LEFT JOIN mesh.device AS destination_device
          ON destination_device.workspace_id = v_workspace AND destination_device.network_id = v_network
         AND destination_device.public_id = rule.destination_node_public_id
         AND destination_device.state = 'active'
        LEFT JOIN mesh.device_group AS destination_group
          ON destination_group.workspace_id = v_workspace AND destination_group.network_id = v_network
         AND destination_group.public_id = rule.destination_device_group_public_id
         AND destination_group.state = 'active'
        WHERE (rule.source_node_public_id IS NULL OR source_device.id IS NOT NULL)
          AND (rule.source_device_group_public_id IS NULL OR source_group.id IS NOT NULL)
          AND (rule.destination_node_public_id IS NULL OR destination_device.id IS NOT NULL)
          AND (rule.destination_device_group_public_id IS NULL OR destination_group.id IS NOT NULL)
    )
    INSERT INTO mesh.compiled_policy_group_rule (
        public_id, access_rule_public_id, workspace_id, network_id, policy_release_id, policy_revision,
        source_device_id, source_device_group_id, destination_device_id, destination_device_group_id,
        protocol, destination_ports, created_at
    )
    SELECT rule.projection_public_id, rule.access_rule_public_id, v_workspace, v_network, v_release.id,
           v_release.policy_revision, rule.source_device_id, rule.source_device_group_id,
           rule.destination_device_id, rule.destination_device_group_id, rule.protocol,
           ports.destination_ports, p_created_at
    FROM resolved_rule AS rule
    CROSS JOIN LATERAL (
        SELECT COALESCE(pg_catalog.range_agg(
            pg_catalog.int4range(port_range.first_port, port_range.last_port + 1, '[)')
        ), '{}'::INT4MULTIRANGE) AS destination_ports
        FROM ROWS FROM (
            pg_catalog.unnest(rule.port_range_first), pg_catalog.unnest(rule.port_range_last)
        ) AS port_range(first_port, last_port)
    ) AS ports
    ORDER BY rule.access_rule_public_id;
    GET DIAGNOSTICS v_inserted = ROW_COUNT;
    IF v_inserted <> v_expected THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'a Device or Device Group changed during publication';
    END IF;
    RETURN v_inserted;
END;
$function$;

-- Resolves the group rules of the bound Network's active release into
-- Device pairs from the current membership; with p_device_id, only pairs
-- that touch that Device. Self-pairs are dropped. Callers apply the same
-- Device liveness checks they apply to mesh.compiled_policy_rule edges.
CREATE FUNCTION mesh_ops.resolve_group_policy_edges_v1(p_device_id BIGINT)
RETURNS TABLE (
    rule_public_id UUID,
    access_rule_public_id UUID,
    source_device_id BIGINT,
    destination_device_id BIGINT,
    protocol TEXT,
    destination_ports INT4MULTIRANGE,
    source_device_group_public_id UUID,
    destination_device_group_public_id UUID
)
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    WITH scope AS (
        SELECT revision.workspace_id, revision.network_id, revision.policy_revision
        FROM mesh_ops.network_revision AS revision
        WHERE revision.workspace_id = mesh_ops.current_workspace_id()
          AND revision.network_id = mesh_ops.current_network_id()
    ),
    rule AS (
        SELECT group_rule.*
        FROM scope
        JOIN mesh.policy_release AS release
          ON release.workspace_id = scope.workspace_id AND release.network_id = scope.network_id
         AND release.policy_revision = scope.policy_revision AND release.state = 'active'
        JOIN mesh.compiled_policy_group_rule AS group_rule ON group_rule.policy_release_id = release.id
    ),
    expanded AS (
        SELECT rule.public_id, rule.access_rule_public_id, rule.protocol, rule.destination_ports,
               COALESCE(rule.source_device_id, source_member.device_id) AS source_device_id,
               COALESCE(rule.destination_device_id, destination_member.device_id) AS destination_device_id,
               source_group.public_id AS source_group_public_id,
               destination_group.public_id AS destination_group_public_id
        FROM rule
        LEFT JOIN mesh.device_group AS source_group
          ON source_group.id = rule.source_device_group_id AND source_group.state = 'active'
        LEFT JOIN mesh.device_group_member AS source_member
          ON source_member.device_group_id = source_group.id
        LEFT JOIN mesh.device_group AS destination_group
          ON destination_group.id = rule.destination_device_group_id AND destination_group.state = 'active'
        LEFT JOIN mesh.device_group_member AS destination_member
          ON destination_member.device_group_id = destination_group.id
    )
    SELECT expanded.public_id, expanded.access_rule_public_id, expanded.source_device_id,
           expanded.destination_device_id, expanded.protocol, expanded.destination_ports,
           expanded.source_group_public_id, expanded.destination_group_public_id
    FROM expanded
    WHERE expanded.source_device_id IS NOT NULL AND expanded.destination_device_id IS NOT NULL
      AND expanded.source_device_id <> expanded.destination_device_id
      AND (p_device_id IS NULL OR expanded.source_device_id = p_device_id
           OR expanded.destination_device_id = p_device_id)
$function$;

REVOKE ALL ON FUNCTION mesh_ops.enforce_device_group_transition_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.list_device_groups_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_device_groups_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.read_device_group_members_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, INTEGER, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_device_group_members_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, INTEGER, TIMESTAMPTZ
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.change_device_group_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    TEXT, UUID, BIGINT, TEXT, TEXT, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_device_group_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    TEXT, UUID, BIGINT, TEXT, TEXT, UUID, TIMESTAMPTZ
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.change_device_group_members_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    UUID, BIGINT, JSONB, UUID[], UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_device_group_members_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    UUID, BIGINT, JSONB, UUID[], UUID, TIMESTAMPTZ
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.attach_policy_group_rules_v1(UUID, TIMESTAMPTZ, JSONB)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.attach_policy_group_rules_v1(UUID, TIMESTAMPTZ, JSONB) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.resolve_group_policy_edges_v1(BIGINT)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.resolve_group_policy_edges_v1(BIGINT) TO mesh_runtime;
