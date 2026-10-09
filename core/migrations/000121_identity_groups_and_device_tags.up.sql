-- Schema 121 (G2): Workspace Identity Groups and device tags.
--
-- An Identity Group is a set of Workspace members. A Device belongs to the
-- groups of its owner, but only while it carries no tag: a tagged Device is a
-- service Device that matches rules by tag alone. Identity Groups are rule
-- sources only.
--
-- A device tag is a Workspace catalog entry applied to Devices inside their
-- Network. Each tag names its owners (Identity Groups or built-in roles); the
-- Workspace owner always owns every tag. A tag owner may tag a Device it owns
-- or a Device of a Network where it holds device.manage; device_tag.manage
-- applies any tag to any Device it can read.
--
-- Rules select groups and tags through new columns of
-- mesh.compiled_policy_group_rule; schema 122 publishes and resolves them.
-- Like Device Groups, membership and tags are resolved when maps are built,
-- so a change advances the revision of every affected Network instead of
-- republishing policy. Tables are reachable only through the SECURITY
-- DEFINER functions below.

INSERT INTO mesh.permission (permission_key, description, risk_class, allowed_scope_kinds, catalog_version)
VALUES
    ('identity_group.read', 'Read workspace identity groups', 'read', ARRAY['workspace'], 1),
    ('device_tag.read', 'Read the workspace device tag catalog', 'read', ARRAY['workspace'], 1),
    ('device_tag.manage', 'Manage the device tag catalog and apply any tag', 'mutation', ARRAY['workspace'], 1);

INSERT INTO mesh.builtin_role_permission (role_key, permission_id)
SELECT grant_row.role_key, permission.id
FROM (VALUES
    ('admin', 'identity_group.read'), ('admin', 'device_tag.read'), ('admin', 'device_tag.manage'),
    ('it_admin', 'identity_group.read'), ('it_admin', 'device_tag.read'), ('it_admin', 'device_tag.manage'),
    ('network_admin', 'identity_group.read'), ('network_admin', 'device_tag.read'),
    ('security_admin', 'identity_group.read'), ('security_admin', 'device_tag.read'),
    ('auditor', 'identity_group.read'), ('auditor', 'device_tag.read')
) AS grant_row(role_key, permission_key)
JOIN mesh.permission AS permission ON permission.permission_key = grant_row.permission_key
ON CONFLICT DO NOTHING;

CREATE TABLE mesh.identity_group (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    name TEXT NOT NULL,
    name_key TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    member_count INTEGER NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'active',
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ,
    CONSTRAINT identity_group_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT identity_group_name_check CHECK (
        name = pg_catalog.btrim(name)
        AND pg_catalog.char_length(name) BETWEEN 1 AND 64
        AND name !~ '[[:cntrl:]]'
        AND name_key = pg_catalog.lower(name)
    ),
    CONSTRAINT identity_group_description_check CHECK (
        pg_catalog.char_length(description) <= 280 AND description !~ '[[:cntrl:]]'
    ),
    CONSTRAINT identity_group_member_count_check CHECK (member_count BETWEEN 0 AND 10000),
    CONSTRAINT identity_group_state_check CHECK (
        (state = 'active' AND deleted_at IS NULL)
        OR (state = 'deleted' AND deleted_at IS NOT NULL AND member_count = 0)
    ),
    CONSTRAINT identity_group_timestamps_check CHECK (updated_at >= created_at),
    CONSTRAINT identity_group_workspace_fk FOREIGN KEY (deployment_id, workspace_id)
        REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    UNIQUE (workspace_id, id)
);

CREATE UNIQUE INDEX identity_group_active_name_uidx
    ON mesh.identity_group (workspace_id, name_key) WHERE state = 'active';

CREATE TABLE mesh.identity_group_member (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    identity_group_id BIGINT NOT NULL,
    principal_id BIGINT NOT NULL REFERENCES mesh.principal (id) ON DELETE RESTRICT,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version = 1),
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT identity_group_member_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT identity_group_member_group_fk FOREIGN KEY (workspace_id, identity_group_id)
        REFERENCES mesh.identity_group (workspace_id, id) ON DELETE RESTRICT,
    UNIQUE (identity_group_id, principal_id)
);

CREATE INDEX identity_group_member_principal_idx
    ON mesh.identity_group_member (workspace_id, principal_id, identity_group_id);

CREATE TABLE mesh.device_tag (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'active',
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ,
    CONSTRAINT device_tag_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT device_tag_name_check CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,46}[a-z0-9])?$'),
    CONSTRAINT device_tag_description_check CHECK (
        pg_catalog.char_length(description) <= 280 AND description !~ '[[:cntrl:]]'
    ),
    CONSTRAINT device_tag_state_check CHECK (
        (state = 'active' AND deleted_at IS NULL) OR (state = 'deleted' AND deleted_at IS NOT NULL)
    ),
    CONSTRAINT device_tag_timestamps_check CHECK (updated_at >= created_at),
    CONSTRAINT device_tag_workspace_fk FOREIGN KEY (deployment_id, workspace_id)
        REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    UNIQUE (workspace_id, id)
);

CREATE UNIQUE INDEX device_tag_active_name_uidx ON mesh.device_tag (workspace_id, name) WHERE state = 'active';

-- Who may apply a tag: an Identity Group or a built-in role. Rows are
-- replaced as a set when the tag changes, never rewritten.
CREATE TABLE mesh.device_tag_owner (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    device_tag_id BIGINT NOT NULL,
    identity_group_id BIGINT,
    role_key TEXT REFERENCES mesh.builtin_role (role_key) ON DELETE RESTRICT,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version = 1),
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT device_tag_owner_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT device_tag_owner_kind_check CHECK (pg_catalog.num_nonnulls(identity_group_id, role_key) = 1),
    CONSTRAINT device_tag_owner_tag_fk FOREIGN KEY (workspace_id, device_tag_id)
        REFERENCES mesh.device_tag (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT device_tag_owner_group_fk FOREIGN KEY (workspace_id, identity_group_id)
        REFERENCES mesh.identity_group (workspace_id, id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX device_tag_owner_group_uidx
    ON mesh.device_tag_owner (device_tag_id, identity_group_id) WHERE identity_group_id IS NOT NULL;
CREATE UNIQUE INDEX device_tag_owner_role_uidx
    ON mesh.device_tag_owner (device_tag_id, role_key) WHERE role_key IS NOT NULL;
CREATE INDEX device_tag_owner_identity_group_idx
    ON mesh.device_tag_owner (identity_group_id) WHERE identity_group_id IS NOT NULL;

CREATE TABLE mesh.device_tag_assignment (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    device_id BIGINT NOT NULL,
    device_tag_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version = 1),
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT device_tag_assignment_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT device_tag_assignment_device_fk FOREIGN KEY (workspace_id, network_id, device_id)
        REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT device_tag_assignment_tag_fk FOREIGN KEY (workspace_id, device_tag_id)
        REFERENCES mesh.device_tag (workspace_id, id) ON DELETE RESTRICT,
    UNIQUE (device_id, device_tag_id)
);

CREATE INDEX device_tag_assignment_tag_idx
    ON mesh.device_tag_assignment (device_tag_id, workspace_id, network_id, device_id);

-- Groups and tags are never hard-deleted; scope and identity never change;
-- every update advances the version by one; deletion is terminal.
CREATE FUNCTION mesh_ops.enforce_identity_catalog_transition_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'identity catalog entries are never deleted';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.version <> 1 OR NEW.state <> 'active' THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'identity catalog entry must start active at version 1';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.public_id <> OLD.public_id OR NEW.deployment_id <> OLD.deployment_id
        OR NEW.workspace_id <> OLD.workspace_id OR NEW.created_at <> OLD.created_at
        OR NEW.version <> OLD.version + 1 OR OLD.state = 'deleted' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid identity catalog transition';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER identity_group_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.identity_group
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_identity_catalog_transition_v1();
CREATE TRIGGER identity_group_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.identity_group
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('identity_group', 'public_id');
CREATE TRIGGER identity_group_member_immutable
BEFORE UPDATE ON mesh.identity_group_member
FOR EACH ROW EXECUTE FUNCTION mesh_audit.reject_immutable_change();
CREATE TRIGGER identity_group_member_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.identity_group_member
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('identity_group_member', 'public_id');
CREATE TRIGGER device_tag_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.device_tag
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_identity_catalog_transition_v1();
CREATE TRIGGER device_tag_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.device_tag
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('device_tag', 'public_id');
CREATE TRIGGER device_tag_owner_immutable
BEFORE UPDATE ON mesh.device_tag_owner
FOR EACH ROW EXECUTE FUNCTION mesh_audit.reject_immutable_change();
CREATE TRIGGER device_tag_owner_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.device_tag_owner
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('device_tag_owner', 'public_id');
CREATE TRIGGER device_tag_assignment_immutable
BEFORE UPDATE ON mesh.device_tag_assignment
FOR EACH ROW EXECUTE FUNCTION mesh_audit.reject_immutable_change();
CREATE TRIGGER device_tag_assignment_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.device_tag_assignment
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('device_tag_assignment', 'public_id');

-- Rules select an Identity Group (source only) or a tag (either side).
ALTER TABLE mesh.compiled_policy_group_rule
    ADD COLUMN source_identity_group_id BIGINT,
    ADD COLUMN source_device_tag_id BIGINT,
    ADD COLUMN destination_device_tag_id BIGINT,
    DROP CONSTRAINT compiled_policy_group_rule_selector_check,
    ADD CONSTRAINT compiled_policy_group_rule_selector_check CHECK (
        pg_catalog.num_nonnulls(
            source_device_id, source_device_group_id, source_identity_group_id, source_device_tag_id) = 1
        AND pg_catalog.num_nonnulls(destination_device_id, destination_device_group_id, destination_device_tag_id) = 1
        AND (source_device_id IS NULL OR destination_device_id IS NULL)
    ),
    ADD CONSTRAINT compiled_policy_group_rule_source_identity_group_fk FOREIGN KEY (
        workspace_id, source_identity_group_id
    ) REFERENCES mesh.identity_group (workspace_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT compiled_policy_group_rule_source_tag_fk FOREIGN KEY (workspace_id, source_device_tag_id)
        REFERENCES mesh.device_tag (workspace_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT compiled_policy_group_rule_destination_tag_fk FOREIGN KEY (
        workspace_id, destination_device_tag_id
    ) REFERENCES mesh.device_tag (workspace_id, id) ON DELETE RESTRICT;

CREATE INDEX compiled_policy_group_rule_source_identity_group_idx
    ON mesh.compiled_policy_group_rule (source_identity_group_id) WHERE source_identity_group_id IS NOT NULL;
CREATE INDEX compiled_policy_group_rule_source_tag_idx
    ON mesh.compiled_policy_group_rule (source_device_tag_id) WHERE source_device_tag_id IS NOT NULL;
CREATE INDEX compiled_policy_group_rule_destination_tag_idx
    ON mesh.compiled_policy_group_rule (destination_device_tag_id) WHERE destination_device_tag_id IS NOT NULL;

ALTER TABLE mesh.identity_group ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.identity_group FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_group_migrator_policy ON mesh.identity_group
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
ALTER TABLE mesh.identity_group_member ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.identity_group_member FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_group_member_migrator_policy ON mesh.identity_group_member
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
ALTER TABLE mesh.device_tag ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.device_tag FORCE ROW LEVEL SECURITY;
CREATE POLICY device_tag_migrator_policy ON mesh.device_tag
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
ALTER TABLE mesh.device_tag_owner ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.device_tag_owner FORCE ROW LEVEL SECURITY;
CREATE POLICY device_tag_owner_migrator_policy ON mesh.device_tag_owner
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
ALTER TABLE mesh.device_tag_assignment ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.device_tag_assignment FORCE ROW LEVEL SECURITY;
CREATE POLICY device_tag_assignment_migrator_policy ON mesh.device_tag_assignment
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.identity_group, mesh.identity_group_member, mesh.device_tag, mesh.device_tag_owner,
    mesh.device_tag_assignment
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The Workspace a Session manages, after one Workspace permission check.
-- Returns the evidence MeshCore records about the authority that was used.
CREATE FUNCTION mesh_ops.authorize_identity_catalog_internal_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_permission TEXT, p_evaluated_at TIMESTAMPTZ
)
RETURNS TABLE (deployment_id BIGINT, workspace_id BIGINT, authority JSONB)
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT;
    v_deployment BIGINT;
    v_grant RECORD;
BEGIN
    IF p_workspace_public_id IS NULL OR p_evaluated_at IS NULL
        OR p_permission NOT IN ('identity_group.read', 'identity_group.manage', 'device_tag.read',
                                'device_tag.manage') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'identity catalog scope input is invalid';
    END IF;
    v_workspace := mesh_ops.enter_workspace_management_scope_v1(p_workspace_public_id);
    IF v_workspace IS NULL OR NOT mesh_ops.session_bound_to_workspace_v1(p_session_public_id, v_workspace) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'identity catalog scope is unavailable';
    END IF;
    SELECT workspace.deployment_id INTO v_deployment FROM mesh.workspace AS workspace
    WHERE workspace.id = v_workspace AND workspace.state = 'active' AND workspace.deleted_at IS NULL;
    IF v_deployment IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'identity catalog scope is unavailable';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.resolve_workspace_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_permission, p_evaluated_at
    ) LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'identity catalog action is not authorized';
    END IF;
    RETURN QUERY SELECT v_deployment, v_workspace, pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
        'binding_id', v_grant.role_binding_public_id,
        'role_id', v_grant.role_definition_public_id,
        'binding_generation', COALESCE(v_grant.binding_authority_generation, 0),
        'membership_generation', COALESCE(v_grant.membership_authority_generation, 0),
        'owner_generation', COALESCE(v_grant.workspace_owner_authority_generation, 0)
    ));
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.authorize_identity_catalog_internal_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, TEXT, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.holds_workspace_permission_internal_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_permission TEXT, p_evaluated_at TIMESTAMPTZ
)
RETURNS BOOLEAN
LANGUAGE sql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
    SELECT EXISTS (
        SELECT 1 FROM mesh_ops.resolve_workspace_permission_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_permission, p_evaluated_at
        )
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.holds_workspace_permission_internal_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, TEXT, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Rules of active releases, in any Network of the Workspace, that select a
-- group or a tag.
CREATE FUNCTION mesh_ops.identity_group_rule_count_internal_v1(p_identity_group_id BIGINT)
RETURNS INTEGER
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.count(*)::INTEGER
    FROM mesh.compiled_policy_group_rule AS rule
    JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id
    WHERE release.state = 'active' AND rule.source_identity_group_id = p_identity_group_id
$function$;
REVOKE ALL ON FUNCTION mesh_ops.identity_group_rule_count_internal_v1(BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.device_tag_rule_count_internal_v1(p_device_tag_id BIGINT)
RETURNS INTEGER
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.count(*)::INTEGER
    FROM mesh.compiled_policy_group_rule AS rule
    JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id
    WHERE release.state = 'active'
      AND (rule.source_device_tag_id = p_device_tag_id OR rule.destination_device_tag_id = p_device_tag_id)
$function$;
REVOKE ALL ON FUNCTION mesh_ops.device_tag_rule_count_internal_v1(BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- SHA-256 over the sorted member principal public IDs, one per line.
CREATE FUNCTION mesh_ops.identity_group_member_hash_internal_v1(p_identity_group_id BIGINT)
RETURNS BYTEA
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.sha256(pg_catalog.convert_to(COALESCE(
        pg_catalog.string_agg(principal.public_id::TEXT, E'\n' ORDER BY principal.public_id::TEXT), ''
    ), 'UTF8'))
    FROM mesh.identity_group_member AS member
    JOIN mesh.principal AS principal ON principal.id = member.principal_id
    WHERE member.identity_group_id = p_identity_group_id
$function$;
REVOKE ALL ON FUNCTION mesh_ops.identity_group_member_hash_internal_v1(BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- SHA-256 over a Device's sorted tag public IDs, one per line.
CREATE FUNCTION mesh_ops.device_tag_set_hash_internal_v1(p_device_id BIGINT)
RETURNS BYTEA
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.sha256(pg_catalog.convert_to(COALESCE(
        pg_catalog.string_agg(tag.public_id::TEXT, E'\n' ORDER BY tag.public_id::TEXT), ''
    ), 'UTF8'))
    FROM mesh.device_tag_assignment AS assignment
    JOIN mesh.device_tag AS tag ON tag.id = assignment.device_tag_id
    WHERE assignment.device_id = p_device_id
$function$;
REVOKE ALL ON FUNCTION mesh_ops.device_tag_set_hash_internal_v1(BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.identity_group_document_internal_v1(p_group mesh.identity_group)
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
        'rule_count', mesh_ops.identity_group_rule_count_internal_v1(p_group.id),
        'state', p_group.state,
        'version', p_group.version,
        'created_at', p_group.created_at,
        'updated_at', p_group.updated_at
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.identity_group_document_internal_v1(mesh.identity_group)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.device_tag_document_internal_v1(p_tag mesh.device_tag)
RETURNS JSONB
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'tag_id', p_tag.public_id,
        'name', p_tag.name,
        'description', p_tag.description,
        'owner_group_ids', COALESCE((
            SELECT pg_catalog.jsonb_agg(owner_group.public_id ORDER BY owner_group.public_id::TEXT)
            FROM mesh.device_tag_owner AS owner
            JOIN mesh.identity_group AS owner_group ON owner_group.id = owner.identity_group_id
            WHERE owner.device_tag_id = p_tag.id
        ), '[]'::JSONB),
        'owner_roles', COALESCE((
            SELECT pg_catalog.jsonb_agg(owner.role_key ORDER BY owner.role_key)
            FROM mesh.device_tag_owner AS owner
            WHERE owner.device_tag_id = p_tag.id AND owner.role_key IS NOT NULL
        ), '[]'::JSONB),
        'device_count', (SELECT pg_catalog.count(*) FROM mesh.device_tag_assignment AS assignment
                         WHERE assignment.device_tag_id = p_tag.id),
        'rule_count', mesh_ops.device_tag_rule_count_internal_v1(p_tag.id),
        'state', p_tag.state,
        'version', p_tag.version,
        'created_at', p_tag.created_at,
        'updated_at', p_tag.updated_at
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.device_tag_document_internal_v1(mesh.device_tag)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- A Workspace change (an Identity Group membership change, a tag deletion)
-- advances several Networks of the bound Workspace in one transaction. The
-- migrator's revision policies require the exact Network scope, so these two
-- policies admit the bound Workspace's rows, and only while the fan-out
-- function below has set mesh.identity_catalog_fanout for that statement.
CREATE POLICY network_revision_identity_fanout_read ON mesh_ops.network_revision
    FOR SELECT TO mesh_migrator
    USING (
        workspace_id = NULLIF(pg_catalog.current_setting('mesh.workspace_id', TRUE), '')::BIGINT
        AND pg_catalog.current_setting('mesh.identity_catalog_fanout', TRUE) = 'on'
    );
CREATE POLICY network_revision_identity_fanout_mutation ON mesh_ops.network_revision
    FOR UPDATE TO mesh_migrator
    USING (
        workspace_id = NULLIF(pg_catalog.current_setting('mesh.workspace_id', TRUE), '')::BIGINT
        AND pg_catalog.current_setting('mesh.identity_catalog_fanout', TRUE) = 'on'
    )
    WITH CHECK (
        workspace_id = NULLIF(pg_catalog.current_setting('mesh.workspace_id', TRUE), '')::BIGINT
        AND pg_catalog.current_setting('mesh.identity_catalog_fanout', TRUE) = 'on'
    );

-- Advances the revision of each listed Network once, in Network order, and
-- returns the new revisions. Callers record evidence on each Network stream.
CREATE FUNCTION mesh_ops.advance_identity_networks_internal_v1(p_workspace_id BIGINT, p_network_ids BIGINT[])
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_result JSONB := '[]'::JSONB;
    v_row RECORD;
BEGIN
    IF p_workspace_id IS NULL OR p_workspace_id <> mesh_ops.current_workspace_id() THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Workspace scope is unavailable';
    END IF;
    PERFORM pg_catalog.set_config('mesh.identity_catalog_fanout', 'on', TRUE);
    FOR v_row IN
        SELECT revision.network_id FROM mesh_ops.network_revision AS revision
        WHERE revision.workspace_id = p_workspace_id AND revision.network_id = ANY (p_network_ids)
        ORDER BY revision.network_id
        FOR UPDATE
    LOOP
        NULL;
    END LOOP;
    WITH advanced AS (
        UPDATE mesh_ops.network_revision AS revision
        SET network_revision = revision.network_revision + 1,
            group_revision = revision.group_revision + 1,
            updated_at = pg_catalog.clock_timestamp()
        WHERE revision.workspace_id = p_workspace_id AND revision.network_id = ANY (p_network_ids)
        RETURNING revision.network_id, revision.network_revision, revision.group_revision
    )
    SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
               'network_id', network.public_id,
               'network_revision', advanced.network_revision,
               'group_revision', advanced.group_revision
           ) ORDER BY network.public_id::TEXT), '[]'::JSONB)
    INTO v_result
    FROM advanced JOIN mesh.network AS network ON network.id = advanced.network_id;
    PERFORM pg_catalog.set_config('mesh.identity_catalog_fanout', '', TRUE);
    IF pg_catalog.jsonb_array_length(v_result) <> pg_catalog.cardinality(p_network_ids) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'a Network revision is unavailable';
    END IF;
    RETURN v_result;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.advance_identity_networks_internal_v1(BIGINT, BIGINT[])
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Networks whose active release would load more than 10000 edges into a
-- Device; MeshCore refuses a change that crosses the bound (MTD06).
CREATE FUNCTION mesh_ops.identity_networks_over_edge_budget_internal_v1(p_workspace_id BIGINT, p_network_ids BIGINT[])
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT EXISTS (
        SELECT 1 FROM pg_catalog.unnest(p_network_ids) AS network(id)
        WHERE mesh_ops.max_device_policy_edges_internal_v1(p_workspace_id, network.id) > 10000
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.identity_networks_over_edge_budget_internal_v1(BIGINT, BIGINT[])
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The Workspace's active Identity Groups (identity_group.read).
CREATE FUNCTION mesh_ops.list_identity_groups_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_evaluated_at TIMESTAMPTZ
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
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_identity_catalog_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'identity_group.read', p_evaluated_at
    );
    RETURN pg_catalog.jsonb_build_object(
        'groups', COALESCE((
            SELECT pg_catalog.jsonb_agg(mesh_ops.identity_group_document_internal_v1(identity_group)
                ORDER BY identity_group.name_key, identity_group.public_id)
            FROM mesh.identity_group AS identity_group
            WHERE identity_group.workspace_id = v_scope.workspace_id AND identity_group.state = 'active'
        ), '[]'::JSONB),
        'can_manage', mesh_ops.holds_workspace_permission_internal_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, 'identity_group.manage', p_evaluated_at)
    );
END;
$function$;

-- One page of a group's members, ordered by principal public ID, at most
-- 500. A member whose membership or principal is no longer active shows as
-- inactive and grants nothing. P0002: unknown group.
CREATE FUNCTION mesh_ops.read_identity_group_members_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_group_public_id UUID, p_after_principal_public_id UUID,
    p_limit INTEGER, p_evaluated_at TIMESTAMPTZ
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
    v_group mesh.identity_group%ROWTYPE;
    v_members JSONB;
    v_count INTEGER;
BEGIN
    IF p_group_public_id IS NULL OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 500 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Identity Group member page input is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_identity_catalog_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'identity_group.read', p_evaluated_at
    );
    SELECT * INTO v_group FROM mesh.identity_group AS identity_group
    WHERE identity_group.workspace_id = v_scope.workspace_id AND identity_group.public_id = p_group_public_id
      AND identity_group.state = 'active';
    IF v_group.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Identity Group is unavailable';
    END IF;
    WITH page AS (
        SELECT principal.public_id, account.display_name, member.created_at,
               principal.state = 'active' AND principal.deleted_at IS NULL
                   AND COALESCE(membership.state = 'active'
                       AND (membership.expires_at IS NULL OR membership.expires_at > p_evaluated_at), FALSE)
                   AS active
        FROM mesh.identity_group_member AS member
        JOIN mesh.principal AS principal ON principal.id = member.principal_id
        LEFT JOIN mesh.account AS account
          ON account.deployment_id = principal.deployment_id AND account.principal_id = principal.id
        LEFT JOIN mesh.workspace_membership AS membership
          ON membership.workspace_id = v_scope.workspace_id AND membership.principal_id = principal.id
        WHERE member.identity_group_id = v_group.id
          AND (p_after_principal_public_id IS NULL OR principal.public_id::TEXT > p_after_principal_public_id::TEXT)
        ORDER BY principal.public_id::TEXT
        LIMIT p_limit + 1
    )
    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
               'principal_id', page.public_id,
               'display_name', COALESCE(page.display_name, ''),
               'active', page.active,
               'added_at', page.created_at
           ) ORDER BY page.public_id::TEXT),
           pg_catalog.count(*)::INTEGER
    INTO v_members, v_count
    FROM page;
    RETURN pg_catalog.jsonb_build_object(
        'group', mesh_ops.identity_group_document_internal_v1(v_group),
        'members', CASE WHEN v_count > p_limit
            THEN (SELECT pg_catalog.jsonb_agg(item.value ORDER BY item.ordinal)
                  FROM pg_catalog.jsonb_array_elements(v_members) WITH ORDINALITY AS item(value, ordinal)
                  WHERE item.ordinal <= p_limit)
            ELSE COALESCE(v_members, '[]'::JSONB) END,
        'has_more', COALESCE(v_count, 0) > p_limit
    );
END;
$function$;

-- Creates, renames or deletes a group (identity_group.manage). A group that
-- an active release selects, or that owns a tag, cannot be deleted.
-- Errors: P0002 unknown group, 40001 stale version, MTI02 more than 500
-- groups, MTI04 name taken, MTI05 group in use.
CREATE FUNCTION mesh_ops.change_identity_group_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_operation TEXT, p_group_public_id UUID, p_expected_version BIGINT,
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
    v_group mesh.identity_group%ROWTYPE;
    v_before JSONB;
    v_hash_before BYTEA;
    v_now TIMESTAMPTZ := GREATEST(pg_catalog.clock_timestamp(), p_evaluated_at);
BEGIN
    IF p_operation NOT IN ('create', 'update', 'delete') OR p_group_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_group_public_id), 6) >> 4 <> 7
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR (p_operation <> 'create' AND (p_expected_version IS NULL OR p_expected_version < 1))
        OR (p_operation <> 'delete' AND (p_name IS NULL OR p_description IS NULL)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Identity Group change is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_identity_catalog_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'identity_group.manage', p_evaluated_at
    );
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    IF p_operation = 'create' THEN
        -- Serializes creations in one Workspace so the limit holds.
        PERFORM 1 FROM mesh.workspace AS workspace WHERE workspace.id = v_scope.workspace_id FOR UPDATE;
        IF (SELECT pg_catalog.count(*) FROM mesh.identity_group AS identity_group
            WHERE identity_group.workspace_id = v_scope.workspace_id AND identity_group.state = 'active') >= 500 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTI02', MESSAGE = 'Workspace already has the maximum Identity Groups';
        END IF;
        BEGIN
            INSERT INTO mesh.identity_group (
                public_id, deployment_id, workspace_id, name, name_key, description, created_at, updated_at
            ) VALUES (
                p_group_public_id, v_scope.deployment_id, v_scope.workspace_id, p_name, pg_catalog.lower(p_name),
                p_description, v_now, v_now
            ) RETURNING * INTO v_group;
        EXCEPTION WHEN unique_violation THEN
            RAISE EXCEPTION USING ERRCODE = 'MTI04', MESSAGE = 'Identity Group name is taken';
        END;
        RETURN pg_catalog.jsonb_build_object(
            'group', mesh_ops.identity_group_document_internal_v1(v_group),
            'previous', NULL,
            'member_hash_before', NULL,
            'member_hash_after', pg_catalog.encode(mesh_ops.identity_group_member_hash_internal_v1(v_group.id), 'hex'),
            'authority', v_scope.authority);
    END IF;

    SELECT * INTO v_group FROM mesh.identity_group AS identity_group
    WHERE identity_group.workspace_id = v_scope.workspace_id AND identity_group.public_id = p_group_public_id
      AND identity_group.state = 'active'
    FOR UPDATE;
    IF v_group.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Identity Group is unavailable';
    END IF;
    IF v_group.version <> p_expected_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Identity Group version changed';
    END IF;
    v_before := mesh_ops.identity_group_document_internal_v1(v_group);
    v_hash_before := mesh_ops.identity_group_member_hash_internal_v1(v_group.id);

    IF p_operation = 'update' THEN
        BEGIN
            UPDATE mesh.identity_group
            SET name = p_name, name_key = pg_catalog.lower(p_name), description = p_description,
                version = version + 1, updated_at = GREATEST(v_now, updated_at)
            WHERE id = v_group.id
            RETURNING * INTO v_group;
        EXCEPTION WHEN unique_violation THEN
            RAISE EXCEPTION USING ERRCODE = 'MTI04', MESSAGE = 'Identity Group name is taken';
        END;
    ELSE
        IF mesh_ops.identity_group_rule_count_internal_v1(v_group.id) > 0
            OR EXISTS (SELECT 1 FROM mesh.device_tag_owner AS owner
                       JOIN mesh.device_tag AS tag ON tag.id = owner.device_tag_id AND tag.state = 'active'
                       WHERE owner.identity_group_id = v_group.id) THEN
            RAISE EXCEPTION USING ERRCODE = 'MTI05', MESSAGE = 'Identity Group is selected by rules or owns tags';
        END IF;
        DELETE FROM mesh.identity_group_member WHERE identity_group_id = v_group.id;
        UPDATE mesh.identity_group
        SET state = 'deleted', member_count = 0, deleted_at = GREATEST(v_now, updated_at),
            version = version + 1, updated_at = GREATEST(v_now, updated_at)
        WHERE id = v_group.id
        RETURNING * INTO v_group;
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'group', mesh_ops.identity_group_document_internal_v1(v_group),
        'previous', v_before,
        'member_hash_before', pg_catalog.encode(v_hash_before, 'hex'),
        'member_hash_after', pg_catalog.encode(mesh_ops.identity_group_member_hash_internal_v1(v_group.id), 'hex'),
        'authority', v_scope.authority);
END;
$function$;

-- Adds and removes members (identity_group.manage), at most 150 of each per
-- call. Added principals must be active members of the Workspace. When the
-- set changes, every Network whose active release selects the group advances
-- its revision so maps rebuild; the result lists them. Errors: P0002 unknown
-- group, 40001 stale version, MTI01 not an active member, MTI03 more than
-- 10000 members, MTD06 a Device would load more than 10000 edges.
CREATE FUNCTION mesh_ops.change_identity_group_members_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_group_public_id UUID, p_expected_version BIGINT,
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
    v_group mesh.identity_group%ROWTYPE;
    v_before JSONB;
    v_hash_before BYTEA;
    v_requested INTEGER;
    v_eligible INTEGER;
    v_added INTEGER := 0;
    v_removed INTEGER := 0;
    v_count INTEGER;
    v_networks BIGINT[];
    v_advanced JSONB := '[]'::JSONB;
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
               OR NOT entry.value ? 'principal_id' OR NOT entry.value ? 'member_id'
        ) OR EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_to_recordset(p_add) AS item(principal_id UUID, member_id UUID)
            WHERE item.principal_id IS NULL OR item.member_id IS NULL
               OR pg_catalog.get_byte(pg_catalog.uuid_send(item.member_id), 6) >> 4 <> 7
        ) OR (
            SELECT pg_catalog.count(DISTINCT item.principal_id) <> pg_catalog.jsonb_array_length(p_add)
            FROM pg_catalog.jsonb_to_recordset(p_add) AS item(principal_id UUID, member_id UUID)
        ) OR EXISTS (SELECT 1 FROM pg_catalog.unnest(p_remove) AS removed(id) WHERE removed.id IS NULL)
        OR EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_to_recordset(p_add) AS item(principal_id UUID, member_id UUID)
            WHERE item.principal_id = ANY (p_remove)
        ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Identity Group membership change is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_identity_catalog_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'identity_group.manage', p_evaluated_at
    );
    SELECT * INTO v_group FROM mesh.identity_group AS identity_group
    WHERE identity_group.workspace_id = v_scope.workspace_id AND identity_group.public_id = p_group_public_id
      AND identity_group.state = 'active'
    FOR UPDATE;
    IF v_group.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Identity Group is unavailable';
    END IF;
    IF v_group.version <> p_expected_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Identity Group version changed';
    END IF;
    v_before := mesh_ops.identity_group_document_internal_v1(v_group);
    v_hash_before := mesh_ops.identity_group_member_hash_internal_v1(v_group.id);

    v_requested := pg_catalog.jsonb_array_length(p_add);
    IF v_requested > 0 THEN
        SELECT pg_catalog.count(*)::INTEGER INTO v_eligible
        FROM pg_catalog.jsonb_to_recordset(p_add) AS item(principal_id UUID, member_id UUID)
        JOIN mesh.principal AS principal
          ON principal.deployment_id = v_scope.deployment_id AND principal.public_id = item.principal_id
         AND principal.state = 'active' AND principal.deleted_at IS NULL
        JOIN mesh.workspace_membership AS membership
          ON membership.workspace_id = v_scope.workspace_id AND membership.principal_id = principal.id
         AND membership.state = 'active'
         AND (membership.expires_at IS NULL OR membership.expires_at > v_now);
        IF v_eligible <> v_requested THEN
            RAISE EXCEPTION USING ERRCODE = 'MTI01', MESSAGE = 'a principal is not an active member of this Workspace';
        END IF;
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    IF pg_catalog.cardinality(p_remove) > 0 THEN
        DELETE FROM mesh.identity_group_member AS member
        USING mesh.principal AS principal
        WHERE member.identity_group_id = v_group.id AND principal.id = member.principal_id
          AND principal.public_id = ANY (p_remove);
        GET DIAGNOSTICS v_removed = ROW_COUNT;
    END IF;
    IF v_requested > 0 THEN
        INSERT INTO mesh.identity_group_member (public_id, workspace_id, identity_group_id, principal_id, created_at)
        SELECT item.member_id, v_scope.workspace_id, v_group.id, principal.id, v_now
        FROM pg_catalog.jsonb_to_recordset(p_add) AS item(principal_id UUID, member_id UUID)
        JOIN mesh.principal AS principal
          ON principal.deployment_id = v_scope.deployment_id AND principal.public_id = item.principal_id
        ORDER BY principal.id
        ON CONFLICT (identity_group_id, principal_id) DO NOTHING;
        GET DIAGNOSTICS v_added = ROW_COUNT;
    END IF;

    IF v_added + v_removed > 0 THEN
        SELECT pg_catalog.count(*)::INTEGER INTO v_count
        FROM mesh.identity_group_member AS member WHERE member.identity_group_id = v_group.id;
        IF v_count > 10000 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTI03', MESSAGE = 'Identity Group would exceed 10000 members';
        END IF;
        UPDATE mesh.identity_group
        SET member_count = v_count, version = version + 1, updated_at = GREATEST(v_now, updated_at)
        WHERE id = v_group.id
        RETURNING * INTO v_group;
        SELECT pg_catalog.array_agg(DISTINCT rule.network_id ORDER BY rule.network_id) INTO v_networks
        FROM mesh.compiled_policy_group_rule AS rule
        JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id AND release.state = 'active'
        WHERE rule.workspace_id = v_scope.workspace_id AND rule.source_identity_group_id = v_group.id;
        IF v_networks IS NOT NULL THEN
            v_advanced := mesh_ops.advance_identity_networks_internal_v1(v_scope.workspace_id, v_networks);
            IF v_added > 0 AND mesh_ops.identity_networks_over_edge_budget_internal_v1(
                    v_scope.workspace_id, v_networks) THEN
                RAISE EXCEPTION USING ERRCODE = 'MTD06', MESSAGE = 'a Device would load more than 10000 rule edges';
            END IF;
        END IF;
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'group', mesh_ops.identity_group_document_internal_v1(v_group),
        'previous', v_before,
        'added', v_added,
        'removed', v_removed,
        'changed', v_added + v_removed > 0,
        'member_hash_before', pg_catalog.encode(v_hash_before, 'hex'),
        'member_hash_after', pg_catalog.encode(mesh_ops.identity_group_member_hash_internal_v1(v_group.id), 'hex'),
        'networks', v_advanced,
        'authority', v_scope.authority
    );
END;
$function$;

-- The Workspace's tag catalog (device_tag.read).
CREATE FUNCTION mesh_ops.list_device_tags_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_evaluated_at TIMESTAMPTZ
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
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_identity_catalog_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'device_tag.read', p_evaluated_at
    );
    RETURN pg_catalog.jsonb_build_object(
        'tags', COALESCE((
            SELECT pg_catalog.jsonb_agg(mesh_ops.device_tag_document_internal_v1(tag) ORDER BY tag.name)
            FROM mesh.device_tag AS tag
            WHERE tag.workspace_id = v_scope.workspace_id AND tag.state = 'active'
        ), '[]'::JSONB),
        'can_manage', mesh_ops.holds_workspace_permission_internal_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, 'device_tag.manage', p_evaluated_at)
    );
END;
$function$;

-- Creates, updates (name, description, owners) or deletes a tag
-- (device_tag.manage). Owners are a full replacement: Identity Groups of the
-- Workspace and built-in role keys. Deleting a tag that an active release
-- selects is refused; otherwise its assignments go too and the Networks that
-- had them advance (the tagged Devices change identity). Errors: P0002
-- unknown tag, 40001 stale version, MTT02 more than 200 tags, MTT03 unknown
-- owner, MTT04 name taken, MTT05 tag in use.
CREATE FUNCTION mesh_ops.change_device_tag_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_operation TEXT, p_tag_public_id UUID, p_expected_version BIGINT,
    p_name TEXT, p_description TEXT, p_owner_group_ids UUID[], p_owner_roles TEXT[], p_owner_row_ids UUID[],
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
    v_scope RECORD;
    v_tag mesh.device_tag%ROWTYPE;
    v_before JSONB;
    v_networks BIGINT[];
    v_advanced JSONB := '[]'::JSONB;
    v_owner_count INTEGER;
    v_now TIMESTAMPTZ := GREATEST(pg_catalog.clock_timestamp(), p_evaluated_at);
BEGIN
    IF p_operation NOT IN ('create', 'update', 'delete') OR p_tag_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_tag_public_id), 6) >> 4 <> 7
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR (p_operation <> 'create' AND (p_expected_version IS NULL OR p_expected_version < 1))
        OR (p_operation <> 'delete' AND (
            p_name IS NULL OR p_description IS NULL OR p_owner_group_ids IS NULL OR p_owner_roles IS NULL
            OR p_owner_row_ids IS NULL
            OR pg_catalog.cardinality(p_owner_group_ids) + pg_catalog.cardinality(p_owner_roles) > 32
            OR pg_catalog.cardinality(p_owner_row_ids)
               <> pg_catalog.cardinality(p_owner_group_ids) + pg_catalog.cardinality(p_owner_roles)
            OR EXISTS (SELECT 1 FROM pg_catalog.unnest(p_owner_row_ids) AS row_id(id)
                       WHERE row_id.id IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(row_id.id), 6) >> 4 <> 7)
            OR (SELECT pg_catalog.count(DISTINCT owner_group.id) FROM pg_catalog.unnest(p_owner_group_ids) AS owner_group(id))
               <> pg_catalog.cardinality(p_owner_group_ids)
            OR (SELECT pg_catalog.count(DISTINCT owner_role.key) FROM pg_catalog.unnest(p_owner_roles) AS owner_role(key))
               <> pg_catalog.cardinality(p_owner_roles)
        )) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'device tag change is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_identity_catalog_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'device_tag.manage', p_evaluated_at
    );
    IF p_operation <> 'delete' THEN
        SELECT pg_catalog.count(*)::INTEGER INTO v_owner_count
        FROM pg_catalog.unnest(p_owner_group_ids) AS owner_group(id)
        JOIN mesh.identity_group AS identity_group
          ON identity_group.workspace_id = v_scope.workspace_id AND identity_group.public_id = owner_group.id
         AND identity_group.state = 'active';
        IF v_owner_count <> pg_catalog.cardinality(p_owner_group_ids)
            OR EXISTS (SELECT 1 FROM pg_catalog.unnest(p_owner_roles) AS owner_role(key)
                       WHERE NOT EXISTS (SELECT 1 FROM mesh.builtin_role AS role
                                         WHERE role.role_key = owner_role.key)) THEN
            RAISE EXCEPTION USING ERRCODE = 'MTT03', MESSAGE = 'a tag owner is not in this Workspace';
        END IF;
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    IF p_operation = 'create' THEN
        PERFORM 1 FROM mesh.workspace AS workspace WHERE workspace.id = v_scope.workspace_id FOR UPDATE;
        IF (SELECT pg_catalog.count(*) FROM mesh.device_tag AS tag
            WHERE tag.workspace_id = v_scope.workspace_id AND tag.state = 'active') >= 200 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTT02', MESSAGE = 'Workspace already has the maximum device tags';
        END IF;
        BEGIN
            INSERT INTO mesh.device_tag (public_id, deployment_id, workspace_id, name, description, created_at, updated_at)
            VALUES (p_tag_public_id, v_scope.deployment_id, v_scope.workspace_id, p_name, p_description, v_now, v_now)
            RETURNING * INTO v_tag;
        EXCEPTION WHEN unique_violation THEN
            RAISE EXCEPTION USING ERRCODE = 'MTT04', MESSAGE = 'device tag name is taken';
        END;
    ELSE
        SELECT * INTO v_tag FROM mesh.device_tag AS tag
        WHERE tag.workspace_id = v_scope.workspace_id AND tag.public_id = p_tag_public_id AND tag.state = 'active'
        FOR UPDATE;
        IF v_tag.id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'device tag is unavailable';
        END IF;
        IF v_tag.version <> p_expected_version THEN
            RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'device tag version changed';
        END IF;
        v_before := mesh_ops.device_tag_document_internal_v1(v_tag);
        DELETE FROM mesh.device_tag_owner WHERE device_tag_id = v_tag.id;
        IF p_operation = 'update' THEN
            BEGIN
                UPDATE mesh.device_tag
                SET name = p_name, description = p_description, version = version + 1,
                    updated_at = GREATEST(v_now, updated_at)
                WHERE id = v_tag.id
                RETURNING * INTO v_tag;
            EXCEPTION WHEN unique_violation THEN
                RAISE EXCEPTION USING ERRCODE = 'MTT04', MESSAGE = 'device tag name is taken';
            END;
        ELSE
            IF mesh_ops.device_tag_rule_count_internal_v1(v_tag.id) > 0 THEN
                RAISE EXCEPTION USING ERRCODE = 'MTT05', MESSAGE = 'device tag is selected by active rules';
            END IF;
            SELECT pg_catalog.array_agg(DISTINCT assignment.network_id ORDER BY assignment.network_id)
            INTO v_networks
            FROM mesh.device_tag_assignment AS assignment WHERE assignment.device_tag_id = v_tag.id;
            DELETE FROM mesh.device_tag_assignment WHERE device_tag_id = v_tag.id;
            IF v_networks IS NOT NULL THEN
                v_advanced := mesh_ops.advance_identity_networks_internal_v1(v_scope.workspace_id, v_networks);
            END IF;
            UPDATE mesh.device_tag
            SET state = 'deleted', deleted_at = GREATEST(v_now, updated_at), version = version + 1,
                updated_at = GREATEST(v_now, updated_at)
            WHERE id = v_tag.id
            RETURNING * INTO v_tag;
        END IF;
    END IF;
    IF p_operation <> 'delete' THEN
        INSERT INTO mesh.device_tag_owner (public_id, workspace_id, device_tag_id, identity_group_id, role_key, created_at)
        SELECT owner.row_id, v_scope.workspace_id, v_tag.id, owner.group_id, owner.role_key, v_now
        FROM (
            SELECT row_ids.id AS row_id, owners.group_id, owners.role_key
            FROM (
                SELECT identity_group.id AS group_id, NULL::TEXT AS role_key,
                       pg_catalog.row_number() OVER (ORDER BY identity_group.public_id::TEXT) AS ordinal
                FROM pg_catalog.unnest(p_owner_group_ids) AS owner_group(id)
                JOIN mesh.identity_group AS identity_group
                  ON identity_group.workspace_id = v_scope.workspace_id AND identity_group.public_id = owner_group.id
                UNION ALL
                SELECT NULL::BIGINT, owner_role.key,
                       pg_catalog.cardinality(p_owner_group_ids) + pg_catalog.row_number() OVER (ORDER BY owner_role.key)
                FROM pg_catalog.unnest(p_owner_roles) AS owner_role(key)
            ) AS owners
            JOIN pg_catalog.unnest(p_owner_row_ids) WITH ORDINALITY AS row_ids(id, ordinal)
              ON row_ids.ordinal = owners.ordinal
        ) AS owner;
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'tag', mesh_ops.device_tag_document_internal_v1(v_tag),
        'previous', v_before,
        'networks', v_advanced,
        'authority', v_scope.authority);
END;
$function$;

-- Whether a principal owns a tag for a Device of a Network: the Workspace
-- owner, a member of an owning Identity Group, or the holder of an owning
-- built-in role for the Workspace or that Network.
CREATE FUNCTION mesh_ops.device_tag_owned_by_internal_v1(
    p_device_tag_id BIGINT, p_workspace_id BIGINT, p_network_id BIGINT, p_principal_id BIGINT,
    p_evaluated_at TIMESTAMPTZ
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT EXISTS (
        SELECT 1 FROM mesh.workspace AS workspace
        WHERE workspace.id = p_workspace_id AND workspace.owner_principal_id = p_principal_id
    ) OR EXISTS (
        SELECT 1 FROM mesh.device_tag_owner AS owner
        JOIN mesh.identity_group AS identity_group
          ON identity_group.id = owner.identity_group_id AND identity_group.state = 'active'
        JOIN mesh.identity_group_member AS member
          ON member.identity_group_id = identity_group.id AND member.principal_id = p_principal_id
        WHERE owner.device_tag_id = p_device_tag_id
    ) OR EXISTS (
        SELECT 1 FROM mesh.device_tag_owner AS owner
        JOIN mesh.workspace_role_assignment AS assignment
          ON assignment.role_key = owner.role_key AND assignment.workspace_id = p_workspace_id
         AND assignment.principal_id = p_principal_id AND assignment.state = 'active'
         AND (assignment.expires_at IS NULL OR assignment.expires_at > p_evaluated_at)
         AND (assignment.network_id IS NULL OR assignment.network_id = p_network_id)
        WHERE owner.device_tag_id = p_device_tag_id
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.device_tag_owned_by_internal_v1(BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Adds and removes tags of one Device of the bound Network, at most 32 of
-- each per call. The caller needs device.read in the Network and, for each
-- tag, device_tag.manage or ownership of the tag together with ownership of
-- the Device or device.manage in the Network. A change advances the Network
-- revision. Errors: P0002 unknown Device or tag, 42501 not allowed, MTD06 a
-- Device would load more than 10000 edges.
CREATE FUNCTION mesh_ops.change_device_tags_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_device_public_id UUID,
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
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_device mesh.device%ROWTYPE;
    v_grant RECORD;
    v_principal BIGINT;
    v_manage_any BOOLEAN;
    v_manage_devices BOOLEAN;
    v_requested UUID[];
    v_known INTEGER;
    v_hash_before BYTEA;
    v_added INTEGER := 0;
    v_removed INTEGER := 0;
    v_network_revision BIGINT;
    v_group_revision BIGINT;
    v_now TIMESTAMPTZ := GREATEST(pg_catalog.clock_timestamp(), p_evaluated_at);
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL OR p_device_public_id IS NULL
        OR p_add IS NULL OR pg_catalog.jsonb_typeof(p_add) <> 'array'
        OR pg_catalog.jsonb_array_length(p_add) > 32
        OR p_remove IS NULL OR pg_catalog.cardinality(p_remove) > 32
        OR pg_catalog.jsonb_array_length(p_add) + pg_catalog.cardinality(p_remove) = 0
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_array_elements(p_add) AS entry(value)
            WHERE pg_catalog.jsonb_typeof(entry.value) <> 'object'
               OR (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(entry.value)) <> 2
               OR NOT entry.value ? 'tag_id' OR NOT entry.value ? 'assignment_id'
        ) OR EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_to_recordset(p_add) AS item(tag_id UUID, assignment_id UUID)
            WHERE item.tag_id IS NULL OR item.assignment_id IS NULL
               OR pg_catalog.get_byte(pg_catalog.uuid_send(item.assignment_id), 6) >> 4 <> 7
        ) OR (
            SELECT pg_catalog.count(DISTINCT item.tag_id) <> pg_catalog.jsonb_array_length(p_add)
            FROM pg_catalog.jsonb_to_recordset(p_add) AS item(tag_id UUID, assignment_id UUID)
        ) OR EXISTS (SELECT 1 FROM pg_catalog.unnest(p_remove) AS removed(id) WHERE removed.id IS NULL)
        OR EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_to_recordset(p_add) AS item(tag_id UUID, assignment_id UUID)
            WHERE item.tag_id = ANY (p_remove)
        ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'device tag assignment change is invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'device.read', p_evaluated_at
    ) LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'device tag assignment is not authorized';
    END IF;
    SELECT principal.id INTO v_principal FROM mesh.principal AS principal
    WHERE principal.public_id = p_principal_public_id AND principal.state = 'active';
    v_manage_any := mesh_ops.holds_workspace_permission_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'device_tag.manage', p_evaluated_at);
    v_manage_devices := mesh_ops.holds_device_group_permission_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'device.manage', p_evaluated_at);

    -- Serializes tag changes with publication and other map inputs.
    SELECT revision.network_revision INTO v_network_revision FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_workspace AND revision.network_id = v_network
    FOR UPDATE;
    SELECT * INTO v_device FROM mesh.device AS device
    WHERE device.workspace_id = v_workspace AND device.network_id = v_network
      AND device.public_id = p_device_public_id AND device.state = 'active' AND device.deleted_at IS NULL
    FOR UPDATE;
    IF v_device.id IS NULL OR v_network_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Device is unavailable';
    END IF;
    v_requested := ARRAY(
        SELECT item.tag_id FROM pg_catalog.jsonb_to_recordset(p_add) AS item(tag_id UUID, assignment_id UUID)
        UNION ALL SELECT removed.id FROM pg_catalog.unnest(p_remove) AS removed(id)
    );
    SELECT pg_catalog.count(*)::INTEGER INTO v_known
    FROM pg_catalog.unnest(v_requested) AS requested(id)
    JOIN mesh.device_tag AS tag
      ON tag.workspace_id = v_workspace AND tag.public_id = requested.id AND tag.state = 'active';
    IF v_known <> pg_catalog.cardinality(v_requested) THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'device tag is unavailable';
    END IF;
    IF NOT v_manage_any AND (
        v_principal IS NULL
        OR (v_device.owner_principal_id <> v_principal AND NOT v_manage_devices)
        OR EXISTS (
            SELECT 1 FROM pg_catalog.unnest(v_requested) AS requested(id)
            JOIN mesh.device_tag AS tag ON tag.workspace_id = v_workspace AND tag.public_id = requested.id
            WHERE NOT mesh_ops.device_tag_owned_by_internal_v1(tag.id, v_workspace, v_network, v_principal, v_now)
        )) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'device tag assignment is not authorized';
    END IF;

    v_hash_before := mesh_ops.device_tag_set_hash_internal_v1(v_device.id);
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    IF pg_catalog.cardinality(p_remove) > 0 THEN
        DELETE FROM mesh.device_tag_assignment AS assignment
        USING mesh.device_tag AS tag
        WHERE assignment.device_id = v_device.id AND tag.id = assignment.device_tag_id
          AND tag.public_id = ANY (p_remove);
        GET DIAGNOSTICS v_removed = ROW_COUNT;
    END IF;
    IF pg_catalog.jsonb_array_length(p_add) > 0 THEN
        INSERT INTO mesh.device_tag_assignment (
            public_id, workspace_id, network_id, device_id, device_tag_id, created_at
        )
        SELECT item.assignment_id, v_workspace, v_network, v_device.id, tag.id, v_now
        FROM pg_catalog.jsonb_to_recordset(p_add) AS item(tag_id UUID, assignment_id UUID)
        JOIN mesh.device_tag AS tag ON tag.workspace_id = v_workspace AND tag.public_id = item.tag_id
        ORDER BY tag.id
        ON CONFLICT (device_id, device_tag_id) DO NOTHING;
        GET DIAGNOSTICS v_added = ROW_COUNT;
    END IF;
    IF v_added + v_removed > 0 THEN
        UPDATE mesh_ops.network_revision AS revision
        SET network_revision = revision.network_revision + 1,
            group_revision = revision.group_revision + 1,
            updated_at = pg_catalog.clock_timestamp()
        WHERE revision.workspace_id = v_workspace AND revision.network_id = v_network
        RETURNING revision.network_revision, revision.group_revision
        INTO v_network_revision, v_group_revision;
        IF v_added > 0 AND mesh_ops.max_device_policy_edges_internal_v1(v_workspace, v_network) > 10000 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTD06', MESSAGE = 'a Device would load more than 10000 rule edges';
        END IF;
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'device_id', v_device.public_id,
        'device_name', v_device.hostname,
        'tag_ids', COALESCE((
            SELECT pg_catalog.jsonb_agg(tag.public_id ORDER BY tag.public_id::TEXT)
            FROM mesh.device_tag_assignment AS assignment
            JOIN mesh.device_tag AS tag ON tag.id = assignment.device_tag_id
            WHERE assignment.device_id = v_device.id
        ), '[]'::JSONB),
        'added', v_added,
        'removed', v_removed,
        'changed', v_added + v_removed > 0,
        'tag_set_hash_before', pg_catalog.encode(v_hash_before, 'hex'),
        'tag_set_hash_after', pg_catalog.encode(mesh_ops.device_tag_set_hash_internal_v1(v_device.id), 'hex'),
        'network_revision', v_network_revision,
        'group_revision', v_group_revision,
        'role_binding_id', v_grant.role_binding_public_id,
        'manage_any', v_manage_any
    );
END;
$function$;

-- The tags of the bound Network's Devices, for inventory views
-- (device.read in the Network). Devices without tags are omitted.
CREATE FUNCTION mesh_ops.read_network_device_tags_v1(
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
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Network scope is unavailable';
    END IF;
    PERFORM 1 FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'device.read', p_evaluated_at
    );
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'device tags are not readable';
    END IF;
    RETURN pg_catalog.jsonb_build_object('devices', COALESCE((
        SELECT pg_catalog.jsonb_agg(item.document ORDER BY item.device_public_id)
        FROM (
            SELECT device.public_id::TEXT AS device_public_id,
                   pg_catalog.jsonb_build_object(
                       'device_id', device.public_id,
                       'tag_ids', pg_catalog.jsonb_agg(tag.public_id ORDER BY tag.public_id::TEXT)
                   ) AS document
            FROM mesh.device_tag_assignment AS assignment
            JOIN mesh.device AS device ON device.id = assignment.device_id
            JOIN mesh.device_tag AS tag ON tag.id = assignment.device_tag_id AND tag.state = 'active'
            WHERE assignment.workspace_id = v_workspace AND assignment.network_id = v_network
            GROUP BY device.public_id
        ) AS item
    ), '[]'::JSONB));
END;
$function$;

-- The audit stream head of one Network of the Workspace bound to this
-- transaction. A Workspace change that rebuilds several Networks (an
-- Identity Group membership change, a tag deletion) records evidence and the
-- revision wakeup on each Network's own stream; the Network scope of the
-- transaction cannot be rebound, so the Network is named explicitly and must
-- belong to the bound Workspace.
CREATE FUNCTION mesh_audit.lock_workspace_network_stream_head_v1(p_network_public_id UUID)
RETURNS TABLE (stream_internal_id BIGINT, next_sequence BIGINT, latest_event_hash BYTEA)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh_audit, mesh
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
BEGIN
    BEGIN
        scoped_workspace_id := NULLIF(pg_catalog.current_setting('mesh.workspace_id', TRUE), '')::BIGINT;
    EXCEPTION
        WHEN invalid_text_representation OR numeric_value_out_of_range THEN
            RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Workspace scope is unavailable';
    END;
    IF scoped_workspace_id IS NULL OR p_network_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Workspace scope is unavailable';
    END IF;
    RETURN QUERY
    SELECT stream.id, stream.next_sequence, stream.latest_event_hash
    FROM mesh_audit.audit_stream AS stream
    JOIN mesh.network AS network ON network.id = stream.network_id AND network.workspace_id = stream.workspace_id
    WHERE stream.scope_kind = 'network' AND stream.workspace_id = scoped_workspace_id
      AND network.public_id = p_network_public_id
    FOR UPDATE OF stream;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Network audit stream is unavailable';
    END IF;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_audit.lock_workspace_network_stream_head_v1(UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_audit.lock_workspace_network_stream_head_v1(UUID) TO mesh_runtime;

REVOKE ALL ON FUNCTION mesh_ops.enforce_identity_catalog_transition_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.list_identity_groups_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_identity_groups_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, TIMESTAMPTZ
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.read_identity_group_members_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, INTEGER, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_identity_group_members_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, INTEGER, TIMESTAMPTZ
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.change_identity_group_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, TEXT, UUID, BIGINT, TEXT, TEXT, UUID,
    TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_identity_group_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, TEXT, UUID, BIGINT, TEXT, TEXT, UUID,
    TIMESTAMPTZ
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.change_identity_group_members_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, BIGINT, JSONB, UUID[], UUID,
    TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_identity_group_members_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, BIGINT, JSONB, UUID[], UUID,
    TIMESTAMPTZ
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.list_device_tags_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_device_tags_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, TIMESTAMPTZ
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.change_device_tag_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, TEXT, UUID, BIGINT, TEXT, TEXT,
    UUID[], TEXT[], UUID[], UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_device_tag_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, TEXT, UUID, BIGINT, TEXT, TEXT,
    UUID[], TEXT[], UUID[], UUID, TIMESTAMPTZ
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.change_device_tags_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, JSONB, UUID[], UUID,
    TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_device_tags_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, JSONB, UUID[], UUID,
    TIMESTAMPTZ
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.read_network_device_tags_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_network_device_tags_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) TO mesh_runtime;
