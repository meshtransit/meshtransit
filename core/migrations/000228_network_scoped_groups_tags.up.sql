-- Schema 228 (G2n): user groups and device tags belong to one Network.
--
-- Schema 121 kept Identity Groups and the tag catalog in the Workspace while
-- rules live in each Network. A tag owner named in the Workspace could tag
-- their own Device into another Network's rules, and whoever managed a group
-- changed access in every Network whose rules named it, with no role there.
-- Now each group, tag and tag owner belongs to exactly one Network:
--
-- * New identity_group and device_tag rows carry network_id, which never
--   changes; names are unique per Network; the limits (500 groups, 200
--   tags) count per Network.
-- * A group's members are active members of its Network: a trigger takes the
--   member's Network membership FOR SHARE when a member row is inserted, and
--   removing someone from the Network removes them from its groups. Both
--   removals lock the Workspace row before anything else and the permission
--   resolver takes it FOR SHARE first, so a membership change and a removal
--   never interleave.
-- * A tag's owner groups, the tags a Device carries and the groups and tags
--   a rule selects all come from the same Network, enforced by triggers and
--   foreign keys that include network_id. Publication looks selectors up in
--   the release's Network only.
-- * Every resolver that expands a group (maps, the shared selector feeding
--   the edge budget and Access Graph, Explain) also requires the group to be
--   of the Network and the owner's Network membership to be active, so a
--   member row that outlives its membership grants nothing.
-- * identity_group.* and device_tag.* are Network permissions. network_admin
--   gains identity_group.manage and device_tag.manage; it_admin loses them
--   and needs a role in the Network.
-- * The Workspace-wide v1 entry points raise 0A000; Network v2 ones replace
--   them. An image older than this schema fails closed on these paths.
--
-- Existing rows are not rewritten: an authority row changes only with its
-- audit evidence, which a migration cannot sign. Rows from schema 121 keep
-- a NULL network_id and become inert: no Network lists, reads, changes,
-- selects or resolves them, so they grant nothing. New rows always name a
-- Network. The migration stops when an active release still selects such a
-- group or tag, or a Device still carries such a tag, since those would lose
-- their meaning silently; deselect and untag first.

-- Permission catalog: the four catalog permissions become Network
-- permissions. The catalog is immutable at runtime; only this migration
-- changes it.
ALTER TABLE mesh.permission DISABLE TRIGGER permission_immutable;
UPDATE mesh.permission
SET allowed_scope_kinds = ARRAY['network']
WHERE permission_key IN ('identity_group.read', 'identity_group.manage', 'device_tag.read', 'device_tag.manage');
ALTER TABLE mesh.permission ENABLE TRIGGER permission_immutable;

ALTER TABLE mesh.builtin_role_permission DISABLE TRIGGER builtin_role_permission_immutable;
DELETE FROM mesh.builtin_role_permission AS grant_row
USING mesh.permission AS permission
WHERE permission.id = grant_row.permission_id AND grant_row.role_key = 'it_admin'
  AND permission.permission_key IN ('identity_group.manage', 'device_tag.manage');
ALTER TABLE mesh.builtin_role_permission ENABLE TRIGGER builtin_role_permission_immutable;
INSERT INTO mesh.builtin_role_permission (role_key, permission_id)
SELECT 'network_admin', permission.id
FROM mesh.permission AS permission
WHERE permission.permission_key IN ('identity_group.manage', 'device_tag.manage')
ON CONFLICT DO NOTHING;

-- Catalog transitions: a new entry names its Network, which never changes.
-- Entries from before schema 228 keep their NULL Network.
CREATE OR REPLACE FUNCTION mesh_ops.enforce_identity_catalog_transition_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'identity catalog entries are never deleted';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.version <> 1 OR NEW.state <> 'active' OR NEW.network_id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                MESSAGE = 'identity catalog entry must start active at version 1 in a Network';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.public_id <> OLD.public_id OR NEW.deployment_id <> OLD.deployment_id
        OR NEW.workspace_id <> OLD.workspace_id OR NEW.network_id IS DISTINCT FROM OLD.network_id
        OR NEW.created_at <> OLD.created_at
        OR NEW.version <> OLD.version + 1 OR OLD.state = 'deleted' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid identity catalog transition';
    END IF;
    RETURN NEW;
END;
$function$;

ALTER TABLE mesh.identity_group ADD COLUMN network_id BIGINT;
ALTER TABLE mesh.device_tag ADD COLUMN network_id BIGINT;

-- Rows from before schema 228 cannot be mapped to a Network without being
-- rewritten. Refuse while anything still depends on them.
DO $migration$
BEGIN
    IF EXISTS (
        SELECT 1 FROM mesh.compiled_policy_group_rule AS rule
        JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id AND release.state = 'active'
        WHERE rule.source_identity_group_id IS NOT NULL OR rule.source_device_tag_id IS NOT NULL
           OR rule.destination_device_tag_id IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM mesh.compiled_policy_route_rule AS rule
        JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id AND release.state = 'active'
        WHERE rule.source_identity_group_id IS NOT NULL OR rule.source_device_tag_id IS NOT NULL
    ) OR EXISTS (
        SELECT 1 FROM mesh.compiled_policy_exit_rule AS rule
        JOIN mesh.policy_release AS release ON release.id = rule.policy_release_id AND release.state = 'active'
        WHERE rule.source_identity_group_id IS NOT NULL OR rule.source_device_tag_id IS NOT NULL
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'schema 228: active rules select Workspace user groups or tags',
            HINT = 'Publish policy without user group and tag selectors, upgrade, then recreate them in a Network.';
    END IF;
    IF EXISTS (SELECT 1 FROM mesh.device_tag_assignment) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'schema 228: Devices carry Workspace tags',
            HINT = 'Remove the tags from every Device, upgrade, then recreate the tags in a Network.';
    END IF;
END;
$migration$;

ALTER TABLE mesh.identity_group
    ADD CONSTRAINT identity_group_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT identity_group_network_scope_key UNIQUE (workspace_id, network_id, id);
ALTER TABLE mesh.device_tag
    ADD CONSTRAINT device_tag_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    ADD CONSTRAINT device_tag_network_scope_key UNIQUE (workspace_id, network_id, id);

DROP INDEX mesh.identity_group_active_name_uidx;
CREATE UNIQUE INDEX identity_group_active_name_uidx
    ON mesh.identity_group (network_id, name_key) WHERE state = 'active';
DROP INDEX mesh.device_tag_active_name_uidx;
CREATE UNIQUE INDEX device_tag_active_name_uidx ON mesh.device_tag (network_id, name) WHERE state = 'active';

-- A tag is applied only in its own Network.
ALTER TABLE mesh.device_tag_assignment
    ADD CONSTRAINT device_tag_assignment_network_tag_fk FOREIGN KEY (workspace_id, network_id, device_tag_id)
        REFERENCES mesh.device_tag (workspace_id, network_id, id) ON DELETE RESTRICT;

-- Rules select groups and tags of their own Network. Rows of earlier
-- releases are not checked again; every new row is.
ALTER TABLE mesh.compiled_policy_group_rule
    ADD CONSTRAINT compiled_policy_group_rule_network_identity_group_fk
        FOREIGN KEY (workspace_id, network_id, source_identity_group_id)
        REFERENCES mesh.identity_group (workspace_id, network_id, id) ON DELETE RESTRICT NOT VALID,
    ADD CONSTRAINT compiled_policy_group_rule_network_source_tag_fk
        FOREIGN KEY (workspace_id, network_id, source_device_tag_id)
        REFERENCES mesh.device_tag (workspace_id, network_id, id) ON DELETE RESTRICT NOT VALID,
    ADD CONSTRAINT compiled_policy_group_rule_network_destination_tag_fk
        FOREIGN KEY (workspace_id, network_id, destination_device_tag_id)
        REFERENCES mesh.device_tag (workspace_id, network_id, id) ON DELETE RESTRICT NOT VALID;
ALTER TABLE mesh.compiled_policy_route_rule
    ADD CONSTRAINT compiled_policy_route_rule_network_identity_group_fk
        FOREIGN KEY (workspace_id, network_id, source_identity_group_id)
        REFERENCES mesh.identity_group (workspace_id, network_id, id) ON DELETE RESTRICT NOT VALID,
    ADD CONSTRAINT compiled_policy_route_rule_network_source_tag_fk
        FOREIGN KEY (workspace_id, network_id, source_device_tag_id)
        REFERENCES mesh.device_tag (workspace_id, network_id, id) ON DELETE RESTRICT NOT VALID;
ALTER TABLE mesh.compiled_policy_exit_rule
    ADD CONSTRAINT compiled_policy_exit_rule_network_identity_group_fk
        FOREIGN KEY (workspace_id, network_id, source_identity_group_id)
        REFERENCES mesh.identity_group (workspace_id, network_id, id) ON DELETE RESTRICT NOT VALID,
    ADD CONSTRAINT compiled_policy_exit_rule_network_source_tag_fk
        FOREIGN KEY (workspace_id, network_id, source_device_tag_id)
        REFERENCES mesh.device_tag (workspace_id, network_id, id) ON DELETE RESTRICT NOT VALID;

-- A member joins only while an active member of the group's Network; the
-- membership row is held FOR SHARE until the change commits, so a removal
-- that revokes it waits, then finds and removes the new member row.
CREATE FUNCTION mesh_ops.enforce_identity_group_member_network_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    PERFORM 1
    FROM mesh.identity_group AS identity_group
    JOIN mesh.network_membership AS network_member
      ON network_member.workspace_id = identity_group.workspace_id
     AND network_member.network_id = identity_group.network_id
     AND network_member.principal_id = NEW.principal_id
    WHERE identity_group.id = NEW.identity_group_id AND identity_group.workspace_id = NEW.workspace_id
      AND network_member.state = 'active'
      AND (network_member.expires_at IS NULL OR network_member.expires_at > pg_catalog.transaction_timestamp())
    FOR SHARE OF network_member;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MTI01', MESSAGE = 'a principal is not an active member of this Network';
    END IF;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.enforce_identity_group_member_network_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER identity_group_member_network
BEFORE INSERT ON mesh.identity_group_member
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_identity_group_member_network_v1();

-- A tag's owner group is a group of the tag's Network.
CREATE FUNCTION mesh_ops.enforce_device_tag_owner_network_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF NEW.identity_group_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM mesh.device_tag AS tag
        JOIN mesh.identity_group AS identity_group
          ON identity_group.workspace_id = tag.workspace_id AND identity_group.network_id = tag.network_id
        WHERE tag.id = NEW.device_tag_id AND tag.workspace_id = NEW.workspace_id
          AND identity_group.id = NEW.identity_group_id
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTT03', MESSAGE = 'a tag owner is not in this Network';
    END IF;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.enforce_device_tag_owner_network_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER device_tag_owner_network
BEFORE INSERT ON mesh.device_tag_owner
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_device_tag_owner_network_v1();

-- The exact Network scope bound by the caller, after one Network permission
-- check, with the evidence MeshCore records about the authority used.
CREATE FUNCTION mesh_ops.authorize_identity_catalog_internal_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_permission TEXT, p_evaluated_at TIMESTAMPTZ
)
RETURNS TABLE (deployment_id BIGINT, workspace_id BIGINT, network_id BIGINT, authority JSONB)
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_deployment BIGINT;
    v_grant RECORD;
BEGIN
    IF p_workspace_public_id IS NULL OR p_network_public_id IS NULL OR p_evaluated_at IS NULL
        OR p_permission NOT IN ('identity_group.read', 'identity_group.manage', 'device_tag.read',
                                'device_tag.manage') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'identity catalog scope input is invalid';
    END IF;
    SELECT workspace.deployment_id INTO v_deployment
    FROM mesh.workspace AS workspace
    JOIN mesh.network AS network ON network.workspace_id = workspace.id
    WHERE workspace.id = v_workspace AND network.id = v_network
      AND workspace.public_id = p_workspace_public_id AND network.public_id = p_network_public_id
      AND workspace.state = 'active' AND workspace.deleted_at IS NULL
      AND network.state = 'active' AND network.deleted_at IS NULL;
    IF v_deployment IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'identity catalog scope is unavailable';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_permission, p_evaluated_at
    ) LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'identity catalog action is not authorized';
    END IF;
    RETURN QUERY SELECT v_deployment, v_workspace, v_network, pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
        'binding_id', v_grant.role_binding_public_id,
        'role_id', v_grant.role_definition_public_id,
        'binding_generation', COALESCE(v_grant.binding_authority_generation, 0),
        'membership_generation', COALESCE(v_grant.membership_authority_generation, 0),
        'owner_generation', COALESCE(v_grant.workspace_owner_authority_generation, 0)
    ));
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.authorize_identity_catalog_internal_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TEXT, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Whether a principal owns a tag of the bound Network: the Workspace owner,
-- an active member of the Network in an owning group, or the holder of an
-- owning built-in role for the Workspace or that Network.
CREATE FUNCTION mesh_ops.device_tag_owned_by_internal_v2(
    p_device_tag_id BIGINT, p_workspace_id BIGINT, p_network_id BIGINT, p_principal_id BIGINT,
    p_evaluated_at TIMESTAMPTZ
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT EXISTS (
        SELECT 1 FROM mesh.device_tag AS tag
        WHERE tag.id = p_device_tag_id AND tag.workspace_id = p_workspace_id AND tag.network_id = p_network_id
    ) AND (
        EXISTS (
            SELECT 1 FROM mesh.workspace AS workspace
            WHERE workspace.id = p_workspace_id AND workspace.owner_principal_id = p_principal_id
        ) OR EXISTS (
            SELECT 1 FROM mesh.device_tag_owner AS owner
            JOIN mesh.identity_group AS identity_group
              ON identity_group.id = owner.identity_group_id AND identity_group.state = 'active'
             AND identity_group.network_id = p_network_id
            JOIN mesh.identity_group_member AS member
              ON member.identity_group_id = identity_group.id AND member.principal_id = p_principal_id
            JOIN mesh.network_membership AS network_member
              ON network_member.workspace_id = p_workspace_id AND network_member.network_id = p_network_id
             AND network_member.principal_id = p_principal_id AND network_member.state = 'active'
             AND (network_member.expires_at IS NULL OR network_member.expires_at > p_evaluated_at)
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
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.device_tag_owned_by_internal_v2(BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The bound Network's active Identity Groups (identity_group.read).
CREATE FUNCTION mesh_ops.list_identity_groups_v2(
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
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_identity_catalog_internal_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'identity_group.read', p_evaluated_at
    );
    RETURN pg_catalog.jsonb_build_object(
        'groups', COALESCE((
            SELECT pg_catalog.jsonb_agg(mesh_ops.identity_group_document_internal_v1(identity_group)
                ORDER BY identity_group.name_key, identity_group.public_id)
            FROM mesh.identity_group AS identity_group
            WHERE identity_group.workspace_id = v_scope.workspace_id
              AND identity_group.network_id = v_scope.network_id AND identity_group.state = 'active'
        ), '[]'::JSONB),
        'can_manage', mesh_ops.holds_device_group_permission_internal_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, 'identity_group.manage', p_evaluated_at)
    );
END;
$function$;

-- One page of a group's members, ordered by principal public ID, at most
-- 500. A member whose principal or Workspace or Network membership is no
-- longer active shows as inactive and grants nothing. P0002: unknown group.
CREATE FUNCTION mesh_ops.read_identity_group_members_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_group_public_id UUID,
    p_after_principal_public_id UUID, p_limit INTEGER, p_evaluated_at TIMESTAMPTZ
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
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_identity_catalog_internal_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'identity_group.read', p_evaluated_at
    );
    SELECT * INTO v_group FROM mesh.identity_group AS identity_group
    WHERE identity_group.workspace_id = v_scope.workspace_id AND identity_group.network_id = v_scope.network_id
      AND identity_group.public_id = p_group_public_id AND identity_group.state = 'active';
    IF v_group.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Identity Group is unavailable';
    END IF;
    WITH page AS (
        SELECT principal.public_id, account.display_name, member.created_at,
               principal.state = 'active' AND principal.deleted_at IS NULL
                   AND COALESCE(membership.state = 'active'
                       AND (membership.expires_at IS NULL OR membership.expires_at > p_evaluated_at), FALSE)
                   AND COALESCE(network_member.state = 'active'
                       AND (network_member.expires_at IS NULL OR network_member.expires_at > p_evaluated_at), FALSE)
                   AS active
        FROM mesh.identity_group_member AS member
        JOIN mesh.principal AS principal ON principal.id = member.principal_id
        LEFT JOIN mesh.account AS account
          ON account.deployment_id = principal.deployment_id AND account.principal_id = principal.id
        LEFT JOIN mesh.workspace_membership AS membership
          ON membership.workspace_id = v_scope.workspace_id AND membership.principal_id = principal.id
        LEFT JOIN mesh.network_membership AS network_member
          ON network_member.workspace_id = v_scope.workspace_id AND network_member.network_id = v_scope.network_id
         AND network_member.principal_id = principal.id AND network_member.state <> 'revoked'
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

-- Creates, renames or deletes a group of the bound Network
-- (identity_group.manage there). A group that an active release selects, or
-- that owns a tag, cannot be deleted. Changes in one Network serialize on its
-- revision row, as publication does. Errors: P0002 unknown group, 40001
-- stale version, MTI02 more than 500 groups in the Network, MTI04 name
-- taken, MTI05 group in use.
CREATE FUNCTION mesh_ops.change_identity_group_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_operation TEXT, p_group_public_id UUID,
    p_expected_version BIGINT, p_name TEXT, p_description TEXT, p_change_public_id UUID,
    p_evaluated_at TIMESTAMPTZ
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
    v_revision BIGINT;
    v_group mesh.identity_group%ROWTYPE;
    v_before JSONB;
    v_hash_before BYTEA;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_operation NOT IN ('create', 'update', 'delete') OR p_group_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_group_public_id), 6) >> 4 <> 7
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR (p_operation <> 'create' AND (p_expected_version IS NULL OR p_expected_version < 1))
        OR (p_operation <> 'delete' AND (p_name IS NULL OR p_description IS NULL)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Identity Group change is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_identity_catalog_internal_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'identity_group.manage', v_now
    );
    SELECT revision.network_revision INTO v_revision FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id
    FOR UPDATE;
    IF v_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'identity catalog scope is unavailable';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    IF p_operation = 'create' THEN
        IF (SELECT pg_catalog.count(*) FROM mesh.identity_group AS identity_group
            WHERE identity_group.workspace_id = v_scope.workspace_id
              AND identity_group.network_id = v_scope.network_id AND identity_group.state = 'active') >= 500 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTI02', MESSAGE = 'Network already has the maximum Identity Groups';
        END IF;
        BEGIN
            INSERT INTO mesh.identity_group (
                public_id, deployment_id, workspace_id, network_id, name, name_key, description,
                created_at, updated_at
            ) VALUES (
                p_group_public_id, v_scope.deployment_id, v_scope.workspace_id, v_scope.network_id, p_name,
                pg_catalog.lower(p_name), p_description, v_now, v_now
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
    WHERE identity_group.workspace_id = v_scope.workspace_id AND identity_group.network_id = v_scope.network_id
      AND identity_group.public_id = p_group_public_id AND identity_group.state = 'active'
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

-- Adds and removes members of a group of the bound Network
-- (identity_group.manage there), at most 150 of each per call. Added
-- principals must be active members of the Workspace and of the Network.
-- When the set changes and active rules select the group, the Network
-- advances so maps rebuild; the result lists it. Errors: P0002 unknown
-- group, 40001 stale version, MTI01 not an active member, MTI03 more than
-- 10000 members, MTD06 a Device would load more than 10000 edges.
CREATE FUNCTION mesh_ops.change_identity_group_members_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_group_public_id UUID, p_expected_version BIGINT,
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
    v_revision BIGINT;
    v_group mesh.identity_group%ROWTYPE;
    v_before JSONB;
    v_hash_before BYTEA;
    v_requested INTEGER;
    v_eligible INTEGER;
    v_added INTEGER := 0;
    v_removed INTEGER := 0;
    v_count INTEGER;
    v_advanced JSONB := '[]'::JSONB;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
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
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_identity_catalog_internal_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'identity_group.manage', v_now
    );
    SELECT revision.network_revision INTO v_revision FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id
    FOR UPDATE;
    IF v_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'identity catalog scope is unavailable';
    END IF;
    SELECT * INTO v_group FROM mesh.identity_group AS identity_group
    WHERE identity_group.workspace_id = v_scope.workspace_id AND identity_group.network_id = v_scope.network_id
      AND identity_group.public_id = p_group_public_id AND identity_group.state = 'active'
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
         AND (membership.expires_at IS NULL OR membership.expires_at > v_now)
        JOIN mesh.network_membership AS network_member
          ON network_member.workspace_id = v_scope.workspace_id AND network_member.network_id = v_scope.network_id
         AND network_member.principal_id = principal.id AND network_member.state = 'active'
         AND (network_member.expires_at IS NULL OR network_member.expires_at > v_now);
        IF v_eligible <> v_requested THEN
            RAISE EXCEPTION USING ERRCODE = 'MTI01', MESSAGE = 'a principal is not an active member of this Network';
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
        -- The group's Network rebuilds when its active rules take the group
        -- as source, whatever the destination: Devices, Sites or Exit Pools.
        IF mesh_ops.identity_group_rule_count_internal_v1(v_group.id) > 0 THEN
            v_advanced := mesh_ops.advance_identity_networks_internal_v1(
                v_scope.workspace_id, ARRAY[v_scope.network_id]);
            IF v_added > 0 AND mesh_ops.identity_networks_over_edge_budget_internal_v1(
                    v_scope.workspace_id, ARRAY[v_scope.network_id]) THEN
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

-- The bound Network's tag catalog (device_tag.read there).
CREATE FUNCTION mesh_ops.list_device_tags_v2(
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
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_identity_catalog_internal_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'device_tag.read', p_evaluated_at
    );
    RETURN pg_catalog.jsonb_build_object(
        'tags', COALESCE((
            SELECT pg_catalog.jsonb_agg(mesh_ops.device_tag_document_internal_v1(tag) ORDER BY tag.name)
            FROM mesh.device_tag AS tag
            WHERE tag.workspace_id = v_scope.workspace_id AND tag.network_id = v_scope.network_id
              AND tag.state = 'active'
        ), '[]'::JSONB),
        'can_manage', mesh_ops.holds_device_group_permission_internal_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, 'device_tag.manage', p_evaluated_at)
    );
END;
$function$;

-- Creates, updates (name, description, owners) or deletes a tag of the
-- bound Network (device_tag.manage there). Owners are a full replacement:
-- active Identity Groups of the same Network and built-in role keys.
-- Deleting a tag that an active release selects is refused; otherwise its
-- assignments go too and the Network advances. Errors: P0002 unknown tag,
-- 40001 stale version, MTT02 more than 200 tags in the Network, MTT03
-- unknown owner, MTT04 name taken, MTT05 tag in use.
CREATE FUNCTION mesh_ops.change_device_tag_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_operation TEXT, p_tag_public_id UUID,
    p_expected_version BIGINT, p_name TEXT, p_description TEXT, p_owner_group_ids UUID[], p_owner_roles TEXT[],
    p_owner_row_ids UUID[], p_change_public_id UUID, p_evaluated_at TIMESTAMPTZ
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
    v_revision BIGINT;
    v_tag mesh.device_tag%ROWTYPE;
    v_before JSONB;
    v_assigned BOOLEAN;
    v_advanced JSONB := '[]'::JSONB;
    v_owner_count INTEGER;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
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
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_identity_catalog_internal_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'device_tag.manage', v_now
    );
    SELECT revision.network_revision INTO v_revision FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id
    FOR UPDATE;
    IF v_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'identity catalog scope is unavailable';
    END IF;
    IF p_operation <> 'delete' THEN
        SELECT pg_catalog.count(*)::INTEGER INTO v_owner_count
        FROM pg_catalog.unnest(p_owner_group_ids) AS owner_group(id)
        JOIN mesh.identity_group AS identity_group
          ON identity_group.workspace_id = v_scope.workspace_id AND identity_group.network_id = v_scope.network_id
         AND identity_group.public_id = owner_group.id AND identity_group.state = 'active';
        IF v_owner_count <> pg_catalog.cardinality(p_owner_group_ids)
            OR EXISTS (SELECT 1 FROM pg_catalog.unnest(p_owner_roles) AS owner_role(key)
                       WHERE NOT EXISTS (SELECT 1 FROM mesh.builtin_role AS role
                                         WHERE role.role_key = owner_role.key)) THEN
            RAISE EXCEPTION USING ERRCODE = 'MTT03', MESSAGE = 'a tag owner is not in this Network';
        END IF;
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    IF p_operation = 'create' THEN
        IF (SELECT pg_catalog.count(*) FROM mesh.device_tag AS tag
            WHERE tag.workspace_id = v_scope.workspace_id AND tag.network_id = v_scope.network_id
              AND tag.state = 'active') >= 200 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTT02', MESSAGE = 'Network already has the maximum device tags';
        END IF;
        BEGIN
            INSERT INTO mesh.device_tag (
                public_id, deployment_id, workspace_id, network_id, name, description, created_at, updated_at
            ) VALUES (
                p_tag_public_id, v_scope.deployment_id, v_scope.workspace_id, v_scope.network_id, p_name,
                p_description, v_now, v_now
            ) RETURNING * INTO v_tag;
        EXCEPTION WHEN unique_violation THEN
            RAISE EXCEPTION USING ERRCODE = 'MTT04', MESSAGE = 'device tag name is taken';
        END;
    ELSE
        SELECT * INTO v_tag FROM mesh.device_tag AS tag
        WHERE tag.workspace_id = v_scope.workspace_id AND tag.network_id = v_scope.network_id
          AND tag.public_id = p_tag_public_id AND tag.state = 'active'
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
            SELECT EXISTS (SELECT 1 FROM mesh.device_tag_assignment AS assignment
                           WHERE assignment.device_tag_id = v_tag.id) INTO v_assigned;
            DELETE FROM mesh.device_tag_assignment WHERE device_tag_id = v_tag.id;
            IF v_assigned THEN
                v_advanced := mesh_ops.advance_identity_networks_internal_v1(
                    v_scope.workspace_id, ARRAY[v_scope.network_id]);
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
                  ON identity_group.workspace_id = v_scope.workspace_id
                 AND identity_group.network_id = v_scope.network_id AND identity_group.public_id = owner_group.id
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

-- change_device_tags_v1 of schema 181 for Network tags: only tags of the
-- bound Network, device_tag.manage held in that Network, and ownership by
-- device_tag_owned_by_internal_v2.
CREATE FUNCTION mesh_ops.change_device_tags_v2(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_network_public_id uuid, p_device_public_id uuid, p_add jsonb, p_remove uuid[], p_change_public_id uuid, p_evaluated_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
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
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
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
        p_workspace_public_id, p_network_public_id, 'device.read', pg_catalog.transaction_timestamp()
    ) LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'device tag assignment is not authorized';
    END IF;
    SELECT principal.id INTO v_principal FROM mesh.principal AS principal
    WHERE principal.public_id = p_principal_public_id AND principal.state = 'active';
    v_manage_any := mesh_ops.holds_device_group_permission_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'device_tag.manage', pg_catalog.transaction_timestamp());
    v_manage_devices := mesh_ops.holds_device_group_permission_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'device.manage', pg_catalog.transaction_timestamp());

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
      ON tag.workspace_id = v_workspace AND tag.network_id = v_network AND tag.public_id = requested.id
     AND tag.state = 'active';
    IF v_known <> pg_catalog.cardinality(v_requested) THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'device tag is unavailable';
    END IF;
    IF NOT v_manage_any AND (
        v_principal IS NULL
        OR (v_device.owner_principal_id <> v_principal AND NOT v_manage_devices)
        OR EXISTS (
            SELECT 1 FROM pg_catalog.unnest(v_requested) AS requested(id)
            JOIN mesh.device_tag AS tag
              ON tag.workspace_id = v_workspace AND tag.network_id = v_network
             AND tag.public_id = requested.id
            WHERE NOT mesh_ops.device_tag_owned_by_internal_v2(tag.id, v_workspace, v_network, v_principal, v_now)
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
        JOIN mesh.device_tag AS tag
          ON tag.workspace_id = v_workspace AND tag.network_id = v_network AND tag.public_id = item.tag_id
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

-- read_network_tag_options_v1 of schema 124 for Network tags: the bound
-- Network's tags only, with device_tag.manage held in that Network.
CREATE FUNCTION mesh_ops.read_network_tag_options_v2(
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
    v_principal BIGINT;
    v_manage_any BOOLEAN;
    v_manage_devices BOOLEAN;
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL OR p_evaluated_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Network scope is unavailable';
    END IF;
    PERFORM 1 FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'device.read', p_evaluated_at
    );
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'tag options are not readable';
    END IF;
    SELECT principal.id INTO v_principal FROM mesh.principal AS principal
    WHERE principal.public_id = p_principal_public_id AND principal.state = 'active';
    IF v_principal IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'tag options are not readable';
    END IF;
    v_manage_any := mesh_ops.holds_device_group_permission_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'device_tag.manage', p_evaluated_at);
    v_manage_devices := mesh_ops.holds_device_group_permission_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'device.manage', p_evaluated_at);

    RETURN pg_catalog.jsonb_build_object(
        'tags', COALESCE((
            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                       'tag_id', option.public_id, 'name', option.name,
                       'description', option.description, 'apply', option.apply
                   ) ORDER BY option.name)
            FROM (
                SELECT tag.public_id, tag.name, tag.description,
                       CASE
                           WHEN v_manage_any THEN 'any_device'
                           WHEN owned.value AND v_manage_devices THEN 'any_device'
                           WHEN owned.value THEN 'own_devices'
                           ELSE 'none'
                       END AS apply,
                       EXISTS (
                           SELECT 1 FROM mesh.device_tag_assignment AS assignment
                           WHERE assignment.workspace_id = v_workspace
                             AND assignment.network_id = v_network
                             AND assignment.device_tag_id = tag.id
                       ) AS assigned
                FROM mesh.device_tag AS tag
                CROSS JOIN LATERAL (
                    SELECT mesh_ops.device_tag_owned_by_internal_v2(
                        tag.id, v_workspace, v_network, v_principal, p_evaluated_at) AS value
                ) AS owned
                WHERE tag.workspace_id = v_workspace AND tag.network_id = v_network AND tag.state = 'active'
            ) AS option
            WHERE option.apply <> 'none' OR option.assigned
        ), '[]'::JSONB),
        'owned_device_ids', COALESCE((
            SELECT pg_catalog.jsonb_agg(owned_device.public_id ORDER BY owned_device.public_id)
            FROM (
                SELECT device.public_id FROM mesh.device AS device
                WHERE device.workspace_id = v_workspace AND device.network_id = v_network
                  AND device.owner_principal_id = v_principal AND device.state = 'active'
                  AND device.deleted_at IS NULL AND device.expires_at > p_evaluated_at
                ORDER BY device.public_id
                LIMIT 1000
            ) AS owned_device
        ), '[]'::JSONB)
    );
END;
$function$;

-- Schema 228: a group selects only as a group of the Network, and only the
-- Devices of owners who are active members of that Network.
CREATE OR REPLACE FUNCTION mesh_ops.selector_devices_internal_v1(p_workspace_id BIGINT, p_network_id BIGINT)
RETURNS TABLE (selector_kind TEXT, selector_id BIGINT, device_id BIGINT)
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT 'device_group', member.device_group_id, member.device_id
    FROM mesh.device_group_member AS member
    JOIN mesh.device_group AS device_group ON device_group.id = member.device_group_id AND device_group.state = 'active'
    WHERE member.workspace_id = p_workspace_id AND member.network_id = p_network_id
    UNION ALL
    SELECT 'identity_group', member.identity_group_id, device.id
    FROM mesh.identity_group_member AS member
    JOIN mesh.identity_group AS identity_group
      ON identity_group.id = member.identity_group_id AND identity_group.state = 'active' AND identity_group.network_id = p_network_id
    JOIN mesh.principal AS principal
      ON principal.id = member.principal_id AND principal.state = 'active' AND principal.deleted_at IS NULL
    JOIN mesh.workspace_membership AS membership
      ON membership.workspace_id = p_workspace_id AND membership.principal_id = principal.id
     AND membership.state = 'active'
     AND (membership.expires_at IS NULL OR membership.expires_at > pg_catalog.transaction_timestamp())
    JOIN mesh.network_membership AS network_member
      ON network_member.workspace_id = p_workspace_id AND network_member.network_id = p_network_id
     AND network_member.principal_id = principal.id AND network_member.state = 'active'
     AND (network_member.expires_at IS NULL OR network_member.expires_at > pg_catalog.transaction_timestamp())
    JOIN mesh.device AS device
      ON device.workspace_id = p_workspace_id AND device.network_id = p_network_id
     AND device.owner_principal_id = principal.id
    WHERE member.workspace_id = p_workspace_id
      AND NOT EXISTS (
          SELECT 1 FROM mesh.device_tag_assignment AS assignment WHERE assignment.device_id = device.id
      )
    UNION ALL
    SELECT 'device_tag', assignment.device_tag_id, assignment.device_id
    FROM mesh.device_tag_assignment AS assignment
    JOIN mesh.device_tag AS tag ON tag.id = assignment.device_tag_id AND tag.state = 'active'
    WHERE assignment.workspace_id = p_workspace_id AND assignment.network_id = p_network_id
$function$;

-- Schema 228: as selector_devices_internal_v1; a member's deadline is the
-- earlier of their Workspace and Network membership expiry.
CREATE OR REPLACE FUNCTION mesh_ops.load_map_network_selector_members_v1(p_limit INTEGER)
RETURNS TABLE (selector_kind TEXT, selector_id BIGINT, device_id BIGINT, valid_until TIMESTAMPTZ)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT := mesh_ops.current_workspace_id();
    scoped_network_id BIGINT := mesh_ops.current_network_id();
BEGIN
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 10000001 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'map network selector request is invalid';
    END IF;
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network selector scope is unavailable';
    END IF;

    RETURN QUERY
    SELECT members.selector_kind, members.selector_id, members.device_id, members.valid_until
    FROM (
        SELECT 'device_group'::TEXT AS selector_kind, member.device_group_id AS selector_id,
               member.device_id, NULL::TIMESTAMPTZ AS valid_until
        FROM mesh.device_group_member AS member
        JOIN mesh.device_group AS device_group
          ON device_group.id = member.device_group_id AND device_group.state = 'active'
        WHERE member.workspace_id = scoped_workspace_id AND member.network_id = scoped_network_id
        UNION ALL
        SELECT 'identity_group'::TEXT, member.identity_group_id, device.id,
               LEAST(membership.expires_at, network_member.expires_at)
        FROM mesh.identity_group_member AS member
        JOIN mesh.identity_group AS identity_group
          ON identity_group.id = member.identity_group_id AND identity_group.state = 'active' AND identity_group.network_id = scoped_network_id
        JOIN mesh.principal AS principal
          ON principal.id = member.principal_id AND principal.state = 'active' AND principal.deleted_at IS NULL
        JOIN mesh.workspace_membership AS membership
          ON membership.workspace_id = scoped_workspace_id AND membership.principal_id = principal.id
         AND membership.state = 'active'
         AND (membership.expires_at IS NULL OR membership.expires_at > pg_catalog.transaction_timestamp())
        JOIN mesh.network_membership AS network_member
          ON network_member.workspace_id = scoped_workspace_id AND network_member.network_id = scoped_network_id
         AND network_member.principal_id = principal.id AND network_member.state = 'active'
         AND (network_member.expires_at IS NULL OR network_member.expires_at > pg_catalog.transaction_timestamp())
        JOIN mesh.device AS device
          ON device.workspace_id = scoped_workspace_id AND device.network_id = scoped_network_id
         AND device.owner_principal_id = principal.id
        WHERE member.workspace_id = scoped_workspace_id
          AND NOT EXISTS (
              SELECT 1 FROM mesh.device_tag_assignment AS assignment WHERE assignment.device_id = device.id
          )
        UNION ALL
        SELECT 'device_tag'::TEXT, assignment.device_tag_id, assignment.device_id, NULL::TIMESTAMPTZ
        FROM mesh.device_tag_assignment AS assignment
        JOIN mesh.device_tag AS tag ON tag.id = assignment.device_tag_id AND tag.state = 'active'
        WHERE assignment.workspace_id = scoped_workspace_id AND assignment.network_id = scoped_network_id
    ) AS members
    ORDER BY members.selector_kind, members.selector_id, members.device_id
    LIMIT p_limit;
END;
$function$;

-- Schema 228: the Device's groups as selector_devices_internal_v1 counts them.
CREATE OR REPLACE FUNCTION mesh_ops.read_access_graph_v3(
    p_session_public_id UUID,
    p_deployment_public_id UUID,
    p_principal_public_id UUID,
    p_identity_subject_public_id UUID,
    p_session_version BIGINT,
    p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT,
    p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID,
    p_network_public_id UUID,
    p_device_public_id UUID,
    p_protocol TEXT,
    p_after_projection_public_id UUID,
    p_page_size INTEGER,
    p_evaluated_at TIMESTAMPTZ
)
RETURNS TABLE (
    network_revision BIGINT,
    inventory_revision BIGINT,
    group_revision BIGINT,
    policy_revision BIGINT,
    dns_revision BIGINT,
    route_revision BIGINT,
    sharing_revision BIGINT,
    isolation_generation BIGINT,
    has_active_release BOOLEAN,
    release_public_id UUID,
    compiler_format_version INTEGER,
    release_semantic_hash BYTEA,
    matching_paths INTEGER,
    has_more BOOLEAN,
    paths JSONB,
    nodes JSONB
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    scoped_workspace BIGINT := mesh_ops.current_workspace_id();
    scoped_network BIGINT := mesh_ops.current_network_id();
    base RECORD;
    v_release_id BIGINT;
    v_device_id BIGINT;
    v_owner BIGINT;
    v_device_groups BIGINT[] := '{}';
    v_identity_groups BIGINT[] := '{}';
    v_tags BIGINT[] := '{}';
    v_tagged BOOLEAN := FALSE;
    v_site_edges BIGINT;
    v_site_matching INTEGER := 0;
    v_site_paths JSONB := '[]'::JSONB;
    v_paths JSONB;
    v_nodes JSONB;
    v_names BOOLEAN;
BEGIN
    -- v2 validates the input, the exact Network scope and policy.read and
    -- device.read authority, and raises on any failure.
    SELECT value.* INTO base
    FROM mesh_ops.read_access_graph_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_device_public_id, p_protocol,
        p_after_projection_public_id, p_page_size, p_evaluated_at
    ) AS value;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Access Graph Network scope is unavailable';
    END IF;
    IF NOT base.has_active_release THEN
        RETURN QUERY SELECT base.*;
        RETURN;
    END IF;

    SELECT release.id INTO v_release_id
    FROM mesh.policy_release AS release
    WHERE release.workspace_id = scoped_workspace AND release.network_id = scoped_network
      AND release.public_id = base.release_public_id AND release.state = 'active';
    IF v_release_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Access Graph release changed during the read';
    END IF;

    IF p_device_public_id IS NOT NULL THEN
        SELECT device.id, device.owner_principal_id INTO v_device_id, v_owner
        FROM mesh.device AS device
        WHERE device.workspace_id = scoped_workspace AND device.network_id = scoped_network
          AND device.public_id = p_device_public_id;
        v_device_id := COALESCE(v_device_id, -1);
        SELECT COALESCE(pg_catalog.array_agg(member.device_group_id), '{}') INTO v_device_groups
        FROM mesh.device_group_member AS member
        JOIN mesh.device_group AS device_group
          ON device_group.id = member.device_group_id AND device_group.state = 'active'
        WHERE member.workspace_id = scoped_workspace AND member.network_id = scoped_network
          AND member.device_id = v_device_id;
        SELECT COALESCE(pg_catalog.array_agg(assignment.device_tag_id) FILTER (WHERE tag.state = 'active'), '{}'),
               pg_catalog.count(*) > 0
        INTO v_tags, v_tagged
        FROM mesh.device_tag_assignment AS assignment
        JOIN mesh.device_tag AS tag ON tag.id = assignment.device_tag_id
        WHERE assignment.device_id = v_device_id;
        IF NOT v_tagged AND v_owner IS NOT NULL THEN
            SELECT COALESCE(pg_catalog.array_agg(member.identity_group_id), '{}') INTO v_identity_groups
            FROM mesh.identity_group_member AS member
            JOIN mesh.identity_group AS identity_group
              ON identity_group.id = member.identity_group_id AND identity_group.state = 'active' AND identity_group.network_id = scoped_network
            JOIN mesh.principal AS principal
              ON principal.id = member.principal_id AND principal.state = 'active' AND principal.deleted_at IS NULL
            JOIN mesh.workspace_membership AS membership
              ON membership.workspace_id = scoped_workspace AND membership.principal_id = principal.id
             AND membership.state = 'active'
             AND (membership.expires_at IS NULL OR membership.expires_at > pg_catalog.transaction_timestamp())
            JOIN mesh.network_membership AS network_member
              ON network_member.workspace_id = scoped_workspace AND network_member.network_id = scoped_network
             AND network_member.principal_id = principal.id AND network_member.state = 'active'
             AND (network_member.expires_at IS NULL OR network_member.expires_at > pg_catalog.transaction_timestamp())
            WHERE member.workspace_id = scoped_workspace AND member.principal_id = v_owner;
        END IF;
    ELSE
        SELECT pg_catalog.count(*) INTO v_site_edges
        FROM (
            SELECT 1 FROM mesh_ops.site_graph_edges_internal_v1(
                scoped_workspace, scoped_network, v_release_id, NULL, '{}', '{}', '{}')
            LIMIT 100001
        ) AS capped;
        IF v_site_edges > 100000 THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MTA01',
                MESSAGE = 'Rules to Sites expand to too many connections to list; choose a Device';
        END IF;
    END IF;

    WITH site_edge AS (
        SELECT (
                SELECT pg_catalog.encode(
                    pg_catalog.set_byte(pg_catalog.set_byte(digest.value,
                        6, (pg_catalog.get_byte(digest.value, 6) & 15) | 112),
                        8, (pg_catalog.get_byte(digest.value, 8) & 63) | 128),
                    'hex')::UUID
                FROM (
                    SELECT pg_catalog.substr(pg_catalog.sha256(pg_catalog.convert_to(
                        'site:' || rule.public_id::TEXT || ':' || source.public_id::TEXT, 'UTF8')), 1, 16) AS value
                ) AS digest
            ) AS projection_id,
            rule.access_rule_public_id AS rule_id,
            source.public_id AS source_id,
            rule.protocol,
            rule.destination_ports,
            rule.prefixes,
            network_site.public_id AS site_id,
            CASE edge.source_selector_kind WHEN 'device_group' THEN device_group.public_id END AS device_group_id,
            CASE edge.source_selector_kind WHEN 'identity_group' THEN identity_group.public_id END
                AS identity_group_id,
            CASE edge.source_selector_kind WHEN 'device_tag' THEN device_tag.public_id END AS tag_id
        FROM mesh_ops.site_graph_edges_internal_v1(
            scoped_workspace, scoped_network, v_release_id, v_device_id,
            v_device_groups, v_identity_groups, v_tags) AS edge
        JOIN mesh.compiled_policy_route_rule AS rule ON rule.id = edge.route_rule_id
        JOIN mesh.network_site AS network_site
          ON network_site.id = rule.destination_site_id AND network_site.state = 'active'
        JOIN mesh.device AS source
          ON source.workspace_id = scoped_workspace AND source.network_id = scoped_network
         AND source.id = edge.source_device_id
        LEFT JOIN mesh.device_group AS device_group ON device_group.id = rule.source_device_group_id
        LEFT JOIN mesh.identity_group AS identity_group ON identity_group.id = rule.source_identity_group_id
        LEFT JOIN mesh.device_tag AS device_tag ON device_tag.id = rule.source_device_tag_id
    ),
    matching AS (
        SELECT site_edge.* FROM site_edge WHERE p_protocol IS NULL OR site_edge.protocol = p_protocol
    ),
    page AS (
        SELECT matching.* FROM matching
        WHERE p_after_projection_public_id IS NULL OR matching.projection_id > p_after_projection_public_id
        ORDER BY matching.projection_id
        LIMIT p_page_size + 1
    )
    SELECT (SELECT pg_catalog.count(*)::INTEGER FROM matching),
        COALESCE((
            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
                'projection_id', page.projection_id,
                'access_rule_id', page.rule_id,
                'source_device_id', page.source_id,
                'protocol', page.protocol,
                'destination_port_range_first', ARRAY(
                    SELECT pg_catalog.lower(port_range)::INTEGER
                    FROM pg_catalog.unnest(page.destination_ports) AS port_range
                    ORDER BY pg_catalog.lower(port_range)),
                'destination_port_range_last', ARRAY(
                    SELECT (pg_catalog.upper(port_range) - 1)::INTEGER
                    FROM pg_catalog.unnest(page.destination_ports) AS port_range
                    ORDER BY pg_catalog.lower(port_range)),
                'selector_kind', 'site',
                'destination_site_id', page.site_id,
                'destination_prefixes', ARRAY(
                    SELECT prefix::TEXT FROM pg_catalog.unnest(page.prefixes) AS prefix ORDER BY prefix),
                'source_device_group_id', page.device_group_id,
                'source_identity_group_id', page.identity_group_id,
                'source_device_tag_id', page.tag_id
            )) ORDER BY page.projection_id)
            FROM page
        ), '[]'::JSONB)
    INTO v_site_matching, v_site_paths;

    -- The first page of both streams, in projection order.
    SELECT COALESCE(pg_catalog.jsonb_agg(kept.value ORDER BY kept.projection_id), '[]'::JSONB)
    INTO v_paths
    FROM (
        SELECT merged.value, (merged.value ->> 'projection_id')::UUID AS projection_id
        FROM (
            SELECT value FROM pg_catalog.jsonb_array_elements(base.paths) AS value
            UNION ALL
            SELECT value FROM pg_catalog.jsonb_array_elements(v_site_paths) AS value
        ) AS merged
        ORDER BY (merged.value ->> 'projection_id')::UUID
        LIMIT p_page_size
    ) AS kept;

    PERFORM permission.role_binding_public_id
    FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'route.read', p_evaluated_at
    ) AS permission;
    v_names := FOUND;

    -- The nodes the kept edges connect: v2's nodes still in use, the source
    -- Devices only Site edges name, and the Sites.
    WITH node_key AS (
        SELECT 'device'::TEXT AS kind, (path.value ->> 'source_device_id')::UUID AS id
        FROM pg_catalog.jsonb_array_elements(v_paths) AS path
        UNION
        SELECT 'device', (path.value ->> 'destination_device_id')::UUID
        FROM pg_catalog.jsonb_array_elements(v_paths) AS path
        WHERE path.value ->> 'selector_kind' = 'device'
        UNION
        SELECT 'resource', (path.value ->> 'destination_resource_id')::UUID
        FROM pg_catalog.jsonb_array_elements(v_paths) AS path
        WHERE path.value ->> 'selector_kind' IN ('resource', 'resource_group')
        UNION
        SELECT 'imported_resource', (path.value ->> 'destination_imported_resource_id')::UUID
        FROM pg_catalog.jsonb_array_elements(v_paths) AS path
        WHERE path.value ->> 'selector_kind' = 'imported_resource'
        UNION
        SELECT 'site', (path.value ->> 'destination_site_id')::UUID
        FROM pg_catalog.jsonb_array_elements(v_paths) AS path
        WHERE path.value ->> 'selector_kind' = 'site'
    ),
    kept_node AS (
        SELECT node.value,
               CASE node.value ->> 'kind' WHEN 'device' THEN 1 WHEN 'resource' THEN 2 ELSE 3 END AS kind_order,
               (node.value ->> 'id')::UUID AS sort_id
        FROM pg_catalog.jsonb_array_elements(base.nodes) AS node
        JOIN node_key ON node_key.kind = node.value ->> 'kind' AND node_key.id = (node.value ->> 'id')::UUID
    ),
    added_device AS (
        SELECT pg_catalog.jsonb_build_object(
                'kind', 'device', 'id', device.public_id, 'name', device.hostname,
                'state', CASE
                    WHEN device.state = 'active' AND device.deleted_at IS NULL
                        AND device.expires_at > p_evaluated_at THEN 'active'
                    ELSE 'inactive'
                END,
                'share', NULL
            ) AS value, 1 AS kind_order, device.public_id AS sort_id
        FROM node_key
        JOIN mesh.device AS device
          ON device.workspace_id = scoped_workspace AND device.network_id = scoped_network
         AND device.public_id = node_key.id
        WHERE node_key.kind = 'device'
          AND NOT EXISTS (SELECT 1 FROM kept_node WHERE kept_node.value ->> 'kind' = 'device'
                          AND kept_node.sort_id = node_key.id)
    ),
    site_node AS (
        SELECT pg_catalog.jsonb_build_object(
                'kind', 'site', 'id', network_site.public_id,
                'name', CASE WHEN v_names THEN network_site.name END,
                'state', CASE WHEN network_site.state = 'active' THEN 'active' ELSE 'inactive' END,
                'share', NULL
            ) AS value, 4 AS kind_order, network_site.public_id AS sort_id
        FROM node_key
        JOIN mesh.network_site AS network_site
          ON network_site.workspace_id = scoped_workspace AND network_site.network_id = scoped_network
         AND network_site.public_id = node_key.id
        WHERE node_key.kind = 'site'
    )
    SELECT COALESCE(pg_catalog.jsonb_agg(node.value ORDER BY node.kind_order, node.sort_id), '[]'::JSONB)
    INTO v_nodes
    FROM (
        SELECT value, kind_order, sort_id FROM kept_node
        UNION ALL SELECT value, kind_order, sort_id FROM added_device
        UNION ALL SELECT value, kind_order, sort_id FROM site_node
    ) AS node;

    RETURN QUERY SELECT base.network_revision, base.inventory_revision, base.group_revision,
        base.policy_revision, base.dns_revision, base.route_revision, base.sharing_revision,
        base.isolation_generation, base.has_active_release, base.release_public_id,
        base.compiler_format_version, base.release_semantic_hash,
        base.matching_paths + v_site_matching,
        pg_catalog.jsonb_array_length(base.paths) + pg_catalog.jsonb_array_length(v_site_paths) > p_page_size
            OR base.has_more,
        v_paths, v_nodes;
END;
$function$;

-- Schema 228: the Device's groups as selector_devices_internal_v1 counts them.
CREATE OR REPLACE FUNCTION mesh_ops.read_access_graph_v4(
    p_session_public_id UUID,
    p_deployment_public_id UUID,
    p_principal_public_id UUID,
    p_identity_subject_public_id UUID,
    p_session_version BIGINT,
    p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT,
    p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID,
    p_network_public_id UUID,
    p_device_public_id UUID,
    p_protocol TEXT,
    p_after_projection_public_id UUID,
    p_page_size INTEGER,
    p_evaluated_at TIMESTAMPTZ
)
RETURNS TABLE (
    network_revision BIGINT,
    inventory_revision BIGINT,
    group_revision BIGINT,
    policy_revision BIGINT,
    dns_revision BIGINT,
    route_revision BIGINT,
    sharing_revision BIGINT,
    isolation_generation BIGINT,
    has_active_release BOOLEAN,
    release_public_id UUID,
    compiler_format_version INTEGER,
    release_semantic_hash BYTEA,
    matching_paths INTEGER,
    has_more BOOLEAN,
    paths JSONB,
    nodes JSONB
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    scoped_workspace BIGINT := mesh_ops.current_workspace_id();
    scoped_network BIGINT := mesh_ops.current_network_id();
    base RECORD;
    v_release_id BIGINT;
    v_device_id BIGINT;
    v_owner BIGINT;
    v_device_groups BIGINT[] := '{}';
    v_identity_groups BIGINT[] := '{}';
    v_tags BIGINT[] := '{}';
    v_tagged BOOLEAN := FALSE;
    v_exit_edges BIGINT;
    v_exit_matching INTEGER := 0;
    v_exit_paths JSONB := '[]'::JSONB;
    v_paths JSONB;
    v_nodes JSONB;
    v_names BOOLEAN;
BEGIN
    -- v3 validates the input, the exact Network scope and policy.read and
    -- device.read authority, and raises on any failure.
    SELECT value.* INTO base
    FROM mesh_ops.read_access_graph_v3(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_device_public_id, p_protocol,
        p_after_projection_public_id, p_page_size, p_evaluated_at
    ) AS value;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Access Graph Network scope is unavailable';
    END IF;
    IF NOT base.has_active_release THEN
        RETURN QUERY SELECT base.*;
        RETURN;
    END IF;

    SELECT release.id INTO v_release_id
    FROM mesh.policy_release AS release
    WHERE release.workspace_id = scoped_workspace AND release.network_id = scoped_network
      AND release.public_id = base.release_public_id AND release.state = 'active';
    IF v_release_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Access Graph release changed during the read';
    END IF;

    IF p_device_public_id IS NOT NULL THEN
        SELECT device.id, device.owner_principal_id INTO v_device_id, v_owner
        FROM mesh.device AS device
        WHERE device.workspace_id = scoped_workspace AND device.network_id = scoped_network
          AND device.public_id = p_device_public_id;
        v_device_id := COALESCE(v_device_id, -1);
        SELECT COALESCE(pg_catalog.array_agg(member.device_group_id), '{}') INTO v_device_groups
        FROM mesh.device_group_member AS member
        JOIN mesh.device_group AS device_group
          ON device_group.id = member.device_group_id AND device_group.state = 'active'
        WHERE member.workspace_id = scoped_workspace AND member.network_id = scoped_network
          AND member.device_id = v_device_id;
        SELECT COALESCE(pg_catalog.array_agg(assignment.device_tag_id) FILTER (WHERE tag.state = 'active'), '{}'),
               pg_catalog.count(*) > 0
        INTO v_tags, v_tagged
        FROM mesh.device_tag_assignment AS assignment
        JOIN mesh.device_tag AS tag ON tag.id = assignment.device_tag_id
        WHERE assignment.device_id = v_device_id;
        IF NOT v_tagged AND v_owner IS NOT NULL THEN
            SELECT COALESCE(pg_catalog.array_agg(member.identity_group_id), '{}') INTO v_identity_groups
            FROM mesh.identity_group_member AS member
            JOIN mesh.identity_group AS identity_group
              ON identity_group.id = member.identity_group_id AND identity_group.state = 'active' AND identity_group.network_id = scoped_network
            JOIN mesh.principal AS principal
              ON principal.id = member.principal_id AND principal.state = 'active' AND principal.deleted_at IS NULL
            JOIN mesh.workspace_membership AS membership
              ON membership.workspace_id = scoped_workspace AND membership.principal_id = principal.id
             AND membership.state = 'active'
             AND (membership.expires_at IS NULL OR membership.expires_at > pg_catalog.transaction_timestamp())
            JOIN mesh.network_membership AS network_member
              ON network_member.workspace_id = scoped_workspace AND network_member.network_id = scoped_network
             AND network_member.principal_id = principal.id AND network_member.state = 'active'
             AND (network_member.expires_at IS NULL OR network_member.expires_at > pg_catalog.transaction_timestamp())
            WHERE member.workspace_id = scoped_workspace AND member.principal_id = v_owner;
        END IF;
    ELSE
        SELECT pg_catalog.count(*) INTO v_exit_edges
        FROM (
            SELECT 1 FROM mesh_ops.exit_graph_edges_internal_v1(
                scoped_workspace, scoped_network, v_release_id, NULL, '{}', '{}', '{}')
            LIMIT 100001
        ) AS capped;
        IF v_exit_edges > 100000 THEN
            RAISE EXCEPTION USING
                ERRCODE = 'MTA01',
                MESSAGE = 'Rules to Exit Pools expand to too many connections to list; choose a Device';
        END IF;
    END IF;

    WITH exit_edge AS (
        SELECT (
                SELECT pg_catalog.encode(
                    pg_catalog.set_byte(pg_catalog.set_byte(digest.value,
                        6, (pg_catalog.get_byte(digest.value, 6) & 15) | 112),
                        8, (pg_catalog.get_byte(digest.value, 8) & 63) | 128),
                    'hex')::UUID
                FROM (
                    SELECT pg_catalog.substr(pg_catalog.sha256(pg_catalog.convert_to(
                        'exit:' || rule.public_id::TEXT || ':' || source.public_id::TEXT, 'UTF8')), 1, 16) AS value
                ) AS digest
            ) AS projection_id,
            rule.access_rule_public_id AS rule_id,
            source.public_id AS source_id,
            rule.protocol,
            rule.destination_ports,
            exit_pool.public_id AS pool_id,
            CASE edge.source_selector_kind WHEN 'device_group' THEN device_group.public_id END AS device_group_id,
            CASE edge.source_selector_kind WHEN 'identity_group' THEN identity_group.public_id END
                AS identity_group_id,
            CASE edge.source_selector_kind WHEN 'device_tag' THEN device_tag.public_id END AS tag_id
        FROM mesh_ops.exit_graph_edges_internal_v1(
            scoped_workspace, scoped_network, v_release_id, v_device_id,
            v_device_groups, v_identity_groups, v_tags) AS edge
        JOIN mesh.compiled_policy_exit_rule AS rule ON rule.id = edge.exit_rule_id
        JOIN mesh.network_exit_pool AS exit_pool
          ON exit_pool.id = rule.destination_exit_pool_id AND exit_pool.state = 'active'
        JOIN mesh.device AS source
          ON source.workspace_id = scoped_workspace AND source.network_id = scoped_network
         AND source.id = edge.source_device_id
        LEFT JOIN mesh.device_group AS device_group ON device_group.id = rule.source_device_group_id
        LEFT JOIN mesh.identity_group AS identity_group ON identity_group.id = rule.source_identity_group_id
        LEFT JOIN mesh.device_tag AS device_tag ON device_tag.id = rule.source_device_tag_id
    ),
    matching AS (
        SELECT exit_edge.* FROM exit_edge WHERE p_protocol IS NULL OR exit_edge.protocol = p_protocol
    ),
    page AS (
        SELECT matching.* FROM matching
        WHERE p_after_projection_public_id IS NULL OR matching.projection_id > p_after_projection_public_id
        ORDER BY matching.projection_id
        LIMIT p_page_size + 1
    )
    SELECT (SELECT pg_catalog.count(*)::INTEGER FROM matching),
        COALESCE((
            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
                'projection_id', page.projection_id,
                'access_rule_id', page.rule_id,
                'source_device_id', page.source_id,
                'protocol', page.protocol,
                'destination_port_range_first', ARRAY(
                    SELECT pg_catalog.lower(port_range)::INTEGER
                    FROM pg_catalog.unnest(page.destination_ports) AS port_range
                    ORDER BY pg_catalog.lower(port_range)),
                'destination_port_range_last', ARRAY(
                    SELECT (pg_catalog.upper(port_range) - 1)::INTEGER
                    FROM pg_catalog.unnest(page.destination_ports) AS port_range
                    ORDER BY pg_catalog.lower(port_range)),
                'selector_kind', 'exit_pool',
                'destination_exit_pool_id', page.pool_id,
                'source_device_group_id', page.device_group_id,
                'source_identity_group_id', page.identity_group_id,
                'source_device_tag_id', page.tag_id
            )) ORDER BY page.projection_id)
            FROM page
        ), '[]'::JSONB)
    INTO v_exit_matching, v_exit_paths;

    -- The first page of both streams, in projection order.
    SELECT COALESCE(pg_catalog.jsonb_agg(kept.value ORDER BY kept.projection_id), '[]'::JSONB)
    INTO v_paths
    FROM (
        SELECT merged.value, (merged.value ->> 'projection_id')::UUID AS projection_id
        FROM (
            SELECT value FROM pg_catalog.jsonb_array_elements(base.paths) AS value
            UNION ALL
            SELECT value FROM pg_catalog.jsonb_array_elements(v_exit_paths) AS value
        ) AS merged
        ORDER BY (merged.value ->> 'projection_id')::UUID
        LIMIT p_page_size
    ) AS kept;

    PERFORM permission.role_binding_public_id
    FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'route.read', p_evaluated_at
    ) AS permission;
    v_names := FOUND;

    -- The nodes the kept edges connect: v3's nodes still in use, the source
    -- Devices only exit edges name, and the Exit Pools.
    WITH node_key AS (
        SELECT 'device'::TEXT AS kind, (path.value ->> 'source_device_id')::UUID AS id
        FROM pg_catalog.jsonb_array_elements(v_paths) AS path
        UNION
        SELECT 'device', (path.value ->> 'destination_device_id')::UUID
        FROM pg_catalog.jsonb_array_elements(v_paths) AS path
        WHERE path.value ->> 'selector_kind' = 'device'
        UNION
        SELECT 'resource', (path.value ->> 'destination_resource_id')::UUID
        FROM pg_catalog.jsonb_array_elements(v_paths) AS path
        WHERE path.value ->> 'selector_kind' IN ('resource', 'resource_group')
        UNION
        SELECT 'imported_resource', (path.value ->> 'destination_imported_resource_id')::UUID
        FROM pg_catalog.jsonb_array_elements(v_paths) AS path
        WHERE path.value ->> 'selector_kind' = 'imported_resource'
        UNION
        SELECT 'site', (path.value ->> 'destination_site_id')::UUID
        FROM pg_catalog.jsonb_array_elements(v_paths) AS path
        WHERE path.value ->> 'selector_kind' = 'site'
        UNION
        SELECT 'exit_pool', (path.value ->> 'destination_exit_pool_id')::UUID
        FROM pg_catalog.jsonb_array_elements(v_paths) AS path
        WHERE path.value ->> 'selector_kind' = 'exit_pool'
    ),
    kept_node AS (
        SELECT node.value,
               CASE node.value ->> 'kind' WHEN 'device' THEN 1 WHEN 'resource' THEN 2
                   WHEN 'imported_resource' THEN 3 ELSE 4 END AS kind_order,
               (node.value ->> 'id')::UUID AS sort_id
        FROM pg_catalog.jsonb_array_elements(base.nodes) AS node
        JOIN node_key ON node_key.kind = node.value ->> 'kind' AND node_key.id = (node.value ->> 'id')::UUID
    ),
    added_device AS (
        SELECT pg_catalog.jsonb_build_object(
                'kind', 'device', 'id', device.public_id, 'name', device.hostname,
                'state', CASE
                    WHEN device.state = 'active' AND device.deleted_at IS NULL
                        AND device.expires_at > p_evaluated_at THEN 'active'
                    ELSE 'inactive'
                END,
                'share', NULL
            ) AS value, 1 AS kind_order, device.public_id AS sort_id
        FROM node_key
        JOIN mesh.device AS device
          ON device.workspace_id = scoped_workspace AND device.network_id = scoped_network
         AND device.public_id = node_key.id
        WHERE node_key.kind = 'device'
          AND NOT EXISTS (SELECT 1 FROM kept_node WHERE kept_node.value ->> 'kind' = 'device'
                          AND kept_node.sort_id = node_key.id)
    ),
    pool_node AS (
        SELECT pg_catalog.jsonb_build_object(
                'kind', 'exit_pool', 'id', exit_pool.public_id,
                'name', CASE WHEN v_names THEN exit_pool.name END,
                'state', CASE WHEN exit_pool.state = 'active' THEN 'active' ELSE 'inactive' END,
                'share', NULL
            ) AS value, 5 AS kind_order, exit_pool.public_id AS sort_id
        FROM node_key
        JOIN mesh.network_exit_pool AS exit_pool
          ON exit_pool.workspace_id = scoped_workspace AND exit_pool.network_id = scoped_network
         AND exit_pool.public_id = node_key.id
        WHERE node_key.kind = 'exit_pool'
    )
    SELECT COALESCE(pg_catalog.jsonb_agg(node.value ORDER BY node.kind_order, node.sort_id), '[]'::JSONB)
    INTO v_nodes
    FROM (
        SELECT value, kind_order, sort_id FROM kept_node
        UNION ALL SELECT value, kind_order, sort_id FROM added_device
        UNION ALL SELECT value, kind_order, sort_id FROM pool_node
    ) AS node;

    RETURN QUERY SELECT base.network_revision, base.inventory_revision, base.group_revision,
        base.policy_revision, base.dns_revision, base.route_revision, base.sharing_revision,
        base.isolation_generation, base.has_active_release, base.release_public_id,
        base.compiler_format_version, base.release_semantic_hash,
        base.matching_paths + v_exit_matching,
        pg_catalog.jsonb_array_length(base.paths) + pg_catalog.jsonb_array_length(v_exit_paths) > p_page_size
            OR base.has_more,
        v_paths, v_nodes;
END;
$function$;

-- Schema 228: the source's groups as selector_devices_internal_v1 counts them.
CREATE OR REPLACE FUNCTION mesh_ops.explain_address_access_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID,
    p_source_device_public_id UUID, p_destination_address INET,
    p_protocol TEXT, p_destination_port INTEGER, p_evaluated_at TIMESTAMPTZ, p_path_limit INTEGER
)
RETURNS TABLE (
    network_revision BIGINT, inventory_revision BIGINT, group_revision BIGINT,
    policy_revision BIGINT, dns_revision BIGINT, route_revision BIGINT,
    sharing_revision BIGINT, isolation_generation BIGINT,
    has_active_release BOOLEAN, release_public_id UUID,
    compiler_format_version INTEGER, release_semantic_hash BYTEA,
    target_public_id UUID, paths JSONB, context JSONB
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    scoped_workspace BIGINT := mesh_ops.current_workspace_id();
    scoped_network BIGINT := mesh_ops.current_network_id();
    scoped_workspace_public_id UUID;
    scoped_network_public_id UUID;
    revision RECORD;
    v_release_id BIGINT;
    v_release_public_id UUID;
    v_compiler_format_version INTEGER;
    v_semantic_hash BYTEA;
    v_source_id BIGINT;
    v_source_owner BIGINT;
    source_name TEXT;
    source_state TEXT;
    v_device_groups BIGINT[] := '{}';
    v_identity_groups BIGINT[] := '{}';
    v_tags BIGINT[] := '{}';
    v_tagged BOOLEAN := FALSE;
    v_evaluate BOOLEAN;
    v_site_id BIGINT;
    v_site_public_id UUID;
    site_name TEXT;
    v_target_kind TEXT := 'site';
    v_pool_id BIGINT;
    v_pool_public_id UUID;
    v_paths JSONB := '[]'::JSONB;
BEGIN
    IF p_source_device_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_source_device_public_id), 6) >> 4 <> 7
        OR p_destination_address IS NULL
        OR NOT ((pg_catalog.family(p_destination_address) = 4 AND pg_catalog.masklen(p_destination_address) = 32)
            OR (pg_catalog.family(p_destination_address) = 6 AND pg_catalog.masklen(p_destination_address) = 128))
        OR p_protocol IS NULL OR p_protocol NOT IN ('tcp', 'udp', 'icmp')
        OR (p_protocol = 'icmp' AND p_destination_port IS DISTINCT FROM 0)
        OR (p_protocol IN ('tcp', 'udp')
            AND (p_destination_port IS NULL OR p_destination_port NOT BETWEEN 1 AND 65535))
        OR p_evaluated_at IS NULL
        OR p_path_limit IS NULL OR p_path_limit NOT BETWEEN 1 AND 65 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Access Graph explanation input is invalid';
    END IF;

    SELECT workspace.public_id, network.public_id
    INTO scoped_workspace_public_id, scoped_network_public_id
    FROM mesh.workspace AS workspace
    JOIN mesh.network AS network ON network.workspace_id = workspace.id
    WHERE workspace.id = scoped_workspace AND network.id = scoped_network;
    IF scoped_workspace_public_id IS NULL OR scoped_network_public_id IS NULL
        OR scoped_workspace_public_id <> p_workspace_public_id
        OR scoped_network_public_id <> p_network_public_id THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Access Graph Network scope is unavailable';
    END IF;

    PERFORM permission.role_binding_public_id
    FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'policy.explain', p_evaluated_at
    ) AS permission;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Access Graph explanation is not authorized';
    END IF;

    SELECT value.* INTO revision FROM mesh_ops.read_network_revision_v1() AS value;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Access Graph explanation is unavailable';
    END IF;

    SELECT release.id, release.public_id, release.compiler_format_version, release.semantic_hash
    INTO v_release_id, v_release_public_id, v_compiler_format_version, v_semantic_hash
    FROM mesh.policy_release AS release
    WHERE release.workspace_id = scoped_workspace
      AND release.network_id = scoped_network
      AND release.policy_revision = revision.policy_revision
      AND release.state = 'active';

    SELECT device.id, device.owner_principal_id, device.hostname,
        CASE WHEN device.state = 'active' AND device.deleted_at IS NULL
                  AND device.expires_at > p_evaluated_at THEN 'active'
             ELSE 'inactive' END
    INTO v_source_id, v_source_owner, source_name, source_state
    FROM mesh.device AS device
    WHERE device.workspace_id = scoped_workspace
      AND device.network_id = scoped_network
      AND device.public_id = p_source_device_public_id;
    v_evaluate := v_release_id IS NOT NULL AND source_state = 'active';

    IF v_evaluate THEN
        SELECT COALESCE(pg_catalog.array_agg(member.device_group_id), '{}')
        INTO v_device_groups
        FROM mesh.device_group_member AS member
        JOIN mesh.device_group AS device_group
          ON device_group.id = member.device_group_id AND device_group.state = 'active'
        WHERE member.workspace_id = scoped_workspace AND member.network_id = scoped_network
          AND member.device_id = v_source_id;
        SELECT COALESCE(pg_catalog.array_agg(assignment.device_tag_id)
                   FILTER (WHERE tag.state = 'active'), '{}'),
               pg_catalog.count(*) > 0
        INTO v_tags, v_tagged
        FROM mesh.device_tag_assignment AS assignment
        JOIN mesh.device_tag AS tag ON tag.id = assignment.device_tag_id
        WHERE assignment.device_id = v_source_id;
        IF NOT v_tagged AND v_source_owner IS NOT NULL THEN
            SELECT COALESCE(pg_catalog.array_agg(member.identity_group_id), '{}')
            INTO v_identity_groups
            FROM mesh.identity_group_member AS member
            JOIN mesh.identity_group AS identity_group
              ON identity_group.id = member.identity_group_id AND identity_group.state = 'active' AND identity_group.network_id = scoped_network
            JOIN mesh.principal AS principal
              ON principal.id = member.principal_id AND principal.state = 'active' AND principal.deleted_at IS NULL
            JOIN mesh.workspace_membership AS membership
              ON membership.workspace_id = scoped_workspace AND membership.principal_id = principal.id
             AND membership.state = 'active'
             AND (membership.expires_at IS NULL OR membership.expires_at > pg_catalog.transaction_timestamp())
            JOIN mesh.network_membership AS network_member
              ON network_member.workspace_id = scoped_workspace AND network_member.network_id = scoped_network
             AND network_member.principal_id = principal.id AND network_member.state = 'active'
             AND (network_member.expires_at IS NULL OR network_member.expires_at > pg_catalog.transaction_timestamp())
            WHERE member.workspace_id = scoped_workspace AND member.principal_id = v_source_owner;
        END IF;
    END IF;

    SELECT holding.id, holding.public_id, holding.name
    INTO v_site_id, v_site_public_id, site_name
    FROM (
        SELECT network_site.id, network_site.public_id, network_site.name,
               pg_catalog.max(pg_catalog.masklen(prefix)) AS bits
        FROM mesh.network_site AS network_site
        CROSS JOIN LATERAL pg_catalog.unnest(network_site.prefixes) AS prefix
        WHERE network_site.workspace_id = scoped_workspace
          AND network_site.network_id = scoped_network
          AND network_site.state = 'active'
          AND prefix >>= p_destination_address
        GROUP BY network_site.id, network_site.public_id, network_site.name
    ) AS holding
    ORDER BY v_evaluate AND EXISTS (
                 SELECT 1 FROM mesh_ops.explain_site_rules_internal_v1(
                     v_release_id, holding.id, v_source_id, v_device_groups, v_identity_groups, v_tags,
                     p_destination_address, p_protocol, p_destination_port)
             ) DESC,
             holding.bits DESC, holding.public_id
    LIMIT 1;

    IF v_evaluate AND v_site_id IS NOT NULL THEN
        SELECT COALESCE(pg_catalog.jsonb_agg(path.value ORDER BY path.rule_id, path.projection_id), '[]'::JSONB)
        INTO v_paths
        FROM (
            SELECT rule.access_rule_public_id::TEXT AS rule_id, rule.public_id::TEXT AS projection_id,
                   pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
                       'projection_id', rule.public_id,
                       'access_rule_id', rule.access_rule_public_id,
                       'source_device_id', p_source_device_public_id,
                       'protocol', rule.protocol,
                       'destination_port_range_first', ARRAY(
                           SELECT pg_catalog.lower(port_range)::INTEGER
                           FROM pg_catalog.unnest(rule.destination_ports) AS port_range
                           ORDER BY pg_catalog.lower(port_range)),
                       'destination_port_range_last', ARRAY(
                           SELECT (pg_catalog.upper(port_range) - 1)::INTEGER
                           FROM pg_catalog.unnest(rule.destination_ports) AS port_range
                           ORDER BY pg_catalog.lower(port_range)),
                       'selector_kind', 'site',
                       'destination_site_id', v_site_public_id,
                       'destination_prefixes', ARRAY(
                           SELECT prefix::TEXT FROM pg_catalog.unnest(rule.prefixes) AS prefix ORDER BY prefix),
                       'source_device_group_id', device_group.public_id,
                       'source_identity_group_id', identity_group.public_id,
                       'source_device_tag_id', device_tag.public_id
                   )) AS value
            FROM mesh_ops.explain_site_rules_internal_v1(
                v_release_id, v_site_id, v_source_id, v_device_groups, v_identity_groups, v_tags,
                p_destination_address, p_protocol, p_destination_port) AS rule
            LEFT JOIN mesh.device_group AS device_group ON device_group.id = rule.source_device_group_id
            LEFT JOIN mesh.identity_group AS identity_group ON identity_group.id = rule.source_identity_group_id
            LEFT JOIN mesh.device_tag AS device_tag ON device_tag.id = rule.source_device_tag_id
            ORDER BY rule.access_rule_public_id, rule.public_id
            LIMIT p_path_limit
        ) AS path;
    END IF;

    -- No Site holds an Internet address: the Exit Pools answer, through
    -- the first pool by identity whose rules grant the Internet to the
    -- source. A source that is an exit node of a pool does not use it.
    IF v_site_id IS NULL AND mesh_ops.internet_address_internal_v1(p_destination_address) THEN
        v_target_kind := 'exit_pool';
        IF v_evaluate THEN
            SELECT exit_pool.id, exit_pool.public_id, exit_pool.name
            INTO v_pool_id, v_pool_public_id, site_name
            FROM mesh.network_exit_pool AS exit_pool
            WHERE exit_pool.workspace_id = scoped_workspace
              AND exit_pool.network_id = scoped_network
              AND exit_pool.state = 'active'
              AND EXISTS (
                  SELECT 1 FROM mesh_ops.explain_exit_rules_internal_v1(
                      v_release_id, exit_pool.id, v_source_id, v_device_groups, v_identity_groups, v_tags,
                      p_protocol, p_destination_port))
            ORDER BY exit_pool.public_id
            LIMIT 1;
        END IF;
        IF v_pool_id IS NOT NULL THEN
            SELECT COALESCE(pg_catalog.jsonb_agg(path.value ORDER BY path.rule_id, path.projection_id), '[]'::JSONB)
            INTO v_paths
            FROM (
                SELECT rule.access_rule_public_id::TEXT AS rule_id, rule.public_id::TEXT AS projection_id,
                       pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
                           'projection_id', rule.public_id,
                           'access_rule_id', rule.access_rule_public_id,
                           'source_device_id', p_source_device_public_id,
                           'protocol', rule.protocol,
                           'destination_port_range_first', ARRAY(
                               SELECT pg_catalog.lower(port_range)::INTEGER
                               FROM pg_catalog.unnest(rule.destination_ports) AS port_range
                               ORDER BY pg_catalog.lower(port_range)),
                           'destination_port_range_last', ARRAY(
                               SELECT (pg_catalog.upper(port_range) - 1)::INTEGER
                               FROM pg_catalog.unnest(rule.destination_ports) AS port_range
                               ORDER BY pg_catalog.lower(port_range)),
                           'selector_kind', 'exit_pool',
                           'destination_exit_pool_id', v_pool_public_id,
                           'source_device_group_id', device_group.public_id,
                           'source_identity_group_id', identity_group.public_id,
                           'source_device_tag_id', device_tag.public_id
                       )) AS value
                FROM mesh_ops.explain_exit_rules_internal_v1(
                    v_release_id, v_pool_id, v_source_id, v_device_groups, v_identity_groups, v_tags,
                    p_protocol, p_destination_port) AS rule
                LEFT JOIN mesh.device_group AS device_group ON device_group.id = rule.source_device_group_id
                LEFT JOIN mesh.identity_group AS identity_group ON identity_group.id = rule.source_identity_group_id
                LEFT JOIN mesh.device_tag AS device_tag ON device_tag.id = rule.source_device_tag_id
                ORDER BY rule.access_rule_public_id, rule.public_id
                LIMIT p_path_limit
            ) AS path;
        END IF;
    END IF;

    IF v_site_id IS NOT NULL OR v_pool_id IS NOT NULL THEN
        PERFORM permission.role_binding_public_id
        FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, 'route.read', p_evaluated_at
        ) AS permission;
        IF NOT FOUND THEN
            site_name := NULL;
        END IF;
    END IF;

    RETURN QUERY SELECT revision.network_revision, revision.inventory_revision, revision.group_revision,
        revision.policy_revision, revision.dns_revision, revision.route_revision,
        revision.sharing_revision, revision.isolation_generation,
        v_release_id IS NOT NULL, v_release_public_id, v_compiler_format_version, v_semantic_hash,
        COALESCE(v_site_public_id, v_pool_public_id), v_paths,
        pg_catalog.jsonb_build_object(
            'source', pg_catalog.jsonb_build_object(
                'state', COALESCE(source_state, 'missing'), 'name', source_name),
            'target', pg_catalog.jsonb_build_object(
                'kind', v_target_kind,
                'state', CASE WHEN v_site_id IS NULL AND v_pool_id IS NULL THEN 'missing' ELSE 'active' END,
                'name', site_name),
            'share', NULL
        );
END;
$function$;

-- Schema 228: the source's groups as selector_devices_internal_v1 counts them.
CREATE OR REPLACE FUNCTION mesh_ops.explain_site_access_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID,
    p_source_device_public_id UUID, p_destination_address INET,
    p_protocol TEXT, p_destination_port INTEGER, p_evaluated_at TIMESTAMPTZ, p_path_limit INTEGER
)
RETURNS TABLE (
    network_revision BIGINT, inventory_revision BIGINT, group_revision BIGINT,
    policy_revision BIGINT, dns_revision BIGINT, route_revision BIGINT,
    sharing_revision BIGINT, isolation_generation BIGINT,
    has_active_release BOOLEAN, release_public_id UUID,
    compiler_format_version INTEGER, release_semantic_hash BYTEA,
    target_site_public_id UUID, paths JSONB, context JSONB
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    scoped_workspace BIGINT := mesh_ops.current_workspace_id();
    scoped_network BIGINT := mesh_ops.current_network_id();
    scoped_workspace_public_id UUID;
    scoped_network_public_id UUID;
    revision RECORD;
    v_release_id BIGINT;
    v_release_public_id UUID;
    v_compiler_format_version INTEGER;
    v_semantic_hash BYTEA;
    v_source_id BIGINT;
    v_source_owner BIGINT;
    source_name TEXT;
    source_state TEXT;
    v_device_groups BIGINT[] := '{}';
    v_identity_groups BIGINT[] := '{}';
    v_tags BIGINT[] := '{}';
    v_tagged BOOLEAN := FALSE;
    v_evaluate BOOLEAN;
    v_site_id BIGINT;
    v_site_public_id UUID;
    site_name TEXT;
    v_paths JSONB := '[]'::JSONB;
BEGIN
    IF p_source_device_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_source_device_public_id), 6) >> 4 <> 7
        OR p_destination_address IS NULL
        OR NOT ((pg_catalog.family(p_destination_address) = 4 AND pg_catalog.masklen(p_destination_address) = 32)
            OR (pg_catalog.family(p_destination_address) = 6 AND pg_catalog.masklen(p_destination_address) = 128))
        OR p_protocol IS NULL OR p_protocol NOT IN ('tcp', 'udp', 'icmp')
        OR (p_protocol = 'icmp' AND p_destination_port IS DISTINCT FROM 0)
        OR (p_protocol IN ('tcp', 'udp')
            AND (p_destination_port IS NULL OR p_destination_port NOT BETWEEN 1 AND 65535))
        OR p_evaluated_at IS NULL
        OR p_path_limit IS NULL OR p_path_limit NOT BETWEEN 1 AND 65 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Access Graph explanation input is invalid';
    END IF;

    SELECT workspace.public_id, network.public_id
    INTO scoped_workspace_public_id, scoped_network_public_id
    FROM mesh.workspace AS workspace
    JOIN mesh.network AS network ON network.workspace_id = workspace.id
    WHERE workspace.id = scoped_workspace AND network.id = scoped_network;
    IF scoped_workspace_public_id IS NULL OR scoped_network_public_id IS NULL
        OR scoped_workspace_public_id <> p_workspace_public_id
        OR scoped_network_public_id <> p_network_public_id THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Access Graph Network scope is unavailable';
    END IF;

    PERFORM permission.role_binding_public_id
    FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'policy.explain', p_evaluated_at
    ) AS permission;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Access Graph explanation is not authorized';
    END IF;

    SELECT value.* INTO revision FROM mesh_ops.read_network_revision_v1() AS value;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Access Graph explanation is unavailable';
    END IF;

    SELECT release.id, release.public_id, release.compiler_format_version, release.semantic_hash
    INTO v_release_id, v_release_public_id, v_compiler_format_version, v_semantic_hash
    FROM mesh.policy_release AS release
    WHERE release.workspace_id = scoped_workspace
      AND release.network_id = scoped_network
      AND release.policy_revision = revision.policy_revision
      AND release.state = 'active';

    SELECT device.id, device.owner_principal_id, device.hostname,
        CASE WHEN device.state = 'active' AND device.deleted_at IS NULL
                  AND device.expires_at > p_evaluated_at THEN 'active'
             ELSE 'inactive' END
    INTO v_source_id, v_source_owner, source_name, source_state
    FROM mesh.device AS device
    WHERE device.workspace_id = scoped_workspace
      AND device.network_id = scoped_network
      AND device.public_id = p_source_device_public_id;
    v_evaluate := v_release_id IS NOT NULL AND source_state = 'active';

    IF v_evaluate THEN
        SELECT COALESCE(pg_catalog.array_agg(member.device_group_id), '{}')
        INTO v_device_groups
        FROM mesh.device_group_member AS member
        JOIN mesh.device_group AS device_group
          ON device_group.id = member.device_group_id AND device_group.state = 'active'
        WHERE member.workspace_id = scoped_workspace AND member.network_id = scoped_network
          AND member.device_id = v_source_id;
        SELECT COALESCE(pg_catalog.array_agg(assignment.device_tag_id)
                   FILTER (WHERE tag.state = 'active'), '{}'),
               pg_catalog.count(*) > 0
        INTO v_tags, v_tagged
        FROM mesh.device_tag_assignment AS assignment
        JOIN mesh.device_tag AS tag ON tag.id = assignment.device_tag_id
        WHERE assignment.device_id = v_source_id;
        IF NOT v_tagged AND v_source_owner IS NOT NULL THEN
            SELECT COALESCE(pg_catalog.array_agg(member.identity_group_id), '{}')
            INTO v_identity_groups
            FROM mesh.identity_group_member AS member
            JOIN mesh.identity_group AS identity_group
              ON identity_group.id = member.identity_group_id AND identity_group.state = 'active' AND identity_group.network_id = scoped_network
            JOIN mesh.principal AS principal
              ON principal.id = member.principal_id AND principal.state = 'active' AND principal.deleted_at IS NULL
            JOIN mesh.workspace_membership AS membership
              ON membership.workspace_id = scoped_workspace AND membership.principal_id = principal.id
             AND membership.state = 'active'
             AND (membership.expires_at IS NULL OR membership.expires_at > pg_catalog.transaction_timestamp())
            JOIN mesh.network_membership AS network_member
              ON network_member.workspace_id = scoped_workspace AND network_member.network_id = scoped_network
             AND network_member.principal_id = principal.id AND network_member.state = 'active'
             AND (network_member.expires_at IS NULL OR network_member.expires_at > pg_catalog.transaction_timestamp())
            WHERE member.workspace_id = scoped_workspace AND member.principal_id = v_source_owner;
        END IF;
    END IF;

    SELECT holding.id, holding.public_id, holding.name
    INTO v_site_id, v_site_public_id, site_name
    FROM (
        SELECT network_site.id, network_site.public_id, network_site.name,
               pg_catalog.max(pg_catalog.masklen(prefix)) AS bits
        FROM mesh.network_site AS network_site
        CROSS JOIN LATERAL pg_catalog.unnest(network_site.prefixes) AS prefix
        WHERE network_site.workspace_id = scoped_workspace
          AND network_site.network_id = scoped_network
          AND network_site.state = 'active'
          AND prefix >>= p_destination_address
        GROUP BY network_site.id, network_site.public_id, network_site.name
    ) AS holding
    ORDER BY v_evaluate AND EXISTS (
                 SELECT 1 FROM mesh_ops.explain_site_rules_internal_v1(
                     v_release_id, holding.id, v_source_id, v_device_groups, v_identity_groups, v_tags,
                     p_destination_address, p_protocol, p_destination_port)
             ) DESC,
             holding.bits DESC, holding.public_id
    LIMIT 1;

    IF v_evaluate AND v_site_id IS NOT NULL THEN
        SELECT COALESCE(pg_catalog.jsonb_agg(path.value ORDER BY path.rule_id, path.projection_id), '[]'::JSONB)
        INTO v_paths
        FROM (
            SELECT rule.access_rule_public_id::TEXT AS rule_id, rule.public_id::TEXT AS projection_id,
                   pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
                       'projection_id', rule.public_id,
                       'access_rule_id', rule.access_rule_public_id,
                       'source_device_id', p_source_device_public_id,
                       'protocol', rule.protocol,
                       'destination_port_range_first', ARRAY(
                           SELECT pg_catalog.lower(port_range)::INTEGER
                           FROM pg_catalog.unnest(rule.destination_ports) AS port_range
                           ORDER BY pg_catalog.lower(port_range)),
                       'destination_port_range_last', ARRAY(
                           SELECT (pg_catalog.upper(port_range) - 1)::INTEGER
                           FROM pg_catalog.unnest(rule.destination_ports) AS port_range
                           ORDER BY pg_catalog.lower(port_range)),
                       'selector_kind', 'site',
                       'destination_site_id', v_site_public_id,
                       'destination_prefixes', ARRAY(
                           SELECT prefix::TEXT FROM pg_catalog.unnest(rule.prefixes) AS prefix ORDER BY prefix),
                       'source_device_group_id', device_group.public_id,
                       'source_identity_group_id', identity_group.public_id,
                       'source_device_tag_id', device_tag.public_id
                   )) AS value
            FROM mesh_ops.explain_site_rules_internal_v1(
                v_release_id, v_site_id, v_source_id, v_device_groups, v_identity_groups, v_tags,
                p_destination_address, p_protocol, p_destination_port) AS rule
            LEFT JOIN mesh.device_group AS device_group ON device_group.id = rule.source_device_group_id
            LEFT JOIN mesh.identity_group AS identity_group ON identity_group.id = rule.source_identity_group_id
            LEFT JOIN mesh.device_tag AS device_tag ON device_tag.id = rule.source_device_tag_id
            ORDER BY rule.access_rule_public_id, rule.public_id
            LIMIT p_path_limit
        ) AS path;
    END IF;

    IF v_site_id IS NOT NULL THEN
        PERFORM permission.role_binding_public_id
        FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, 'route.read', p_evaluated_at
        ) AS permission;
        IF NOT FOUND THEN
            site_name := NULL;
        END IF;
    END IF;

    RETURN QUERY SELECT revision.network_revision, revision.inventory_revision, revision.group_revision,
        revision.policy_revision, revision.dns_revision, revision.route_revision,
        revision.sharing_revision, revision.isolation_generation,
        v_release_id IS NOT NULL, v_release_public_id, v_compiler_format_version, v_semantic_hash,
        v_site_public_id, v_paths,
        pg_catalog.jsonb_build_object(
            'source', pg_catalog.jsonb_build_object(
                'state', COALESCE(source_state, 'missing'), 'name', source_name),
            'target', pg_catalog.jsonb_build_object(
                'kind', 'site', 'state', CASE WHEN v_site_id IS NULL THEN 'missing' ELSE 'active' END,
                'name', site_name),
            'share', NULL
        );
END;
$function$;

-- Schema 228: groups and tags are looked up in the release's Network only.
CREATE OR REPLACE FUNCTION mesh_ops.attach_policy_group_rules_v2(
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
    v_previous_release BIGINT;
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
          SELECT 1 FROM mesh.compiled_policy_group_rule AS attached WHERE attached.policy_release_id = release.id
      );
    IF v_release.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'policy group rules need the release published now';
    END IF;
    SELECT previous.id INTO v_previous_release FROM mesh.policy_release AS previous
    WHERE previous.workspace_id = v_workspace AND previous.network_id = v_network
      AND previous.policy_revision = v_release.policy_revision - 1
      AND previous.state = 'superseded';
    v_expected := pg_catalog.jsonb_array_length(p_rules);

    WITH input_rule AS (
        SELECT rule.*
        FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
            projection_public_id UUID, access_rule_public_id UUID,
            source_node_public_id UUID, source_device_group_public_id UUID,
            source_identity_group_public_id UUID, source_device_tag_public_id UUID,
            destination_node_public_id UUID, destination_device_group_public_id UUID,
            destination_device_tag_public_id UUID,
            protocol TEXT, port_range_first INTEGER[], port_range_last INTEGER[]
        )
    ),
    valid_rule AS (
        SELECT rule.* FROM input_rule AS rule
        WHERE rule.projection_public_id IS NOT NULL
          AND pg_catalog.get_byte(pg_catalog.uuid_send(rule.projection_public_id), 6) >> 4 = 7
          AND rule.access_rule_public_id IS NOT NULL
          AND pg_catalog.get_byte(pg_catalog.uuid_send(rule.access_rule_public_id), 6) >> 4 = 7
          AND pg_catalog.num_nonnulls(rule.source_node_public_id, rule.source_device_group_public_id,
                                      rule.source_identity_group_public_id, rule.source_device_tag_public_id) = 1
          AND pg_catalog.num_nonnulls(rule.destination_node_public_id, rule.destination_device_group_public_id,
                                      rule.destination_device_tag_public_id) = 1
          AND (rule.source_node_public_id IS NULL OR rule.destination_node_public_id IS NULL)
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
               source_identity.id AS source_identity_group_id, source_tag.id AS source_device_tag_id,
               destination_device.id AS destination_device_id,
               destination_group.id AS destination_device_group_id, destination_tag.id AS destination_device_tag_id,
               ports.destination_ports
        FROM valid_rule AS rule
        LEFT JOIN mesh.device AS source_device
          ON source_device.workspace_id = v_workspace AND source_device.network_id = v_network
         AND source_device.public_id = rule.source_node_public_id
        LEFT JOIN mesh.device_group AS source_group
          ON source_group.workspace_id = v_workspace AND source_group.network_id = v_network
         AND source_group.public_id = rule.source_device_group_public_id AND source_group.state = 'active'
        LEFT JOIN mesh.identity_group AS source_identity
          ON source_identity.workspace_id = v_workspace AND source_identity.network_id = v_network
         AND source_identity.public_id = rule.source_identity_group_public_id AND source_identity.state = 'active'
        LEFT JOIN mesh.device_tag AS source_tag
          ON source_tag.workspace_id = v_workspace AND source_tag.network_id = v_network
         AND source_tag.public_id = rule.source_device_tag_public_id AND source_tag.state = 'active'
        LEFT JOIN mesh.device AS destination_device
          ON destination_device.workspace_id = v_workspace AND destination_device.network_id = v_network
         AND destination_device.public_id = rule.destination_node_public_id
        LEFT JOIN mesh.device_group AS destination_group
          ON destination_group.workspace_id = v_workspace AND destination_group.network_id = v_network
         AND destination_group.public_id = rule.destination_device_group_public_id
         AND destination_group.state = 'active'
        LEFT JOIN mesh.device_tag AS destination_tag
          ON destination_tag.workspace_id = v_workspace AND destination_tag.network_id = v_network
         AND destination_tag.public_id = rule.destination_device_tag_public_id AND destination_tag.state = 'active'
        CROSS JOIN LATERAL (
            SELECT COALESCE(pg_catalog.range_agg(
                pg_catalog.int4range(port_range.first_port, port_range.last_port + 1, '[)')
            ), '{}'::INT4MULTIRANGE) AS destination_ports
            FROM ROWS FROM (
                pg_catalog.unnest(rule.port_range_first), pg_catalog.unnest(rule.port_range_last)
            ) AS port_range(first_port, last_port)
        ) AS ports
        WHERE (rule.source_node_public_id IS NULL OR source_device.id IS NOT NULL)
          AND (rule.source_device_group_public_id IS NULL OR source_group.id IS NOT NULL)
          AND (rule.source_identity_group_public_id IS NULL OR source_identity.id IS NOT NULL)
          AND (rule.source_device_tag_public_id IS NULL OR source_tag.id IS NOT NULL)
          AND (rule.destination_node_public_id IS NULL OR destination_device.id IS NOT NULL)
          AND (rule.destination_device_group_public_id IS NULL OR destination_group.id IS NOT NULL)
          AND (rule.destination_device_tag_public_id IS NULL OR destination_tag.id IS NOT NULL)
          -- A revoked or deleted Device side only for a rule the replaced
          -- release held unchanged: same sides, protocol and ports.
          AND ((source_device.id IS NULL OR source_device.state IN ('active', 'expired', 'suspended'))
               AND (destination_device.id IS NULL OR destination_device.state IN ('active', 'expired', 'suspended'))
               OR EXISTS (
                   SELECT 1 FROM mesh.compiled_policy_group_rule AS carried
                   WHERE carried.policy_release_id = v_previous_release
                     AND carried.access_rule_public_id = rule.access_rule_public_id
                     AND carried.source_device_id IS NOT DISTINCT FROM source_device.id
                     AND carried.source_device_group_id IS NOT DISTINCT FROM source_group.id
                     AND carried.source_identity_group_id IS NOT DISTINCT FROM source_identity.id
                     AND carried.source_device_tag_id IS NOT DISTINCT FROM source_tag.id
                     AND carried.destination_device_id IS NOT DISTINCT FROM destination_device.id
                     AND carried.destination_device_group_id IS NOT DISTINCT FROM destination_group.id
                     AND carried.destination_device_tag_id IS NOT DISTINCT FROM destination_tag.id
                     AND carried.protocol = rule.protocol
                     AND carried.destination_ports = ports.destination_ports))
    )
    INSERT INTO mesh.compiled_policy_group_rule (
        public_id, access_rule_public_id, workspace_id, network_id, policy_release_id, policy_revision,
        source_device_id, source_device_group_id, source_identity_group_id, source_device_tag_id,
        destination_device_id, destination_device_group_id, destination_device_tag_id,
        protocol, destination_ports, created_at
    )
    SELECT rule.projection_public_id, rule.access_rule_public_id, v_workspace, v_network, v_release.id,
           v_release.policy_revision, rule.source_device_id, rule.source_device_group_id,
           rule.source_identity_group_id, rule.source_device_tag_id, rule.destination_device_id,
           rule.destination_device_group_id, rule.destination_device_tag_id, rule.protocol,
           rule.destination_ports, p_created_at
    FROM resolved_rule AS rule
    ORDER BY rule.access_rule_public_id;
    GET DIAGNOSTICS v_inserted = ROW_COUNT;
    IF v_inserted <> v_expected THEN
        -- A rule left out that names a Device not in this Network, or one
        -- that is gone, is new or changed: refuse it as such.
        IF EXISTS (
            SELECT 1 FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
                projection_public_id UUID, source_node_public_id UUID, destination_node_public_id UUID
            )
            CROSS JOIN LATERAL (VALUES
                (rule.source_node_public_id), (rule.destination_node_public_id)
            ) AS side(node_public_id)
            WHERE side.node_public_id IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1 FROM mesh.compiled_policy_group_rule AS attached
                  WHERE attached.public_id = rule.projection_public_id
              )
              AND NOT EXISTS (
                  SELECT 1 FROM mesh.device AS device
                  WHERE device.workspace_id = v_workspace AND device.network_id = v_network
                    AND device.public_id = side.node_public_id AND device.state IN ('active', 'expired', 'suspended')
              )
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'MTP05',
                MESSAGE = 'a new policy rule names a Device that is not in this Network or was removed';
        END IF;
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'a Device, group or tag changed during publication';
    END IF;
    IF mesh_ops.max_device_policy_edges_internal_v1(v_workspace, v_network) > 10000 THEN
        RAISE EXCEPTION USING ERRCODE = 'MTD06', MESSAGE = 'a Device would load more than 10000 rule edges';
    END IF;
    RETURN v_inserted;
END;
$function$;

-- Schema 228: groups and tags are looked up in the release's Network only.
CREATE OR REPLACE FUNCTION mesh_ops.attach_policy_route_rules_v1(
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
    v_previous_release BIGINT;
    v_expected INTEGER;
    v_inserted INTEGER;
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_release_public_id IS NULL OR p_created_at IS NULL OR p_rules IS NULL
        OR pg_catalog.jsonb_typeof(p_rules) <> 'array'
        OR pg_catalog.jsonb_array_length(p_rules) NOT BETWEEN 1 AND 10000 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'policy route rule input is invalid';
    END IF;
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
          SELECT 1 FROM mesh.compiled_policy_route_rule AS attached WHERE attached.policy_release_id = release.id
      );
    IF v_release.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'policy route rules need the release published now';
    END IF;
    -- Publication holds the Network scope lock that change_site_v1 takes, so
    -- the Sites read below cannot change or be deleted before commit.
    SELECT previous.id INTO v_previous_release FROM mesh.policy_release AS previous
    WHERE previous.workspace_id = v_workspace AND previous.network_id = v_network
      AND previous.policy_revision = v_release.policy_revision - 1
      AND previous.state = 'superseded';
    v_expected := pg_catalog.jsonb_array_length(p_rules);

    WITH input_rule AS (
        SELECT rule.*
        FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
            projection_public_id UUID, access_rule_public_id UUID,
            source_node_public_id UUID, source_device_group_public_id UUID,
            source_identity_group_public_id UUID, source_device_tag_public_id UUID,
            site_public_id UUID, prefixes CIDR[],
            protocol TEXT, port_range_first INTEGER[], port_range_last INTEGER[]
        )
    ),
    valid_rule AS (
        SELECT rule.* FROM input_rule AS rule
        WHERE rule.projection_public_id IS NOT NULL
          AND pg_catalog.get_byte(pg_catalog.uuid_send(rule.projection_public_id), 6) >> 4 = 7
          AND rule.access_rule_public_id IS NOT NULL
          AND pg_catalog.get_byte(pg_catalog.uuid_send(rule.access_rule_public_id), 6) >> 4 = 7
          AND pg_catalog.num_nonnulls(rule.source_node_public_id, rule.source_device_group_public_id,
                                      rule.source_identity_group_public_id, rule.source_device_tag_public_id) = 1
          AND rule.site_public_id IS NOT NULL
          AND rule.prefixes IS NOT NULL AND mesh_ops.site_prefixes_valid_internal_v1(rule.prefixes)
          -- IPv4-mapped IPv6 prefixes would alias IPv4 space.
          AND NOT EXISTS (SELECT 1 FROM pg_catalog.unnest(rule.prefixes) AS mapped(prefix)
                          WHERE pg_catalog.family(mapped.prefix) = 6
                            AND mapped.prefix <<= '::ffff:0:0/96'::CIDR)
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
          AND NOT EXISTS (
              SELECT 1 FROM mesh.compiled_policy_group_rule AS group_rule
              WHERE group_rule.policy_release_id = v_release.id
                AND group_rule.access_rule_public_id = rule.access_rule_public_id
          )
    ),
    resolved_rule AS (
        SELECT rule.*, source_device.id AS source_device_id, source_group.id AS source_device_group_id,
               source_identity.id AS source_identity_group_id, source_tag.id AS source_device_tag_id,
               network_site.id AS destination_site_id, ports.destination_ports
        FROM valid_rule AS rule
        JOIN mesh.network_site AS network_site
          ON network_site.workspace_id = v_workspace AND network_site.network_id = v_network
         AND network_site.public_id = rule.site_public_id AND network_site.state = 'active'
         -- Every granted prefix lies inside one prefix of the Site.
         AND NOT EXISTS (
             SELECT 1 FROM pg_catalog.unnest(rule.prefixes) AS granted
             WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.unnest(network_site.prefixes) AS owned
                               WHERE granted <<= owned))
        LEFT JOIN mesh.device AS source_device
          ON source_device.workspace_id = v_workspace AND source_device.network_id = v_network
         AND source_device.public_id = rule.source_node_public_id
        LEFT JOIN mesh.device_group AS source_group
          ON source_group.workspace_id = v_workspace AND source_group.network_id = v_network
         AND source_group.public_id = rule.source_device_group_public_id AND source_group.state = 'active'
        LEFT JOIN mesh.identity_group AS source_identity
          ON source_identity.workspace_id = v_workspace AND source_identity.network_id = v_network
         AND source_identity.public_id = rule.source_identity_group_public_id AND source_identity.state = 'active'
        LEFT JOIN mesh.device_tag AS source_tag
          ON source_tag.workspace_id = v_workspace AND source_tag.network_id = v_network
         AND source_tag.public_id = rule.source_device_tag_public_id AND source_tag.state = 'active'
        CROSS JOIN LATERAL (
            SELECT COALESCE(pg_catalog.range_agg(
                pg_catalog.int4range(port_range.first_port, port_range.last_port + 1, '[)')
            ), '{}'::INT4MULTIRANGE) AS destination_ports
            FROM ROWS FROM (
                pg_catalog.unnest(rule.port_range_first), pg_catalog.unnest(rule.port_range_last)
            ) AS port_range(first_port, last_port)
        ) AS ports
        WHERE (rule.source_node_public_id IS NULL OR source_device.id IS NOT NULL)
          AND (rule.source_device_group_public_id IS NULL OR source_group.id IS NOT NULL)
          AND (rule.source_identity_group_public_id IS NULL OR source_identity.id IS NOT NULL)
          AND (rule.source_device_tag_public_id IS NULL OR source_tag.id IS NOT NULL)
          -- A revoked or deleted source Device only for a rule the replaced
          -- release held unchanged.
          AND (source_device.id IS NULL OR source_device.state IN ('active', 'expired', 'suspended')
               OR EXISTS (
                   SELECT 1 FROM mesh.compiled_policy_route_rule AS carried
                   WHERE carried.policy_release_id = v_previous_release
                     AND carried.access_rule_public_id = rule.access_rule_public_id
                     AND carried.source_device_id = source_device.id
                     AND carried.destination_site_id = network_site.id
                     AND carried.prefixes = rule.prefixes
                     AND carried.protocol = rule.protocol
                     AND carried.destination_ports = ports.destination_ports))
    )
    INSERT INTO mesh.compiled_policy_route_rule (
        public_id, access_rule_public_id, workspace_id, network_id, policy_release_id, policy_revision,
        source_device_id, source_device_group_id, source_identity_group_id, source_device_tag_id,
        destination_site_id, prefixes, protocol, destination_ports, created_at
    )
    SELECT rule.projection_public_id, rule.access_rule_public_id, v_workspace, v_network, v_release.id,
           v_release.policy_revision, rule.source_device_id, rule.source_device_group_id,
           rule.source_identity_group_id, rule.source_device_tag_id, rule.destination_site_id,
           rule.prefixes, rule.protocol, rule.destination_ports, p_created_at
    FROM resolved_rule AS rule
    ORDER BY rule.access_rule_public_id;
    GET DIAGNOSTICS v_inserted = ROW_COUNT;
    IF v_inserted <> v_expected THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001',
            MESSAGE = 'a Site, Device, group or tag changed during publication';
    END IF;
    IF (SELECT pg_catalog.sum(pg_catalog.cardinality(rule.prefixes)) FROM mesh.compiled_policy_route_rule AS rule
        WHERE rule.policy_release_id = v_release.id) > 16384 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'a release grants more than 16384 route prefixes';
    END IF;
    IF mesh_ops.release_route_overlap_internal_v1(v_release.id) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTS07', MESSAGE = 'route rules of different Sites overlap';
    END IF;
    RETURN v_inserted;
END;
$function$;

-- Schema 228: groups and tags are looked up in the release's Network only.
CREATE OR REPLACE FUNCTION mesh_ops.attach_policy_exit_rules_v1(
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
    v_previous_release BIGINT;
    v_expected INTEGER;
    v_inserted INTEGER;
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_release_public_id IS NULL OR p_created_at IS NULL OR p_rules IS NULL
        OR pg_catalog.jsonb_typeof(p_rules) <> 'array'
        OR pg_catalog.jsonb_array_length(p_rules) NOT BETWEEN 1 AND 10000 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'policy exit rule input is invalid';
    END IF;
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
          SELECT 1 FROM mesh.compiled_policy_exit_rule AS attached WHERE attached.policy_release_id = release.id
      );
    IF v_release.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'policy exit rules need the release published now';
    END IF;
    -- Publication holds the Network scope lock that change_exit_pool_v1
    -- takes, so the pools read below cannot be deleted before commit.
    SELECT previous.id INTO v_previous_release FROM mesh.policy_release AS previous
    WHERE previous.workspace_id = v_workspace AND previous.network_id = v_network
      AND previous.policy_revision = v_release.policy_revision - 1
      AND previous.state = 'superseded';
    v_expected := pg_catalog.jsonb_array_length(p_rules);

    WITH input_rule AS (
        SELECT rule.*
        FROM pg_catalog.jsonb_to_recordset(p_rules) AS rule(
            projection_public_id UUID, access_rule_public_id UUID,
            source_node_public_id UUID, source_device_group_public_id UUID,
            source_identity_group_public_id UUID, source_device_tag_public_id UUID,
            exit_pool_public_id UUID,
            protocol TEXT, port_range_first INTEGER[], port_range_last INTEGER[]
        )
    ),
    valid_rule AS (
        SELECT rule.* FROM input_rule AS rule
        WHERE rule.projection_public_id IS NOT NULL
          AND pg_catalog.get_byte(pg_catalog.uuid_send(rule.projection_public_id), 6) >> 4 = 7
          AND rule.access_rule_public_id IS NOT NULL
          AND pg_catalog.get_byte(pg_catalog.uuid_send(rule.access_rule_public_id), 6) >> 4 = 7
          AND pg_catalog.num_nonnulls(rule.source_node_public_id, rule.source_device_group_public_id,
                                      rule.source_identity_group_public_id, rule.source_device_tag_public_id) = 1
          AND rule.exit_pool_public_id IS NOT NULL
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
          AND NOT EXISTS (
              SELECT 1 FROM mesh.compiled_policy_group_rule AS group_rule
              WHERE group_rule.policy_release_id = v_release.id
                AND group_rule.access_rule_public_id = rule.access_rule_public_id
          )
          AND NOT EXISTS (
              SELECT 1 FROM mesh.compiled_policy_route_rule AS route_rule
              WHERE route_rule.policy_release_id = v_release.id
                AND route_rule.access_rule_public_id = rule.access_rule_public_id
          )
          AND NOT EXISTS (
              SELECT 1 FROM mesh.compiled_policy_imported_resource_destination AS imported_rule
              WHERE imported_rule.policy_release_id = v_release.id
                AND imported_rule.access_rule_public_id = rule.access_rule_public_id
          )
    ),
    resolved_rule AS (
        SELECT rule.*, source_device.id AS source_device_id, source_group.id AS source_device_group_id,
               source_identity.id AS source_identity_group_id, source_tag.id AS source_device_tag_id,
               exit_pool.id AS destination_exit_pool_id, ports.destination_ports
        FROM valid_rule AS rule
        JOIN mesh.network_exit_pool AS exit_pool
          ON exit_pool.workspace_id = v_workspace AND exit_pool.network_id = v_network
         AND exit_pool.public_id = rule.exit_pool_public_id AND exit_pool.state = 'active'
        LEFT JOIN mesh.device AS source_device
          ON source_device.workspace_id = v_workspace AND source_device.network_id = v_network
         AND source_device.public_id = rule.source_node_public_id
        LEFT JOIN mesh.device_group AS source_group
          ON source_group.workspace_id = v_workspace AND source_group.network_id = v_network
         AND source_group.public_id = rule.source_device_group_public_id AND source_group.state = 'active'
        LEFT JOIN mesh.identity_group AS source_identity
          ON source_identity.workspace_id = v_workspace AND source_identity.network_id = v_network
         AND source_identity.public_id = rule.source_identity_group_public_id AND source_identity.state = 'active'
        LEFT JOIN mesh.device_tag AS source_tag
          ON source_tag.workspace_id = v_workspace AND source_tag.network_id = v_network
         AND source_tag.public_id = rule.source_device_tag_public_id AND source_tag.state = 'active'
        CROSS JOIN LATERAL (
            SELECT COALESCE(pg_catalog.range_agg(
                pg_catalog.int4range(port_range.first_port, port_range.last_port + 1, '[)')
            ), '{}'::INT4MULTIRANGE) AS destination_ports
            FROM ROWS FROM (
                pg_catalog.unnest(rule.port_range_first), pg_catalog.unnest(rule.port_range_last)
            ) AS port_range(first_port, last_port)
        ) AS ports
        WHERE (rule.source_node_public_id IS NULL OR source_device.id IS NOT NULL)
          AND (rule.source_device_group_public_id IS NULL OR source_group.id IS NOT NULL)
          AND (rule.source_identity_group_public_id IS NULL OR source_identity.id IS NOT NULL)
          AND (rule.source_device_tag_public_id IS NULL OR source_tag.id IS NOT NULL)
          -- A revoked or deleted source Device only for a rule the replaced
          -- release held unchanged.
          AND (source_device.id IS NULL OR source_device.state IN ('active', 'expired', 'suspended')
               OR EXISTS (
                   SELECT 1 FROM mesh.compiled_policy_exit_rule AS carried
                   WHERE carried.policy_release_id = v_previous_release
                     AND carried.access_rule_public_id = rule.access_rule_public_id
                     AND carried.source_device_id = source_device.id
                     AND carried.destination_exit_pool_id = exit_pool.id
                     AND carried.protocol = rule.protocol
                     AND carried.destination_ports = ports.destination_ports))
    )
    INSERT INTO mesh.compiled_policy_exit_rule (
        public_id, access_rule_public_id, workspace_id, network_id, policy_release_id, policy_revision,
        source_device_id, source_device_group_id, source_identity_group_id, source_device_tag_id,
        destination_exit_pool_id, protocol, destination_ports, created_at
    )
    SELECT rule.projection_public_id, rule.access_rule_public_id, v_workspace, v_network, v_release.id,
           v_release.policy_revision, rule.source_device_id, rule.source_device_group_id,
           rule.source_identity_group_id, rule.source_device_tag_id, rule.destination_exit_pool_id,
           rule.protocol, rule.destination_ports, p_created_at
    FROM resolved_rule AS rule
    ORDER BY rule.access_rule_public_id;
    GET DIAGNOSTICS v_inserted = ROW_COUNT;
    IF v_inserted <> v_expected THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001',
            MESSAGE = 'an Exit Pool, Device, group or tag changed during publication';
    END IF;
    RETURN v_inserted;
END;
$function$;

-- remove_network_member_v1 of schema 182: the member also leaves every user
-- group of the Network. The Workspace row is locked first, as before, so a
-- concurrent group membership change finishes first or sees the removal.
CREATE OR REPLACE FUNCTION mesh_ops.remove_network_member_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_network_public_id uuid, p_member_public_id uuid, p_plan jsonb, p_change_public_id uuid, p_evaluated_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
 SET join_collapse_limit TO '1'
 SET from_collapse_limit TO '1'
 SET plan_cache_mode TO 'force_generic_plan'
AS $function$
DECLARE
    v_scope RECORD;
    v_owner BIGINT;
    v_workspace_device_owner BIGINT;
    v_grant RECORD;
    v_actor BIGINT;
    v_member BIGINT;
    v_membership mesh.network_membership%ROWTYPE;
    v_before JSONB;
    v_item RECORD;
    v_device mesh.device%ROWTYPE;
    v_target BIGINT;
    v_action TEXT;
    v_devices JSONB := '[]'::JSONB;
    v_advanced JSONB;
    v_handovers INTEGER := 0;
    v_keys INTEGER := 0;
    v_roles INTEGER := 0;
    v_bindings INTEGER := 0;
    v_assigners TEXT[];
    v_network_assigners TEXT[];
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_member_public_id IS NULL OR p_plan IS NULL OR pg_catalog.jsonb_typeof(p_plan) <> 'array'
        OR pg_catalog.jsonb_array_length(p_plan) > 250
        OR p_change_public_id IS NULL OR p_evaluated_at IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Network member removal is invalid';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.jsonb_array_elements(p_plan) AS item(value)
        WHERE pg_catalog.jsonb_typeof(item.value) <> 'object'
           OR NOT (item.value ?& ARRAY['device_id', 'action'])
           OR EXISTS (SELECT 1 FROM pg_catalog.jsonb_object_keys(item.value) AS key(name)
                      WHERE key.name NOT IN ('device_id', 'action', 'new_owner_id'))
           OR item.value ->> 'action' NOT IN ('transfer_workspace', 'transfer_member', 'revoke')
           OR (item.value ->> 'action' = 'transfer_member') <> (item.value ? 'new_owner_id')
           OR (item.value ->> 'device_id') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
           OR ((item.value ? 'new_owner_id') AND (item.value ->> 'new_owner_id')
               !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
    ) OR (
        SELECT pg_catalog.count(DISTINCT item.value ->> 'device_id') <> pg_catalog.count(*)
        FROM pg_catalog.jsonb_array_elements(p_plan) AS item(value)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Network member removal plan is invalid';
    END IF;

    SELECT * INTO v_scope FROM mesh_ops.network_member_scope_internal_v1(
        p_session_public_id, p_workspace_public_id, p_network_public_id);
    IF v_scope.network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Network member removal is not authorized';
    END IF;
    -- Member changes in one Workspace are serialized by its row lock, taken
    -- before the Network revision.
    SELECT workspace.owner_principal_id INTO v_owner FROM mesh.workspace AS workspace
    WHERE workspace.id = v_scope.workspace_id
    FOR NO KEY UPDATE;
    SELECT * INTO v_grant FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'network.member.manage', v_now
    ) LIMIT 1;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Network member removal is not authorized';
    END IF;
    SELECT principal.id INTO STRICT v_actor FROM mesh.principal AS principal
    WHERE principal.public_id = p_principal_public_id;

    SELECT principal.id INTO v_member FROM mesh.principal AS principal
    WHERE principal.public_id = p_member_public_id AND principal.kind = 'account' AND principal.deleted_at IS NULL;
    SELECT * INTO v_membership FROM mesh.network_membership AS network_member
    WHERE network_member.workspace_id = v_scope.workspace_id AND network_member.network_id = v_scope.network_id
      AND network_member.principal_id = v_member AND network_member.state <> 'revoked'
    FOR UPDATE;
    IF v_membership.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Network member is unavailable';
    END IF;
    IF v_member = v_owner OR v_member = v_actor THEN
        RAISE EXCEPTION USING ERRCODE = 'MTM02', MESSAGE = 'nobody removes the owner or themselves';
    END IF;
    -- The actor's assigners: from the Workspace, and for roles bound to this
    -- Network also their own admin/it_admin role bound to this Network.
    v_assigners := mesh_ops.workspace_role_assigners_v1(v_scope.workspace_id, v_actor, v_now);
    SELECT v_assigners || COALESCE(pg_catalog.array_agg(DISTINCT assignment.role_key), ARRAY[]::TEXT[])
    INTO v_network_assigners
    FROM mesh.workspace_role_assignment AS assignment
    JOIN mesh.workspace_membership AS actor_membership
      ON actor_membership.id = assignment.workspace_membership_id AND actor_membership.state = 'active'
     AND actor_membership.valid_from <= v_now
     AND (actor_membership.expires_at IS NULL OR actor_membership.expires_at > v_now)
    WHERE assignment.workspace_id = v_scope.workspace_id AND assignment.principal_id = v_actor
      AND assignment.network_id = v_scope.network_id AND assignment.role_key IN ('admin', 'it_admin')
      AND assignment.state = 'active' AND assignment.valid_from <= v_now
      AND (assignment.expires_at IS NULL OR assignment.expires_at > v_now);
    IF EXISTS (
        SELECT 1 FROM mesh.workspace_role_assignment AS assignment
        JOIN mesh.builtin_role AS role ON role.role_key = assignment.role_key
        WHERE assignment.workspace_id = v_scope.workspace_id
          AND assignment.workspace_membership_id = v_membership.workspace_membership_id
          AND assignment.state = 'active'
          AND ((assignment.network_id IS NULL AND NOT (role.assignable_by && v_assigners))
               OR (assignment.network_id = v_scope.network_id
                   AND NOT (role.assignable_by && v_network_assigners)))
    ) OR (pg_catalog.cardinality(v_assigners) = 0 AND EXISTS (
        SELECT 1 FROM mesh.role_binding AS binding
        WHERE binding.workspace_id = v_scope.workspace_id AND binding.network_id = v_scope.network_id
          AND binding.workspace_membership_id = v_membership.workspace_membership_id
          AND binding.state <> 'revoked'
    )) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'the member holds a role beyond the delegation ceiling';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.jsonb_array_elements(p_plan) AS item(value)
        WHERE NOT EXISTS (
            SELECT 1 FROM mesh.device AS device
            WHERE device.workspace_id = v_scope.workspace_id AND device.network_id = v_scope.network_id
              AND device.public_id = (item.value ->> 'device_id')::UUID
              AND device.ownership = 'member' AND device.owner_principal_id = v_member
              AND device.state IN ('active', 'suspended', 'expired') AND device.deleted_at IS NULL
        )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTM03', MESSAGE = 'the plan names a Device the member does not own here';
    END IF;
    v_before := mesh_ops.network_member_document_internal_v1(v_membership);
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    PERFORM 1 FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id
    FOR UPDATE;

    -- Devices, in a stable order: the plan's choice or, unnamed, revocation.
    v_workspace_device_owner := mesh_ops.workspace_device_principal_internal_v1(v_scope.workspace_id);
    FOR v_item IN
        SELECT device.id, plan.value AS choice
        FROM mesh.device AS device
        LEFT JOIN pg_catalog.jsonb_array_elements(p_plan) AS plan(value)
          ON (plan.value ->> 'device_id')::UUID = device.public_id
        WHERE device.workspace_id = v_scope.workspace_id AND device.network_id = v_scope.network_id
          AND device.ownership = 'member' AND device.owner_principal_id = v_member
          AND device.state IN ('active', 'suspended', 'expired') AND device.deleted_at IS NULL
        ORDER BY device.id
    LOOP
        SELECT * INTO STRICT v_device FROM mesh.device AS device WHERE device.id = v_item.id FOR UPDATE;
        v_action := COALESCE(v_item.choice ->> 'action', 'revoke');
        CASE v_action
        WHEN 'transfer_workspace' THEN
            -- An administrator's suspension stays; the member's and a
            -- pending handover end with the member's ownership.
            UPDATE mesh.device SET ownership = 'workspace',
                owner_principal_id = v_workspace_device_owner, custodian_principal_id = v_workspace_device_owner,
                expires_at = mesh_ops.device_never_expires_v1(),
                state = CASE WHEN state = 'expired' OR suspended_reason IN ('handover', 'member') THEN 'active'
                             ELSE state END,
                suspended_reason = CASE WHEN suspended_reason IN ('handover', 'member') THEN NULL
                                        ELSE suspended_reason END,
                handover_principal_id = NULL,
                session_generation = session_generation + 1, version = version + 1,
                updated_at = GREATEST(v_now, updated_at)
            WHERE id = v_device.id RETURNING * INTO v_device;
        WHEN 'transfer_member' THEN
            IF v_device.state = 'expired' OR v_device.suspended_reason = 'admin' THEN
                RAISE EXCEPTION USING ERRCODE = 'MTM03', MESSAGE = 'this Device cannot be handed over';
            END IF;
            SELECT principal.id INTO v_target
            FROM mesh.principal AS principal
            JOIN mesh.workspace_membership AS membership
              ON membership.workspace_id = v_scope.workspace_id AND membership.principal_id = principal.id
             AND membership.state = 'active'
             AND (membership.expires_at IS NULL OR membership.expires_at > v_now)
            JOIN mesh.network_membership AS network_member
              ON network_member.workspace_id = v_scope.workspace_id AND network_member.network_id = v_scope.network_id
             AND network_member.principal_id = principal.id AND network_member.state = 'active'
             AND (network_member.expires_at IS NULL OR network_member.expires_at > v_now)
            WHERE principal.public_id = (v_item.choice ->> 'new_owner_id')::UUID
              AND principal.id <> v_member AND principal.state = 'active' AND principal.deleted_at IS NULL;
            IF v_target IS NULL THEN
                RAISE EXCEPTION USING ERRCODE = 'MTM04',
                    MESSAGE = 'new owner is not an active member of this Network';
            END IF;
            UPDATE mesh.device SET state = 'suspended', suspended_reason = 'handover',
                handover_principal_id = v_target,
                session_generation = session_generation + 1, version = version + 1,
                updated_at = GREATEST(v_now, updated_at)
            WHERE id = v_device.id RETURNING * INTO v_device;
        ELSE
            PERFORM mesh_ops.revoke_member_device_internal_v1(v_device.id, 'network member removed', v_now);
            SELECT * INTO STRICT v_device FROM mesh.device AS device WHERE device.id = v_item.id;
        END CASE;
        v_devices := v_devices || pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object(
            'device_id', v_device.public_id,
            'hostname', v_device.hostname, 'action', v_action, 'state', v_device.state
        ));
    END LOOP;

    -- A Device of this Network waiting to be handed to the member stays
    -- suspended for an administrator to decide.
    UPDATE mesh.device AS device
    SET suspended_reason = 'admin', handover_principal_id = NULL,
        version = device.version + 1, updated_at = GREATEST(v_now, device.updated_at)
    WHERE device.workspace_id = v_scope.workspace_id AND device.network_id = v_scope.network_id
      AND device.handover_principal_id = v_member AND device.deleted_at IS NULL;
    GET DIAGNOSTICS v_handovers = ROW_COUNT;

    UPDATE mesh.enrollment_credential AS credential
    SET state = 'revoked', revoked_at = GREATEST(v_now, credential.valid_from),
        version = credential.version + 1, updated_at = GREATEST(v_now, credential.updated_at)
    WHERE credential.workspace_id = v_scope.workspace_id AND credential.network_id = v_scope.network_id
      AND credential.issuer_principal_id = v_member AND credential.state = 'active';
    GET DIAGNOSTICS v_keys = ROW_COUNT;

    UPDATE mesh.workspace_role_assignment AS assignment
    SET state = 'revoked', revoked_at = GREATEST(v_now, assignment.created_at),
        authority_generation = assignment.authority_generation + 1, version = assignment.version + 1,
        updated_at = GREATEST(v_now, assignment.updated_at)
    WHERE assignment.workspace_id = v_scope.workspace_id
      AND assignment.workspace_membership_id = v_membership.workspace_membership_id
      AND assignment.network_id = v_scope.network_id AND assignment.state = 'active';
    GET DIAGNOSTICS v_roles = ROW_COUNT;
    UPDATE mesh.role_binding AS binding
    SET state = 'revoked', authority_generation = binding.authority_generation + 1,
        version = binding.version + 1, updated_at = GREATEST(v_now, binding.updated_at)
    WHERE binding.workspace_id = v_scope.workspace_id AND binding.network_id = v_scope.network_id
      AND binding.workspace_membership_id = v_membership.workspace_membership_id AND binding.state <> 'revoked';
    GET DIAGNOSTICS v_bindings = ROW_COUNT;
    -- Schema 228: the member leaves the Network's user groups with it.
    WITH removed AS (
        DELETE FROM mesh.identity_group_member AS member
        USING mesh.identity_group AS identity_group
        WHERE identity_group.id = member.identity_group_id
          AND identity_group.workspace_id = v_scope.workspace_id
          AND identity_group.network_id = v_scope.network_id AND member.principal_id = v_member
        RETURNING member.identity_group_id
    )
    UPDATE mesh.identity_group AS identity_group
    SET member_count = identity_group.member_count - changed.removed,
        version = identity_group.version + 1, updated_at = GREATEST(v_now, identity_group.updated_at)
    FROM (SELECT removed.identity_group_id, pg_catalog.count(*)::INTEGER AS removed
          FROM removed GROUP BY removed.identity_group_id) AS changed
    WHERE identity_group.id = changed.identity_group_id;
    UPDATE mesh.network_membership
    SET state = 'revoked', authority_generation = authority_generation + 1, version = version + 1,
        updated_at = GREATEST(v_now, updated_at)
    WHERE id = v_membership.id
    RETURNING * INTO v_membership;

    v_advanced := mesh_ops.advance_member_networks_internal_v1(v_scope.workspace_id, ARRAY[v_scope.network_id]);

    RETURN pg_catalog.jsonb_build_object(
        'before', v_before,
        'after', mesh_ops.network_member_document_internal_v1(v_membership),
        'devices', v_devices,
        'handovers_cancelled', v_handovers,
        'keys_revoked', v_keys,
        'roles_revoked', v_roles + v_bindings,
        'networks', v_advanced,
        'authority', pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object(
            'binding_id', v_grant.role_binding_public_id,
            'role_id', v_grant.role_definition_public_id,
            'binding_generation', COALESCE(v_grant.binding_authority_generation, 0),
            'membership_generation', COALESCE(v_grant.membership_authority_generation, 0),
            'owner_generation', COALESCE(v_grant.workspace_owner_authority_generation, 0)
        ))
    );
END;
$function$;


-- The Workspace-wide entry points of schemas 121 and 124 now refuse: a stray
-- grant or an older image cannot reach a Workspace catalog that no longer
-- exists. Network v2 entry points replace them.

CREATE OR REPLACE FUNCTION mesh_ops.list_identity_groups_v1(
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
BEGIN
    RAISE EXCEPTION USING ERRCODE = '0A000',
        MESSAGE = 'user groups and tags belong to a Network since schema 228';
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.read_identity_group_members_v1(
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
BEGIN
    RAISE EXCEPTION USING ERRCODE = '0A000',
        MESSAGE = 'user groups and tags belong to a Network since schema 228';
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.change_identity_group_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_operation text, p_group_public_id uuid, p_expected_version bigint, p_name text, p_description text, p_change_public_id uuid, p_evaluated_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '0A000',
        MESSAGE = 'user groups and tags belong to a Network since schema 228';
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.change_identity_group_members_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_group_public_id uuid, p_expected_version bigint, p_add jsonb, p_remove uuid[], p_change_public_id uuid, p_evaluated_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '0A000',
        MESSAGE = 'user groups and tags belong to a Network since schema 228';
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.list_device_tags_v1(
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
BEGIN
    RAISE EXCEPTION USING ERRCODE = '0A000',
        MESSAGE = 'user groups and tags belong to a Network since schema 228';
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.change_device_tag_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_operation text, p_tag_public_id uuid, p_expected_version bigint, p_name text, p_description text, p_owner_group_ids uuid[], p_owner_roles text[], p_owner_row_ids uuid[], p_change_public_id uuid, p_evaluated_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '0A000',
        MESSAGE = 'user groups and tags belong to a Network since schema 228';
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.change_device_tags_v1(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_network_public_id uuid, p_device_public_id uuid, p_add jsonb, p_remove uuid[], p_change_public_id uuid, p_evaluated_at timestamp with time zone)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '0A000',
        MESSAGE = 'user groups and tags belong to a Network since schema 228';
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.read_network_tag_options_v1(
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
BEGIN
    RAISE EXCEPTION USING ERRCODE = '0A000',
        MESSAGE = 'user groups and tags belong to a Network since schema 228';
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.enforce_identity_catalog_transition_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.list_identity_groups_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_identity_groups_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.read_identity_group_members_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, INTEGER, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_identity_group_members_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, INTEGER, TIMESTAMPTZ
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.change_identity_group_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TEXT, UUID, BIGINT, TEXT, TEXT, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_identity_group_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TEXT, UUID, BIGINT, TEXT, TEXT, UUID, TIMESTAMPTZ
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.change_identity_group_members_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, BIGINT, JSONB, UUID[], UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_identity_group_members_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, BIGINT, JSONB, UUID[], UUID, TIMESTAMPTZ
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.list_device_tags_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_device_tags_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.change_device_tag_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TEXT, UUID, BIGINT, TEXT, TEXT, UUID[], TEXT[], UUID[], UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_device_tag_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TEXT, UUID, BIGINT, TEXT, TEXT, UUID[], TEXT[], UUID[], UUID, TIMESTAMPTZ
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.change_device_tags_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, JSONB, UUID[], UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_device_tags_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, JSONB, UUID[], UUID, TIMESTAMPTZ
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.read_network_tag_options_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_network_tag_options_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) TO mesh_runtime;
