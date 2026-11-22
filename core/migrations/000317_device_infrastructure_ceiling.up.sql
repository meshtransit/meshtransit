-- Schema 317 (TD-SEC-97): a Workspace Device that is a site router or an exit
-- node is the Network's infrastructure, not a member's machine. Until now
-- anyone with device.manage or device.transfer (it_admin included) could
-- suspend, revoke, rename or hand it over and so cut the Network's routes or
-- exit. device_actor_within_ceiling_v1 now answers yes for such a Device only
-- when the actor also holds route.withdraw in the Network (admin and
-- network_admin hold it, it_admin does not), and one that resolves a DNS
-- zone only when the actor holds dns.manage. Other Workspace Devices are as
-- before. change_device_tags_v2 (schema 228) let a tag owner with
-- device.manage (it_admin) tag the Workspace owner's or an admin's Device and
-- so change the rules that apply to it: it now also needs the same ceiling
-- for a Device not its own. The helper becomes VOLATILE: the permission
-- check it calls takes row locks, as resolve_network_permission_v2 does.
-- As schemas 181 and 314-316 did, it decides at the transaction's time;
-- p_evaluated_at is only checked to be sent (the api calls it directly).
-- The body is schema 295's otherwise, and change_device_tags_v2's schema
-- 228's but that check; replacing keeps their owners and grants.

CREATE OR REPLACE FUNCTION mesh_ops.device_actor_within_ceiling_v1(
    p_workspace_id BIGINT,
    p_network_id BIGINT,
    p_device_id BIGINT,
    p_actor_public_id UUID,
    p_evaluated_at TIMESTAMPTZ
)
RETURNS BOOLEAN
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_ownership TEXT;
    v_owner BIGINT;
    v_actor BIGINT;
    v_assigners TEXT[];
BEGIN
    IF p_workspace_id IS NULL OR p_network_id IS NULL OR p_device_id IS NULL OR p_actor_public_id IS NULL
        OR p_evaluated_at IS NULL
        -- Only about the transaction's own Network: the runtime may call this,
        -- so it never answers about another tenant.
        OR p_workspace_id IS DISTINCT FROM mesh_ops.current_workspace_id()
        OR p_network_id IS DISTINCT FROM mesh_ops.current_network_id() THEN
        RETURN FALSE;
    END IF;
    SELECT device.ownership, device.owner_principal_id INTO v_ownership, v_owner
    FROM mesh.device AS device
    WHERE device.id = p_device_id AND device.workspace_id = p_workspace_id AND device.network_id = p_network_id;
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;
    SELECT principal.id INTO v_actor FROM mesh.principal AS principal WHERE principal.public_id = p_actor_public_id;
    IF v_actor IS NULL THEN
        RETURN FALSE;
    END IF;
    IF v_ownership = 'workspace' THEN
        -- A site router or exit node carries the Network's routes: only one
        -- who may withdraw routes takes it out (TD-SEC-97).
        IF (EXISTS (SELECT 1 FROM mesh.network_site_router AS router
                    WHERE router.device_id = p_device_id AND router.network_id = p_network_id)
            OR EXISTS (SELECT 1 FROM mesh.network_exit_node AS node
                       WHERE node.device_id = p_device_id AND node.network_id = p_network_id))
            AND NOT mesh_ops.kubernetes_principal_holds_permission_internal_v1(
                v_actor, p_workspace_id, p_network_id, 'route.withdraw', pg_catalog.transaction_timestamp()) THEN
            RETURN FALSE;
        END IF;
        -- A DNS zone's resolver answers the Network's names: only one who
        -- may change DNS takes it out.
        IF mesh_ops.device_is_dns_resolver_internal_v1(p_device_id)
            AND NOT mesh_ops.kubernetes_principal_holds_permission_internal_v1(
                v_actor, p_workspace_id, p_network_id, 'dns.manage', pg_catalog.transaction_timestamp()) THEN
            RETURN FALSE;
        END IF;
        RETURN TRUE;
    END IF;
    IF v_owner = v_actor THEN
        RETURN TRUE;
    END IF;
    IF EXISTS (
        SELECT 1 FROM mesh.workspace AS workspace
        WHERE workspace.id = p_workspace_id AND workspace.owner_principal_id = v_owner
    ) THEN
        RETURN FALSE;
    END IF;
    v_assigners := mesh_ops.workspace_role_assigners_v1(p_workspace_id, v_actor, pg_catalog.transaction_timestamp());
    IF pg_catalog.cardinality(v_assigners) = 0 AND EXISTS (
        SELECT 1 FROM mesh.role_binding AS binding
        JOIN mesh.workspace_membership AS membership ON membership.id = binding.workspace_membership_id
        WHERE binding.workspace_id = p_workspace_id AND membership.principal_id = v_owner
          AND (binding.network_id IS NULL OR binding.network_id = p_network_id)
          AND binding.state <> 'revoked'
    ) THEN
        RETURN FALSE;
    END IF;
    RETURN NOT EXISTS (
        SELECT 1
        FROM mesh.workspace_role_assignment AS assignment
        JOIN mesh.builtin_role AS role ON role.role_key = assignment.role_key
        WHERE assignment.workspace_id = p_workspace_id AND assignment.principal_id = v_owner
          AND (assignment.network_id IS NULL OR assignment.network_id = p_network_id)
          AND assignment.state = 'active'
          AND (assignment.expires_at IS NULL OR assignment.expires_at > pg_catalog.transaction_timestamp())
          AND NOT (role.assignable_by && v_assigners)
    );
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.change_device_tags_v2(p_session_public_id uuid, p_deployment_public_id uuid, p_principal_public_id uuid, p_identity_subject_public_id uuid, p_session_version bigint, p_principal_authority_generation bigint, p_account_session_generation bigint, p_provider_generation bigint, p_deployment_recovery_epoch bigint, p_workspace_public_id uuid, p_network_public_id uuid, p_device_public_id uuid, p_add jsonb, p_remove uuid[], p_change_public_id uuid, p_evaluated_at timestamp with time zone)
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
        -- Schema 317 (TD-SEC-97): within the owner's ceiling, as the Device's
        -- lifecycle and revocation are.
        OR (v_device.owner_principal_id IS DISTINCT FROM v_principal AND NOT mesh_ops.device_actor_within_ceiling_v1(
            v_workspace, v_network, v_device.id, p_principal_public_id, v_now))
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
