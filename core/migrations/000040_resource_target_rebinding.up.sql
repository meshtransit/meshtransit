CREATE OR REPLACE FUNCTION mesh_ops.enforce_resource_authority_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Resource authority is retained';
    END IF;
    IF TG_OP = 'INSERT' THEN
        RETURN NEW;
    END IF;
    IF TG_TABLE_NAME = 'resource_device_target' THEN
        IF OLD.public_id <> NEW.public_id
            OR OLD.workspace_id <> NEW.workspace_id
            OR OLD.network_id <> NEW.network_id
            OR OLD.resource_id <> NEW.resource_id
            OR OLD.device_id <> NEW.device_id
            OR OLD.target_generation <> NEW.target_generation
            OR OLD.bound_by_principal_id <> NEW.bound_by_principal_id
            OR OLD.bound_at <> NEW.bound_at
            OR OLD.created_at <> NEW.created_at
            OR OLD.state <> 'active'
            OR NEW.state <> 'superseded'
            OR NEW.version <> OLD.version + 1
            OR NEW.updated_at < OLD.updated_at THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource target transition';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_TABLE_NAME IN ('resource_group_version', 'resource_group_version_member') THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'immutable Resource authority cannot change';
    END IF;
    IF OLD.public_id <> NEW.public_id
        OR OLD.deployment_id <> NEW.deployment_id
        OR OLD.workspace_id <> NEW.workspace_id
        OR OLD.network_id <> NEW.network_id
        OR OLD.display_name <> NEW.display_name
        OR OLD.name_key <> NEW.name_key
        OR OLD.owner_principal_id <> NEW.owner_principal_id
        OR OLD.custodian_principal_id <> NEW.custodian_principal_id
        OR OLD.created_at <> NEW.created_at
        OR NEW.version <> OLD.version + 1
        OR NEW.updated_at < OLD.updated_at
        OR NEW.activated_network_revision <= OLD.activated_network_revision
        OR OLD.state = 'deleted' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource authority transition';
    END IF;
    IF TG_TABLE_NAME = 'resource' THEN
        IF OLD.kind <> NEW.kind
            OR OLD.provenance_kind <> NEW.provenance_kind
            OR OLD.provenance_principal_id <> NEW.provenance_principal_id
            OR OLD.provenance_at <> NEW.provenance_at
            OR NEW.inventory_revision <= OLD.inventory_revision THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource transition';
        END IF;
        IF OLD.state <> NEW.state THEN
            IF OLD.semantic_hash <> NEW.semantic_hash
                OR OLD.target_generation <> NEW.target_generation
                OR NOT (
                    (OLD.state = 'active' AND NEW.state IN ('suspended', 'deleted'))
                    OR (OLD.state = 'suspended' AND NEW.state IN ('active', 'deleted'))
                )
                OR (NEW.state = 'deleted' AND (
                    NEW.deleted_at IS NULL OR NEW.deleted_at <> NEW.updated_at
                ))
                OR (NEW.state <> 'deleted' AND NEW.deleted_at IS NOT NULL) THEN
                RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource lifecycle transition';
            END IF;
        ELSIF NEW.target_generation = OLD.target_generation + 1 THEN
            IF NEW.semantic_hash = OLD.semantic_hash
                OR NEW.deleted_at IS NOT NULL THEN
                RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource rebind transition';
            END IF;
        ELSE
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource transition';
        END IF;
    ELSIF TG_TABLE_NAME = 'resource_group' THEN
        IF OLD.semantic_hash <> NEW.semantic_hash
            OR OLD.active_definition_version <> NEW.active_definition_version
            OR NEW.group_revision <= OLD.group_revision
            OR NOT (
                (OLD.state = 'active' AND NEW.state IN ('suspended', 'deleted'))
                OR (OLD.state = 'suspended' AND NEW.state IN ('active', 'deleted'))
            )
            OR (NEW.state = 'deleted' AND (
                NEW.deleted_at IS NULL OR NEW.deleted_at <> NEW.updated_at
            ))
            OR (NEW.state <> 'deleted' AND NEW.deleted_at IS NOT NULL) THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource Group transition';
        END IF;
    ELSE
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource trigger configuration';
    END IF;
    RETURN NEW;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.enforce_resource_authority_transition() FROM PUBLIC;

CREATE FUNCTION mesh_ops.preview_device_resource_rebind_v1(
    p_resource_public_id UUID,
    p_device_public_id UUID
)
RETURNS TABLE (
    display_name TEXT,
    owner_principal_public_id UUID,
    custodian_principal_public_id UUID,
    resource_state TEXT,
    resource_version BIGINT,
    current_target_generation BIGINT,
    current_semantic_hash BYTEA,
    current_device_public_id UUID,
    proposed_device_public_id UUID,
    proposed_device_state TEXT,
    proposed_device_already_bound BOOLEAN,
    affected_resource_group_ids JSONB,
    approval_required BOOLEAN
)
LANGUAGE sql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
    WITH current_resource AS MATERIALIZED (
        SELECT resource.id, resource.display_name,
               owner.public_id AS owner_public_id,
               custodian.public_id AS custodian_public_id,
               resource.state, resource.version, resource.target_generation,
               resource.semantic_hash,
               current_device.public_id AS current_device_public_id
        FROM mesh.resource AS resource
        JOIN mesh.resource_device_target AS target
          ON target.workspace_id = resource.workspace_id
         AND target.network_id = resource.network_id
         AND target.resource_id = resource.id
         AND target.target_generation = resource.target_generation
         AND target.state = 'active'
        JOIN mesh.device AS current_device ON current_device.id = target.device_id
        JOIN mesh.principal AS owner ON owner.id = resource.owner_principal_id
        JOIN mesh.principal AS custodian ON custodian.id = resource.custodian_principal_id
        WHERE resource.workspace_id = mesh_ops.current_workspace_id()
          AND resource.network_id = mesh_ops.current_network_id()
          AND resource.public_id = p_resource_public_id
          AND resource.kind = 'device'
        FOR SHARE OF resource, target
    ), proposed_device AS MATERIALIZED (
        SELECT device.public_id, device.state,
               EXISTS (
                   SELECT 1
                   FROM mesh.resource_device_target AS bound_target
                   WHERE bound_target.workspace_id = device.workspace_id
                     AND bound_target.network_id = device.network_id
                     AND bound_target.device_id = device.id
                     AND bound_target.state = 'active'
               ) AS already_bound
        FROM mesh.device AS device
        WHERE device.workspace_id = mesh_ops.current_workspace_id()
          AND device.network_id = mesh_ops.current_network_id()
          AND device.public_id = p_device_public_id
        FOR SHARE OF device
    ), affected_groups AS (
        SELECT resource_group.public_id
        FROM current_resource
        JOIN mesh.resource_group_version_member AS member
          ON member.workspace_id = mesh_ops.current_workspace_id()
         AND member.network_id = mesh_ops.current_network_id()
         AND member.resource_id = current_resource.id
         AND member.target_generation = current_resource.target_generation
        JOIN mesh.resource_group AS resource_group
          ON resource_group.workspace_id = member.workspace_id
         AND resource_group.network_id = member.network_id
         AND resource_group.id = member.resource_group_id
         AND resource_group.state <> 'deleted'
        JOIN mesh.resource_group_version AS definition
          ON definition.workspace_id = resource_group.workspace_id
         AND definition.network_id = resource_group.network_id
         AND definition.resource_group_id = resource_group.id
         AND definition.id = member.resource_group_version_id
         AND definition.definition_version = resource_group.active_definition_version
        ORDER BY resource_group.public_id
        LIMIT 257
    )
    SELECT current_resource.display_name, current_resource.owner_public_id,
           current_resource.custodian_public_id, current_resource.state,
           current_resource.version, current_resource.target_generation,
           current_resource.semantic_hash, current_resource.current_device_public_id,
           proposed_device.public_id, proposed_device.state, proposed_device.already_bound,
           COALESCE((
               SELECT pg_catalog.jsonb_agg(affected_groups.public_id ORDER BY affected_groups.public_id)
               FROM affected_groups
           ), '[]'::JSONB),
           FALSE
    FROM current_resource
    CROSS JOIN proposed_device
$function$;

CREATE FUNCTION mesh_ops.lock_device_resource_rebind_v1(
    p_resource_public_id UUID,
    p_device_public_id UUID
)
RETURNS TABLE (
    display_name TEXT,
    owner_principal_public_id UUID,
    custodian_principal_public_id UUID,
    resource_state TEXT,
    resource_version BIGINT,
    current_target_generation BIGINT,
    current_semantic_hash BYTEA,
    current_device_public_id UUID,
    proposed_device_public_id UUID,
    proposed_device_state TEXT,
    proposed_device_already_bound BOOLEAN,
    affected_resource_group_ids JSONB,
    approval_required BOOLEAN
)
LANGUAGE sql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
    WITH current_resource AS MATERIALIZED (
        SELECT resource.id, resource.display_name,
               owner.public_id AS owner_public_id,
               custodian.public_id AS custodian_public_id,
               resource.state, resource.version, resource.target_generation,
               resource.semantic_hash,
               current_device.public_id AS current_device_public_id
        FROM mesh.resource AS resource
        JOIN mesh.resource_device_target AS target
          ON target.workspace_id = resource.workspace_id
         AND target.network_id = resource.network_id
         AND target.resource_id = resource.id
         AND target.target_generation = resource.target_generation
         AND target.state = 'active'
        JOIN mesh.device AS current_device ON current_device.id = target.device_id
        JOIN mesh.principal AS owner ON owner.id = resource.owner_principal_id
        JOIN mesh.principal AS custodian ON custodian.id = resource.custodian_principal_id
        WHERE resource.workspace_id = mesh_ops.current_workspace_id()
          AND resource.network_id = mesh_ops.current_network_id()
          AND resource.public_id = p_resource_public_id
          AND resource.kind = 'device'
        FOR UPDATE OF resource, target
    ), proposed_device AS MATERIALIZED (
        SELECT device.public_id, device.state,
               EXISTS (
                   SELECT 1
                   FROM mesh.resource_device_target AS bound_target
                   WHERE bound_target.workspace_id = device.workspace_id
                     AND bound_target.network_id = device.network_id
                     AND bound_target.device_id = device.id
                     AND bound_target.state = 'active'
               ) AS already_bound
        FROM mesh.device AS device
        WHERE device.workspace_id = mesh_ops.current_workspace_id()
          AND device.network_id = mesh_ops.current_network_id()
          AND device.public_id = p_device_public_id
        FOR SHARE OF device
    ), affected_groups AS (
        SELECT resource_group.public_id
        FROM current_resource
        JOIN mesh.resource_group_version_member AS member
          ON member.workspace_id = mesh_ops.current_workspace_id()
         AND member.network_id = mesh_ops.current_network_id()
         AND member.resource_id = current_resource.id
         AND member.target_generation = current_resource.target_generation
        JOIN mesh.resource_group AS resource_group
          ON resource_group.workspace_id = member.workspace_id
         AND resource_group.network_id = member.network_id
         AND resource_group.id = member.resource_group_id
         AND resource_group.state <> 'deleted'
        JOIN mesh.resource_group_version AS definition
          ON definition.workspace_id = resource_group.workspace_id
         AND definition.network_id = resource_group.network_id
         AND definition.resource_group_id = resource_group.id
         AND definition.id = member.resource_group_version_id
         AND definition.definition_version = resource_group.active_definition_version
        ORDER BY resource_group.public_id
        LIMIT 257
    )
    SELECT current_resource.display_name, current_resource.owner_public_id,
           current_resource.custodian_public_id, current_resource.state,
           current_resource.version, current_resource.target_generation,
           current_resource.semantic_hash, current_resource.current_device_public_id,
           proposed_device.public_id, proposed_device.state, proposed_device.already_bound,
           COALESCE((
               SELECT pg_catalog.jsonb_agg(affected_groups.public_id ORDER BY affected_groups.public_id)
               FROM affected_groups
           ), '[]'::JSONB),
           FALSE
    FROM current_resource
    CROSS JOIN proposed_device
$function$;

REVOKE ALL ON FUNCTION mesh_ops.preview_device_resource_rebind_v1(UUID, UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.lock_device_resource_rebind_v1(UUID, UUID) FROM PUBLIC;

CREATE FUNCTION mesh_ops.rebind_device_resource_v1(
    p_resource_public_id UUID,
    p_expected_resource_version BIGINT,
    p_target_public_id UUID,
    p_device_public_id UUID,
    p_actor_principal_public_id UUID,
    p_semantic_hash BYTEA,
    p_occurred_at TIMESTAMPTZ
)
RETURNS TABLE (
    network_revision BIGINT,
    inventory_revision BIGINT,
    resource_version BIGINT,
    target_generation BIGINT,
    semantic_hash BYTEA
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
    actor_principal_id BIGINT;
    replacement_device_id BIGINT;
    current_network_revision BIGINT;
    current_inventory_revision BIGINT;
    current_resource_id BIGINT;
    current_resource_version BIGINT;
    current_resource_state TEXT;
    current_target_generation BIGINT;
    current_target_id BIGINT;
    current_device_id BIGINT;
    advanced_network_revision BIGINT;
    advanced_inventory_revision BIGINT;
    advanced_resource_version BIGINT;
    advanced_target_generation BIGINT;
BEGIN
    scoped_workspace_id := mesh_ops.current_workspace_id();
    scoped_network_id := mesh_ops.current_network_id();
    IF p_resource_public_id IS NULL OR p_target_public_id IS NULL
        OR p_device_public_id IS NULL OR p_actor_principal_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_resource_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_target_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_device_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_actor_principal_public_id), 6) >> 4 <> 7
        OR p_expected_resource_version IS NULL OR p_expected_resource_version <= 0
        OR p_semantic_hash IS NULL OR pg_catalog.octet_length(p_semantic_hash) <> 32
        OR p_semantic_hash = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_occurred_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource rebind input';
    END IF;

    SELECT revision.network_revision, revision.inventory_revision
    INTO current_network_revision, current_inventory_revision
    FROM mesh_ops.lock_network_revision() AS revision;

    SELECT principal.id INTO actor_principal_id
    FROM mesh.workspace AS workspace
    JOIN mesh.principal AS principal
      ON principal.deployment_id = workspace.deployment_id
     AND principal.public_id = p_actor_principal_public_id
     AND principal.state = 'active'
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = workspace.deployment_id
     AND membership.workspace_id = workspace.id
     AND membership.principal_id = principal.id
     AND membership.state = 'active'
     AND membership.valid_from <= p_occurred_at
     AND (membership.expires_at IS NULL OR membership.expires_at > p_occurred_at)
    WHERE workspace.id = scoped_workspace_id
      AND workspace.state = 'active'
    FOR SHARE OF workspace, principal, membership;
    IF actor_principal_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Resource rebind authority is unavailable';
    END IF;

    SELECT resource.id, resource.version, resource.state, resource.target_generation
    INTO current_resource_id, current_resource_version, current_resource_state, current_target_generation
    FROM mesh.resource AS resource
    WHERE resource.workspace_id = scoped_workspace_id
      AND resource.network_id = scoped_network_id
      AND resource.public_id = p_resource_public_id
      AND resource.kind = 'device'
    FOR UPDATE;
    IF current_resource_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT404', MESSAGE = 'Resource is unavailable';
    END IF;
    IF current_resource_version <> p_expected_resource_version THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'Resource version changed';
    END IF;
    IF current_resource_state = 'deleted' OR current_target_generation = 9223372036854775807 THEN
        RAISE EXCEPTION USING ERRCODE = 'MT004', MESSAGE = 'Resource cannot be rebound';
    END IF;

    SELECT target.id, target.device_id
    INTO current_target_id, current_device_id
    FROM mesh.resource_device_target AS target
    WHERE target.workspace_id = scoped_workspace_id
      AND target.network_id = scoped_network_id
      AND target.resource_id = current_resource_id
      AND target.target_generation = current_target_generation
      AND target.state = 'active'
    FOR UPDATE;
    IF current_target_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'active Resource target is unavailable';
    END IF;

    SELECT device.id INTO replacement_device_id
    FROM mesh.device AS device
    WHERE device.workspace_id = scoped_workspace_id
      AND device.network_id = scoped_network_id
      AND device.public_id = p_device_public_id
      AND device.state = 'active'
    FOR SHARE;
    IF replacement_device_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT404', MESSAGE = 'Device is unavailable';
    END IF;
    IF replacement_device_id = current_device_id OR EXISTS (
        SELECT 1
        FROM mesh.resource_device_target AS target
        WHERE target.workspace_id = scoped_workspace_id
          AND target.network_id = scoped_network_id
          AND target.device_id = replacement_device_id
          AND target.state = 'active'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MT005', MESSAGE = 'Device target is already bound';
    END IF;

    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        inventory_revision = revision.inventory_revision + 1,
        updated_at = pg_catalog.clock_timestamp()
    WHERE revision.workspace_id = scoped_workspace_id
      AND revision.network_id = scoped_network_id
      AND revision.network_revision = current_network_revision
      AND revision.inventory_revision = current_inventory_revision
    RETURNING revision.network_revision, revision.inventory_revision
    INTO advanced_network_revision, advanced_inventory_revision;
    IF advanced_network_revision IS NULL OR advanced_inventory_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Resource inventory revision changed';
    END IF;

    UPDATE mesh.resource_device_target AS target
    SET state = 'superseded',
        version = target.version + 1,
        updated_at = p_occurred_at
    WHERE target.id = current_target_id
      AND target.state = 'active';
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MT005', MESSAGE = 'Device target changed';
    END IF;

    advanced_target_generation := current_target_generation + 1;
    INSERT INTO mesh.resource_device_target (
        public_id, workspace_id, network_id, resource_id, device_id,
        target_generation, state, bound_by_principal_id, bound_at,
        version, created_at, updated_at
    ) VALUES (
        p_target_public_id, scoped_workspace_id, scoped_network_id, current_resource_id,
        replacement_device_id, advanced_target_generation, 'active', actor_principal_id,
        p_occurred_at, 1, p_occurred_at, p_occurred_at
    );

    UPDATE mesh.resource AS resource
    SET target_generation = advanced_target_generation,
        semantic_hash = p_semantic_hash,
        activated_network_revision = advanced_network_revision,
        inventory_revision = advanced_inventory_revision,
        version = resource.version + 1,
        updated_at = p_occurred_at
    WHERE resource.id = current_resource_id
      AND resource.version = current_resource_version
    RETURNING resource.version INTO advanced_resource_version;
    IF advanced_resource_version IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'Resource version changed';
    END IF;

    network_revision := advanced_network_revision;
    inventory_revision := advanced_inventory_revision;
    resource_version := advanced_resource_version;
    target_generation := advanced_target_generation;
    semantic_hash := p_semantic_hash;
    RETURN NEXT;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.rebind_device_resource_v1(
    UUID, BIGINT, UUID, UUID, UUID, BYTEA, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

GRANT EXECUTE ON FUNCTION mesh_ops.rebind_device_resource_v1(
    UUID, BIGINT, UUID, UUID, UUID, BYTEA, TIMESTAMPTZ
) TO mesh_runtime;

GRANT EXECUTE ON FUNCTION mesh_ops.preview_device_resource_rebind_v1(UUID, UUID)
TO mesh_runtime;

GRANT EXECUTE ON FUNCTION mesh_ops.lock_device_resource_rebind_v1(UUID, UUID)
TO mesh_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
