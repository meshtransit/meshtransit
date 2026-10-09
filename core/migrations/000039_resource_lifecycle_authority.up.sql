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
    IF TG_TABLE_NAME IN (
        'resource_device_target',
        'resource_group_version',
        'resource_group_version_member'
    ) THEN
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
        OR OLD.semantic_hash <> NEW.semantic_hash
        OR OLD.created_at <> NEW.created_at
        OR NEW.version <> OLD.version + 1
        OR NEW.updated_at < OLD.updated_at
        OR NEW.activated_network_revision <= OLD.activated_network_revision
        OR OLD.state = 'deleted'
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
    IF TG_TABLE_NAME = 'resource' THEN
        IF OLD.kind <> NEW.kind
            OR OLD.target_generation <> NEW.target_generation
            OR OLD.provenance_kind <> NEW.provenance_kind
            OR OLD.provenance_principal_id <> NEW.provenance_principal_id
            OR OLD.provenance_at <> NEW.provenance_at
            OR NEW.inventory_revision <= OLD.inventory_revision THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource transition';
        END IF;
    ELSIF TG_TABLE_NAME = 'resource_group' THEN
        IF OLD.active_definition_version <> NEW.active_definition_version
            OR NEW.group_revision <= OLD.group_revision THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource Group transition';
        END IF;
    ELSE
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource trigger configuration';
    END IF;
    RETURN NEW;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.enforce_resource_authority_transition() FROM PUBLIC;

CREATE FUNCTION mesh_ops.transition_resource_lifecycle_v1(
    p_resource_public_id UUID,
    p_expected_resource_version BIGINT,
    p_target_state TEXT,
    p_actor_principal_public_id UUID,
    p_occurred_at TIMESTAMPTZ
)
RETURNS TABLE (
    network_revision BIGINT,
    inventory_revision BIGINT,
    resource_version BIGINT,
    resource_state TEXT,
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
    current_network_revision BIGINT;
    current_inventory_revision BIGINT;
    current_resource_id BIGINT;
    current_resource_version BIGINT;
    current_resource_state TEXT;
    current_semantic_hash BYTEA;
    advanced_network_revision BIGINT;
    advanced_inventory_revision BIGINT;
    advanced_resource_version BIGINT;
BEGIN
    scoped_workspace_id := mesh_ops.current_workspace_id();
    scoped_network_id := mesh_ops.current_network_id();
    IF p_resource_public_id IS NULL OR p_actor_principal_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_resource_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_actor_principal_public_id), 6) >> 4 <> 7
        OR p_expected_resource_version IS NULL OR p_expected_resource_version <= 0
        OR p_target_state IS NULL OR p_target_state NOT IN ('active', 'suspended', 'deleted')
        OR p_occurred_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource lifecycle input';
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
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Resource lifecycle authority is unavailable';
    END IF;

    SELECT resource.id, resource.version, resource.state, resource.semantic_hash
    INTO current_resource_id, current_resource_version, current_resource_state, current_semantic_hash
    FROM mesh.resource AS resource
    WHERE resource.workspace_id = scoped_workspace_id
      AND resource.network_id = scoped_network_id
      AND resource.public_id = p_resource_public_id
    FOR UPDATE;
    IF current_resource_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT404', MESSAGE = 'Resource is unavailable';
    END IF;
    IF current_resource_version <> p_expected_resource_version THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'Resource version changed';
    END IF;
    IF current_resource_state = 'deleted'
        OR (p_target_state = 'active' AND current_resource_state <> 'suspended')
        OR (p_target_state = 'suspended' AND current_resource_state <> 'active')
        OR p_target_state = current_resource_state THEN
        RAISE EXCEPTION USING ERRCODE = 'MT003', MESSAGE = 'invalid Resource lifecycle transition';
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

    UPDATE mesh.resource AS resource
    SET state = p_target_state,
        activated_network_revision = advanced_network_revision,
        inventory_revision = advanced_inventory_revision,
        version = resource.version + 1,
        updated_at = p_occurred_at,
        deleted_at = CASE WHEN p_target_state = 'deleted' THEN p_occurred_at ELSE NULL END
    WHERE resource.id = current_resource_id
      AND resource.version = current_resource_version
    RETURNING resource.version INTO advanced_resource_version;
    IF advanced_resource_version IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'Resource version changed';
    END IF;

    network_revision := advanced_network_revision;
    inventory_revision := advanced_inventory_revision;
    resource_version := advanced_resource_version;
    resource_state := p_target_state;
    semantic_hash := current_semantic_hash;
    RETURN NEXT;
END;
$function$;

CREATE FUNCTION mesh_ops.transition_resource_group_lifecycle_v1(
    p_group_public_id UUID,
    p_expected_group_version BIGINT,
    p_target_state TEXT,
    p_actor_principal_public_id UUID,
    p_occurred_at TIMESTAMPTZ
)
RETURNS TABLE (
    network_revision BIGINT,
    group_revision BIGINT,
    group_version BIGINT,
    group_state TEXT,
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
    current_network_revision BIGINT;
    current_group_revision BIGINT;
    current_group_id BIGINT;
    current_group_version BIGINT;
    current_group_state TEXT;
    current_semantic_hash BYTEA;
    advanced_network_revision BIGINT;
    advanced_group_revision BIGINT;
    advanced_group_version BIGINT;
BEGIN
    scoped_workspace_id := mesh_ops.current_workspace_id();
    scoped_network_id := mesh_ops.current_network_id();
    IF p_group_public_id IS NULL OR p_actor_principal_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_group_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_actor_principal_public_id), 6) >> 4 <> 7
        OR p_expected_group_version IS NULL OR p_expected_group_version <= 0
        OR p_target_state IS NULL OR p_target_state NOT IN ('active', 'suspended', 'deleted')
        OR p_occurred_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource Group lifecycle input';
    END IF;

    SELECT revision.network_revision, revision.group_revision
    INTO current_network_revision, current_group_revision
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
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Resource Group lifecycle authority is unavailable';
    END IF;

    SELECT resource_group.id, resource_group.version,
           resource_group.state, resource_group.semantic_hash
    INTO current_group_id, current_group_version, current_group_state, current_semantic_hash
    FROM mesh.resource_group AS resource_group
    WHERE resource_group.workspace_id = scoped_workspace_id
      AND resource_group.network_id = scoped_network_id
      AND resource_group.public_id = p_group_public_id
    FOR UPDATE;
    IF current_group_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT404', MESSAGE = 'Resource Group is unavailable';
    END IF;
    IF current_group_version <> p_expected_group_version THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'Resource Group version changed';
    END IF;
    IF current_group_state = 'deleted'
        OR (p_target_state = 'active' AND current_group_state <> 'suspended')
        OR (p_target_state = 'suspended' AND current_group_state <> 'active')
        OR p_target_state = current_group_state THEN
        RAISE EXCEPTION USING ERRCODE = 'MT003', MESSAGE = 'invalid Resource Group lifecycle transition';
    END IF;

    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        group_revision = revision.group_revision + 1,
        updated_at = pg_catalog.clock_timestamp()
    WHERE revision.workspace_id = scoped_workspace_id
      AND revision.network_id = scoped_network_id
      AND revision.network_revision = current_network_revision
      AND revision.group_revision = current_group_revision
    RETURNING revision.network_revision, revision.group_revision
    INTO advanced_network_revision, advanced_group_revision;
    IF advanced_network_revision IS NULL OR advanced_group_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Resource Group revision changed';
    END IF;

    UPDATE mesh.resource_group AS resource_group
    SET state = p_target_state,
        activated_network_revision = advanced_network_revision,
        group_revision = advanced_group_revision,
        version = resource_group.version + 1,
        updated_at = p_occurred_at,
        deleted_at = CASE WHEN p_target_state = 'deleted' THEN p_occurred_at ELSE NULL END
    WHERE resource_group.id = current_group_id
      AND resource_group.version = current_group_version
    RETURNING resource_group.version INTO advanced_group_version;
    IF advanced_group_version IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'Resource Group version changed';
    END IF;

    network_revision := advanced_network_revision;
    group_revision := advanced_group_revision;
    group_version := advanced_group_version;
    group_state := p_target_state;
    semantic_hash := current_semantic_hash;
    RETURN NEXT;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.transition_resource_lifecycle_v1(
    UUID, BIGINT, TEXT, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.transition_resource_group_lifecycle_v1(
    UUID, BIGINT, TEXT, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

GRANT EXECUTE ON FUNCTION mesh_ops.transition_resource_lifecycle_v1(
    UUID, BIGINT, TEXT, UUID, TIMESTAMPTZ
) TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.transition_resource_group_lifecycle_v1(
    UUID, BIGINT, TEXT, UUID, TIMESTAMPTZ
) TO mesh_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
