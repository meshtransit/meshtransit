CREATE FUNCTION mesh_ops.read_network_revision_v1()
RETURNS TABLE (
    network_revision BIGINT,
    inventory_revision BIGINT,
    group_revision BIGINT,
    policy_revision BIGINT,
    dns_revision BIGINT,
    route_revision BIGINT,
    sharing_revision BIGINT,
    isolation_generation BIGINT
)
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
    SELECT
        revision.network_revision,
        revision.inventory_revision,
        revision.group_revision,
        revision.policy_revision,
        revision.dns_revision,
        revision.route_revision,
        revision.sharing_revision,
        revision.isolation_generation
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = mesh_ops.current_workspace_id()
      AND revision.network_id = mesh_ops.current_network_id()
$function$;

CREATE FUNCTION mesh_ops.read_resource_v2(p_resource_public_id UUID)
RETURNS TABLE (
    resource_public_id UUID,
    display_name TEXT,
    owner_principal_public_id UUID,
    custodian_principal_public_id UUID,
    device_public_id UUID,
    resource_state TEXT,
    resource_kind TEXT,
    provenance_kind TEXT,
    resource_version BIGINT,
    target_generation BIGINT,
    semantic_hash BYTEA,
    activated_network_revision BIGINT,
    inventory_revision BIGINT,
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ
)
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
    SELECT
        resource.public_id,
        resource.display_name,
        owner.public_id,
        custodian.public_id,
        device.public_id,
        resource.state,
        resource.kind,
        resource.provenance_kind,
        resource.version,
        resource.target_generation,
        resource.semantic_hash,
        resource.activated_network_revision,
        resource.inventory_revision,
        resource.created_at,
        resource.updated_at
    FROM mesh.resource AS resource
    JOIN mesh.principal AS owner ON owner.id = resource.owner_principal_id
    JOIN mesh.principal AS custodian ON custodian.id = resource.custodian_principal_id
    JOIN mesh.resource_device_target AS target
      ON target.workspace_id = resource.workspace_id
     AND target.network_id = resource.network_id
     AND target.resource_id = resource.id
     AND target.target_generation = resource.target_generation
     AND target.state = 'active'
    JOIN mesh.device AS device
      ON device.workspace_id = target.workspace_id
     AND device.network_id = target.network_id
     AND device.id = target.device_id
    WHERE resource.workspace_id = mesh_ops.current_workspace_id()
      AND resource.network_id = mesh_ops.current_network_id()
      AND resource.public_id = p_resource_public_id
$function$;

CREATE FUNCTION mesh_ops.list_resources_v1(
    p_after_public_id UUID,
    p_state TEXT,
    p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    result JSONB;
BEGIN
    IF p_limit < 1 OR p_limit > 101 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource page limit';
    END IF;
    IF p_state IS NOT NULL AND p_state NOT IN ('active', 'suspended', 'deleted') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource state filter';
    END IF;

    SELECT COALESCE(
        pg_catalog.jsonb_agg(candidate.payload ORDER BY candidate.public_id),
        '[]'::JSONB
    ) INTO result
    FROM (
        SELECT
            resource.public_id,
            pg_catalog.jsonb_build_object(
                'resource_public_id', resource.public_id,
                'display_name', resource.display_name,
                'owner_principal_public_id', owner.public_id,
                'custodian_principal_public_id', custodian.public_id,
                'device_public_id', device.public_id,
                'state', resource.state,
                'kind', resource.kind,
                'provenance_kind', resource.provenance_kind,
                'version', resource.version,
                'target_generation', resource.target_generation,
                'semantic_hash', pg_catalog.encode(resource.semantic_hash, 'hex'),
                'activated_network_revision', resource.activated_network_revision,
                'inventory_revision', resource.inventory_revision,
                'created_at', resource.created_at,
                'updated_at', resource.updated_at
            ) AS payload
        FROM mesh.resource AS resource
        JOIN mesh.principal AS owner ON owner.id = resource.owner_principal_id
        JOIN mesh.principal AS custodian ON custodian.id = resource.custodian_principal_id
        JOIN mesh.resource_device_target AS target
          ON target.workspace_id = resource.workspace_id
         AND target.network_id = resource.network_id
         AND target.resource_id = resource.id
         AND target.target_generation = resource.target_generation
         AND target.state = 'active'
        JOIN mesh.device AS device
          ON device.workspace_id = target.workspace_id
         AND device.network_id = target.network_id
         AND device.id = target.device_id
        WHERE resource.workspace_id = mesh_ops.current_workspace_id()
          AND resource.network_id = mesh_ops.current_network_id()
          AND (p_after_public_id IS NULL OR resource.public_id > p_after_public_id)
          AND (p_state IS NULL OR resource.state = p_state)
        ORDER BY resource.public_id
        LIMIT p_limit
    ) AS candidate;
    RETURN result;
END;
$function$;

CREATE FUNCTION mesh_ops.read_resource_group_v2(p_group_public_id UUID)
RETURNS TABLE (
    group_public_id UUID,
    display_name TEXT,
    owner_principal_public_id UUID,
    custodian_principal_public_id UUID,
    group_state TEXT,
    group_version BIGINT,
    definition_version BIGINT,
    semantic_hash BYTEA,
    activated_network_revision BIGINT,
    group_revision BIGINT,
    created_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ,
    members JSONB
)
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
    SELECT
        resource_group.public_id,
        resource_group.display_name,
        owner.public_id,
        custodian.public_id,
        resource_group.state,
        resource_group.version,
        resource_group.active_definition_version,
        version.semantic_hash,
        resource_group.activated_network_revision,
        resource_group.group_revision,
        resource_group.created_at,
        resource_group.updated_at,
        pg_catalog.jsonb_agg(
            pg_catalog.jsonb_build_object(
                'resource_public_id', resource.public_id,
                'resource_version', member.resource_version,
                'target_generation', member.target_generation
            ) ORDER BY member.ordinal
        )
    FROM mesh.resource_group AS resource_group
    JOIN mesh.principal AS owner ON owner.id = resource_group.owner_principal_id
    JOIN mesh.principal AS custodian ON custodian.id = resource_group.custodian_principal_id
    JOIN mesh.resource_group_version AS version
      ON version.workspace_id = resource_group.workspace_id
     AND version.network_id = resource_group.network_id
     AND version.resource_group_id = resource_group.id
     AND version.definition_version = resource_group.active_definition_version
    JOIN mesh.resource_group_version_member AS member
      ON member.workspace_id = version.workspace_id
     AND member.network_id = version.network_id
     AND member.resource_group_id = version.resource_group_id
     AND member.resource_group_version_id = version.id
    JOIN mesh.resource AS resource
      ON resource.workspace_id = member.workspace_id
     AND resource.network_id = member.network_id
     AND resource.id = member.resource_id
    WHERE resource_group.workspace_id = mesh_ops.current_workspace_id()
      AND resource_group.network_id = mesh_ops.current_network_id()
      AND resource_group.public_id = p_group_public_id
    GROUP BY
        resource_group.public_id,
        resource_group.display_name,
        owner.public_id,
        custodian.public_id,
        resource_group.state,
        resource_group.version,
        resource_group.active_definition_version,
        version.semantic_hash,
        resource_group.activated_network_revision,
        resource_group.group_revision,
        resource_group.created_at,
        resource_group.updated_at
$function$;

CREATE FUNCTION mesh_ops.list_resource_groups_v1(
    p_after_public_id UUID,
    p_state TEXT,
    p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    result JSONB;
BEGIN
    IF p_limit < 1 OR p_limit > 101 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource Group page limit';
    END IF;
    IF p_state IS NOT NULL AND p_state NOT IN ('active', 'suspended', 'deleted') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource Group state filter';
    END IF;

    SELECT COALESCE(
        pg_catalog.jsonb_agg(candidate.payload ORDER BY candidate.public_id),
        '[]'::JSONB
    ) INTO result
    FROM (
        SELECT
            resource_group.public_id,
            pg_catalog.jsonb_build_object(
                'group_public_id', resource_group.public_id,
                'display_name', resource_group.display_name,
                'owner_principal_public_id', owner.public_id,
                'custodian_principal_public_id', custodian.public_id,
                'state', resource_group.state,
                'version', resource_group.version,
                'definition_version', resource_group.active_definition_version,
                'semantic_hash', pg_catalog.encode(version.semantic_hash, 'hex'),
                'activated_network_revision', resource_group.activated_network_revision,
                'group_revision', resource_group.group_revision,
                'created_at', resource_group.created_at,
                'updated_at', resource_group.updated_at,
                'members', (
                    SELECT pg_catalog.jsonb_agg(
                        pg_catalog.jsonb_build_object(
                            'resource_public_id', resource.public_id,
                            'resource_version', member.resource_version,
                            'target_generation', member.target_generation
                        ) ORDER BY member.ordinal
                    )
                    FROM mesh.resource_group_version_member AS member
                    JOIN mesh.resource AS resource
                      ON resource.workspace_id = member.workspace_id
                     AND resource.network_id = member.network_id
                     AND resource.id = member.resource_id
                    WHERE member.workspace_id = version.workspace_id
                      AND member.network_id = version.network_id
                      AND member.resource_group_id = version.resource_group_id
                      AND member.resource_group_version_id = version.id
                )
            ) AS payload
        FROM mesh.resource_group AS resource_group
        JOIN mesh.principal AS owner ON owner.id = resource_group.owner_principal_id
        JOIN mesh.principal AS custodian ON custodian.id = resource_group.custodian_principal_id
        JOIN mesh.resource_group_version AS version
          ON version.workspace_id = resource_group.workspace_id
         AND version.network_id = resource_group.network_id
         AND version.resource_group_id = resource_group.id
         AND version.definition_version = resource_group.active_definition_version
        WHERE resource_group.workspace_id = mesh_ops.current_workspace_id()
          AND resource_group.network_id = mesh_ops.current_network_id()
          AND (p_after_public_id IS NULL OR resource_group.public_id > p_after_public_id)
          AND (p_state IS NULL OR resource_group.state = p_state)
        ORDER BY resource_group.public_id
        LIMIT p_limit
    ) AS candidate;
    RETURN result;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.read_network_revision_v1()
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.read_resource_v2(UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.list_resources_v1(UUID, TEXT, INTEGER)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.read_resource_group_v2(UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.list_resource_groups_v1(UUID, TEXT, INTEGER)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

GRANT EXECUTE ON FUNCTION mesh_ops.read_network_revision_v1() TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.read_resource_v2(UUID) TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.list_resources_v1(UUID, TEXT, INTEGER) TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.read_resource_group_v2(UUID) TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.list_resource_groups_v1(UUID, TEXT, INTEGER) TO mesh_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
