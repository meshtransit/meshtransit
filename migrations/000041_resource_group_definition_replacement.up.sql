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
        IF NEW.group_revision <= OLD.group_revision THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource Group revision';
        END IF;
        IF OLD.state <> NEW.state THEN
            IF OLD.semantic_hash <> NEW.semantic_hash
                OR OLD.active_definition_version <> NEW.active_definition_version
                OR NOT (
                    (OLD.state = 'active' AND NEW.state IN ('suspended', 'deleted'))
                    OR (OLD.state = 'suspended' AND NEW.state IN ('active', 'deleted'))
                )
                OR (NEW.state = 'deleted' AND (
                    NEW.deleted_at IS NULL OR NEW.deleted_at <> NEW.updated_at
                ))
                OR (NEW.state <> 'deleted' AND NEW.deleted_at IS NOT NULL) THEN
                RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource Group lifecycle transition';
            END IF;
        ELSIF NEW.active_definition_version = OLD.active_definition_version + 1 THEN
            IF NEW.semantic_hash = OLD.semantic_hash
                OR NEW.deleted_at IS NOT NULL THEN
                RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource Group replacement';
            END IF;
        ELSE
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource Group transition';
        END IF;
    ELSE
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource trigger configuration';
    END IF;
    RETURN NEW;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.enforce_resource_authority_transition() FROM PUBLIC;

CREATE FUNCTION mesh_ops.resource_group_replace_impact_v1(
    p_group_public_id UUID,
    p_members JSONB,
    p_lock BOOLEAN
)
RETURNS TABLE (
    display_name TEXT,
    owner_principal_public_id UUID,
    custodian_principal_public_id UUID,
    group_state TEXT,
    group_version BIGINT,
    current_definition_version BIGINT,
    current_semantic_hash BYTEA,
    current_members JSONB,
    approval_required BOOLEAN
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
    current_group_id BIGINT;
    proposed_member_count INTEGER;
    resolved_member_count INTEGER;
BEGIN
    scoped_workspace_id := mesh_ops.current_workspace_id();
    scoped_network_id := mesh_ops.current_network_id();
    IF p_group_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_group_public_id), 6) >> 4 <> 7
        OR p_members IS NULL OR pg_catalog.jsonb_typeof(p_members) <> 'array'
        OR pg_catalog.jsonb_array_length(p_members) NOT BETWEEN 1 AND 256
        OR p_lock IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource Group replacement impact input';
    END IF;
    proposed_member_count := pg_catalog.jsonb_array_length(p_members);
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.jsonb_array_elements(p_members) AS entry(value)
        WHERE pg_catalog.jsonb_typeof(entry.value) <> 'object'
           OR NOT entry.value ? 'resource_public_id'
           OR NOT entry.value ? 'resource_version'
           OR NOT entry.value ? 'target_generation'
           OR EXISTS (
               SELECT 1
               FROM pg_catalog.jsonb_object_keys(entry.value) AS field(key)
               WHERE field.key NOT IN (
                   'resource_public_id', 'resource_version', 'target_generation'
               )
           )
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.jsonb_to_recordset(p_members) AS member(
            resource_public_id UUID,
            resource_version BIGINT,
            target_generation BIGINT
        )
        WHERE member.resource_public_id IS NULL
           OR pg_catalog.get_byte(pg_catalog.uuid_send(member.resource_public_id), 6) >> 4 <> 7
           OR member.resource_version <= 0
           OR member.target_generation <= 0
    ) OR (
        SELECT pg_catalog.count(DISTINCT member.resource_public_id) <> proposed_member_count
        FROM pg_catalog.jsonb_to_recordset(p_members) AS member(
            resource_public_id UUID,
            resource_version BIGINT,
            target_generation BIGINT
        )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid proposed Resource Group membership';
    END IF;

    IF p_lock THEN
        SELECT resource_group.id INTO current_group_id
        FROM mesh.resource_group AS resource_group
        WHERE resource_group.workspace_id = scoped_workspace_id
          AND resource_group.network_id = scoped_network_id
          AND resource_group.public_id = p_group_public_id
        FOR UPDATE;
    ELSE
        SELECT resource_group.id INTO current_group_id
        FROM mesh.resource_group AS resource_group
        WHERE resource_group.workspace_id = scoped_workspace_id
          AND resource_group.network_id = scoped_network_id
          AND resource_group.public_id = p_group_public_id
        FOR SHARE;
    END IF;
    IF current_group_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT404', MESSAGE = 'Resource Group is unavailable';
    END IF;

    PERFORM resource.id
    FROM pg_catalog.jsonb_to_recordset(p_members) AS member(
        resource_public_id UUID,
        resource_version BIGINT,
        target_generation BIGINT
    )
    JOIN mesh.resource AS resource
      ON resource.workspace_id = scoped_workspace_id
     AND resource.network_id = scoped_network_id
     AND resource.public_id = member.resource_public_id
    ORDER BY resource.id
    FOR SHARE OF resource;

    SELECT pg_catalog.count(*) INTO resolved_member_count
    FROM pg_catalog.jsonb_to_recordset(p_members) AS member(
        resource_public_id UUID,
        resource_version BIGINT,
        target_generation BIGINT
    )
    JOIN mesh.resource AS resource
      ON resource.workspace_id = scoped_workspace_id
     AND resource.network_id = scoped_network_id
     AND resource.public_id = member.resource_public_id
     AND resource.version = member.resource_version
     AND resource.target_generation = member.target_generation
     AND resource.state = 'active'
    JOIN mesh.resource_device_target AS target
      ON target.workspace_id = resource.workspace_id
     AND target.network_id = resource.network_id
     AND target.resource_id = resource.id
     AND target.target_generation = member.target_generation
     AND target.state = 'active';
    IF resolved_member_count <> proposed_member_count THEN
        RAISE EXCEPTION USING ERRCODE = 'MT006', MESSAGE = 'Resource Group member changed or is unavailable';
    END IF;

    RETURN QUERY
    SELECT resource_group.display_name,
           owner.public_id,
           custodian.public_id,
           resource_group.state,
           resource_group.version,
           resource_group.active_definition_version,
           resource_group.semantic_hash,
           pg_catalog.jsonb_agg(
               pg_catalog.jsonb_build_object(
                   'resource_public_id', resource.public_id,
                   'resource_version', member.resource_version,
                   'target_generation', member.target_generation
               ) ORDER BY member.ordinal
           ),
           FALSE
    FROM mesh.resource_group AS resource_group
    JOIN mesh.principal AS owner ON owner.id = resource_group.owner_principal_id
    JOIN mesh.principal AS custodian ON custodian.id = resource_group.custodian_principal_id
    JOIN mesh.resource_group_version AS version
      ON version.workspace_id = resource_group.workspace_id
     AND version.network_id = resource_group.network_id
     AND version.resource_group_id = resource_group.id
     AND version.definition_version = resource_group.active_definition_version
     AND version.semantic_hash = resource_group.semantic_hash
    JOIN mesh.resource_group_version_member AS member
      ON member.workspace_id = version.workspace_id
     AND member.network_id = version.network_id
     AND member.resource_group_id = version.resource_group_id
     AND member.resource_group_version_id = version.id
    JOIN mesh.resource AS resource
      ON resource.workspace_id = member.workspace_id
     AND resource.network_id = member.network_id
     AND resource.id = member.resource_id
    WHERE resource_group.id = current_group_id
    GROUP BY resource_group.display_name, owner.public_id, custodian.public_id,
             resource_group.state, resource_group.version,
             resource_group.active_definition_version, resource_group.semantic_hash;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.resource_group_replace_impact_v1(UUID, JSONB, BOOLEAN)
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.preview_resource_group_replace_v1(
    p_group_public_id UUID,
    p_members JSONB
)
RETURNS TABLE (
    display_name TEXT,
    owner_principal_public_id UUID,
    custodian_principal_public_id UUID,
    group_state TEXT,
    group_version BIGINT,
    current_definition_version BIGINT,
    current_semantic_hash BYTEA,
    current_members JSONB,
    approval_required BOOLEAN
)
LANGUAGE sql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
    SELECT * FROM mesh_ops.resource_group_replace_impact_v1(
        p_group_public_id, p_members, FALSE
    )
$function$;

CREATE FUNCTION mesh_ops.lock_resource_group_replace_v1(
    p_group_public_id UUID,
    p_members JSONB
)
RETURNS TABLE (
    display_name TEXT,
    owner_principal_public_id UUID,
    custodian_principal_public_id UUID,
    group_state TEXT,
    group_version BIGINT,
    current_definition_version BIGINT,
    current_semantic_hash BYTEA,
    current_members JSONB,
    approval_required BOOLEAN
)
LANGUAGE sql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
    SELECT * FROM mesh_ops.resource_group_replace_impact_v1(
        p_group_public_id, p_members, TRUE
    )
$function$;

CREATE FUNCTION mesh_ops.replace_resource_group_definition_v1(
    p_group_public_id UUID,
    p_expected_group_version BIGINT,
    p_group_version_public_id UUID,
    p_actor_principal_public_id UUID,
    p_semantic_hash BYTEA,
    p_occurred_at TIMESTAMPTZ,
    p_members JSONB
)
RETURNS TABLE (
    network_revision BIGINT,
    group_revision BIGINT,
    group_version BIGINT,
    definition_version BIGINT,
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
    current_definition_version BIGINT;
    new_group_version_id BIGINT;
    proposed_member_count INTEGER;
    resolved_member_count INTEGER;
    advanced_network_revision BIGINT;
    advanced_group_revision BIGINT;
    advanced_group_version BIGINT;
    advanced_definition_version BIGINT;
BEGIN
    scoped_workspace_id := mesh_ops.current_workspace_id();
    scoped_network_id := mesh_ops.current_network_id();
    IF p_group_public_id IS NULL OR p_group_version_public_id IS NULL
        OR p_actor_principal_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_group_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_group_version_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_actor_principal_public_id), 6) >> 4 <> 7
        OR p_expected_group_version IS NULL OR p_expected_group_version <= 0
        OR p_semantic_hash IS NULL OR pg_catalog.octet_length(p_semantic_hash) <> 32
        OR p_semantic_hash = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_occurred_at IS NULL OR p_members IS NULL
        OR pg_catalog.jsonb_typeof(p_members) <> 'array'
        OR pg_catalog.jsonb_array_length(p_members) NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource Group replacement input';
    END IF;
    proposed_member_count := pg_catalog.jsonb_array_length(p_members);
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.jsonb_array_elements(p_members) AS entry(value)
        WHERE pg_catalog.jsonb_typeof(entry.value) <> 'object'
           OR NOT entry.value ? 'member_public_id'
           OR NOT entry.value ? 'ordinal'
           OR NOT entry.value ? 'resource_public_id'
           OR NOT entry.value ? 'resource_version'
           OR NOT entry.value ? 'target_generation'
           OR EXISTS (
               SELECT 1
               FROM pg_catalog.jsonb_object_keys(entry.value) AS field(key)
               WHERE field.key NOT IN (
                   'member_public_id', 'ordinal', 'resource_public_id',
                   'resource_version', 'target_generation'
               )
           )
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.jsonb_to_recordset(p_members) AS member(
            member_public_id UUID,
            ordinal INTEGER,
            resource_public_id UUID,
            resource_version BIGINT,
            target_generation BIGINT
        )
        WHERE member.member_public_id IS NULL OR member.resource_public_id IS NULL
           OR pg_catalog.get_byte(pg_catalog.uuid_send(member.member_public_id), 6) >> 4 <> 7
           OR pg_catalog.get_byte(pg_catalog.uuid_send(member.resource_public_id), 6) >> 4 <> 7
           OR member.ordinal NOT BETWEEN 1 AND proposed_member_count
           OR member.resource_version <= 0 OR member.target_generation <= 0
    ) OR (
        SELECT pg_catalog.count(DISTINCT member.ordinal) <> proposed_member_count
            OR pg_catalog.count(DISTINCT member.member_public_id) <> proposed_member_count
            OR pg_catalog.count(DISTINCT member.resource_public_id) <> proposed_member_count
        FROM pg_catalog.jsonb_to_recordset(p_members) AS member(
            member_public_id UUID,
            ordinal INTEGER,
            resource_public_id UUID,
            resource_version BIGINT,
            target_generation BIGINT
        )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid replacement Resource Group membership';
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
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Resource Group replacement authority is unavailable';
    END IF;

    SELECT resource_group.id, resource_group.version, resource_group.state,
           resource_group.active_definition_version
    INTO current_group_id, current_group_version, current_group_state,
         current_definition_version
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
    IF current_group_state = 'deleted' OR current_definition_version = 9223372036854775807 THEN
        RAISE EXCEPTION USING ERRCODE = 'MT004', MESSAGE = 'Resource Group cannot be replaced';
    END IF;

    PERFORM resource.id
    FROM pg_catalog.jsonb_to_recordset(p_members) AS member(
        member_public_id UUID,
        ordinal INTEGER,
        resource_public_id UUID,
        resource_version BIGINT,
        target_generation BIGINT
    )
    JOIN mesh.resource AS resource
      ON resource.workspace_id = scoped_workspace_id
     AND resource.network_id = scoped_network_id
     AND resource.public_id = member.resource_public_id
    ORDER BY resource.id
    FOR SHARE OF resource;

    SELECT pg_catalog.count(*) INTO resolved_member_count
    FROM pg_catalog.jsonb_to_recordset(p_members) AS member(
        member_public_id UUID,
        ordinal INTEGER,
        resource_public_id UUID,
        resource_version BIGINT,
        target_generation BIGINT
    )
    JOIN mesh.resource AS resource
      ON resource.workspace_id = scoped_workspace_id
     AND resource.network_id = scoped_network_id
     AND resource.public_id = member.resource_public_id
     AND resource.version = member.resource_version
     AND resource.target_generation = member.target_generation
     AND resource.state = 'active'
    JOIN mesh.resource_device_target AS target
      ON target.workspace_id = resource.workspace_id
     AND target.network_id = resource.network_id
     AND target.resource_id = resource.id
     AND target.target_generation = member.target_generation
     AND target.state = 'active';
    IF resolved_member_count <> proposed_member_count THEN
        RAISE EXCEPTION USING ERRCODE = 'MT006', MESSAGE = 'Resource Group member changed or is unavailable';
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

    advanced_definition_version := current_definition_version + 1;
    INSERT INTO mesh.resource_group_version (
        public_id, workspace_id, network_id, resource_group_id,
        definition_version, semantic_hash, member_count,
        created_by_principal_id, created_at
    ) VALUES (
        p_group_version_public_id, scoped_workspace_id, scoped_network_id, current_group_id,
        advanced_definition_version, p_semantic_hash, proposed_member_count,
        actor_principal_id, p_occurred_at
    ) RETURNING id INTO new_group_version_id;

    INSERT INTO mesh.resource_group_version_member (
        public_id, workspace_id, network_id, resource_group_id,
        resource_group_version_id, ordinal, resource_id,
        resource_version, target_generation, created_at
    )
    SELECT member.member_public_id, scoped_workspace_id, scoped_network_id,
           current_group_id, new_group_version_id, member.ordinal, resource.id,
           member.resource_version, member.target_generation, p_occurred_at
    FROM pg_catalog.jsonb_to_recordset(p_members) AS member(
        member_public_id UUID,
        ordinal INTEGER,
        resource_public_id UUID,
        resource_version BIGINT,
        target_generation BIGINT
    )
    JOIN mesh.resource AS resource
      ON resource.workspace_id = scoped_workspace_id
     AND resource.network_id = scoped_network_id
     AND resource.public_id = member.resource_public_id
    ORDER BY member.ordinal;

    UPDATE mesh.resource_group AS resource_group
    SET active_definition_version = advanced_definition_version,
        semantic_hash = p_semantic_hash,
        activated_network_revision = advanced_network_revision,
        group_revision = advanced_group_revision,
        version = resource_group.version + 1,
        updated_at = p_occurred_at
    WHERE resource_group.id = current_group_id
      AND resource_group.version = current_group_version
    RETURNING resource_group.version INTO advanced_group_version;
    IF advanced_group_version IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'Resource Group version changed';
    END IF;

    network_revision := advanced_network_revision;
    group_revision := advanced_group_revision;
    group_version := advanced_group_version;
    definition_version := advanced_definition_version;
    semantic_hash := p_semantic_hash;
    RETURN NEXT;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.preview_resource_group_replace_v1(UUID, JSONB)
FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.lock_resource_group_replace_v1(UUID, JSONB)
FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.replace_resource_group_definition_v1(
    UUID, BIGINT, UUID, UUID, BYTEA, TIMESTAMPTZ, JSONB
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

GRANT EXECUTE ON FUNCTION mesh_ops.preview_resource_group_replace_v1(UUID, JSONB)
TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.lock_resource_group_replace_v1(UUID, JSONB)
TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.replace_resource_group_definition_v1(
    UUID, BIGINT, UUID, UUID, BYTEA, TIMESTAMPTZ, JSONB
) TO mesh_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
