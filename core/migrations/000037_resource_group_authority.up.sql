CREATE TABLE mesh.resource (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    kind TEXT NOT NULL,
    display_name TEXT NOT NULL,
    name_key TEXT NOT NULL,
    owner_principal_id BIGINT NOT NULL,
    custodian_principal_id BIGINT NOT NULL,
    state TEXT NOT NULL,
    target_generation BIGINT NOT NULL DEFAULT 1 CHECK (target_generation > 0),
    provenance_kind TEXT NOT NULL,
    provenance_principal_id BIGINT NOT NULL,
    provenance_at TIMESTAMPTZ NOT NULL,
    semantic_hash BYTEA NOT NULL,
    activated_network_revision BIGINT NOT NULL CHECK (activated_network_revision > 1),
    inventory_revision BIGINT NOT NULL CHECK (inventory_revision > 1),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ,
    CONSTRAINT resource_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT resource_kind_check CHECK (kind IN ('device')),
    CONSTRAINT resource_display_name_check CHECK (
        pg_catalog.char_length(display_name) BETWEEN 1 AND 128
        AND display_name = pg_catalog.btrim(display_name)
    ),
    CONSTRAINT resource_name_key_check CHECK (
        pg_catalog.char_length(name_key) BETWEEN 1 AND 128
        AND name_key = pg_catalog.btrim(name_key)
        AND name_key = pg_catalog.lower(display_name)
    ),
    CONSTRAINT resource_state_check CHECK (state IN ('active', 'suspended', 'deleted')),
    CONSTRAINT resource_provenance_check CHECK (provenance_kind IN ('manual')),
    CONSTRAINT resource_semantic_hash_check CHECK (
        pg_catalog.octet_length(semantic_hash) = 32
        AND semantic_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
    ),
    CONSTRAINT resource_timestamps_check CHECK (
        updated_at >= created_at
        AND provenance_at = created_at
        AND (
            (state <> 'deleted' AND deleted_at IS NULL)
            OR (state = 'deleted' AND deleted_at IS NOT NULL AND deleted_at >= created_at)
        )
    ),
    CONSTRAINT resource_workspace_scope_fk FOREIGN KEY (deployment_id, workspace_id)
        REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT resource_network_scope_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT resource_owner_scope_fk FOREIGN KEY (deployment_id, owner_principal_id)
        REFERENCES mesh.principal (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT resource_custodian_scope_fk FOREIGN KEY (deployment_id, custodian_principal_id)
        REFERENCES mesh.principal (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT resource_provenance_scope_fk FOREIGN KEY (deployment_id, provenance_principal_id)
        REFERENCES mesh.principal (deployment_id, id) ON DELETE RESTRICT,
    UNIQUE (workspace_id, network_id, id)
);

CREATE UNIQUE INDEX resource_network_name_current_uidx
    ON mesh.resource (workspace_id, network_id, name_key)
    WHERE state <> 'deleted';
CREATE INDEX resource_network_state_id_idx
    ON mesh.resource (workspace_id, network_id, state, id);
CREATE INDEX resource_owner_state_idx
    ON mesh.resource (deployment_id, owner_principal_id, state, id);

CREATE TABLE mesh.resource_device_target (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    resource_id BIGINT NOT NULL,
    device_id BIGINT NOT NULL,
    target_generation BIGINT NOT NULL CHECK (target_generation > 0),
    state TEXT NOT NULL,
    bound_by_principal_id BIGINT NOT NULL,
    bound_at TIMESTAMPTZ NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT resource_device_target_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT resource_device_target_state_check CHECK (state IN ('active', 'superseded')),
    CONSTRAINT resource_device_target_timestamps_check CHECK (
        updated_at >= created_at AND bound_at = created_at
    ),
    CONSTRAINT resource_device_target_resource_scope_fk FOREIGN KEY (
        workspace_id, network_id, resource_id
    ) REFERENCES mesh.resource (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT resource_device_target_device_scope_fk FOREIGN KEY (
        workspace_id, network_id, device_id
    ) REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT resource_device_target_principal_fk FOREIGN KEY (bound_by_principal_id)
        REFERENCES mesh.principal (id) ON DELETE RESTRICT,
    UNIQUE (workspace_id, network_id, resource_id, target_generation),
    UNIQUE (workspace_id, network_id, id)
);

CREATE UNIQUE INDEX resource_device_target_active_resource_uidx
    ON mesh.resource_device_target (workspace_id, network_id, resource_id)
    WHERE state = 'active';
CREATE UNIQUE INDEX resource_device_target_active_device_uidx
    ON mesh.resource_device_target (workspace_id, network_id, device_id)
    WHERE state = 'active';

ALTER TABLE mesh.resource
ADD CONSTRAINT resource_active_target_generation_fk FOREIGN KEY (
    workspace_id, network_id, id, target_generation
) REFERENCES mesh.resource_device_target (
    workspace_id, network_id, resource_id, target_generation
) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE mesh.resource_group (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    display_name TEXT NOT NULL,
    name_key TEXT NOT NULL,
    owner_principal_id BIGINT NOT NULL,
    custodian_principal_id BIGINT NOT NULL,
    state TEXT NOT NULL,
    active_definition_version BIGINT NOT NULL DEFAULT 1 CHECK (active_definition_version > 0),
    semantic_hash BYTEA NOT NULL,
    activated_network_revision BIGINT NOT NULL CHECK (activated_network_revision > 1),
    group_revision BIGINT NOT NULL CHECK (group_revision > 1),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ,
    CONSTRAINT resource_group_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT resource_group_display_name_check CHECK (
        pg_catalog.char_length(display_name) BETWEEN 1 AND 128
        AND display_name = pg_catalog.btrim(display_name)
    ),
    CONSTRAINT resource_group_name_key_check CHECK (
        pg_catalog.char_length(name_key) BETWEEN 1 AND 128
        AND name_key = pg_catalog.btrim(name_key)
        AND name_key = pg_catalog.lower(display_name)
    ),
    CONSTRAINT resource_group_state_check CHECK (state IN ('active', 'suspended', 'deleted')),
    CONSTRAINT resource_group_semantic_hash_check CHECK (
        pg_catalog.octet_length(semantic_hash) = 32
        AND semantic_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
    ),
    CONSTRAINT resource_group_timestamps_check CHECK (
        updated_at >= created_at
        AND (
            (state <> 'deleted' AND deleted_at IS NULL)
            OR (state = 'deleted' AND deleted_at IS NOT NULL AND deleted_at >= created_at)
        )
    ),
    CONSTRAINT resource_group_workspace_scope_fk FOREIGN KEY (deployment_id, workspace_id)
        REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT resource_group_network_scope_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT resource_group_owner_scope_fk FOREIGN KEY (deployment_id, owner_principal_id)
        REFERENCES mesh.principal (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT resource_group_custodian_scope_fk FOREIGN KEY (deployment_id, custodian_principal_id)
        REFERENCES mesh.principal (deployment_id, id) ON DELETE RESTRICT,
    UNIQUE (workspace_id, network_id, id)
);

CREATE UNIQUE INDEX resource_group_network_name_current_uidx
    ON mesh.resource_group (workspace_id, network_id, name_key)
    WHERE state <> 'deleted';
CREATE INDEX resource_group_network_state_id_idx
    ON mesh.resource_group (workspace_id, network_id, state, id);

CREATE TABLE mesh.resource_group_version (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    resource_group_id BIGINT NOT NULL,
    definition_version BIGINT NOT NULL CHECK (definition_version > 0),
    semantic_hash BYTEA NOT NULL,
    member_count INTEGER NOT NULL CHECK (member_count BETWEEN 1 AND 256),
    created_by_principal_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version = 1),
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT resource_group_version_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT resource_group_version_semantic_hash_check CHECK (
        pg_catalog.octet_length(semantic_hash) = 32
        AND semantic_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
    ),
    CONSTRAINT resource_group_version_group_scope_fk FOREIGN KEY (
        workspace_id, network_id, resource_group_id
    ) REFERENCES mesh.resource_group (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT resource_group_version_principal_fk FOREIGN KEY (created_by_principal_id)
        REFERENCES mesh.principal (id) ON DELETE RESTRICT,
    UNIQUE (workspace_id, network_id, resource_group_id, definition_version),
    UNIQUE (
        workspace_id,
        network_id,
        resource_group_id,
        definition_version,
        semantic_hash
    ),
    UNIQUE (workspace_id, network_id, resource_group_id, id),
    UNIQUE (workspace_id, network_id, id)
);

ALTER TABLE mesh.resource_group
ADD CONSTRAINT resource_group_active_version_fk FOREIGN KEY (
    workspace_id, network_id, id, active_definition_version, semantic_hash
) REFERENCES mesh.resource_group_version (
    workspace_id, network_id, resource_group_id, definition_version, semantic_hash
) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE mesh.resource_group_version_member (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    resource_group_id BIGINT NOT NULL,
    resource_group_version_id BIGINT NOT NULL,
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 1 AND 256),
    resource_id BIGINT NOT NULL,
    resource_version BIGINT NOT NULL CHECK (resource_version > 0),
    target_generation BIGINT NOT NULL CHECK (target_generation > 0),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version = 1),
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT resource_group_member_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT resource_group_member_version_scope_fk FOREIGN KEY (
        workspace_id, network_id, resource_group_id, resource_group_version_id
    ) REFERENCES mesh.resource_group_version (
        workspace_id, network_id, resource_group_id, id
    ) ON DELETE RESTRICT,
    CONSTRAINT resource_group_member_resource_scope_fk FOREIGN KEY (
        workspace_id, network_id, resource_id
    ) REFERENCES mesh.resource (workspace_id, network_id, id) ON DELETE RESTRICT,
    UNIQUE (resource_group_version_id, ordinal),
    UNIQUE (resource_group_version_id, resource_id)
);

CREATE INDEX resource_group_member_resource_idx
    ON mesh.resource_group_version_member (workspace_id, network_id, resource_id, resource_group_id);

CREATE FUNCTION mesh_ops.enforce_resource_authority_transition()
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
        OR NEW.version <> OLD.version + 1
        OR NEW.updated_at < OLD.updated_at
        OR OLD.state = 'deleted' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource authority transition';
    END IF;
    IF TG_TABLE_NAME = 'resource' THEN
        IF OLD.kind <> NEW.kind
            OR OLD.owner_principal_id <> NEW.owner_principal_id
            OR OLD.custodian_principal_id <> NEW.custodian_principal_id
            OR OLD.provenance_kind <> NEW.provenance_kind
            OR OLD.provenance_principal_id <> NEW.provenance_principal_id
            OR OLD.provenance_at <> NEW.provenance_at
            OR OLD.activated_network_revision <> NEW.activated_network_revision
            OR OLD.inventory_revision <> NEW.inventory_revision
            OR NEW.target_generation < OLD.target_generation
            OR NEW.target_generation > OLD.target_generation + 1 THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource transition';
        END IF;
    ELSIF TG_TABLE_NAME = 'resource_group' THEN
        IF OLD.owner_principal_id <> NEW.owner_principal_id
            OR OLD.custodian_principal_id <> NEW.custodian_principal_id
            OR OLD.activated_network_revision <> NEW.activated_network_revision
            OR OLD.group_revision <> NEW.group_revision
            OR NEW.active_definition_version < OLD.active_definition_version
            OR NEW.active_definition_version > OLD.active_definition_version + 1 THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource Group transition';
        END IF;
    ELSE
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource trigger configuration';
    END IF;
    RETURN NEW;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.enforce_resource_authority_transition() FROM PUBLIC;

CREATE TRIGGER resource_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.resource
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_resource_authority_transition();
CREATE TRIGGER resource_device_target_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.resource_device_target
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_resource_authority_transition();
CREATE TRIGGER resource_group_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.resource_group
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_resource_authority_transition();
CREATE TRIGGER resource_group_version_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.resource_group_version
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_resource_authority_transition();
CREATE TRIGGER resource_group_member_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.resource_group_version_member
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_resource_authority_transition();

CREATE TRIGGER resource_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.resource
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('resource', 'public_id');
CREATE TRIGGER resource_device_target_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.resource_device_target
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('resource_device_target', 'public_id');
CREATE TRIGGER resource_group_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.resource_group
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('resource_group', 'public_id');
CREATE TRIGGER resource_group_version_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.resource_group_version
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('resource_group_version', 'public_id');
CREATE TRIGGER resource_group_member_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.resource_group_version_member
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('resource_group_version_member', 'public_id');

ALTER TABLE mesh.resource ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.resource FORCE ROW LEVEL SECURITY;
CREATE POLICY resource_migrator_policy ON mesh.resource TO mesh_migrator
    USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY resource_exact_scope_policy ON mesh.resource TO mesh_runtime
    USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    )
    WITH CHECK (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    );

ALTER TABLE mesh.resource_device_target ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.resource_device_target FORCE ROW LEVEL SECURITY;
CREATE POLICY resource_device_target_migrator_policy ON mesh.resource_device_target TO mesh_migrator
    USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY resource_device_target_exact_scope_policy ON mesh.resource_device_target TO mesh_runtime
    USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    )
    WITH CHECK (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    );

ALTER TABLE mesh.resource_group ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.resource_group FORCE ROW LEVEL SECURITY;
CREATE POLICY resource_group_migrator_policy ON mesh.resource_group TO mesh_migrator
    USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY resource_group_exact_scope_policy ON mesh.resource_group TO mesh_runtime
    USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    )
    WITH CHECK (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    );

ALTER TABLE mesh.resource_group_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.resource_group_version FORCE ROW LEVEL SECURITY;
CREATE POLICY resource_group_version_migrator_policy ON mesh.resource_group_version TO mesh_migrator
    USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY resource_group_version_exact_scope_policy ON mesh.resource_group_version TO mesh_runtime
    USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    )
    WITH CHECK (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    );

ALTER TABLE mesh.resource_group_version_member ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.resource_group_version_member FORCE ROW LEVEL SECURITY;
CREATE POLICY resource_group_member_migrator_policy ON mesh.resource_group_version_member TO mesh_migrator
    USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY resource_group_member_exact_scope_policy ON mesh.resource_group_version_member TO mesh_runtime
    USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    )
    WITH CHECK (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    );

CREATE FUNCTION mesh_ops.create_device_resource_v1(
    p_resource_public_id UUID,
    p_target_public_id UUID,
    p_expected_inventory_revision BIGINT,
    p_device_public_id UUID,
    p_actor_principal_public_id UUID,
    p_display_name TEXT,
    p_semantic_hash BYTEA,
    p_occurred_at TIMESTAMPTZ
)
RETURNS TABLE (
    network_revision BIGINT,
    inventory_revision BIGINT,
    resource_version BIGINT,
    target_generation BIGINT
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
    scoped_deployment_id BIGINT;
    actor_principal_id BIGINT;
    target_device_id BIGINT;
    new_resource_id BIGINT;
    current_network_revision BIGINT;
    current_inventory_revision BIGINT;
    advanced_network_revision BIGINT;
    advanced_inventory_revision BIGINT;
    new_resource_version BIGINT;
BEGIN
    scoped_workspace_id := mesh_ops.current_workspace_id();
    scoped_network_id := mesh_ops.current_network_id();
    IF p_resource_public_id IS NULL OR p_target_public_id IS NULL
        OR p_device_public_id IS NULL OR p_actor_principal_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_resource_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_target_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_device_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_actor_principal_public_id), 6) >> 4 <> 7
        OR p_expected_inventory_revision IS NULL OR p_expected_inventory_revision <= 0
        OR p_display_name IS NULL OR pg_catalog.char_length(p_display_name) NOT BETWEEN 1 AND 128
        OR p_display_name <> pg_catalog.btrim(p_display_name)
        OR p_semantic_hash IS NULL OR pg_catalog.octet_length(p_semantic_hash) <> 32
        OR p_semantic_hash = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_occurred_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Device Resource input';
    END IF;

    SELECT revision.network_revision, revision.inventory_revision
    INTO current_network_revision, current_inventory_revision
    FROM mesh_ops.lock_network_revision() AS revision;
    IF current_inventory_revision <> p_expected_inventory_revision THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Resource inventory revision changed';
    END IF;

    SELECT workspace.deployment_id, principal.id
    INTO scoped_deployment_id, actor_principal_id
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
    IF scoped_deployment_id IS NULL OR actor_principal_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Resource creator authority is unavailable';
    END IF;

    SELECT device.id INTO target_device_id
    FROM mesh.device AS device
    WHERE device.workspace_id = scoped_workspace_id
      AND device.network_id = scoped_network_id
      AND device.public_id = p_device_public_id
      AND device.state = 'active'
      AND device.deleted_at IS NULL
    FOR SHARE;
    IF target_device_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Device target changed or is unavailable';
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

    INSERT INTO mesh.resource (
        public_id, deployment_id, workspace_id, network_id, kind,
        display_name, name_key, owner_principal_id, custodian_principal_id,
        state, target_generation, provenance_kind, provenance_principal_id,
        provenance_at, semantic_hash, activated_network_revision, inventory_revision,
        created_at, updated_at
    ) VALUES (
        p_resource_public_id, scoped_deployment_id, scoped_workspace_id, scoped_network_id, 'device',
        p_display_name, pg_catalog.lower(p_display_name), actor_principal_id, actor_principal_id,
        'active', 1, 'manual', actor_principal_id,
        p_occurred_at, p_semantic_hash, advanced_network_revision, advanced_inventory_revision,
        p_occurred_at, p_occurred_at
    ) RETURNING id, version INTO new_resource_id, new_resource_version;

    INSERT INTO mesh.resource_device_target (
        public_id, workspace_id, network_id, resource_id, device_id,
        target_generation, state, bound_by_principal_id, bound_at, created_at, updated_at
    ) VALUES (
        p_target_public_id, scoped_workspace_id, scoped_network_id, new_resource_id, target_device_id,
        1, 'active', actor_principal_id, p_occurred_at, p_occurred_at, p_occurred_at
    );

    network_revision := advanced_network_revision;
    inventory_revision := advanced_inventory_revision;
    resource_version := new_resource_version;
    target_generation := 1;
    RETURN NEXT;
END;
$function$;

CREATE FUNCTION mesh_ops.create_resource_group_v1(
    p_group_public_id UUID,
    p_group_version_public_id UUID,
    p_expected_group_revision BIGINT,
    p_actor_principal_public_id UUID,
    p_display_name TEXT,
    p_semantic_hash BYTEA,
    p_occurred_at TIMESTAMPTZ,
    p_members JSONB
)
RETURNS TABLE (
    network_revision BIGINT,
    group_revision BIGINT,
    group_version BIGINT,
    definition_version BIGINT
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
    scoped_deployment_id BIGINT;
    actor_principal_id BIGINT;
    new_group_id BIGINT;
    new_group_version_id BIGINT;
    current_network_revision BIGINT;
    current_group_revision BIGINT;
    advanced_network_revision BIGINT;
    advanced_group_revision BIGINT;
    new_group_version BIGINT;
    expected_member_count INTEGER;
    resolved_member_count INTEGER;
BEGIN
    scoped_workspace_id := mesh_ops.current_workspace_id();
    scoped_network_id := mesh_ops.current_network_id();
    IF p_group_public_id IS NULL OR p_group_version_public_id IS NULL
        OR p_actor_principal_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_group_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_group_version_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_actor_principal_public_id), 6) >> 4 <> 7
        OR p_expected_group_revision IS NULL OR p_expected_group_revision <= 0
        OR p_display_name IS NULL OR pg_catalog.char_length(p_display_name) NOT BETWEEN 1 AND 128
        OR p_display_name <> pg_catalog.btrim(p_display_name)
        OR p_semantic_hash IS NULL OR pg_catalog.octet_length(p_semantic_hash) <> 32
        OR p_semantic_hash = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_occurred_at IS NULL OR p_members IS NULL
        OR pg_catalog.jsonb_typeof(p_members) <> 'array'
        OR pg_catalog.jsonb_array_length(p_members) NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource Group input';
    END IF;
    expected_member_count := pg_catalog.jsonb_array_length(p_members);
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.jsonb_to_recordset(p_members) AS member(
            member_public_id UUID,
            ordinal INTEGER,
            resource_public_id UUID,
            resource_version BIGINT,
            target_generation BIGINT
        )
        WHERE member.member_public_id IS NULL
           OR member.resource_public_id IS NULL
           OR pg_catalog.get_byte(pg_catalog.uuid_send(member.member_public_id), 6) >> 4 <> 7
           OR pg_catalog.get_byte(pg_catalog.uuid_send(member.resource_public_id), 6) >> 4 <> 7
           OR member.ordinal NOT BETWEEN 1 AND expected_member_count
           OR member.resource_version <= 0
           OR member.target_generation <= 0
    ) OR (
        SELECT pg_catalog.count(DISTINCT member.ordinal) <> expected_member_count
            OR pg_catalog.count(DISTINCT member.member_public_id) <> expected_member_count
            OR pg_catalog.count(DISTINCT member.resource_public_id) <> expected_member_count
        FROM pg_catalog.jsonb_to_recordset(p_members) AS member(
            member_public_id UUID,
            ordinal INTEGER,
            resource_public_id UUID,
            resource_version BIGINT,
            target_generation BIGINT
        )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource Group membership';
    END IF;

    SELECT revision.network_revision, revision.group_revision
    INTO current_network_revision, current_group_revision
    FROM mesh_ops.lock_network_revision() AS revision;
    IF current_group_revision <> p_expected_group_revision THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Resource Group revision changed';
    END IF;

    SELECT workspace.deployment_id, principal.id
    INTO scoped_deployment_id, actor_principal_id
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
    IF scoped_deployment_id IS NULL OR actor_principal_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Resource Group creator authority is unavailable';
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
    IF resolved_member_count <> expected_member_count THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Resource Group member changed or is unavailable';
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

    INSERT INTO mesh.resource_group (
        public_id, deployment_id, workspace_id, network_id,
        display_name, name_key, owner_principal_id, custodian_principal_id,
        state, active_definition_version, semantic_hash,
        activated_network_revision, group_revision, created_at, updated_at
    ) VALUES (
        p_group_public_id, scoped_deployment_id, scoped_workspace_id, scoped_network_id,
        p_display_name, pg_catalog.lower(p_display_name), actor_principal_id, actor_principal_id,
        'active', 1, p_semantic_hash,
        advanced_network_revision, advanced_group_revision, p_occurred_at, p_occurred_at
    ) RETURNING id, version INTO new_group_id, new_group_version;

    INSERT INTO mesh.resource_group_version (
        public_id, workspace_id, network_id, resource_group_id,
        definition_version, semantic_hash, member_count,
        created_by_principal_id, created_at
    ) VALUES (
        p_group_version_public_id, scoped_workspace_id, scoped_network_id, new_group_id,
        1, p_semantic_hash, expected_member_count,
        actor_principal_id, p_occurred_at
    ) RETURNING id INTO new_group_version_id;

    INSERT INTO mesh.resource_group_version_member (
        public_id, workspace_id, network_id, resource_group_id,
        resource_group_version_id, ordinal, resource_id,
        resource_version, target_generation, created_at
    )
    SELECT
        member.member_public_id,
        scoped_workspace_id,
        scoped_network_id,
        new_group_id,
        new_group_version_id,
        member.ordinal,
        resource.id,
        member.resource_version,
        member.target_generation,
        p_occurred_at
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

    network_revision := advanced_network_revision;
    group_revision := advanced_group_revision;
    group_version := new_group_version;
    definition_version := 1;
    RETURN NEXT;
END;
$function$;

CREATE FUNCTION mesh_ops.resolve_resource_v1(p_resource_public_id UUID)
RETURNS TABLE (
    resource_public_id UUID,
    display_name TEXT,
    owner_principal_public_id UUID,
    custodian_principal_public_id UUID,
    device_public_id UUID,
    resource_version BIGINT,
    target_generation BIGINT,
    semantic_hash BYTEA,
    state TEXT,
    activated_network_revision BIGINT,
    inventory_revision BIGINT
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
        resource.version,
        resource.target_generation,
        resource.semantic_hash,
        resource.state,
        resource.activated_network_revision,
        resource.inventory_revision
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

CREATE FUNCTION mesh_ops.resolve_resource_group_v1(p_group_public_id UUID)
RETURNS TABLE (
    group_public_id UUID,
    display_name TEXT,
    owner_principal_public_id UUID,
    custodian_principal_public_id UUID,
    group_version BIGINT,
    definition_version BIGINT,
    semantic_hash BYTEA,
    state TEXT,
    activated_network_revision BIGINT,
    group_revision BIGINT,
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
        resource_group.version,
        resource_group.active_definition_version,
        version.semantic_hash,
        resource_group.state,
        resource_group.activated_network_revision,
        resource_group.group_revision,
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
        resource_group.version,
        resource_group.active_definition_version,
        version.semantic_hash,
        resource_group.state,
        resource_group.activated_network_revision,
        resource_group.group_revision
$function$;

REVOKE ALL ON
    mesh.resource,
    mesh.resource_device_target,
    mesh.resource_group,
    mesh.resource_group_version,
    mesh.resource_group_version_member
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA mesh
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

REVOKE ALL ON FUNCTION mesh_ops.create_device_resource_v1(
    UUID, UUID, BIGINT, UUID, UUID, TEXT, BYTEA, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.create_resource_group_v1(
    UUID, UUID, BIGINT, UUID, TEXT, BYTEA, TIMESTAMPTZ, JSONB
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.resolve_resource_v1(UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.resolve_resource_group_v1(UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

GRANT EXECUTE ON FUNCTION mesh_ops.create_device_resource_v1(
    UUID, UUID, BIGINT, UUID, UUID, TEXT, BYTEA, TIMESTAMPTZ
) TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.create_resource_group_v1(
    UUID, UUID, BIGINT, UUID, TEXT, BYTEA, TIMESTAMPTZ, JSONB
) TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.resolve_resource_v1(UUID) TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.resolve_resource_group_v1(UUID) TO mesh_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
