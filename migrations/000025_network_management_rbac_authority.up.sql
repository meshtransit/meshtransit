DO $database_privileges$
BEGIN
    EXECUTE pg_catalog.format(
        'REVOKE ALL ON DATABASE %I FROM PUBLIC',
        pg_catalog.current_database()
    );
END;
$database_privileges$;

CREATE TABLE mesh.workspace_membership (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    principal_id BIGINT NOT NULL,
    state TEXT NOT NULL,
    authority_generation BIGINT NOT NULL DEFAULT 1 CHECK (authority_generation > 0),
    valid_from TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT workspace_membership_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT workspace_membership_state_check CHECK (
        state IN ('active', 'suspended', 'revoked')
    ),
    CONSTRAINT workspace_membership_validity_check CHECK (
        expires_at IS NULL OR expires_at > valid_from
    ),
    CONSTRAINT workspace_membership_timestamps_check CHECK (updated_at >= created_at),
    CONSTRAINT workspace_membership_workspace_scope_fk FOREIGN KEY (
        deployment_id,
        workspace_id
    ) REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT workspace_membership_principal_scope_fk FOREIGN KEY (
        deployment_id,
        principal_id
    ) REFERENCES mesh.principal (deployment_id, id) ON DELETE RESTRICT,
    UNIQUE (deployment_id, workspace_id, principal_id, id)
);

CREATE UNIQUE INDEX workspace_membership_current_uidx
    ON mesh.workspace_membership (deployment_id, workspace_id, principal_id)
    WHERE state <> 'revoked';
CREATE INDEX workspace_membership_principal_state_idx
    ON mesh.workspace_membership (deployment_id, principal_id, state, workspace_id);

CREATE TABLE mesh.role_definition (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    role_key TEXT NOT NULL,
    display_name TEXT NOT NULL,
    kind TEXT NOT NULL,
    state TEXT NOT NULL,
    authority_generation BIGINT NOT NULL DEFAULT 1 CHECK (authority_generation > 0),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT role_definition_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT role_definition_key_check CHECK (
        pg_catalog.char_length(role_key) BETWEEN 3 AND 64
        AND role_key = pg_catalog.btrim(role_key)
        AND role_key ~ '^[a-z][a-z0-9_]*$'
    ),
    CONSTRAINT role_definition_display_name_check CHECK (
        pg_catalog.char_length(display_name) BETWEEN 1 AND 128
        AND display_name = pg_catalog.btrim(display_name)
    ),
    CONSTRAINT role_definition_kind_check CHECK (kind IN ('built_in', 'custom')),
    CONSTRAINT role_definition_state_check CHECK (state IN ('active', 'revoked')),
    CONSTRAINT role_definition_timestamps_check CHECK (updated_at >= created_at),
    CONSTRAINT role_definition_workspace_scope_fk FOREIGN KEY (
        deployment_id,
        workspace_id
    ) REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    UNIQUE (deployment_id, workspace_id, id)
);

CREATE UNIQUE INDEX role_definition_active_key_uidx
    ON mesh.role_definition (deployment_id, workspace_id, role_key)
    WHERE state = 'active';
CREATE INDEX role_definition_workspace_state_idx
    ON mesh.role_definition (workspace_id, state, id);

CREATE TABLE mesh.role_permission (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    role_definition_id BIGINT NOT NULL,
    permission_id BIGINT NOT NULL,
    state TEXT NOT NULL DEFAULT 'active',
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT role_permission_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT role_permission_role_scope_fk FOREIGN KEY (
        deployment_id,
        workspace_id,
        role_definition_id
    ) REFERENCES mesh.role_definition (deployment_id, workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT role_permission_permission_fk FOREIGN KEY (permission_id)
        REFERENCES mesh.permission (id) ON DELETE RESTRICT,
    CONSTRAINT role_permission_state_check CHECK (state IN ('active', 'revoked')),
    CONSTRAINT role_permission_timestamps_check CHECK (updated_at >= created_at)
);

CREATE UNIQUE INDEX role_permission_active_uidx
    ON mesh.role_permission (role_definition_id, permission_id)
    WHERE state = 'active';
CREATE INDEX role_permission_workspace_role_idx
    ON mesh.role_permission (workspace_id, role_definition_id, permission_id);

CREATE TABLE mesh.role_binding (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    principal_id BIGINT NOT NULL,
    workspace_membership_id BIGINT NOT NULL,
    role_definition_id BIGINT NOT NULL,
    state TEXT NOT NULL,
    authority_generation BIGINT NOT NULL DEFAULT 1 CHECK (authority_generation > 0),
    valid_from TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT role_binding_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT role_binding_state_check CHECK (
        state IN ('active', 'suspended', 'revoked')
    ),
    CONSTRAINT role_binding_validity_check CHECK (
        expires_at IS NULL OR expires_at > valid_from
    ),
    CONSTRAINT role_binding_timestamps_check CHECK (updated_at >= created_at),
    CONSTRAINT role_binding_network_scope_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT role_binding_membership_scope_fk FOREIGN KEY (
        deployment_id,
        workspace_id,
        principal_id,
        workspace_membership_id
    ) REFERENCES mesh.workspace_membership (
        deployment_id,
        workspace_id,
        principal_id,
        id
    ) ON DELETE RESTRICT,
    CONSTRAINT role_binding_role_scope_fk FOREIGN KEY (
        deployment_id,
        workspace_id,
        role_definition_id
    ) REFERENCES mesh.role_definition (deployment_id, workspace_id, id) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX role_binding_current_uidx
    ON mesh.role_binding (workspace_id, network_id, principal_id, role_definition_id)
    WHERE state <> 'revoked';
CREATE INDEX role_binding_principal_scope_state_idx
    ON mesh.role_binding (
        deployment_id,
        principal_id,
        workspace_id,
        network_id,
        state,
        id
    );

CREATE FUNCTION mesh_ops.enforce_management_rbac_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'management RBAC authority is retained';
    END IF;
    IF TG_OP = 'INSERT' THEN
        RETURN NEW;
    END IF;

    IF OLD.public_id <> NEW.public_id
        OR OLD.deployment_id <> NEW.deployment_id
        OR OLD.workspace_id <> NEW.workspace_id
        OR NEW.version <> OLD.version + 1
        OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'invalid management RBAC authority transition';
    END IF;

    IF TG_TABLE_NAME = 'workspace_membership' THEN
        IF OLD.principal_id <> NEW.principal_id
            OR NEW.authority_generation <> OLD.authority_generation + 1
            OR OLD.state = 'revoked'
            OR (OLD.state = 'active' AND NEW.state NOT IN ('active', 'suspended', 'revoked'))
            OR (OLD.state = 'suspended' AND NEW.state NOT IN ('active', 'suspended', 'revoked')) THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Workspace membership transition';
        END IF;
    ELSIF TG_TABLE_NAME = 'role_definition' THEN
        IF OLD.role_key <> NEW.role_key
            OR OLD.kind <> NEW.kind
            OR NEW.authority_generation <> OLD.authority_generation + 1
            OR OLD.state = 'revoked' THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid RoleDefinition transition';
        END IF;
    ELSIF TG_TABLE_NAME = 'role_binding' THEN
        IF OLD.network_id <> NEW.network_id
            OR OLD.principal_id <> NEW.principal_id
            OR OLD.workspace_membership_id <> NEW.workspace_membership_id
            OR OLD.role_definition_id <> NEW.role_definition_id
            OR NEW.authority_generation <> OLD.authority_generation + 1
            OR OLD.state = 'revoked' THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid RoleBinding transition';
        END IF;
    ELSIF TG_TABLE_NAME = 'role_permission' THEN
        IF OLD.role_definition_id <> NEW.role_definition_id
            OR OLD.permission_id <> NEW.permission_id
            OR OLD.state = 'revoked'
            OR (OLD.state = 'active' AND NEW.state NOT IN ('active', 'revoked')) THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid RolePermission transition';
        END IF;
    ELSE
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'invalid management RBAC trigger configuration';
    END IF;

    RETURN NEW;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.enforce_management_rbac_transition() FROM PUBLIC;

CREATE TRIGGER workspace_membership_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.workspace_membership
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_management_rbac_transition();

CREATE TRIGGER role_definition_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.role_definition
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_management_rbac_transition();

CREATE TRIGGER role_binding_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.role_binding
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_management_rbac_transition();

CREATE TRIGGER role_permission_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.role_permission
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_management_rbac_transition();

CREATE TRIGGER workspace_membership_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.workspace_membership
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation(
    'workspace_membership',
    'public_id'
);

CREATE TRIGGER role_definition_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.role_definition
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation(
    'role_definition',
    'public_id'
);

CREATE TRIGGER role_permission_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.role_permission
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation(
    'role_permission',
    'public_id'
);

CREATE TRIGGER role_binding_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.role_binding
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation(
    'role_binding',
    'public_id'
);

ALTER TABLE mesh.workspace_membership ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.workspace_membership FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_membership_migrator_policy ON mesh.workspace_membership
    TO mesh_migrator
    USING (TRUE)
    WITH CHECK (TRUE);
CREATE POLICY workspace_membership_exact_scope_policy ON mesh.workspace_membership
    TO mesh_runtime
    USING (workspace_id = mesh_ops.current_workspace_id())
    WITH CHECK (workspace_id = mesh_ops.current_workspace_id());

ALTER TABLE mesh.role_definition ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.role_definition FORCE ROW LEVEL SECURITY;
CREATE POLICY role_definition_migrator_policy ON mesh.role_definition
    TO mesh_migrator
    USING (TRUE)
    WITH CHECK (TRUE);
CREATE POLICY role_definition_exact_scope_policy ON mesh.role_definition
    TO mesh_runtime
    USING (workspace_id = mesh_ops.current_workspace_id())
    WITH CHECK (workspace_id = mesh_ops.current_workspace_id());

ALTER TABLE mesh.role_permission ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.role_permission FORCE ROW LEVEL SECURITY;
CREATE POLICY role_permission_migrator_policy ON mesh.role_permission
    TO mesh_migrator
    USING (TRUE)
    WITH CHECK (TRUE);
CREATE POLICY role_permission_exact_scope_policy ON mesh.role_permission
    TO mesh_runtime
    USING (workspace_id = mesh_ops.current_workspace_id())
    WITH CHECK (workspace_id = mesh_ops.current_workspace_id());

ALTER TABLE mesh.role_binding ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.role_binding FORCE ROW LEVEL SECURITY;
CREATE POLICY role_binding_migrator_policy ON mesh.role_binding
    TO mesh_migrator
    USING (TRUE)
    WITH CHECK (TRUE);
CREATE POLICY role_binding_exact_scope_policy ON mesh.role_binding
    TO mesh_runtime
    USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    )
    WITH CHECK (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    );

CREATE POLICY workspace_management_authorization_lock_policy ON mesh.workspace
    FOR UPDATE
    TO mesh_migrator
    USING (id = mesh_ops.current_workspace_id())
    WITH CHECK (id = mesh_ops.current_workspace_id());

CREATE POLICY network_management_authorization_lock_policy ON mesh.network
    FOR UPDATE
    TO mesh_migrator
    USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND id = mesh_ops.current_network_id()
    )
    WITH CHECK (
        workspace_id = mesh_ops.current_workspace_id()
        AND id = mesh_ops.current_network_id()
    );

CREATE FUNCTION mesh_ops.resolve_network_permission_v1(
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
    p_permission_key TEXT,
    p_evaluated_at TIMESTAMPTZ
)
RETURNS TABLE (
    role_binding_public_id UUID,
    role_definition_public_id UUID,
    scope_authority_generation BIGINT,
    membership_authority_generation BIGINT,
    binding_authority_generation BIGINT,
    role_authority_generation BIGINT,
    binding_expires_at TIMESTAMPTZ
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
BEGIN
    IF p_session_public_id IS NULL
        OR p_deployment_public_id IS NULL
        OR p_principal_public_id IS NULL
        OR p_identity_subject_public_id IS NULL
        OR p_workspace_public_id IS NULL
        OR p_network_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_session_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_deployment_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_principal_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_identity_subject_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_workspace_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_network_public_id), 6) >> 4 <> 7
        OR p_session_version IS NULL OR p_session_version <= 0
        OR p_principal_authority_generation IS NULL
        OR p_principal_authority_generation <= 0
        OR p_account_session_generation IS NULL OR p_account_session_generation <= 0
        OR p_provider_generation IS NULL OR p_provider_generation <= 0
        OR p_deployment_recovery_epoch IS NULL OR p_deployment_recovery_epoch <= 0
        OR p_permission_key IS NULL
        OR pg_catalog.char_length(p_permission_key) NOT BETWEEN 3 AND 128
        OR p_permission_key <> pg_catalog.btrim(p_permission_key)
        OR p_permission_key !~ '^[a-z][a-z0-9_]*[.][a-z][a-z0-9_.]*$'
        OR p_evaluated_at IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid Network permission resolution input';
    END IF;

    RETURN QUERY
    SELECT
        binding.public_id,
        role_definition.public_id,
        network.authority_generation,
        membership.authority_generation,
        binding.authority_generation,
        role_definition.authority_generation,
        binding.expires_at
    FROM mesh.account_session AS session
    JOIN mesh.deployment AS deployment
      ON deployment.id = session.deployment_id
    JOIN mesh.principal AS principal
      ON principal.deployment_id = session.deployment_id
     AND principal.id = session.principal_id
    JOIN mesh.account AS account
      ON account.deployment_id = session.deployment_id
     AND account.principal_id = session.principal_id
    JOIN mesh.identity_subject AS subject
      ON subject.deployment_id = session.deployment_id
     AND subject.identity_provider_id = session.identity_provider_id
     AND subject.principal_id = session.principal_id
     AND subject.id = session.identity_subject_id
    JOIN mesh.identity_provider AS provider
      ON provider.deployment_id = session.deployment_id
     AND provider.id = session.identity_provider_id
    JOIN mesh.identity_provider_client AS client
      ON client.deployment_id = session.deployment_id
     AND client.identity_provider_id = session.identity_provider_id
     AND client.id = session.identity_provider_client_id
    JOIN mesh.workspace AS workspace
      ON workspace.deployment_id = session.deployment_id
     AND workspace.public_id = p_workspace_public_id
    JOIN mesh.network AS network
      ON network.workspace_id = workspace.id
     AND network.public_id = p_network_public_id
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = session.deployment_id
     AND membership.workspace_id = workspace.id
     AND membership.principal_id = session.principal_id
    JOIN mesh.role_binding AS binding
      ON binding.deployment_id = session.deployment_id
     AND binding.workspace_id = workspace.id
     AND binding.network_id = network.id
     AND binding.principal_id = session.principal_id
     AND binding.workspace_membership_id = membership.id
    JOIN mesh.role_definition AS role_definition
      ON role_definition.deployment_id = session.deployment_id
     AND role_definition.workspace_id = workspace.id
     AND role_definition.id = binding.role_definition_id
    JOIN mesh.role_permission AS role_permission
      ON role_permission.deployment_id = session.deployment_id
     AND role_permission.workspace_id = workspace.id
     AND role_permission.role_definition_id = role_definition.id
    JOIN mesh.permission AS permission
      ON permission.id = role_permission.permission_id
     AND permission.permission_key = p_permission_key
     AND 'network' = ANY(permission.allowed_scope_kinds)
    WHERE session.public_id = p_session_public_id
      AND deployment.installation_public_id = p_deployment_public_id
      AND principal.public_id = p_principal_public_id
      AND subject.public_id = p_identity_subject_public_id
      AND session.version = p_session_version
      AND session.principal_authority_generation = p_principal_authority_generation
      AND session.account_session_generation = p_account_session_generation
      AND session.provider_generation = p_provider_generation
      AND session.deployment_recovery_epoch = p_deployment_recovery_epoch
      AND session.state = 'active'
      AND session.authentication_time <= p_evaluated_at
      AND session.idle_expires_at > p_evaluated_at
      AND session.absolute_expires_at > p_evaluated_at
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND deployment.recovery_epoch = p_deployment_recovery_epoch
      AND principal.state = 'active'
      AND principal.authority_generation = p_principal_authority_generation
      AND account.recovery_state = 'verified'
      AND account.session_generation = p_account_session_generation
      AND subject.state = 'active'
      AND provider.state = 'active'
      AND provider.recovery_state = 'verified'
      AND provider.current_generation = p_provider_generation
      AND client.state = 'active'
      AND workspace.state = 'active'
      AND network.state = 'active'
      AND membership.state = 'active'
      AND membership.valid_from <= p_evaluated_at
      AND (membership.expires_at IS NULL OR membership.expires_at > p_evaluated_at)
      AND binding.state = 'active'
      AND binding.valid_from <= p_evaluated_at
      AND (binding.expires_at IS NULL OR binding.expires_at > p_evaluated_at)
      AND role_definition.state = 'active'
      AND role_permission.state = 'active'
    ORDER BY binding.id
    LIMIT 256
    FOR SHARE OF session, deployment, principal, account, subject, provider, client,
        workspace, network, membership, binding, role_definition, role_permission, permission;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.resolve_network_permission_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, TEXT, TIMESTAMPTZ
) FROM PUBLIC;

REVOKE ALL ON
    mesh.workspace_membership,
    mesh.role_definition,
    mesh.role_permission,
    mesh.role_binding
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

REVOKE ALL ON ALL SEQUENCES IN SCHEMA mesh
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

GRANT EXECUTE ON FUNCTION mesh_ops.resolve_network_permission_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, TEXT, TIMESTAMPTZ
) TO mesh_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
