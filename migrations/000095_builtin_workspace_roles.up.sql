-- Schema 95 implements the built-in Workspace roles of ADR-050 D6. Roles are a
-- Deployment-independent immutable catalog; assignments bind one Principal's
-- active membership to one role at Workspace scope (network_id NULL, every
-- current and future Network) or at one Network. `owner` stays the existing
-- workspace.owner_principal_id authority and `member` is implicit membership,
-- so neither is assignable. The Network resolver and the Console projection
-- gain built-in assignments as an additional evidence source while keeping
-- their result shapes and the legacy custom-role fallback for rollback.

CREATE TABLE mesh.builtin_role (
    role_key TEXT PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    network_scope_allowed BOOLEAN NOT NULL,
    -- Roles whose holders, bound at Workspace scope, may assign this role.
    -- `owner` denotes workspace ownership rather than an assignment.
    assignable_by TEXT[] NOT NULL,
    catalog_version INTEGER NOT NULL CHECK (catalog_version > 0),
    CONSTRAINT builtin_role_key_check CHECK (
        role_key IN ('admin', 'network_admin', 'it_admin', 'billing_admin', 'auditor')
    ),
    CONSTRAINT builtin_role_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT builtin_role_assignable_by_check CHECK (
        pg_catalog.cardinality(assignable_by) BETWEEN 1 AND 4
        AND assignable_by <@ ARRAY['owner', 'admin', 'it_admin']::TEXT[]
    )
);

CREATE TABLE mesh.builtin_role_permission (
    role_key TEXT NOT NULL REFERENCES mesh.builtin_role (role_key) ON DELETE RESTRICT,
    permission_id BIGINT NOT NULL REFERENCES mesh.permission (id) ON DELETE RESTRICT,
    PRIMARY KEY (role_key, permission_id)
);

CREATE FUNCTION mesh_ops.enforce_builtin_role_immutable_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'built-in role catalog is immutable';
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.enforce_builtin_role_immutable_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER builtin_role_immutable
BEFORE UPDATE OR DELETE ON mesh.builtin_role
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_builtin_role_immutable_v1();
CREATE TRIGGER builtin_role_permission_immutable
BEFORE UPDATE OR DELETE ON mesh.builtin_role_permission
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_builtin_role_immutable_v1();

INSERT INTO mesh.builtin_role (
    role_key, public_id, display_name, network_scope_allowed, assignable_by, catalog_version
) VALUES
    ('admin', '01a10e00-0000-7000-8000-000000000001', 'Admin', FALSE, ARRAY['owner', 'admin'], 1),
    ('network_admin', '01a10e00-0000-7000-8000-000000000002', 'Network admin', TRUE,
        ARRAY['owner', 'admin', 'it_admin'], 1),
    ('it_admin', '01a10e00-0000-7000-8000-000000000003', 'IT admin', TRUE,
        ARRAY['owner', 'admin', 'it_admin'], 1),
    ('billing_admin', '01a10e00-0000-7000-8000-000000000004', 'Billing admin', FALSE,
        ARRAY['owner', 'admin', 'it_admin'], 1),
    ('auditor', '01a10e00-0000-7000-8000-000000000005', 'Auditor', TRUE,
        ARRAY['owner', 'admin', 'it_admin'], 1);

-- Explicit permission sets keep every grant reviewable; a catalog addition
-- needs a new migration that states which roles receive it.
INSERT INTO mesh.builtin_role_permission (role_key, permission_id)
SELECT grants.role_key, permission.id
FROM (VALUES
    -- admin: everything in the Workspace except deletion, owner transfer,
    -- platform support grants and custom role definitions.
    ('admin', 'workspace.read'), ('admin', 'workspace.update'), ('admin', 'network.create'),
    ('admin', 'member.read'), ('admin', 'member.invite'), ('admin', 'member.manage'),
    ('admin', 'identity_provider.manage'), ('admin', 'identity_group.manage'),
    ('admin', 'role_definition.read'), ('admin', 'role_binding.read'), ('admin', 'role_binding.manage'),
    ('admin', 'approval_policy.manage'), ('admin', 'access_review.manage'),
    ('admin', 'support.grant.read'), ('admin', 'billing.read'), ('admin', 'billing.manage'),
    ('admin', 'isolation.read'), ('admin', 'isolation.quarantine'), ('admin', 'isolation.restore'),
    ('admin', 'guardrail.read'), ('admin', 'guardrail.manage'), ('admin', 'guardrail.weaken'),
    ('admin', 'audit.read'), ('admin', 'audit.export'),
    ('admin', 'network.read'), ('admin', 'network.update'), ('admin', 'network.suspend'),
    ('admin', 'network.delete'), ('admin', 'dns.manage'),
    ('admin', 'device.read'), ('admin', 'device.manage'), ('admin', 'device.transfer'),
    ('admin', 'device.quarantine'), ('admin', 'session.revoke'),
    ('admin', 'enrollment_profile.read'), ('admin', 'enrollment_profile.manage'),
    ('admin', 'enrollment_credential.issue'), ('admin', 'enrollment_credential.revoke'),
    ('admin', 'device_group.read'), ('admin', 'device_group.manage'),
    ('admin', 'device_group.members.manage'), ('admin', 'device_group.delegation.manage'),
    ('admin', 'policy.read'), ('admin', 'policy.draft'), ('admin', 'policy.validate'),
    ('admin', 'policy.approve'), ('admin', 'policy.publish'), ('admin', 'policy.rollback'),
    ('admin', 'policy.explain'),
    ('admin', 'route.read'), ('admin', 'route.approve'), ('admin', 'route.withdraw'),
    ('admin', 'connector.read'), ('admin', 'connector.manage'),
    ('admin', 'resource.read'), ('admin', 'resource.manage'), ('admin', 'resource.export'),
    ('admin', 'resource.transfer'), ('admin', 'resource_group.read'),
    ('admin', 'resource_group.manage'), ('admin', 'resource_group.transfer'),
    ('admin', 'share.read'), ('admin', 'share.offer'), ('admin', 'share.accept'), ('admin', 'share.revoke'),
    -- network_admin: policy, DNS, routes, Resources and sharing; reads the rest.
    ('network_admin', 'workspace.read'), ('network_admin', 'network.create'),
    ('network_admin', 'member.read'), ('network_admin', 'role_binding.read'),
    ('network_admin', 'isolation.read'), ('network_admin', 'guardrail.read'), ('network_admin', 'audit.read'),
    ('network_admin', 'network.read'), ('network_admin', 'network.update'), ('network_admin', 'dns.manage'),
    ('network_admin', 'device.read'), ('network_admin', 'device_group.read'),
    ('network_admin', 'enrollment_profile.read'),
    ('network_admin', 'policy.read'), ('network_admin', 'policy.draft'), ('network_admin', 'policy.validate'),
    ('network_admin', 'policy.approve'), ('network_admin', 'policy.publish'),
    ('network_admin', 'policy.rollback'), ('network_admin', 'policy.explain'),
    ('network_admin', 'route.read'), ('network_admin', 'route.approve'), ('network_admin', 'route.withdraw'),
    ('network_admin', 'connector.read'), ('network_admin', 'connector.manage'),
    ('network_admin', 'resource.read'), ('network_admin', 'resource.manage'), ('network_admin', 'resource.export'),
    ('network_admin', 'resource_group.read'), ('network_admin', 'resource_group.manage'),
    ('network_admin', 'share.read'), ('network_admin', 'share.offer'), ('network_admin', 'share.accept'),
    ('network_admin', 'share.revoke'),
    -- it_admin: members, identity, roles up to it_admin, Devices and enrollment.
    ('it_admin', 'workspace.read'), ('it_admin', 'member.read'), ('it_admin', 'member.invite'),
    ('it_admin', 'member.manage'), ('it_admin', 'identity_provider.manage'),
    ('it_admin', 'identity_group.manage'), ('it_admin', 'role_definition.read'),
    ('it_admin', 'role_binding.read'), ('it_admin', 'role_binding.manage'),
    ('it_admin', 'access_review.manage'),
    ('it_admin', 'isolation.read'), ('it_admin', 'guardrail.read'), ('it_admin', 'audit.read'),
    ('it_admin', 'network.read'), ('it_admin', 'device.read'), ('it_admin', 'device.manage'),
    ('it_admin', 'device.transfer'), ('it_admin', 'device.quarantine'), ('it_admin', 'session.revoke'),
    ('it_admin', 'enrollment_profile.read'), ('it_admin', 'enrollment_profile.manage'),
    ('it_admin', 'enrollment_credential.issue'), ('it_admin', 'enrollment_credential.revoke'),
    ('it_admin', 'device_group.read'), ('it_admin', 'device_group.manage'),
    ('it_admin', 'device_group.members.manage'), ('it_admin', 'device_group.delegation.manage'),
    ('it_admin', 'policy.read'), ('it_admin', 'policy.explain'), ('it_admin', 'route.read'),
    ('it_admin', 'connector.read'), ('it_admin', 'resource.read'), ('it_admin', 'resource_group.read'),
    ('it_admin', 'share.read'),
    -- billing_admin: billing only.
    ('billing_admin', 'workspace.read'), ('billing_admin', 'billing.read'), ('billing_admin', 'billing.manage')
) AS grants(role_key, permission_key)
JOIN mesh.permission AS permission ON permission.permission_key = grants.permission_key;

-- auditor: every read permission in Workspace or Network scope, plus export.
INSERT INTO mesh.builtin_role_permission (role_key, permission_id)
SELECT 'auditor', permission.id
FROM mesh.permission AS permission
WHERE (permission.risk_class = 'read' OR permission.permission_key = 'audit.export')
  AND permission.allowed_scope_kinds && ARRAY['workspace', 'network']::TEXT[];

ALTER TABLE mesh.builtin_role ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.builtin_role FORCE ROW LEVEL SECURITY;
ALTER TABLE mesh.builtin_role_permission ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.builtin_role_permission FORCE ROW LEVEL SECURITY;
CREATE POLICY builtin_role_migrator_policy ON mesh.builtin_role
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY builtin_role_permission_migrator_policy ON mesh.builtin_role_permission
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.builtin_role, mesh.builtin_role_permission
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE TABLE mesh.workspace_role_assignment (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    -- NULL binds the role in every current and future Network of the Workspace.
    network_id BIGINT,
    principal_id BIGINT NOT NULL,
    workspace_membership_id BIGINT NOT NULL,
    role_key TEXT NOT NULL REFERENCES mesh.builtin_role (role_key) ON DELETE RESTRICT,
    state TEXT NOT NULL,
    authority_generation BIGINT NOT NULL DEFAULT 1 CHECK (authority_generation > 0),
    valid_from TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT workspace_role_assignment_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT workspace_role_assignment_state_check CHECK (
        (state = 'active' AND revoked_at IS NULL)
        OR (state = 'revoked' AND revoked_at IS NOT NULL AND revoked_at >= created_at)
    ),
    CONSTRAINT workspace_role_assignment_validity_check CHECK (
        expires_at IS NULL OR expires_at > valid_from
    ),
    CONSTRAINT workspace_role_assignment_timestamps_check CHECK (updated_at >= created_at),
    -- Mirrors builtin_role.network_scope_allowed, which a CHECK cannot read.
    CONSTRAINT workspace_role_assignment_network_scope_check CHECK (
        network_id IS NULL OR role_key IN ('network_admin', 'it_admin', 'auditor')
    ),
    CONSTRAINT workspace_role_assignment_network_scope_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT workspace_role_assignment_membership_scope_fk FOREIGN KEY (
        deployment_id, workspace_id, principal_id, workspace_membership_id
    ) REFERENCES mesh.workspace_membership (
        deployment_id, workspace_id, principal_id, id
    ) ON DELETE RESTRICT
);

CREATE UNIQUE INDEX workspace_role_assignment_workspace_scope_uidx
    ON mesh.workspace_role_assignment (workspace_id, principal_id, role_key)
    WHERE state = 'active' AND network_id IS NULL;
CREATE UNIQUE INDEX workspace_role_assignment_network_scope_uidx
    ON mesh.workspace_role_assignment (workspace_id, network_id, principal_id, role_key)
    WHERE state = 'active' AND network_id IS NOT NULL;
CREATE INDEX workspace_role_assignment_principal_idx
    ON mesh.workspace_role_assignment (workspace_id, principal_id, state, id);

-- Assignments are immutable except one terminal revocation. Renewal or a scope
-- change is a new assignment, so every grant has one auditable lifetime.
CREATE FUNCTION mesh_ops.enforce_workspace_role_assignment_transition_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Workspace role assignment is retained';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'active' OR NEW.version <> 1 OR NEW.authority_generation <> 1
            OR NEW.revoked_at IS NOT NULL OR NEW.updated_at <> NEW.created_at THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Workspace role assignment';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.public_id <> NEW.public_id
        OR OLD.deployment_id <> NEW.deployment_id
        OR OLD.workspace_id <> NEW.workspace_id
        OR OLD.network_id IS DISTINCT FROM NEW.network_id
        OR OLD.principal_id <> NEW.principal_id
        OR OLD.workspace_membership_id <> NEW.workspace_membership_id
        OR OLD.role_key <> NEW.role_key
        OR OLD.valid_from <> NEW.valid_from
        OR OLD.expires_at IS DISTINCT FROM NEW.expires_at
        OR OLD.created_at <> NEW.created_at
        OR OLD.state <> 'active'
        OR NEW.state <> 'revoked'
        OR NEW.version <> OLD.version + 1
        OR NEW.authority_generation <> OLD.authority_generation + 1
        OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Workspace role assignment transition';
    END IF;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.enforce_workspace_role_assignment_transition_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER workspace_role_assignment_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.workspace_role_assignment
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_workspace_role_assignment_transition_v1();
CREATE TRIGGER workspace_role_assignment_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.workspace_role_assignment
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation(
    'workspace_role_assignment', 'public_id'
);

ALTER TABLE mesh.workspace_role_assignment ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.workspace_role_assignment FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_role_assignment_migrator_policy ON mesh.workspace_role_assignment
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.workspace_role_assignment
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The Network resolver keeps its signature, result shape and owner branch.
-- A built-in assignment is checked after ownership and before the legacy
-- custom-role resolver; its evidence is role evidence (assignment and role
-- public IDs, positive generations), so callers need no change.
CREATE OR REPLACE FUNCTION mesh_ops.resolve_network_permission_v2(
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
    binding_expires_at TIMESTAMPTZ,
    workspace_owner_authority_generation BIGINT
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
        NULL::UUID,
        NULL::UUID,
        network.authority_generation,
        membership.authority_generation,
        0::BIGINT,
        0::BIGINT,
        NULL::TIMESTAMPTZ,
        workspace.authority_generation
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
    JOIN mesh.permission AS permission
      ON permission.permission_key = p_permission_key
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
      AND principal.kind = 'account'
      AND workspace.owner_principal_id = principal.id
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
    LIMIT 1
    FOR SHARE OF session, deployment, principal, account, subject, provider, client,
        workspace, network, membership, permission;
    IF FOUND THEN RETURN; END IF;

    -- Built-in roles: a Workspace-scope assignment covers every Network of the
    -- Workspace; a Network-scope one only its Network. The exact Network
    -- assignment is preferred so evidence names the narrowest grant.
    RETURN QUERY
    SELECT
        assignment.public_id,
        role.public_id,
        network.authority_generation,
        membership.authority_generation,
        assignment.authority_generation,
        role.catalog_version::BIGINT,
        assignment.expires_at,
        0::BIGINT
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
    JOIN mesh.permission AS permission
      ON permission.permission_key = p_permission_key
     AND 'network' = ANY(permission.allowed_scope_kinds)
    JOIN mesh.workspace_role_assignment AS assignment
      ON assignment.deployment_id = session.deployment_id
     AND assignment.workspace_id = workspace.id
     AND assignment.principal_id = principal.id
     AND assignment.workspace_membership_id = membership.id
     AND (assignment.network_id IS NULL OR assignment.network_id = network.id)
    JOIN mesh.builtin_role AS role
      ON role.role_key = assignment.role_key
    JOIN mesh.builtin_role_permission AS role_permission
      ON role_permission.role_key = role.role_key
     AND role_permission.permission_id = permission.id
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
      AND principal.kind = 'account'
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
      AND assignment.state = 'active'
      AND assignment.valid_from <= p_evaluated_at
      AND (assignment.expires_at IS NULL OR assignment.expires_at > p_evaluated_at)
    ORDER BY assignment.network_id IS NULL, assignment.id
    LIMIT 1
    FOR SHARE OF session, deployment, principal, account, subject, provider, client,
        workspace, network, membership, permission, assignment;
    IF FOUND THEN RETURN; END IF;

    -- Members retain the existing exact-Network role resolver and its locks.
    RETURN QUERY
    SELECT resolved.role_binding_public_id, resolved.role_definition_public_id,
        resolved.scope_authority_generation, resolved.membership_authority_generation,
        resolved.binding_authority_generation, resolved.role_authority_generation,
        resolved.binding_expires_at, 0::BIGINT
    FROM mesh_ops.resolve_network_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version,
        p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_permission_key, p_evaluated_at
    ) AS resolved;

END;
$function$;

-- The Console projection adds Network permissions granted by built-in
-- assignments to the existing custom-role ones, filtered by the same
-- allowlist, so deployed Consoles keep parsing it.
CREATE OR REPLACE FUNCTION mesh_ops.read_console_management_scopes_v1(
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
    p_evaluated_at TIMESTAMPTZ,
    p_after_network_public_id UUID,
    p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh
AS $function$
DECLARE
    result JSONB;
    previous_requested_workspace_public_id TEXT;
    previous_projection_workspace_public_id TEXT;
BEGIN
    previous_requested_workspace_public_id := pg_catalog.current_setting(
        'mesh.requested_workspace_public_id',
        TRUE
    );
    previous_projection_workspace_public_id := pg_catalog.current_setting(
        'mesh.console_management_scope_workspace_public_id',
        TRUE
    );
    IF p_session_public_id IS NULL
        OR p_deployment_public_id IS NULL
        OR p_principal_public_id IS NULL
        OR p_identity_subject_public_id IS NULL
        OR p_workspace_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_session_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_deployment_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_principal_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_identity_subject_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_workspace_public_id), 6) >> 4 <> 7
        OR (
            p_after_network_public_id IS NOT NULL
            AND pg_catalog.get_byte(pg_catalog.uuid_send(p_after_network_public_id), 6) >> 4 <> 7
        )
        OR p_session_version IS NULL OR p_session_version <= 0
        OR p_principal_authority_generation IS NULL OR p_principal_authority_generation <= 0
        OR p_account_session_generation IS NULL OR p_account_session_generation <= 0
        OR p_provider_generation IS NULL OR p_provider_generation <= 0
        OR p_deployment_recovery_epoch IS NULL OR p_deployment_recovery_epoch <= 0
        OR p_evaluated_at IS NULL
        OR p_limit IS NULL OR p_limit < 1 OR p_limit > 101 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid Console management scope input';
    END IF;

    PERFORM pg_catalog.set_config(
        'mesh.requested_workspace_public_id',
        p_workspace_public_id::TEXT,
        TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.console_management_scope_workspace_public_id',
        p_workspace_public_id::TEXT,
        TRUE
    );

    WITH authority AS MATERIALIZED (
        SELECT
            workspace.id AS workspace_id,
            workspace.public_id AS workspace_public_id,
            workspace.display_name AS workspace_display_name,
            session.deployment_id,
            session.principal_id,
            membership.id AS membership_id,
            workspace.owner_principal_id = session.principal_id AS is_workspace_owner
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
         AND workspace.id = session.login_workspace_id
         AND workspace.public_id = p_workspace_public_id
        JOIN mesh.workspace_membership AS membership
          ON membership.deployment_id = session.deployment_id
         AND membership.workspace_id = workspace.id
         AND membership.principal_id = session.principal_id
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
          AND membership.state = 'active'
          AND membership.valid_from <= p_evaluated_at
          AND (membership.expires_at IS NULL OR membership.expires_at > p_evaluated_at)
        LIMIT 1
    ), scope_permissions AS (
        SELECT
            network.public_id,
            network.display_name,
            CASE WHEN authority.is_workspace_owner THEN ARRAY(
                SELECT permission.permission_key FROM mesh.permission AS permission
                WHERE permission.permission_key = ANY(ARRAY[
                     'device.read', 'network.read', 'policy.approve', 'policy.read', 'policy.publish', 'policy.validate',
                     'share.accept', 'share.offer', 'share.read', 'share.revoke'
                ]::TEXT[])
                  AND 'network' = ANY(permission.allowed_scope_kinds)
                ORDER BY permission.permission_key
            ) ELSE ARRAY(
                SELECT granted.permission_key FROM (
                SELECT permission.permission_key
                FROM mesh.workspace_role_assignment AS assignment
                JOIN mesh.builtin_role_permission AS role_permission
                  ON role_permission.role_key = assignment.role_key
                JOIN mesh.permission AS permission
                  ON permission.id = role_permission.permission_id
                 AND permission.permission_key = ANY(ARRAY[
                     'device.read', 'network.read', 'policy.approve', 'policy.read', 'policy.publish', 'policy.validate',
                     'share.accept', 'share.offer', 'share.read', 'share.revoke'
                 ]::TEXT[])
                 AND 'network' = ANY(permission.allowed_scope_kinds)
                WHERE assignment.deployment_id = authority.deployment_id
                  AND assignment.workspace_id = authority.workspace_id
                  AND (assignment.network_id IS NULL OR assignment.network_id = network.id)
                  AND assignment.principal_id = authority.principal_id
                  AND assignment.workspace_membership_id = authority.membership_id
                  AND assignment.state = 'active'
                  AND assignment.valid_from <= p_evaluated_at
                  AND (assignment.expires_at IS NULL OR assignment.expires_at > p_evaluated_at)
                UNION
                SELECT permission.permission_key
                FROM mesh.role_binding AS binding
                JOIN mesh.role_definition AS role_definition
                  ON role_definition.deployment_id = binding.deployment_id
                 AND role_definition.workspace_id = binding.workspace_id
                 AND role_definition.id = binding.role_definition_id
                JOIN mesh.role_permission AS role_permission
                  ON role_permission.deployment_id = role_definition.deployment_id
                 AND role_permission.workspace_id = role_definition.workspace_id
                 AND role_permission.role_definition_id = role_definition.id
                JOIN mesh.permission AS permission
                  ON permission.id = role_permission.permission_id
                 AND permission.permission_key = ANY(ARRAY[
                     'device.read', 'network.read', 'policy.approve', 'policy.read', 'policy.publish', 'policy.validate',
                     'share.accept', 'share.offer', 'share.read', 'share.revoke'
                 ]::TEXT[])
                 AND 'network' = ANY(permission.allowed_scope_kinds)
                WHERE binding.deployment_id = authority.deployment_id
                  AND binding.workspace_id = authority.workspace_id
                  AND binding.network_id = network.id
                  AND binding.principal_id = authority.principal_id
                  AND binding.workspace_membership_id = authority.membership_id
                  AND binding.state = 'active'
                  AND binding.valid_from <= p_evaluated_at
                  AND (binding.expires_at IS NULL OR binding.expires_at > p_evaluated_at)
                  AND role_definition.state = 'active'
                  AND role_permission.state = 'active'
                ) AS granted
                ORDER BY granted.permission_key
            ) END AS permissions
        FROM authority
        JOIN mesh.network AS network
          ON network.workspace_id = authority.workspace_id
        WHERE network.state = 'active'
          AND (p_after_network_public_id IS NULL OR network.public_id > p_after_network_public_id)
    ), scopes AS (
        SELECT scope_permissions.*
        FROM scope_permissions
        WHERE pg_catalog.cardinality(scope_permissions.permissions) > 0
        ORDER BY scope_permissions.public_id
        LIMIT p_limit
    )
    SELECT pg_catalog.jsonb_build_object(
        'workspace_id', authority.workspace_public_id,
        'workspace_display_name', authority.workspace_display_name,
        'scopes', COALESCE(
            (
                SELECT pg_catalog.jsonb_agg(
                    pg_catalog.jsonb_build_object(
                        'network_id', scopes.public_id,
                        'network_display_name', scopes.display_name,
                        'permissions', pg_catalog.to_jsonb(scopes.permissions)
                    )
                    ORDER BY scopes.public_id
                )
                FROM scopes
            ),
            '[]'::JSONB
        )
    )
    INTO result
    FROM authority;

    PERFORM pg_catalog.set_config(
        'mesh.requested_workspace_public_id',
        COALESCE(previous_requested_workspace_public_id, ''),
        TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.console_management_scope_workspace_public_id',
        COALESCE(previous_projection_workspace_public_id, ''),
        TRUE
    );
    RETURN result;
EXCEPTION
    WHEN OTHERS THEN
        PERFORM pg_catalog.set_config(
            'mesh.requested_workspace_public_id',
            COALESCE(previous_requested_workspace_public_id, ''),
            TRUE
        );
        PERFORM pg_catalog.set_config(
            'mesh.console_management_scope_workspace_public_id',
            COALESCE(previous_projection_workspace_public_id, ''),
            TRUE
        );
        RAISE;
END;
$function$;

-- Workspace-target permissions (members, role bindings, billing, settings).
-- Ownership grants every Workspace permission; otherwise only a Workspace-scope
-- built-in assignment counts, because a Network-scope role never administers
-- the Workspace. Callers establish the exact Workspace scope first. The result
-- mirrors the Network resolver; scope_authority_generation is the Workspace's.
CREATE FUNCTION mesh_ops.resolve_workspace_permission_v1(
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
    binding_expires_at TIMESTAMPTZ,
    workspace_owner_authority_generation BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    resolved RECORD;
BEGIN
    IF p_session_public_id IS NULL
        OR p_deployment_public_id IS NULL
        OR p_principal_public_id IS NULL
        OR p_identity_subject_public_id IS NULL
        OR p_workspace_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_session_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_deployment_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_principal_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_identity_subject_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_workspace_public_id), 6) >> 4 <> 7
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
            MESSAGE = 'invalid Workspace permission resolution input';
    END IF;

    SELECT
        workspace.owner_principal_id = principal.id AS is_owner,
        assignment.id AS assignment_id,
        assignment.public_id AS assignment_public_id,
        role.public_id AS role_public_id,
        role.catalog_version AS role_generation,
        assignment.authority_generation AS assignment_generation,
        assignment.expires_at AS assignment_expires_at,
        workspace.authority_generation AS workspace_generation,
        membership.authority_generation AS membership_generation
    INTO resolved
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
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = session.deployment_id
     AND membership.workspace_id = workspace.id
     AND membership.principal_id = session.principal_id
    JOIN mesh.permission AS permission
      ON permission.permission_key = p_permission_key
     AND 'workspace' = ANY(permission.allowed_scope_kinds)
    LEFT JOIN mesh.workspace_role_assignment AS assignment
      ON assignment.deployment_id = session.deployment_id
     AND assignment.workspace_id = workspace.id
     AND assignment.principal_id = principal.id
     AND assignment.workspace_membership_id = membership.id
     AND assignment.network_id IS NULL
     AND assignment.state = 'active'
     AND assignment.valid_from <= p_evaluated_at
     AND (assignment.expires_at IS NULL OR assignment.expires_at > p_evaluated_at)
     AND EXISTS (
        SELECT 1 FROM mesh.builtin_role_permission AS role_permission
        WHERE role_permission.role_key = assignment.role_key
          AND role_permission.permission_id = permission.id
     )
    LEFT JOIN mesh.builtin_role AS role
      ON role.role_key = assignment.role_key
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
      AND principal.kind = 'account'
      AND principal.authority_generation = p_principal_authority_generation
      AND account.recovery_state = 'verified'
      AND account.session_generation = p_account_session_generation
      AND subject.state = 'active'
      AND provider.state = 'active'
      AND provider.recovery_state = 'verified'
      AND provider.current_generation = p_provider_generation
      AND client.state = 'active'
      AND workspace.state = 'active'
      AND membership.state = 'active'
      AND membership.valid_from <= p_evaluated_at
      AND (membership.expires_at IS NULL OR membership.expires_at > p_evaluated_at)
      AND (workspace.owner_principal_id = principal.id OR assignment.id IS NOT NULL)
    ORDER BY workspace.owner_principal_id = principal.id DESC, assignment.id
    LIMIT 1
    FOR SHARE OF session, deployment, principal, account, subject, provider, client,
        workspace, membership, permission;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    scope_authority_generation := resolved.workspace_generation;
    membership_authority_generation := resolved.membership_generation;
    IF resolved.is_owner THEN
        role_binding_public_id := NULL;
        role_definition_public_id := NULL;
        binding_authority_generation := 0;
        role_authority_generation := 0;
        binding_expires_at := NULL;
        workspace_owner_authority_generation := resolved.workspace_generation;
        RETURN NEXT;
        RETURN;
    END IF;
    -- The outer join cannot lock the assignment, so lock it now and recheck it:
    -- a concurrent revocation that committed first denies this operation.
    PERFORM 1 FROM mesh.workspace_role_assignment AS assignment
    WHERE assignment.id = resolved.assignment_id
      AND assignment.state = 'active'
      AND assignment.authority_generation = resolved.assignment_generation
    FOR SHARE;
    IF NOT FOUND THEN
        RETURN;
    END IF;
    role_binding_public_id := resolved.assignment_public_id;
    role_definition_public_id := resolved.role_public_id;
    binding_authority_generation := resolved.assignment_generation;
    role_authority_generation := resolved.role_generation;
    binding_expires_at := resolved.assignment_expires_at;
    workspace_owner_authority_generation := 0;
    RETURN NEXT;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.resolve_workspace_permission_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, TEXT, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.resolve_workspace_permission_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, TEXT, TIMESTAMPTZ
) TO mesh_runtime;
