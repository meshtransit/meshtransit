DO $database_privileges$
BEGIN
    EXECUTE pg_catalog.format(
        'REVOKE ALL ON DATABASE %I FROM PUBLIC',
        pg_catalog.current_database()
    );
END;
$database_privileges$;

ALTER TABLE mesh.principal
    ADD CONSTRAINT principal_deployment_id_kind_unique
    UNIQUE (deployment_id, id, kind);

CREATE TABLE mesh.account (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    principal_id BIGINT NOT NULL,
    principal_kind TEXT NOT NULL DEFAULT 'account',
    display_name TEXT NOT NULL,
    login_identifier_digest_algorithm TEXT,
    login_identifier_digest_key_id TEXT,
    login_identifier_digest BYTEA,
    profile_encryption_algorithm TEXT,
    profile_encryption_key_id TEXT,
    profile_ciphertext BYTEA,
    session_generation BIGINT NOT NULL DEFAULT 1 CHECK (session_generation > 0),
    recovery_state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT account_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT account_principal_kind_check CHECK (principal_kind = 'account'),
    CONSTRAINT account_display_name_check CHECK (
        pg_catalog.char_length(display_name) BETWEEN 1 AND 128
        AND display_name = pg_catalog.btrim(display_name)
    ),
    CONSTRAINT account_login_identifier_digest_check CHECK (
        (
            login_identifier_digest_algorithm IS NULL
            AND login_identifier_digest_key_id IS NULL
            AND login_identifier_digest IS NULL
        )
        OR (
            login_identifier_digest_algorithm IS NOT NULL
            AND login_identifier_digest_key_id IS NOT NULL
            AND login_identifier_digest IS NOT NULL
            AND login_identifier_digest_algorithm = 'hmac-sha256-v1'
            AND pg_catalog.char_length(login_identifier_digest_key_id) BETWEEN 1 AND 128
            AND login_identifier_digest_key_id = pg_catalog.btrim(login_identifier_digest_key_id)
            AND login_identifier_digest_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
            AND pg_catalog.octet_length(login_identifier_digest) = 32
        )
    ),
    CONSTRAINT account_profile_encryption_check CHECK (
        (
            profile_encryption_algorithm IS NULL
            AND profile_encryption_key_id IS NULL
            AND profile_ciphertext IS NULL
        )
        OR (
            profile_encryption_algorithm IS NOT NULL
            AND profile_encryption_key_id IS NOT NULL
            AND profile_ciphertext IS NOT NULL
            AND profile_encryption_algorithm = 'aead-aes-256-gcm-v1'
            AND pg_catalog.char_length(profile_encryption_key_id) BETWEEN 1 AND 128
            AND profile_encryption_key_id = pg_catalog.btrim(profile_encryption_key_id)
            AND profile_encryption_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
            AND pg_catalog.octet_length(profile_ciphertext) BETWEEN 1 AND 8192
        )
    ),
    CONSTRAINT account_recovery_state_check CHECK (
        recovery_state IN ('verified', 'quarantined')
    ),
    CONSTRAINT account_principal_scope_fk FOREIGN KEY (
        deployment_id,
        principal_id,
        principal_kind
    ) REFERENCES mesh.principal (deployment_id, id, kind) ON DELETE RESTRICT,
    CONSTRAINT account_timestamps_check CHECK (updated_at >= created_at),
    UNIQUE (deployment_id, id),
    UNIQUE (deployment_id, principal_id)
);

CREATE INDEX account_deployment_recovery_state_idx
    ON mesh.account (deployment_id, recovery_state, id);

CREATE UNIQUE INDEX account_login_identifier_active_uidx
    ON mesh.account (
        deployment_id,
        login_identifier_digest_key_id,
        login_identifier_digest
    )
    WHERE login_identifier_digest IS NOT NULL;

CREATE TABLE mesh.identity_subject (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    identity_provider_id BIGINT NOT NULL,
    principal_id BIGINT NOT NULL,
    subject_digest_algorithm TEXT NOT NULL,
    subject_digest_key_id TEXT NOT NULL,
    subject_digest BYTEA NOT NULL,
    claims_revision BIGINT NOT NULL DEFAULT 1 CHECK (claims_revision > 0),
    last_seen_at TIMESTAMPTZ NOT NULL,
    state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT identity_subject_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT identity_subject_digest_algorithm_check CHECK (
        subject_digest_algorithm = 'hmac-sha256-v1'
    ),
    CONSTRAINT identity_subject_digest_key_id_check CHECK (
        pg_catalog.char_length(subject_digest_key_id) BETWEEN 1 AND 128
        AND subject_digest_key_id = pg_catalog.btrim(subject_digest_key_id)
        AND subject_digest_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    CONSTRAINT identity_subject_digest_check CHECK (
        pg_catalog.octet_length(subject_digest) = 32
    ),
    CONSTRAINT identity_subject_state_check CHECK (
        state IN ('active', 'unlinked', 'deleted')
    ),
    CONSTRAINT identity_subject_deletion_check CHECK (
        (state = 'deleted' AND deleted_at IS NOT NULL)
        OR (state <> 'deleted' AND deleted_at IS NULL)
    ),
    CONSTRAINT identity_subject_provider_scope_fk FOREIGN KEY (
        deployment_id,
        identity_provider_id
    ) REFERENCES mesh.identity_provider (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT identity_subject_account_scope_fk FOREIGN KEY (
        deployment_id,
        principal_id
    ) REFERENCES mesh.account (deployment_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT identity_subject_timestamps_check CHECK (
        updated_at >= created_at
        AND last_seen_at >= created_at
        AND (deleted_at IS NULL OR deleted_at >= created_at)
    ),
    UNIQUE (deployment_id, id),
    UNIQUE (
        deployment_id,
        identity_provider_id,
        subject_digest_algorithm,
        subject_digest_key_id,
        subject_digest
    )
);

CREATE INDEX identity_subject_account_state_idx
    ON mesh.identity_subject (deployment_id, principal_id, state, id);

CREATE INDEX identity_subject_provider_state_idx
    ON mesh.identity_subject (deployment_id, identity_provider_id, state, id);

CREATE TABLE mesh.permission (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    permission_key TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL,
    risk_class TEXT NOT NULL,
    allowed_scope_kinds TEXT[] NOT NULL,
    catalog_version BIGINT NOT NULL CHECK (catalog_version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT permission_key_check CHECK (
        pg_catalog.char_length(permission_key) BETWEEN 3 AND 128
        AND permission_key = pg_catalog.btrim(permission_key)
        AND permission_key ~ '^[a-z][a-z0-9_]*[.][a-z][a-z0-9_.]*$'
    ),
    CONSTRAINT permission_description_check CHECK (
        pg_catalog.char_length(description) BETWEEN 1 AND 256
        AND description = pg_catalog.btrim(description)
    ),
    CONSTRAINT permission_risk_class_check CHECK (
        risk_class IN ('read', 'mutation', 'privileged')
    ),
    CONSTRAINT permission_allowed_scope_kinds_check CHECK (
        pg_catalog.cardinality(allowed_scope_kinds) BETWEEN 1 AND 3
        AND allowed_scope_kinds <@ ARRAY['deployment', 'workspace', 'network']::TEXT[]
    )
);

INSERT INTO mesh.permission (
    permission_key,
    description,
    risk_class,
    allowed_scope_kinds,
    catalog_version
) VALUES
    ('deployment.read', 'Read deployment configuration', 'read', ARRAY['deployment'], 1),
    ('deployment.security.manage', 'Manage deployment security configuration', 'privileged', ARRAY['deployment'], 1),
    ('deployment.role.bind', 'Change deployment role bindings', 'privileged', ARRAY['deployment'], 1),
    ('deployment.operate', 'Perform bounded deployment operations', 'mutation', ARRAY['deployment'], 1),
    ('support.grant.use', 'Use an authorized support grant', 'privileged', ARRAY['deployment'], 1),
    ('workspace.read', 'Read workspace configuration', 'read', ARRAY['workspace'], 1),
    ('workspace.update', 'Update workspace configuration', 'mutation', ARRAY['workspace'], 1),
    ('workspace.delete', 'Delete a workspace through its protected workflow', 'privileged', ARRAY['workspace'], 1),
    ('workspace.owner.transfer', 'Transfer workspace ownership', 'privileged', ARRAY['workspace'], 1),
    ('network.read', 'Read network configuration', 'read', ARRAY['network'], 1),
    ('network.create', 'Create a network in a workspace', 'mutation', ARRAY['workspace'], 1),
    ('network.update', 'Update network configuration', 'mutation', ARRAY['network'], 1),
    ('network.suspend', 'Suspend a network', 'privileged', ARRAY['network'], 1),
    ('network.delete', 'Delete a network through its protected workflow', 'privileged', ARRAY['network'], 1),
    ('dns.manage', 'Manage network DNS configuration', 'mutation', ARRAY['network'], 1),
    ('member.read', 'Read workspace membership', 'read', ARRAY['workspace'], 1),
    ('member.invite', 'Invite a workspace member', 'mutation', ARRAY['workspace'], 1),
    ('member.manage', 'Manage workspace membership', 'privileged', ARRAY['workspace'], 1),
    ('identity_provider.manage', 'Manage workspace identity providers', 'privileged', ARRAY['workspace'], 1),
    ('identity_group.manage', 'Manage workspace identity groups', 'mutation', ARRAY['workspace'], 1),
    ('role_definition.read', 'Read role definitions', 'read', ARRAY['workspace'], 1),
    ('role_definition.manage', 'Manage custom role definitions', 'privileged', ARRAY['workspace'], 1),
    ('role_binding.read', 'Read role bindings', 'read', ARRAY['workspace'], 1),
    ('role_binding.manage', 'Manage role bindings', 'privileged', ARRAY['workspace'], 1),
    ('approval_policy.manage', 'Manage approval policy', 'privileged', ARRAY['workspace'], 1),
    ('device.read', 'Read device inventory', 'read', ARRAY['network'], 1),
    ('device.manage', 'Manage device lifecycle', 'mutation', ARRAY['network'], 1),
    ('device.transfer', 'Transfer device ownership or custody', 'privileged', ARRAY['network'], 1),
    ('device.quarantine', 'Quarantine a device', 'privileged', ARRAY['network'], 1),
    ('session.revoke', 'Revoke an authenticated session', 'privileged', ARRAY['network'], 1),
    ('enrollment_profile.read', 'Read enrollment profiles', 'read', ARRAY['network'], 1),
    ('enrollment_profile.manage', 'Manage enrollment profiles', 'mutation', ARRAY['network'], 1),
    ('enrollment_credential.issue', 'Issue an enrollment credential', 'privileged', ARRAY['network'], 1),
    ('enrollment_credential.revoke', 'Revoke an enrollment credential', 'privileged', ARRAY['network'], 1),
    ('device_group.read', 'Read device groups', 'read', ARRAY['network'], 1),
    ('device_group.manage', 'Manage device groups', 'mutation', ARRAY['network'], 1),
    ('device_group.members.manage', 'Manage eligible device group membership', 'mutation', ARRAY['network'], 1),
    ('device_group.delegation.manage', 'Manage device group delegation', 'privileged', ARRAY['network'], 1),
    ('policy.read', 'Read policy intent and effective state', 'read', ARRAY['network'], 1),
    ('policy.draft', 'Change a policy draft', 'mutation', ARRAY['network'], 1),
    ('policy.validate', 'Validate and test a policy draft', 'read', ARRAY['network'], 1),
    ('policy.approve', 'Approve an unchanged policy candidate', 'privileged', ARRAY['network'], 1),
    ('policy.publish', 'Publish an approved policy release', 'privileged', ARRAY['network'], 1),
    ('policy.rollback', 'Activate an eligible previous policy release', 'privileged', ARRAY['network'], 1),
    ('policy.explain', 'Read bounded policy explanations', 'read', ARRAY['network'], 1),
    ('route.read', 'Read routes and connector health', 'read', ARRAY['network'], 1),
    ('route.approve', 'Approve a route advertisement', 'privileged', ARRAY['network'], 1),
    ('route.withdraw', 'Withdraw an approved route', 'privileged', ARRAY['network'], 1),
    ('connector.read', 'Read connector configuration', 'read', ARRAY['network'], 1),
    ('connector.manage', 'Manage connector configuration', 'mutation', ARRAY['network'], 1),
    ('resource.read', 'Read local resources', 'read', ARRAY['network'], 1),
    ('resource.manage', 'Manage local resources', 'mutation', ARRAY['network'], 1),
    ('resource.export', 'Export a resource through a protected workflow', 'privileged', ARRAY['network'], 1),
    ('resource_group.read', 'Read resource groups', 'read', ARRAY['network'], 1),
    ('resource_group.manage', 'Manage resource groups', 'mutation', ARRAY['network'], 1),
    ('share.read', 'Read local sharing state', 'read', ARRAY['network'], 1),
    ('share.offer', 'Create a resource share offer', 'privileged', ARRAY['network'], 1),
    ('share.accept', 'Accept a share into an authorized network', 'privileged', ARRAY['network'], 1),
    ('share.revoke', 'Revoke local sharing authority', 'privileged', ARRAY['network'], 1),
    ('isolation.read', 'Read isolation state', 'read', ARRAY['workspace', 'network'], 1),
    ('isolation.quarantine', 'Narrow authority through quarantine', 'privileged', ARRAY['workspace', 'network'], 1),
    ('isolation.restore', 'Restore authority through a protected workflow', 'privileged', ARRAY['workspace', 'network'], 1),
    ('guardrail.read', 'Read governance guardrails', 'read', ARRAY['workspace', 'network'], 1),
    ('guardrail.manage', 'Create or strengthen governance guardrails', 'mutation', ARRAY['workspace', 'network'], 1),
    ('guardrail.weaken', 'Weaken a guardrail through a protected workflow', 'privileged', ARRAY['workspace', 'network'], 1),
    ('audit.read', 'Read scoped audit evidence', 'read', ARRAY['deployment', 'workspace', 'network'], 1),
    ('audit.export', 'Export scoped audit evidence', 'privileged', ARRAY['deployment', 'workspace', 'network'], 1),
    ('access_review.manage', 'Manage access review lifecycle', 'privileged', ARRAY['workspace'], 1),
    ('support.grant.read', 'Read workspace support grants', 'read', ARRAY['workspace'], 1),
    ('support.grant.manage', 'Manage workspace support grants', 'privileged', ARRAY['workspace'], 1),
    ('billing.read', 'Read workspace billing state', 'read', ARRAY['workspace'], 1),
    ('billing.manage', 'Manage workspace billing state', 'privileged', ARRAY['workspace'], 1);

CREATE FUNCTION mesh_ops.reject_immutable_permission_change()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    RAISE EXCEPTION USING
        ERRCODE = '55000',
        MESSAGE = 'permission catalog rows are immutable';
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.reject_immutable_permission_change() FROM PUBLIC;

CREATE TRIGGER permission_immutable
BEFORE UPDATE OR DELETE ON mesh.permission
FOR EACH ROW EXECUTE FUNCTION mesh_ops.reject_immutable_permission_change();

CREATE TRIGGER account_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.account
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('account', 'public_id');

CREATE TRIGGER identity_subject_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.identity_subject
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('identity_subject', 'public_id');

REVOKE ALL ON ALL TABLES IN SCHEMA mesh FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA mesh FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mesh, mesh_ops, mesh_audit FROM PUBLIC;

REVOKE ALL ON mesh.account, mesh.identity_subject, mesh.permission
    FROM mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
