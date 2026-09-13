DO $database_privileges$
BEGIN
    EXECUTE pg_catalog.format(
        'REVOKE ALL ON DATABASE %I FROM PUBLIC',
        pg_catalog.current_database()
    );
    EXECUTE pg_catalog.format(
        'GRANT CONNECT ON DATABASE %I TO mesh_runtime, mesh_worker',
        pg_catalog.current_database()
    );
END;
$database_privileges$;

CREATE TABLE mesh.deployment (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    installation_public_id UUID NOT NULL UNIQUE,
    profile TEXT NOT NULL,
    state TEXT NOT NULL,
    schema_epoch BIGINT NOT NULL CHECK (schema_epoch > 0),
    authority_generation BIGINT NOT NULL CHECK (authority_generation > 0),
    recovery_epoch BIGINT NOT NULL CHECK (recovery_epoch > 0),
    recovery_state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT deployment_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(installation_public_id), 6) >> 4 = 7
    ),
    CONSTRAINT deployment_profile_check CHECK (profile IN ('cloud', 'self_hosted')),
    CONSTRAINT deployment_state_check CHECK (state IN ('active', 'suspended', 'deleted')),
    CONSTRAINT deployment_recovery_state_check CHECK (recovery_state IN ('verified', 'quarantined')),
    CONSTRAINT deployment_timestamps_check CHECK (
        updated_at >= created_at
        AND (deleted_at IS NULL OR deleted_at >= created_at)
    )
);

CREATE UNIQUE INDEX deployment_one_active_uidx
    ON mesh.deployment ((TRUE))
    WHERE state = 'active' AND deleted_at IS NULL;

CREATE TABLE mesh.principal (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    kind TEXT NOT NULL,
    state TEXT NOT NULL,
    authority_generation BIGINT NOT NULL DEFAULT 1 CHECK (authority_generation > 0),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT principal_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT principal_kind_check CHECK (kind IN ('account', 'service')),
    CONSTRAINT principal_state_check CHECK (state IN ('active', 'suspended', 'revoked', 'deleted')),
    CONSTRAINT principal_deployment_fk FOREIGN KEY (deployment_id)
        REFERENCES mesh.deployment (id) ON DELETE RESTRICT,
    CONSTRAINT principal_timestamps_check CHECK (
        updated_at >= created_at
        AND (deleted_at IS NULL OR deleted_at >= created_at)
    ),
    UNIQUE (deployment_id, id)
);

CREATE INDEX principal_deployment_id_idx ON mesh.principal (deployment_id);

CREATE TABLE mesh.workspace (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    owner_principal_id BIGINT NOT NULL,
    display_name TEXT NOT NULL,
    name_key TEXT NOT NULL,
    state TEXT NOT NULL,
    authority_generation BIGINT NOT NULL DEFAULT 1 CHECK (authority_generation > 0),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT workspace_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT workspace_display_name_check CHECK (
        pg_catalog.char_length(display_name) BETWEEN 1 AND 128
        AND display_name = pg_catalog.btrim(display_name)
    ),
    CONSTRAINT workspace_name_key_check CHECK (
        pg_catalog.char_length(name_key) BETWEEN 1 AND 128
        AND name_key = pg_catalog.btrim(name_key)
    ),
    CONSTRAINT workspace_state_check CHECK (state IN ('active', 'suspended', 'deleted')),
    CONSTRAINT workspace_deployment_fk FOREIGN KEY (deployment_id)
        REFERENCES mesh.deployment (id) ON DELETE RESTRICT,
    CONSTRAINT workspace_owner_scope_fk FOREIGN KEY (deployment_id, owner_principal_id)
        REFERENCES mesh.principal (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT workspace_timestamps_check CHECK (
        updated_at >= created_at
        AND (deleted_at IS NULL OR deleted_at >= created_at)
    ),
    UNIQUE (deployment_id, id),
    UNIQUE (id, deployment_id)
);

CREATE UNIQUE INDEX workspace_deployment_name_active_uidx
    ON mesh.workspace (deployment_id, name_key)
    WHERE deleted_at IS NULL;
CREATE INDEX workspace_deployment_owner_idx
    ON mesh.workspace (deployment_id, owner_principal_id);
CREATE INDEX workspace_deployment_state_created_idx
    ON mesh.workspace (deployment_id, state, created_at DESC, id DESC);

CREATE TABLE mesh.network (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    display_name TEXT NOT NULL,
    name_key TEXT NOT NULL,
    node_limit BIGINT NOT NULL CHECK (node_limit > 0),
    state TEXT NOT NULL,
    authority_generation BIGINT NOT NULL DEFAULT 1 CHECK (authority_generation > 0),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT network_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT network_display_name_check CHECK (
        pg_catalog.char_length(display_name) BETWEEN 1 AND 128
        AND display_name = pg_catalog.btrim(display_name)
    ),
    CONSTRAINT network_name_key_check CHECK (
        pg_catalog.char_length(name_key) BETWEEN 1 AND 128
        AND name_key = pg_catalog.btrim(name_key)
    ),
    CONSTRAINT network_state_check CHECK (state IN ('active', 'suspended', 'deleted')),
    CONSTRAINT network_workspace_fk FOREIGN KEY (workspace_id)
        REFERENCES mesh.workspace (id) ON DELETE RESTRICT,
    CONSTRAINT network_timestamps_check CHECK (
        updated_at >= created_at
        AND (deleted_at IS NULL OR deleted_at >= created_at)
    ),
    UNIQUE (workspace_id, id)
);

CREATE UNIQUE INDEX network_workspace_name_active_uidx
    ON mesh.network (workspace_id, name_key)
    WHERE deleted_at IS NULL;
CREATE INDEX network_workspace_state_created_idx
    ON mesh.network (workspace_id, state, created_at DESC, id DESC);

CREATE TABLE mesh.address_realm (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT,
    kind TEXT NOT NULL,
    ipv4_enabled BOOLEAN NOT NULL,
    ipv6_enabled BOOLEAN NOT NULL,
    state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT address_realm_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT address_realm_scope_check CHECK (
        (kind = 'workspace_overlay' AND workspace_id IS NOT NULL)
        OR (kind = 'federation_alias' AND workspace_id IS NULL)
    ),
    CONSTRAINT address_realm_family_check CHECK (ipv4_enabled OR ipv6_enabled),
    CONSTRAINT address_realm_state_check CHECK (state IN ('active', 'suspended', 'deleted')),
    CONSTRAINT address_realm_deployment_fk FOREIGN KEY (deployment_id)
        REFERENCES mesh.deployment (id) ON DELETE RESTRICT,
    CONSTRAINT address_realm_workspace_scope_fk FOREIGN KEY (deployment_id, workspace_id)
        REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT address_realm_timestamps_check CHECK (
        updated_at >= created_at
        AND (deleted_at IS NULL OR deleted_at >= created_at)
    ),
    UNIQUE (deployment_id, id),
    UNIQUE (workspace_id, id)
);

CREATE UNIQUE INDEX address_realm_workspace_active_uidx
    ON mesh.address_realm (workspace_id)
    WHERE kind = 'workspace_overlay' AND state = 'active' AND deleted_at IS NULL;
CREATE UNIQUE INDEX address_realm_federation_active_uidx
    ON mesh.address_realm (deployment_id)
    WHERE kind = 'federation_alias' AND state = 'active' AND deleted_at IS NULL;
CREATE INDEX address_realm_deployment_workspace_idx
    ON mesh.address_realm (deployment_id, workspace_id);

CREATE TABLE mesh.address_pool (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT,
    address_realm_id BIGINT NOT NULL,
    purpose TEXT NOT NULL,
    prefix CIDR NOT NULL,
    family INTEGER NOT NULL,
    state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT address_pool_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT address_pool_purpose_scope_check CHECK (
        (
            workspace_id IS NOT NULL
            AND purpose IN ('node_overlay', 'workspace_service')
        )
        OR (
            workspace_id IS NULL
            AND purpose IN ('federation_resource_alias', 'federation_consumer_alias')
        )
    ),
    CONSTRAINT address_pool_family_check CHECK (
        family IN (4, 6)
        AND family = pg_catalog.family(prefix)
    ),
    CONSTRAINT address_pool_state_check CHECK (state IN ('reserved', 'active', 'quarantined', 'released')),
    CONSTRAINT address_pool_deployment_realm_fk FOREIGN KEY (deployment_id, address_realm_id)
        REFERENCES mesh.address_realm (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT address_pool_workspace_realm_fk FOREIGN KEY (workspace_id, address_realm_id)
        REFERENCES mesh.address_realm (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT address_pool_timestamps_check CHECK (
        updated_at >= created_at
        AND (deleted_at IS NULL OR deleted_at >= created_at)
    ),
    UNIQUE (deployment_id, id),
    UNIQUE (workspace_id, id),
    UNIQUE (workspace_id, address_realm_id, id)
);

ALTER TABLE mesh.address_pool
    ADD CONSTRAINT address_pool_realm_prefix_excl
    EXCLUDE USING gist (
        address_realm_id WITH =,
        prefix inet_ops WITH &&
    )
    WHERE (state IN ('reserved', 'active', 'quarantined'));

CREATE INDEX address_pool_deployment_realm_idx
    ON mesh.address_pool (deployment_id, address_realm_id);
CREATE INDEX address_pool_workspace_realm_idx
    ON mesh.address_pool (workspace_id, address_realm_id);

CREATE TABLE mesh.network_prefix (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    address_realm_id BIGINT NOT NULL,
    address_pool_id BIGINT NOT NULL,
    prefix CIDR NOT NULL,
    family INTEGER NOT NULL,
    state TEXT NOT NULL,
    quarantine_until TIMESTAMPTZ,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT network_prefix_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT network_prefix_family_check CHECK (
        family IN (4, 6)
        AND family = pg_catalog.family(prefix)
    ),
    CONSTRAINT network_prefix_state_check CHECK (state IN ('reserved', 'active', 'quarantined', 'released')),
    CONSTRAINT network_prefix_quarantine_check CHECK (
        (state = 'quarantined' AND quarantine_until IS NOT NULL)
        OR (state <> 'quarantined' AND quarantine_until IS NULL)
    ),
    CONSTRAINT network_prefix_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT network_prefix_realm_fk FOREIGN KEY (workspace_id, address_realm_id)
        REFERENCES mesh.address_realm (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT network_prefix_pool_fk FOREIGN KEY (workspace_id, address_realm_id, address_pool_id)
        REFERENCES mesh.address_pool (workspace_id, address_realm_id, id) ON DELETE RESTRICT,
    CONSTRAINT network_prefix_timestamps_check CHECK (
        updated_at >= created_at
        AND (deleted_at IS NULL OR deleted_at >= created_at)
    ),
    UNIQUE (workspace_id, network_id, id)
);

ALTER TABLE mesh.network_prefix
    ADD CONSTRAINT network_prefix_realm_prefix_excl
    EXCLUDE USING gist (
        address_realm_id WITH =,
        prefix inet_ops WITH &&
    )
    WHERE (state IN ('reserved', 'active', 'quarantined'));

CREATE INDEX network_prefix_workspace_realm_idx
    ON mesh.network_prefix (workspace_id, address_realm_id);
CREATE INDEX network_prefix_workspace_realm_pool_idx
    ON mesh.network_prefix (workspace_id, address_realm_id, address_pool_id);

CREATE TABLE mesh_ops.network_revision (
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    network_revision BIGINT NOT NULL DEFAULT 1 CHECK (network_revision > 0),
    inventory_revision BIGINT NOT NULL DEFAULT 1 CHECK (inventory_revision > 0),
    group_revision BIGINT NOT NULL DEFAULT 1 CHECK (group_revision > 0),
    policy_revision BIGINT NOT NULL DEFAULT 1 CHECK (policy_revision > 0),
    dns_revision BIGINT NOT NULL DEFAULT 1 CHECK (dns_revision > 0),
    route_revision BIGINT NOT NULL DEFAULT 1 CHECK (route_revision > 0),
    sharing_revision BIGINT NOT NULL DEFAULT 1 CHECK (sharing_revision > 0),
    isolation_generation BIGINT NOT NULL DEFAULT 1 CHECK (isolation_generation > 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    PRIMARY KEY (workspace_id, network_id),
    CONSTRAINT network_revision_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT
);

CREATE FUNCTION mesh_ops.current_workspace_id()
RETURNS BIGINT
LANGUAGE plpgsql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
DECLARE
    scope_id BIGINT;
BEGIN
    BEGIN
        scope_id := pg_catalog.current_setting('mesh.workspace_id', TRUE);
    EXCEPTION
        WHEN invalid_text_representation OR numeric_value_out_of_range THEN
            RETURN NULL;
    END;
    IF scope_id IS NULL OR scope_id <= 0 THEN
        RETURN NULL;
    END IF;
    RETURN scope_id;
END;
$function$;

CREATE FUNCTION mesh_ops.current_network_id()
RETURNS BIGINT
LANGUAGE plpgsql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
DECLARE
    scope_id BIGINT;
BEGIN
    BEGIN
        scope_id := pg_catalog.current_setting('mesh.network_id', TRUE);
    EXCEPTION
        WHEN invalid_text_representation OR numeric_value_out_of_range THEN
            RETURN NULL;
    END;
    IF scope_id IS NULL OR scope_id <= 0 THEN
        RETURN NULL;
    END IF;
    RETURN scope_id;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.current_workspace_id() FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.current_network_id() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mesh_ops.current_workspace_id() TO mesh_runtime, mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.current_network_id() TO mesh_runtime, mesh_worker;

ALTER TABLE mesh.workspace ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.workspace FORCE ROW LEVEL SECURITY;
CREATE POLICY workspace_exact_scope_policy ON mesh.workspace
    TO mesh_runtime, mesh_worker
    USING (id = mesh_ops.current_workspace_id())
    WITH CHECK (id = mesh_ops.current_workspace_id());

ALTER TABLE mesh.network ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.network FORCE ROW LEVEL SECURITY;
CREATE POLICY network_exact_scope_policy ON mesh.network
    TO mesh_runtime, mesh_worker
    USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND id = mesh_ops.current_network_id()
    )
    WITH CHECK (
        workspace_id = mesh_ops.current_workspace_id()
        AND id = mesh_ops.current_network_id()
    );

ALTER TABLE mesh.address_realm ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.address_realm FORCE ROW LEVEL SECURITY;
CREATE POLICY address_realm_exact_scope_policy ON mesh.address_realm
    TO mesh_runtime, mesh_worker
    USING (workspace_id = mesh_ops.current_workspace_id())
    WITH CHECK (workspace_id = mesh_ops.current_workspace_id());

ALTER TABLE mesh.address_pool ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.address_pool FORCE ROW LEVEL SECURITY;
CREATE POLICY address_pool_exact_scope_policy ON mesh.address_pool
    TO mesh_runtime, mesh_worker
    USING (workspace_id = mesh_ops.current_workspace_id())
    WITH CHECK (workspace_id = mesh_ops.current_workspace_id());

ALTER TABLE mesh.network_prefix ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.network_prefix FORCE ROW LEVEL SECURITY;
CREATE POLICY network_prefix_exact_scope_policy ON mesh.network_prefix
    TO mesh_runtime, mesh_worker
    USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    )
    WITH CHECK (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    );

ALTER TABLE mesh_ops.network_revision ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.network_revision FORCE ROW LEVEL SECURITY;
CREATE POLICY network_revision_exact_scope_policy ON mesh_ops.network_revision
    TO mesh_runtime, mesh_worker
    USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    )
    WITH CHECK (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    );

REVOKE ALL ON ALL TABLES IN SCHEMA mesh FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA mesh FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mesh FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA mesh_ops FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA mesh_ops FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mesh_ops FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA mesh_audit FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA mesh_audit FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mesh_audit FROM PUBLIC;

REVOKE ALL ON SCHEMA mesh, mesh_ops, mesh_audit
    FROM mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON ALL TABLES IN SCHEMA mesh, mesh_ops, mesh_audit
    FROM mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA mesh, mesh_ops, mesh_audit
    FROM mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mesh, mesh_ops, mesh_audit
    FROM mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

GRANT USAGE ON SCHEMA mesh, mesh_ops TO mesh_runtime, mesh_worker;
GRANT SELECT ON
    mesh.workspace,
    mesh.network,
    mesh.address_realm,
    mesh.address_pool,
    mesh.network_prefix,
    mesh_ops.network_revision
    TO mesh_runtime, mesh_worker;
GRANT SELECT (version, checksum, result)
    ON mesh_ops.schema_migration TO mesh_runtime, mesh_worker;
GRANT SELECT (
    singleton,
    current_schema_version,
    minimum_reader_generation,
    maximum_reader_generation,
    minimum_writer_generation,
    maximum_writer_generation,
    migration_state
) ON mesh_ops.schema_compatibility TO mesh_runtime, mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.current_workspace_id() TO mesh_runtime, mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.current_network_id() TO mesh_runtime, mesh_worker;
