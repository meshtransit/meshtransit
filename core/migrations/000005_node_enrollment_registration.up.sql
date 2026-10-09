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

CREATE TABLE mesh.enrollment_profile (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    created_by_principal_id BIGINT NOT NULL,
    display_name TEXT NOT NULL,
    name_key TEXT NOT NULL,
    node_lifetime_seconds BIGINT NOT NULL CHECK (node_lifetime_seconds > 0),
    ephemeral_mode TEXT NOT NULL,
    route_advertisement_allowed BOOLEAN NOT NULL DEFAULT FALSE,
    credential_use_policy TEXT NOT NULL,
    credential_max_uses BIGINT,
    state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT enrollment_profile_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT enrollment_profile_display_name_check CHECK (
        pg_catalog.char_length(display_name) BETWEEN 1 AND 128
        AND display_name = pg_catalog.btrim(display_name)
    ),
    CONSTRAINT enrollment_profile_name_key_check CHECK (
        pg_catalog.char_length(name_key) BETWEEN 1 AND 128
        AND name_key = pg_catalog.btrim(name_key)
    ),
    CONSTRAINT enrollment_profile_ephemeral_mode_check CHECK (
        ephemeral_mode IN ('persistent', 'ephemeral')
    ),
    CONSTRAINT enrollment_profile_use_policy_check CHECK (
        (
            credential_use_policy = 'bounded'
            AND credential_max_uses > 0
        )
        OR (
            credential_use_policy = 'unlimited'
            AND credential_max_uses IS NULL
        )
    ),
    CONSTRAINT enrollment_profile_state_check CHECK (
        state IN ('active', 'suspended', 'deleted')
    ),
    CONSTRAINT enrollment_profile_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT enrollment_profile_creator_fk FOREIGN KEY (created_by_principal_id)
        REFERENCES mesh.principal (id) ON DELETE RESTRICT,
    CONSTRAINT enrollment_profile_timestamps_check CHECK (
        updated_at >= created_at
        AND (deleted_at IS NULL OR deleted_at >= created_at)
    ),
    UNIQUE (workspace_id, network_id, id)
);

CREATE UNIQUE INDEX enrollment_profile_network_name_active_uidx
    ON mesh.enrollment_profile (workspace_id, network_id, name_key)
    WHERE deleted_at IS NULL;
CREATE INDEX enrollment_profile_network_state_created_idx
    ON mesh.enrollment_profile (workspace_id, network_id, state, created_at DESC, id DESC);
CREATE INDEX enrollment_profile_creator_idx
    ON mesh.enrollment_profile (created_by_principal_id);

CREATE TABLE mesh.enrollment_credential (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    enrollment_profile_id BIGINT NOT NULL,
    issuer_principal_id BIGINT NOT NULL,
    digest_algorithm TEXT NOT NULL,
    digest_key_id TEXT NOT NULL,
    token_digest BYTEA NOT NULL,
    token_fingerprint BYTEA NOT NULL,
    issued_recovery_epoch BIGINT NOT NULL CHECK (issued_recovery_epoch > 0),
    use_limit_kind TEXT NOT NULL,
    max_uses BIGINT,
    used_count BIGINT NOT NULL DEFAULT 0 CHECK (used_count >= 0),
    valid_from TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT enrollment_credential_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT enrollment_credential_digest_algorithm_check CHECK (
        digest_algorithm = 'hmac-sha256-v1'
    ),
    CONSTRAINT enrollment_credential_digest_key_id_check CHECK (
        pg_catalog.char_length(digest_key_id) BETWEEN 1 AND 128
        AND digest_key_id = pg_catalog.btrim(digest_key_id)
        AND digest_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    CONSTRAINT enrollment_credential_digest_check CHECK (
        pg_catalog.octet_length(token_digest) = 32
        AND pg_catalog.octet_length(token_fingerprint) = 16
    ),
    CONSTRAINT enrollment_credential_use_limit_check CHECK (
        (
            use_limit_kind = 'bounded'
            AND max_uses > 0
            AND used_count <= max_uses
        )
        OR (
            use_limit_kind = 'unlimited'
            AND max_uses IS NULL
        )
    ),
    CONSTRAINT enrollment_credential_validity_check CHECK (
        expires_at > valid_from
    ),
    CONSTRAINT enrollment_credential_state_check CHECK (
        state IN ('active', 'revoked')
    ),
    CONSTRAINT enrollment_credential_revocation_check CHECK (
        (state = 'active' AND revoked_at IS NULL AND deleted_at IS NULL)
        OR (state = 'revoked' AND revoked_at IS NOT NULL AND revoked_at >= valid_from)
    ),
    CONSTRAINT enrollment_credential_profile_fk FOREIGN KEY (
        workspace_id,
        network_id,
        enrollment_profile_id
    ) REFERENCES mesh.enrollment_profile (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT enrollment_credential_issuer_fk FOREIGN KEY (issuer_principal_id)
        REFERENCES mesh.principal (id) ON DELETE RESTRICT,
    CONSTRAINT enrollment_credential_timestamps_check CHECK (
        updated_at >= created_at
        AND (deleted_at IS NULL OR deleted_at >= created_at)
    ),
    UNIQUE (workspace_id, network_id, id),
    UNIQUE (digest_key_id, token_digest)
);

CREATE INDEX enrollment_credential_profile_idx
    ON mesh.enrollment_credential (workspace_id, network_id, enrollment_profile_id);
CREATE INDEX enrollment_credential_issuer_idx
    ON mesh.enrollment_credential (issuer_principal_id);
CREATE INDEX enrollment_credential_expiry_idx
    ON mesh.enrollment_credential (state, expires_at, id)
    WHERE state = 'active';

CREATE TABLE mesh.device (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    enrollment_profile_id BIGINT NOT NULL,
    owner_principal_id BIGINT NOT NULL,
    custodian_principal_id BIGINT NOT NULL,
    registered_by_kind TEXT NOT NULL,
    registered_by_principal_id BIGINT,
    registered_by_credential_id BIGINT,
    hostname TEXT NOT NULL,
    hostname_key TEXT NOT NULL,
    is_ephemeral BOOLEAN NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    current_machine_key_epoch BIGINT NOT NULL DEFAULT 1 CHECK (current_machine_key_epoch > 0),
    current_node_key_epoch BIGINT NOT NULL DEFAULT 1 CHECK (current_node_key_epoch > 0),
    session_generation BIGINT NOT NULL DEFAULT 1 CHECK (session_generation > 0),
    state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    deleted_at TIMESTAMPTZ,
    CONSTRAINT device_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT device_hostname_check CHECK (
        pg_catalog.char_length(hostname) BETWEEN 1 AND 253
        AND hostname = pg_catalog.btrim(hostname)
    ),
    CONSTRAINT device_hostname_key_check CHECK (
        pg_catalog.char_length(hostname_key) BETWEEN 1 AND 253
        AND hostname_key = pg_catalog.btrim(hostname_key)
    ),
    CONSTRAINT device_registered_by_check CHECK (
        (
            registered_by_kind = 'principal'
            AND registered_by_principal_id IS NOT NULL
            AND registered_by_credential_id IS NULL
        )
        OR (
            registered_by_kind = 'credential'
            AND registered_by_principal_id IS NULL
            AND registered_by_credential_id IS NOT NULL
        )
    ),
    CONSTRAINT device_state_check CHECK (
        state IN ('active', 'expired', 'revoked', 'deleted')
    ),
    CONSTRAINT device_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT device_profile_fk FOREIGN KEY (
        workspace_id,
        network_id,
        enrollment_profile_id
    ) REFERENCES mesh.enrollment_profile (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT device_owner_fk FOREIGN KEY (owner_principal_id)
        REFERENCES mesh.principal (id) ON DELETE RESTRICT,
    CONSTRAINT device_custodian_fk FOREIGN KEY (custodian_principal_id)
        REFERENCES mesh.principal (id) ON DELETE RESTRICT,
    CONSTRAINT device_registered_by_principal_fk FOREIGN KEY (registered_by_principal_id)
        REFERENCES mesh.principal (id) ON DELETE RESTRICT,
    CONSTRAINT device_registered_by_credential_fk FOREIGN KEY (
        workspace_id,
        network_id,
        registered_by_credential_id
    ) REFERENCES mesh.enrollment_credential (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT device_timestamps_check CHECK (
        updated_at >= created_at
        AND expires_at > created_at
        AND (deleted_at IS NULL OR deleted_at >= created_at)
    ),
    UNIQUE (workspace_id, network_id, id)
);

CREATE UNIQUE INDEX device_network_hostname_active_uidx
    ON mesh.device (workspace_id, network_id, hostname_key)
    WHERE deleted_at IS NULL;
CREATE INDEX device_network_state_created_idx
    ON mesh.device (workspace_id, network_id, state, created_at DESC, id DESC);
CREATE INDEX device_profile_idx
    ON mesh.device (workspace_id, network_id, enrollment_profile_id);
CREATE INDEX device_owner_idx ON mesh.device (owner_principal_id);
CREATE INDEX device_custodian_idx ON mesh.device (custodian_principal_id);
CREATE INDEX device_registered_principal_idx ON mesh.device (registered_by_principal_id);
CREATE INDEX device_registered_credential_idx
    ON mesh.device (workspace_id, network_id, registered_by_credential_id);

CREATE TABLE mesh.device_machine_key_epoch (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    device_id BIGINT NOT NULL,
    epoch BIGINT NOT NULL CHECK (epoch > 0),
    public_key BYTEA NOT NULL,
    fingerprint BYTEA NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ,
    revocation_reason TEXT,
    state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT device_machine_key_epoch_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT device_machine_key_epoch_material_check CHECK (
        pg_catalog.octet_length(public_key) = 32
        AND pg_catalog.octet_length(fingerprint) = 32
    ),
    CONSTRAINT device_machine_key_epoch_state_check CHECK (
        state IN ('active', 'expired', 'revoked')
    ),
    CONSTRAINT device_machine_key_epoch_lifecycle_check CHECK (
        (state = 'active' AND valid_until IS NULL AND revocation_reason IS NULL)
        OR (
            state = 'expired'
            AND valid_until IS NOT NULL
            AND valid_until >= valid_from
            AND revocation_reason IS NULL
        )
        OR (
            state = 'revoked'
            AND valid_until IS NOT NULL
            AND valid_until >= valid_from
            AND pg_catalog.char_length(revocation_reason) BETWEEN 1 AND 256
            AND revocation_reason = pg_catalog.btrim(revocation_reason)
        )
    ),
    CONSTRAINT device_machine_key_epoch_device_fk FOREIGN KEY (
        workspace_id,
        network_id,
        device_id
    ) REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT device_machine_key_epoch_timestamps_check CHECK (updated_at >= created_at),
    UNIQUE (workspace_id, network_id, device_id, epoch)
);

CREATE UNIQUE INDEX device_machine_key_epoch_device_active_uidx
    ON mesh.device_machine_key_epoch (workspace_id, network_id, device_id)
    WHERE state = 'active';
CREATE UNIQUE INDEX device_machine_key_epoch_key_active_uidx
    ON mesh.device_machine_key_epoch (public_key)
    WHERE state = 'active';
CREATE INDEX device_machine_key_epoch_fingerprint_idx
    ON mesh.device_machine_key_epoch (fingerprint, state);

CREATE TABLE mesh.device_node_key_epoch (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    device_id BIGINT NOT NULL,
    epoch BIGINT NOT NULL CHECK (epoch > 0),
    public_key BYTEA NOT NULL,
    fingerprint BYTEA NOT NULL,
    valid_from TIMESTAMPTZ NOT NULL,
    valid_until TIMESTAMPTZ,
    rotation_proof_hash BYTEA,
    revocation_reason TEXT,
    state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT device_node_key_epoch_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT device_node_key_epoch_material_check CHECK (
        pg_catalog.octet_length(public_key) = 32
        AND pg_catalog.octet_length(fingerprint) = 32
        AND (
            rotation_proof_hash IS NULL
            OR pg_catalog.octet_length(rotation_proof_hash) = 32
        )
    ),
    CONSTRAINT device_node_key_epoch_state_check CHECK (
        state IN ('active', 'expired', 'revoked')
    ),
    CONSTRAINT device_node_key_epoch_lifecycle_check CHECK (
        (state = 'active' AND valid_until IS NULL AND revocation_reason IS NULL)
        OR (
            state = 'expired'
            AND valid_until IS NOT NULL
            AND valid_until >= valid_from
            AND revocation_reason IS NULL
        )
        OR (
            state = 'revoked'
            AND valid_until IS NOT NULL
            AND valid_until >= valid_from
            AND pg_catalog.char_length(revocation_reason) BETWEEN 1 AND 256
            AND revocation_reason = pg_catalog.btrim(revocation_reason)
        )
    ),
    CONSTRAINT device_node_key_epoch_device_fk FOREIGN KEY (
        workspace_id,
        network_id,
        device_id
    ) REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT device_node_key_epoch_timestamps_check CHECK (updated_at >= created_at),
    UNIQUE (workspace_id, network_id, device_id, epoch)
);

CREATE UNIQUE INDEX device_node_key_epoch_device_active_uidx
    ON mesh.device_node_key_epoch (workspace_id, network_id, device_id)
    WHERE state = 'active';
CREATE UNIQUE INDEX device_node_key_epoch_key_active_uidx
    ON mesh.device_node_key_epoch (public_key)
    WHERE state = 'active';
CREATE INDEX device_node_key_epoch_fingerprint_idx
    ON mesh.device_node_key_epoch (fingerprint, state);

CREATE TABLE mesh.pending_registration (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    enrollment_profile_id BIGINT NOT NULL,
    authorization_kind TEXT NOT NULL,
    enrollment_credential_id BIGINT,
    browser_authorization_public_id UUID,
    authorized_principal_id BIGINT,
    machine_key_fingerprint BYTEA NOT NULL,
    device_id BIGINT,
    expires_at TIMESTAMPTZ NOT NULL,
    state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT pending_registration_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT pending_registration_browser_public_id_v7_check CHECK (
        browser_authorization_public_id IS NULL
        OR pg_catalog.get_byte(
            pg_catalog.uuid_send(browser_authorization_public_id),
            6
        ) >> 4 = 7
    ),
    CONSTRAINT pending_registration_machine_key_check CHECK (
        pg_catalog.octet_length(machine_key_fingerprint) = 32
    ),
    CONSTRAINT pending_registration_authorization_check CHECK (
        (
            authorization_kind = 'credential'
            AND enrollment_credential_id IS NOT NULL
            AND browser_authorization_public_id IS NULL
            AND authorized_principal_id IS NULL
        )
        OR (
            authorization_kind = 'interactive'
            AND enrollment_credential_id IS NULL
            AND browser_authorization_public_id IS NOT NULL
            AND (
                state IN ('pending', 'rejected', 'expired')
                OR authorized_principal_id IS NOT NULL
            )
        )
    ),
    CONSTRAINT pending_registration_state_check CHECK (
        state IN ('pending', 'authorized', 'completed', 'rejected', 'expired')
    ),
    CONSTRAINT pending_registration_result_check CHECK (
        (state = 'completed' AND device_id IS NOT NULL)
        OR (state <> 'completed' AND device_id IS NULL)
    ),
    CONSTRAINT pending_registration_profile_fk FOREIGN KEY (
        workspace_id,
        network_id,
        enrollment_profile_id
    ) REFERENCES mesh.enrollment_profile (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT pending_registration_credential_fk FOREIGN KEY (
        workspace_id,
        network_id,
        enrollment_credential_id
    ) REFERENCES mesh.enrollment_credential (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT pending_registration_principal_fk FOREIGN KEY (authorized_principal_id)
        REFERENCES mesh.principal (id) ON DELETE RESTRICT,
    CONSTRAINT pending_registration_device_fk FOREIGN KEY (
        workspace_id,
        network_id,
        device_id
    ) REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT pending_registration_timestamps_check CHECK (
        updated_at >= created_at
        AND expires_at > created_at
    ),
    UNIQUE (workspace_id, network_id, id)
);

CREATE UNIQUE INDEX pending_registration_machine_active_uidx
    ON mesh.pending_registration (workspace_id, network_id, machine_key_fingerprint)
    WHERE state IN ('pending', 'authorized');
CREATE INDEX pending_registration_profile_idx
    ON mesh.pending_registration (workspace_id, network_id, enrollment_profile_id);
CREATE INDEX pending_registration_credential_idx
    ON mesh.pending_registration (workspace_id, network_id, enrollment_credential_id);
CREATE INDEX pending_registration_principal_idx
    ON mesh.pending_registration (authorized_principal_id);
CREATE INDEX pending_registration_device_idx
    ON mesh.pending_registration (workspace_id, network_id, device_id);
CREATE INDEX pending_registration_expiry_idx
    ON mesh.pending_registration (state, expires_at, id)
    WHERE state IN ('pending', 'authorized');

CREATE TABLE mesh.enrollment_credential_use (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    enrollment_credential_id BIGINT NOT NULL,
    pending_registration_id BIGINT NOT NULL,
    device_id BIGINT NOT NULL,
    machine_key_fingerprint BYTEA NOT NULL,
    result TEXT NOT NULL,
    used_at TIMESTAMPTZ NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version = 1),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT enrollment_credential_use_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT enrollment_credential_use_machine_key_check CHECK (
        pg_catalog.octet_length(machine_key_fingerprint) = 32
    ),
    CONSTRAINT enrollment_credential_use_result_check CHECK (
        result IN ('created', 'resumed')
    ),
    CONSTRAINT enrollment_credential_use_time_check CHECK (used_at >= created_at),
    CONSTRAINT enrollment_credential_use_credential_fk FOREIGN KEY (
        workspace_id,
        network_id,
        enrollment_credential_id
    ) REFERENCES mesh.enrollment_credential (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT enrollment_credential_use_registration_fk FOREIGN KEY (
        workspace_id,
        network_id,
        pending_registration_id
    ) REFERENCES mesh.pending_registration (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT enrollment_credential_use_device_fk FOREIGN KEY (
        workspace_id,
        network_id,
        device_id
    ) REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE RESTRICT,
    UNIQUE (workspace_id, network_id, pending_registration_id),
    UNIQUE (enrollment_credential_id, pending_registration_id)
);

CREATE INDEX enrollment_credential_use_credential_idx
    ON mesh.enrollment_credential_use (workspace_id, network_id, enrollment_credential_id);
CREATE INDEX enrollment_credential_use_device_idx
    ON mesh.enrollment_credential_use (workspace_id, network_id, device_id);

CREATE TABLE mesh.node_address_lease (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    address_realm_id BIGINT NOT NULL,
    address_pool_id BIGINT NOT NULL,
    network_prefix_id BIGINT NOT NULL,
    device_id BIGINT NOT NULL,
    address INET NOT NULL,
    family INTEGER NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    lease_role TEXT NOT NULL,
    state TEXT NOT NULL,
    released_at TIMESTAMPTZ,
    quarantine_until TIMESTAMPTZ,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT node_address_lease_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT node_address_lease_family_check CHECK (
        family IN (4, 6)
        AND family = pg_catalog.family(address)
        AND (
            (family = 4 AND pg_catalog.masklen(address) = 32)
            OR (family = 6 AND pg_catalog.masklen(address) = 128)
        )
    ),
    CONSTRAINT node_address_lease_role_check CHECK (
        lease_role IN ('primary', 'secondary', 'draining')
    ),
    CONSTRAINT node_address_lease_state_check CHECK (
        state IN ('active', 'quarantined', 'released')
    ),
    CONSTRAINT node_address_lease_lifecycle_check CHECK (
        (
            state = 'active'
            AND released_at IS NULL
            AND quarantine_until IS NULL
        )
        OR (
            state = 'quarantined'
            AND released_at IS NOT NULL
            AND quarantine_until > released_at
        )
        OR (
            state = 'released'
            AND released_at IS NOT NULL
            AND quarantine_until IS NULL
        )
    ),
    CONSTRAINT node_address_lease_device_fk FOREIGN KEY (
        workspace_id,
        network_id,
        device_id
    ) REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT node_address_lease_realm_fk FOREIGN KEY (workspace_id, address_realm_id)
        REFERENCES mesh.address_realm (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT node_address_lease_pool_fk FOREIGN KEY (
        workspace_id,
        address_realm_id,
        address_pool_id
    ) REFERENCES mesh.address_pool (workspace_id, address_realm_id, id) ON DELETE RESTRICT,
    CONSTRAINT node_address_lease_prefix_fk FOREIGN KEY (
        workspace_id,
        network_id,
        network_prefix_id
    ) REFERENCES mesh.network_prefix (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT node_address_lease_timestamps_check CHECK (updated_at >= created_at),
    UNIQUE (workspace_id, network_id, id)
);

CREATE UNIQUE INDEX node_address_lease_address_live_uidx
    ON mesh.node_address_lease (address_realm_id, address)
    WHERE state IN ('active', 'quarantined');
CREATE UNIQUE INDEX node_address_lease_device_primary_uidx
    ON mesh.node_address_lease (workspace_id, network_id, device_id, family)
    WHERE state = 'active' AND lease_role = 'primary';
CREATE INDEX node_address_lease_pool_allocation_idx
    ON mesh.node_address_lease (
        address_realm_id,
        address_pool_id,
        state,
        quarantine_until,
        id
    );
CREATE INDEX node_address_lease_device_idx
    ON mesh.node_address_lease (workspace_id, network_id, device_id, family, state);
CREATE INDEX node_address_lease_prefix_idx
    ON mesh.node_address_lease (workspace_id, network_id, network_prefix_id);

ALTER TABLE mesh.enrollment_profile ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.enrollment_profile FORCE ROW LEVEL SECURITY;
CREATE POLICY enrollment_profile_migrator_policy ON mesh.enrollment_profile
    TO mesh_migrator
    USING (TRUE)
    WITH CHECK (TRUE);
CREATE POLICY enrollment_profile_exact_scope_policy ON mesh.enrollment_profile
    TO mesh_runtime
    USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    )
    WITH CHECK (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    );

ALTER TABLE mesh.enrollment_credential ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.enrollment_credential FORCE ROW LEVEL SECURITY;
CREATE POLICY enrollment_credential_migrator_policy ON mesh.enrollment_credential
    TO mesh_migrator
    USING (TRUE)
    WITH CHECK (TRUE);
CREATE POLICY enrollment_credential_exact_scope_policy ON mesh.enrollment_credential
    TO mesh_runtime
    USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    )
    WITH CHECK (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    );

ALTER TABLE mesh.device ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.device FORCE ROW LEVEL SECURITY;
CREATE POLICY device_migrator_policy ON mesh.device
    TO mesh_migrator
    USING (TRUE)
    WITH CHECK (TRUE);
CREATE POLICY device_exact_scope_policy ON mesh.device
    TO mesh_runtime
    USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    )
    WITH CHECK (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    );

ALTER TABLE mesh.device_machine_key_epoch ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.device_machine_key_epoch FORCE ROW LEVEL SECURITY;
CREATE POLICY device_machine_key_epoch_migrator_policy ON mesh.device_machine_key_epoch
    TO mesh_migrator
    USING (TRUE)
    WITH CHECK (TRUE);
CREATE POLICY device_machine_key_epoch_exact_scope_policy ON mesh.device_machine_key_epoch
    TO mesh_runtime
    USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    )
    WITH CHECK (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    );

ALTER TABLE mesh.device_node_key_epoch ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.device_node_key_epoch FORCE ROW LEVEL SECURITY;
CREATE POLICY device_node_key_epoch_migrator_policy ON mesh.device_node_key_epoch
    TO mesh_migrator
    USING (TRUE)
    WITH CHECK (TRUE);
CREATE POLICY device_node_key_epoch_exact_scope_policy ON mesh.device_node_key_epoch
    TO mesh_runtime
    USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    )
    WITH CHECK (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    );

ALTER TABLE mesh.pending_registration ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.pending_registration FORCE ROW LEVEL SECURITY;
CREATE POLICY pending_registration_migrator_policy ON mesh.pending_registration
    TO mesh_migrator
    USING (TRUE)
    WITH CHECK (TRUE);
CREATE POLICY pending_registration_exact_scope_policy ON mesh.pending_registration
    TO mesh_runtime
    USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    )
    WITH CHECK (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    );

ALTER TABLE mesh.enrollment_credential_use ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.enrollment_credential_use FORCE ROW LEVEL SECURITY;
CREATE POLICY enrollment_credential_use_migrator_policy ON mesh.enrollment_credential_use
    TO mesh_migrator
    USING (TRUE)
    WITH CHECK (TRUE);
CREATE POLICY enrollment_credential_use_exact_scope_policy ON mesh.enrollment_credential_use
    TO mesh_runtime
    USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    )
    WITH CHECK (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    );

ALTER TABLE mesh.node_address_lease ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.node_address_lease FORCE ROW LEVEL SECURITY;
CREATE POLICY node_address_lease_migrator_policy ON mesh.node_address_lease
    TO mesh_migrator
    USING (TRUE)
    WITH CHECK (TRUE);
CREATE POLICY node_address_lease_exact_scope_policy ON mesh.node_address_lease
    TO mesh_runtime
    USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    )
    WITH CHECK (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    );

CREATE TRIGGER enrollment_profile_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.enrollment_profile
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('enrollment_profile', 'public_id');
CREATE TRIGGER enrollment_credential_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.enrollment_credential
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('enrollment_credential', 'public_id');
CREATE TRIGGER device_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.device
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('device', 'public_id');
CREATE TRIGGER device_machine_key_epoch_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.device_machine_key_epoch
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('device_machine_key_epoch', 'public_id');
CREATE TRIGGER device_node_key_epoch_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.device_node_key_epoch
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('device_node_key_epoch', 'public_id');
CREATE TRIGGER pending_registration_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.pending_registration
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('pending_registration', 'public_id');
CREATE TRIGGER enrollment_credential_use_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.enrollment_credential_use
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('enrollment_credential_use', 'public_id');
CREATE TRIGGER node_address_lease_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.node_address_lease
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('node_address_lease', 'public_id');

CREATE TRIGGER enrollment_credential_use_immutable
BEFORE UPDATE OR DELETE ON mesh.enrollment_credential_use
FOR EACH ROW EXECUTE FUNCTION mesh_audit.reject_immutable_change();

REVOKE ALL ON ALL TABLES IN SCHEMA mesh FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA mesh FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mesh, mesh_audit FROM PUBLIC;

REVOKE ALL ON
    mesh.enrollment_profile,
    mesh.enrollment_credential,
    mesh.device,
    mesh.device_machine_key_epoch,
    mesh.device_node_key_epoch,
    mesh.pending_registration,
    mesh.enrollment_credential_use,
    mesh.node_address_lease
    FROM mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

GRANT SELECT ON
    mesh.enrollment_profile,
    mesh.enrollment_credential,
    mesh.device,
    mesh.device_machine_key_epoch,
    mesh.device_node_key_epoch,
    mesh.pending_registration,
    mesh.enrollment_credential_use,
    mesh.node_address_lease
    TO mesh_runtime;

GRANT INSERT ON
    mesh.enrollment_profile,
    mesh.enrollment_credential,
    mesh.device,
    mesh.device_machine_key_epoch,
    mesh.device_node_key_epoch,
    mesh.pending_registration,
    mesh.enrollment_credential_use,
    mesh.node_address_lease
    TO mesh_runtime;

GRANT UPDATE (
    display_name,
    name_key,
    node_lifetime_seconds,
    ephemeral_mode,
    route_advertisement_allowed,
    credential_use_policy,
    credential_max_uses,
    state,
    version,
    updated_at,
    deleted_at
) ON mesh.enrollment_profile TO mesh_runtime;

GRANT UPDATE (
    used_count,
    revoked_at,
    state,
    version,
    updated_at,
    deleted_at
) ON mesh.enrollment_credential TO mesh_runtime;

GRANT UPDATE (
    owner_principal_id,
    custodian_principal_id,
    hostname,
    hostname_key,
    expires_at,
    current_machine_key_epoch,
    current_node_key_epoch,
    session_generation,
    state,
    version,
    updated_at,
    deleted_at
) ON mesh.device TO mesh_runtime;

GRANT UPDATE (
    valid_until,
    revocation_reason,
    state,
    version,
    updated_at
) ON mesh.device_machine_key_epoch TO mesh_runtime;

GRANT UPDATE (
    valid_until,
    rotation_proof_hash,
    revocation_reason,
    state,
    version,
    updated_at
) ON mesh.device_node_key_epoch TO mesh_runtime;

GRANT UPDATE (
    authorized_principal_id,
    device_id,
    state,
    version,
    updated_at
) ON mesh.pending_registration TO mesh_runtime;

GRANT UPDATE (
    lease_role,
    state,
    released_at,
    quarantine_until,
    version,
    updated_at
) ON mesh.node_address_lease TO mesh_runtime;

GRANT USAGE ON SEQUENCE
    mesh.enrollment_profile_id_seq,
    mesh.enrollment_credential_id_seq,
    mesh.device_id_seq,
    mesh.device_machine_key_epoch_id_seq,
    mesh.device_node_key_epoch_id_seq,
    mesh.pending_registration_id_seq,
    mesh.enrollment_credential_use_id_seq,
    mesh.node_address_lease_id_seq
    TO mesh_runtime;

GRANT EXECUTE ON FUNCTION mesh_audit.append_authority_evidence(
    BIGINT, UUID, UUID, BIGINT, BYTEA, BYTEA, TEXT, UUID, BIGINT, BIGINT,
    UUID, TEXT, TEXT, UUID, BYTEA, BYTEA, JSONB, TEXT, JSONB
) TO mesh_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
