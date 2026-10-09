CREATE TABLE mesh.resource_export (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    provider_workspace_id BIGINT NOT NULL,
    provider_network_id BIGINT NOT NULL,
    consumer_workspace_id BIGINT NOT NULL,
    consumer_network_id BIGINT NOT NULL,
    resource_id BIGINT NOT NULL,
    resource_public_id UUID NOT NULL,
    resource_version BIGINT NOT NULL CHECK (resource_version > 0),
    target_generation BIGINT NOT NULL CHECK (target_generation > 0),
    resource_semantic_hash BYTEA NOT NULL,
    constraint_hash BYTEA NOT NULL,
    provider_authority_generation BIGINT NOT NULL CHECK (provider_authority_generation > 0),
    expires_at TIMESTAMPTZ NOT NULL,
    state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT resource_export_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT resource_export_resource_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(resource_public_id), 6) >> 4 = 7
    ),
    CONSTRAINT resource_export_scope_check CHECK (
        provider_workspace_id <> consumer_workspace_id
        OR provider_network_id <> consumer_network_id
    ),
    CONSTRAINT resource_export_state_check CHECK (state IN ('active', 'revoked')),
    CONSTRAINT resource_export_hashes_check CHECK (
        pg_catalog.octet_length(resource_semantic_hash) = 32
        AND resource_semantic_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        AND pg_catalog.octet_length(constraint_hash) = 32
        AND constraint_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
    ),
    CONSTRAINT resource_export_timestamps_check CHECK (
        updated_at >= created_at
        AND expires_at > created_at
        AND (
            (state = 'active' AND revoked_at IS NULL)
            OR (state = 'revoked' AND revoked_at >= created_at)
        )
    ),
    CONSTRAINT resource_export_provider_workspace_fk FOREIGN KEY (
        deployment_id, provider_workspace_id
    ) REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT resource_export_consumer_workspace_fk FOREIGN KEY (
        deployment_id, consumer_workspace_id
    ) REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT resource_export_provider_network_fk FOREIGN KEY (
        provider_workspace_id, provider_network_id
    ) REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT resource_export_consumer_network_fk FOREIGN KEY (
        consumer_workspace_id, consumer_network_id
    ) REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT resource_export_resource_fk FOREIGN KEY (
        provider_workspace_id, provider_network_id, resource_id
    ) REFERENCES mesh.resource (workspace_id, network_id, id) ON DELETE RESTRICT,
    UNIQUE (provider_workspace_id, provider_network_id, id),
    UNIQUE (provider_workspace_id, provider_network_id, consumer_workspace_id, consumer_network_id, id)
);

CREATE INDEX resource_export_provider_resource_active_idx
    ON mesh.resource_export (
        provider_workspace_id, provider_network_id, resource_id, state, expires_at, id
    );
CREATE INDEX resource_export_consumer_active_idx
    ON mesh.resource_export (
        consumer_workspace_id, consumer_network_id, state, expires_at, id
    );

CREATE TABLE mesh.resource_export_constraint (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    provider_workspace_id BIGINT NOT NULL,
    provider_network_id BIGINT NOT NULL,
    consumer_workspace_id BIGINT NOT NULL,
    consumer_network_id BIGINT NOT NULL,
    resource_export_id BIGINT NOT NULL,
    protocol TEXT NOT NULL,
    destination_ports INT4MULTIRANGE NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version = 1),
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT resource_export_constraint_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT resource_export_constraint_protocol_check CHECK (
        protocol IN ('tcp', 'udp', 'icmp')
    ),
    CONSTRAINT resource_export_constraint_ports_check CHECK (
        (
            protocol IN ('tcp', 'udp')
            AND destination_ports <> '{}'::INT4MULTIRANGE
            AND destination_ports <@ INT4MULTIRANGE(INT4RANGE(1, 65536, '[)'))
        )
        OR (protocol = 'icmp' AND destination_ports = '{}'::INT4MULTIRANGE)
    ),
    CONSTRAINT resource_export_constraint_export_fk FOREIGN KEY (
        provider_workspace_id,
        provider_network_id,
        consumer_workspace_id,
        consumer_network_id,
        resource_export_id
    ) REFERENCES mesh.resource_export (
        provider_workspace_id,
        provider_network_id,
        consumer_workspace_id,
        consumer_network_id,
        id
    ) ON DELETE RESTRICT,
    UNIQUE (resource_export_id, protocol)
);

CREATE INDEX resource_export_constraint_export_idx
    ON mesh.resource_export_constraint (
        provider_workspace_id, provider_network_id, resource_export_id, id
    );

CREATE TABLE mesh.share_offer (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    provider_workspace_id BIGINT NOT NULL,
    provider_network_id BIGINT NOT NULL,
    consumer_workspace_id BIGINT NOT NULL,
    consumer_network_id BIGINT NOT NULL,
    resource_export_id BIGINT NOT NULL,
    nonce_digest BYTEA NOT NULL,
    constraint_hash BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    state TEXT NOT NULL,
    accepted_contract_public_id UUID,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    decided_at TIMESTAMPTZ,
    CONSTRAINT share_offer_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT share_offer_contract_public_id_v7_check CHECK (
        accepted_contract_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(accepted_contract_public_id), 6) >> 4 = 7
    ),
    CONSTRAINT share_offer_scope_check CHECK (
        provider_workspace_id <> consumer_workspace_id
        OR provider_network_id <> consumer_network_id
    ),
    CONSTRAINT share_offer_hashes_check CHECK (
        pg_catalog.octet_length(nonce_digest) = 32
        AND nonce_digest <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        AND pg_catalog.octet_length(constraint_hash) = 32
        AND constraint_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
    ),
    CONSTRAINT share_offer_state_check CHECK (
        state IN ('offered', 'accepted', 'rejected', 'expired', 'revoked')
    ),
    CONSTRAINT share_offer_state_shape_check CHECK (
        (
            state = 'offered'
            AND accepted_contract_public_id IS NULL
            AND decided_at IS NULL
        )
        OR (
            state = 'accepted'
            AND accepted_contract_public_id IS NOT NULL
            AND decided_at IS NOT NULL
        )
        OR (
            state IN ('rejected', 'revoked')
            AND accepted_contract_public_id IS NULL
            AND decided_at IS NOT NULL
            AND decided_at < expires_at
        )
        OR (
            state = 'expired'
            AND accepted_contract_public_id IS NULL
            AND decided_at >= expires_at
        )
    ),
    CONSTRAINT share_offer_timestamps_check CHECK (
        updated_at >= created_at AND expires_at > created_at
    ),
    CONSTRAINT share_offer_export_fk FOREIGN KEY (
        provider_workspace_id,
        provider_network_id,
        consumer_workspace_id,
        consumer_network_id,
        resource_export_id
    ) REFERENCES mesh.resource_export (
        provider_workspace_id,
        provider_network_id,
        consumer_workspace_id,
        consumer_network_id,
        id
    ) ON DELETE RESTRICT,
    UNIQUE (provider_workspace_id, provider_network_id, consumer_workspace_id, consumer_network_id, id)
);

CREATE INDEX share_offer_consumer_state_expiry_idx
    ON mesh.share_offer (
        consumer_workspace_id, consumer_network_id, state, expires_at, id
    );
CREATE INDEX share_offer_provider_state_expiry_idx
    ON mesh.share_offer (
        provider_workspace_id, provider_network_id, state, expires_at, id
    );

-- This immutable, non-authoritative locator permits one exact local Network
-- scope to discover the other side before the bilateral RLS scope is fixed.
-- Lifecycle and traffic authority remain exclusively in the sharing tables.
CREATE TABLE mesh.share_offer_locator (
    local_workspace_id BIGINT NOT NULL,
    local_network_id BIGINT NOT NULL,
    offer_id BIGINT NOT NULL,
    offer_public_id UUID NOT NULL,
    provider_workspace_id BIGINT NOT NULL,
    provider_network_id BIGINT NOT NULL,
    consumer_workspace_id BIGINT NOT NULL,
    consumer_network_id BIGINT NOT NULL,
    provider_workspace_public_id UUID NOT NULL,
    provider_network_public_id UUID NOT NULL,
    consumer_workspace_public_id UUID NOT NULL,
    consumer_network_public_id UUID NOT NULL,
    direction TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT share_offer_locator_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(offer_public_id), 6) >> 4 = 7
    ),
    CONSTRAINT share_offer_locator_scope_public_ids_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(provider_workspace_public_id), 6) >> 4 = 7
        AND pg_catalog.get_byte(pg_catalog.uuid_send(provider_network_public_id), 6) >> 4 = 7
        AND pg_catalog.get_byte(pg_catalog.uuid_send(consumer_workspace_public_id), 6) >> 4 = 7
        AND pg_catalog.get_byte(pg_catalog.uuid_send(consumer_network_public_id), 6) >> 4 = 7
    ),
    CONSTRAINT share_offer_locator_direction_check CHECK (
        direction IN ('outgoing', 'incoming')
    ),
    CONSTRAINT share_offer_locator_state_check CHECK (
        state IN ('offered', 'accepted', 'rejected', 'expired', 'revoked')
    ),
    CONSTRAINT share_offer_locator_local_scope_check CHECK (
        (
            direction = 'outgoing'
            AND local_workspace_id = provider_workspace_id
            AND local_network_id = provider_network_id
        ) OR (
            direction = 'incoming'
            AND local_workspace_id = consumer_workspace_id
            AND local_network_id = consumer_network_id
        )
    ),
    CONSTRAINT share_offer_locator_offer_fk FOREIGN KEY (
        provider_workspace_id,
        provider_network_id,
        consumer_workspace_id,
        consumer_network_id,
        offer_id
    ) REFERENCES mesh.share_offer (
        provider_workspace_id,
        provider_network_id,
        consumer_workspace_id,
        consumer_network_id,
        id
    ) ON DELETE RESTRICT,
    CONSTRAINT share_offer_locator_local_network_fk FOREIGN KEY (
        local_workspace_id, local_network_id
    ) REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    PRIMARY KEY (local_workspace_id, local_network_id, offer_id)
);

CREATE INDEX share_offer_locator_network_direction_offer_idx
    ON mesh.share_offer_locator (
        local_workspace_id, local_network_id, direction, state, offer_public_id
    );

CREATE TABLE mesh.trust_contract (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    imported_resource_public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    provider_workspace_id BIGINT NOT NULL,
    provider_network_id BIGINT NOT NULL,
    consumer_workspace_id BIGINT NOT NULL,
    consumer_network_id BIGINT NOT NULL,
    share_offer_id BIGINT NOT NULL UNIQUE,
    resource_export_id BIGINT NOT NULL,
    resource_id BIGINT NOT NULL,
    resource_version BIGINT NOT NULL CHECK (resource_version > 0),
    target_generation BIGINT NOT NULL CHECK (target_generation > 0),
    resource_semantic_hash BYTEA NOT NULL,
    constraint_hash BYTEA NOT NULL,
    provider_authority_generation BIGINT NOT NULL CHECK (provider_authority_generation > 0),
    consumer_authority_generation BIGINT NOT NULL CHECK (consumer_authority_generation > 0),
    recovery_epoch BIGINT NOT NULL CHECK (recovery_epoch > 0),
    expires_at TIMESTAMPTZ NOT NULL,
    state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    ended_at TIMESTAMPTZ,
    CONSTRAINT trust_contract_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT trust_contract_import_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(imported_resource_public_id), 6) >> 4 = 7
    ),
    CONSTRAINT trust_contract_scope_check CHECK (
        provider_workspace_id <> consumer_workspace_id
        OR provider_network_id <> consumer_network_id
    ),
    CONSTRAINT trust_contract_hashes_check CHECK (
        pg_catalog.octet_length(resource_semantic_hash) = 32
        AND resource_semantic_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        AND pg_catalog.octet_length(constraint_hash) = 32
        AND constraint_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
    ),
    CONSTRAINT trust_contract_state_check CHECK (
        state IN ('activating', 'active', 'revoked', 'expired', 'invalidated')
    ),
    CONSTRAINT trust_contract_state_shape_check CHECK (
        (state IN ('activating', 'active') AND ended_at IS NULL)
        OR (state IN ('revoked', 'invalidated') AND ended_at IS NOT NULL)
        OR (state = 'expired' AND ended_at >= expires_at)
    ),
    CONSTRAINT trust_contract_timestamps_check CHECK (
        updated_at >= created_at AND expires_at > created_at
    ),
    CONSTRAINT trust_contract_offer_fk FOREIGN KEY (
        provider_workspace_id,
        provider_network_id,
        consumer_workspace_id,
        consumer_network_id,
        share_offer_id
    ) REFERENCES mesh.share_offer (
        provider_workspace_id,
        provider_network_id,
        consumer_workspace_id,
        consumer_network_id,
        id
    ) ON DELETE RESTRICT,
    CONSTRAINT trust_contract_export_fk FOREIGN KEY (
        provider_workspace_id,
        provider_network_id,
        consumer_workspace_id,
        consumer_network_id,
        resource_export_id
    ) REFERENCES mesh.resource_export (
        provider_workspace_id,
        provider_network_id,
        consumer_workspace_id,
        consumer_network_id,
        id
    ) ON DELETE RESTRICT,
    CONSTRAINT trust_contract_resource_fk FOREIGN KEY (
        provider_workspace_id, provider_network_id, resource_id
    ) REFERENCES mesh.resource (workspace_id, network_id, id) ON DELETE RESTRICT,
    UNIQUE (provider_workspace_id, provider_network_id, consumer_workspace_id, consumer_network_id, id),
    UNIQUE (consumer_workspace_id, consumer_network_id, id)
);

ALTER TABLE mesh.share_offer
ADD CONSTRAINT share_offer_accepted_contract_fk FOREIGN KEY (accepted_contract_public_id)
    REFERENCES mesh.trust_contract (public_id) ON DELETE RESTRICT
    DEFERRABLE INITIALLY DEFERRED;

CREATE INDEX trust_contract_provider_resource_state_idx
    ON mesh.trust_contract (
        provider_workspace_id, provider_network_id, resource_id, state, expires_at, id
    );
CREATE INDEX trust_contract_consumer_state_idx
    ON mesh.trust_contract (
        consumer_workspace_id, consumer_network_id, state, expires_at, id
    );

CREATE TABLE mesh.imported_resource (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    trust_contract_id BIGINT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    name_key TEXT NOT NULL,
    state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    ended_at TIMESTAMPTZ,
    CONSTRAINT imported_resource_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT imported_resource_display_name_check CHECK (
        pg_catalog.char_length(display_name) BETWEEN 1 AND 128
        AND display_name = pg_catalog.btrim(display_name)
    ),
    CONSTRAINT imported_resource_name_key_check CHECK (
        pg_catalog.char_length(name_key) BETWEEN 1 AND 128
        AND name_key = pg_catalog.lower(display_name)
    ),
    CONSTRAINT imported_resource_state_check CHECK (
        state IN ('activating', 'active', 'revoked', 'expired', 'invalidated')
    ),
    CONSTRAINT imported_resource_state_shape_check CHECK (
        (state IN ('activating', 'active') AND ended_at IS NULL)
        OR (state IN ('revoked', 'invalidated') AND ended_at IS NOT NULL)
        OR (state = 'expired' AND ended_at IS NOT NULL)
    ),
    CONSTRAINT imported_resource_timestamps_check CHECK (updated_at >= created_at),
    CONSTRAINT imported_resource_workspace_fk FOREIGN KEY (deployment_id, workspace_id)
        REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT imported_resource_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT imported_resource_contract_fk FOREIGN KEY (
        workspace_id, network_id, trust_contract_id
    ) REFERENCES mesh.trust_contract (
        consumer_workspace_id, consumer_network_id, id
    ) ON DELETE RESTRICT,
    UNIQUE (workspace_id, network_id, id)
);

CREATE UNIQUE INDEX imported_resource_network_name_current_uidx
    ON mesh.imported_resource (workspace_id, network_id, name_key)
    WHERE state IN ('activating', 'active');
CREATE INDEX imported_resource_network_state_id_idx
    ON mesh.imported_resource (workspace_id, network_id, state, id);

CREATE FUNCTION mesh_ops.current_share_provider_workspace_id()
RETURNS BIGINT
LANGUAGE plpgsql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
BEGIN
    RETURN NULLIF(pg_catalog.current_setting('mesh.share_provider_workspace_id', TRUE), '')::BIGINT;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
    RETURN NULL;
END;
$function$;

CREATE FUNCTION mesh_ops.enforce_share_offer_locator_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Share Offer locator is retained';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'offered' THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Share Offer locator insertion';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.local_workspace_id <> NEW.local_workspace_id
        OR OLD.local_network_id <> NEW.local_network_id
        OR OLD.offer_id <> NEW.offer_id
        OR OLD.offer_public_id <> NEW.offer_public_id
        OR OLD.provider_workspace_id <> NEW.provider_workspace_id
        OR OLD.provider_network_id <> NEW.provider_network_id
        OR OLD.consumer_workspace_id <> NEW.consumer_workspace_id
        OR OLD.consumer_network_id <> NEW.consumer_network_id
        OR OLD.provider_workspace_public_id <> NEW.provider_workspace_public_id
        OR OLD.provider_network_public_id <> NEW.provider_network_public_id
        OR OLD.consumer_workspace_public_id <> NEW.consumer_workspace_public_id
        OR OLD.consumer_network_public_id <> NEW.consumer_network_public_id
        OR OLD.direction <> NEW.direction
        OR OLD.created_at <> NEW.created_at
        OR OLD.state <> 'offered'
        OR NEW.state NOT IN ('accepted', 'rejected', 'expired', 'revoked') THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Share Offer locator transition';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE FUNCTION mesh_ops.current_share_provider_network_id()
RETURNS BIGINT
LANGUAGE plpgsql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
BEGIN
    RETURN NULLIF(pg_catalog.current_setting('mesh.share_provider_network_id', TRUE), '')::BIGINT;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
    RETURN NULL;
END;
$function$;

CREATE FUNCTION mesh_ops.current_share_consumer_workspace_id()
RETURNS BIGINT
LANGUAGE plpgsql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
BEGIN
    RETURN NULLIF(pg_catalog.current_setting('mesh.share_consumer_workspace_id', TRUE), '')::BIGINT;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
    RETURN NULL;
END;
$function$;

CREATE FUNCTION mesh_ops.current_share_consumer_network_id()
RETURNS BIGINT
LANGUAGE plpgsql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
BEGIN
    RETURN NULLIF(pg_catalog.current_setting('mesh.share_consumer_network_id', TRUE), '')::BIGINT;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
    RETURN NULL;
END;
$function$;

CREATE FUNCTION mesh_ops.set_share_scope_v1(
    p_provider_workspace_id BIGINT,
    p_provider_network_id BIGINT,
    p_consumer_workspace_id BIGINT,
    p_consumer_network_id BIGINT
)
RETURNS VOID
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF p_provider_workspace_id <= 0 OR p_provider_network_id <= 0
        OR p_consumer_workspace_id <= 0 OR p_consumer_network_id <= 0
        OR (
            p_provider_workspace_id = p_consumer_workspace_id
            AND p_provider_network_id = p_consumer_network_id
        ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid sharing scope';
    END IF;
    PERFORM pg_catalog.set_config(
        'mesh.share_provider_workspace_id', p_provider_workspace_id::TEXT, TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.share_provider_network_id', p_provider_network_id::TEXT, TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.share_consumer_workspace_id', p_consumer_workspace_id::TEXT, TRUE
    );
    PERFORM pg_catalog.set_config(
        'mesh.share_consumer_network_id', p_consumer_network_id::TEXT, TRUE
    );
END;
$function$;

CREATE FUNCTION mesh_ops.enforce_resource_sharing_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Resource sharing authority is retained';
    END IF;
    IF TG_OP = 'INSERT' THEN
        RETURN NEW;
    END IF;
    IF TG_TABLE_NAME = 'resource_export_constraint' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Resource export constraints are immutable';
    END IF;
    IF OLD.public_id <> NEW.public_id OR NEW.version <> OLD.version + 1
        OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource sharing transition';
    END IF;
    IF TG_TABLE_NAME = 'resource_export' THEN
        IF OLD.deployment_id <> NEW.deployment_id
            OR OLD.provider_workspace_id <> NEW.provider_workspace_id
            OR OLD.provider_network_id <> NEW.provider_network_id
            OR OLD.consumer_workspace_id <> NEW.consumer_workspace_id
            OR OLD.consumer_network_id <> NEW.consumer_network_id
            OR OLD.resource_id <> NEW.resource_id
            OR OLD.resource_public_id <> NEW.resource_public_id
            OR OLD.resource_version <> NEW.resource_version
            OR OLD.target_generation <> NEW.target_generation
            OR OLD.resource_semantic_hash <> NEW.resource_semantic_hash
            OR OLD.constraint_hash <> NEW.constraint_hash
            OR OLD.provider_authority_generation <> NEW.provider_authority_generation
            OR OLD.expires_at <> NEW.expires_at
            OR OLD.state <> 'active' OR NEW.state <> 'revoked' THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource Export transition';
        END IF;
    ELSIF TG_TABLE_NAME = 'share_offer' THEN
        IF OLD.deployment_id <> NEW.deployment_id
            OR OLD.provider_workspace_id <> NEW.provider_workspace_id
            OR OLD.provider_network_id <> NEW.provider_network_id
            OR OLD.consumer_workspace_id <> NEW.consumer_workspace_id
            OR OLD.consumer_network_id <> NEW.consumer_network_id
            OR OLD.resource_export_id <> NEW.resource_export_id
            OR OLD.nonce_digest <> NEW.nonce_digest
            OR OLD.constraint_hash <> NEW.constraint_hash
            OR OLD.expires_at <> NEW.expires_at
            OR OLD.state <> 'offered'
            OR NEW.state NOT IN ('accepted', 'rejected', 'expired', 'revoked') THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Share Offer transition';
        END IF;
    ELSIF TG_TABLE_NAME = 'trust_contract' THEN
        IF OLD.imported_resource_public_id <> NEW.imported_resource_public_id
            OR OLD.deployment_id <> NEW.deployment_id
            OR OLD.provider_workspace_id <> NEW.provider_workspace_id
            OR OLD.provider_network_id <> NEW.provider_network_id
            OR OLD.consumer_workspace_id <> NEW.consumer_workspace_id
            OR OLD.consumer_network_id <> NEW.consumer_network_id
            OR OLD.share_offer_id <> NEW.share_offer_id
            OR OLD.resource_export_id <> NEW.resource_export_id
            OR OLD.resource_id <> NEW.resource_id
            OR OLD.resource_version <> NEW.resource_version
            OR OLD.target_generation <> NEW.target_generation
            OR OLD.resource_semantic_hash <> NEW.resource_semantic_hash
            OR OLD.constraint_hash <> NEW.constraint_hash
            OR OLD.provider_authority_generation <> NEW.provider_authority_generation
            OR OLD.consumer_authority_generation <> NEW.consumer_authority_generation
            OR OLD.recovery_epoch <> NEW.recovery_epoch
            OR OLD.expires_at <> NEW.expires_at
            OR OLD.state NOT IN ('activating', 'active')
            OR (
                OLD.state = 'activating'
                AND NEW.state NOT IN ('active', 'revoked', 'expired', 'invalidated')
            )
            OR (
                OLD.state = 'active'
                AND NEW.state NOT IN ('revoked', 'expired', 'invalidated')
            ) THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Trust Contract transition';
        END IF;
    ELSIF TG_TABLE_NAME = 'imported_resource' THEN
        IF OLD.deployment_id <> NEW.deployment_id
            OR OLD.workspace_id <> NEW.workspace_id
            OR OLD.network_id <> NEW.network_id
            OR OLD.trust_contract_id <> NEW.trust_contract_id
            OR OLD.state NOT IN ('activating', 'active')
            OR (
                OLD.state = 'activating'
                AND NEW.state NOT IN ('active', 'revoked', 'expired', 'invalidated')
            )
            OR (
                OLD.state = 'active'
                AND NEW.state NOT IN ('revoked', 'expired', 'invalidated')
            ) THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Imported Resource transition';
        END IF;
    ELSE
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Resource sharing trigger configuration';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER resource_export_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.resource_export
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_resource_sharing_transition();
CREATE TRIGGER resource_export_constraint_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.resource_export_constraint
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_resource_sharing_transition();
CREATE TRIGGER share_offer_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.share_offer
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_resource_sharing_transition();
CREATE TRIGGER share_offer_locator_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.share_offer_locator
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_share_offer_locator_transition();
CREATE TRIGGER trust_contract_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.trust_contract
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_resource_sharing_transition();
CREATE TRIGGER imported_resource_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.imported_resource
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_resource_sharing_transition();

CREATE TRIGGER resource_export_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.resource_export
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('resource_export', 'public_id');
CREATE TRIGGER resource_export_constraint_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.resource_export_constraint
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('resource_export_constraint', 'public_id');
CREATE TRIGGER share_offer_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.share_offer
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('share_offer', 'public_id');
CREATE TRIGGER trust_contract_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.trust_contract
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('trust_contract', 'public_id');
CREATE TRIGGER imported_resource_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.imported_resource
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('imported_resource', 'public_id');

ALTER TABLE mesh.resource_export ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.resource_export FORCE ROW LEVEL SECURITY;
ALTER TABLE mesh.resource_export_constraint ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.resource_export_constraint FORCE ROW LEVEL SECURITY;
ALTER TABLE mesh.share_offer ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.share_offer FORCE ROW LEVEL SECURITY;
ALTER TABLE mesh.share_offer_locator ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.share_offer_locator FORCE ROW LEVEL SECURITY;
ALTER TABLE mesh.trust_contract ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.trust_contract FORCE ROW LEVEL SECURITY;
ALTER TABLE mesh.imported_resource ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.imported_resource FORCE ROW LEVEL SECURITY;

CREATE POLICY resource_export_migrator_policy ON mesh.resource_export
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY resource_export_constraint_migrator_policy ON mesh.resource_export_constraint
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY share_offer_migrator_policy ON mesh.share_offer
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY share_offer_locator_migrator_policy ON mesh.share_offer_locator
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY trust_contract_migrator_policy ON mesh.trust_contract
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY imported_resource_migrator_policy ON mesh.imported_resource
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);

CREATE POLICY resource_export_share_writer_policy ON mesh.resource_export
    TO mesh_share_writer
    USING (
        provider_workspace_id = mesh_ops.current_share_provider_workspace_id()
        AND provider_network_id = mesh_ops.current_share_provider_network_id()
        AND consumer_workspace_id = mesh_ops.current_share_consumer_workspace_id()
        AND consumer_network_id = mesh_ops.current_share_consumer_network_id()
    )
    WITH CHECK (
        provider_workspace_id = mesh_ops.current_share_provider_workspace_id()
        AND provider_network_id = mesh_ops.current_share_provider_network_id()
        AND consumer_workspace_id = mesh_ops.current_share_consumer_workspace_id()
        AND consumer_network_id = mesh_ops.current_share_consumer_network_id()
    );
CREATE POLICY resource_export_constraint_share_writer_policy ON mesh.resource_export_constraint
    TO mesh_share_writer
    USING (
        provider_workspace_id = mesh_ops.current_share_provider_workspace_id()
        AND provider_network_id = mesh_ops.current_share_provider_network_id()
        AND consumer_workspace_id = mesh_ops.current_share_consumer_workspace_id()
        AND consumer_network_id = mesh_ops.current_share_consumer_network_id()
    )
    WITH CHECK (
        provider_workspace_id = mesh_ops.current_share_provider_workspace_id()
        AND provider_network_id = mesh_ops.current_share_provider_network_id()
        AND consumer_workspace_id = mesh_ops.current_share_consumer_workspace_id()
        AND consumer_network_id = mesh_ops.current_share_consumer_network_id()
    );
CREATE POLICY share_offer_share_writer_policy ON mesh.share_offer
    TO mesh_share_writer
    USING (
        provider_workspace_id = mesh_ops.current_share_provider_workspace_id()
        AND provider_network_id = mesh_ops.current_share_provider_network_id()
        AND consumer_workspace_id = mesh_ops.current_share_consumer_workspace_id()
        AND consumer_network_id = mesh_ops.current_share_consumer_network_id()
    )
    WITH CHECK (
        provider_workspace_id = mesh_ops.current_share_provider_workspace_id()
        AND provider_network_id = mesh_ops.current_share_provider_network_id()
        AND consumer_workspace_id = mesh_ops.current_share_consumer_workspace_id()
        AND consumer_network_id = mesh_ops.current_share_consumer_network_id()
    );
CREATE POLICY share_offer_locator_share_writer_policy ON mesh.share_offer_locator
    TO mesh_share_writer
    USING (
        (
            local_workspace_id = mesh_ops.current_share_provider_workspace_id()
            AND local_network_id = mesh_ops.current_share_provider_network_id()
        ) OR (
            local_workspace_id = mesh_ops.current_share_consumer_workspace_id()
            AND local_network_id = mesh_ops.current_share_consumer_network_id()
        ) OR (
            local_workspace_id = mesh_ops.current_workspace_id()
            AND local_network_id = mesh_ops.current_network_id()
        )
    )
    WITH CHECK (
        provider_workspace_id = mesh_ops.current_share_provider_workspace_id()
        AND provider_network_id = mesh_ops.current_share_provider_network_id()
        AND consumer_workspace_id = mesh_ops.current_share_consumer_workspace_id()
        AND consumer_network_id = mesh_ops.current_share_consumer_network_id()
        AND (
            (
                local_workspace_id = provider_workspace_id
                AND local_network_id = provider_network_id
            ) OR (
                local_workspace_id = consumer_workspace_id
                AND local_network_id = consumer_network_id
            )
        )
    );
CREATE POLICY share_offer_locator_runtime_policy ON mesh.share_offer_locator
    FOR SELECT TO mesh_runtime
    USING (
        local_workspace_id = mesh_ops.current_workspace_id()
        AND local_network_id = mesh_ops.current_network_id()
    );
CREATE POLICY resource_export_runtime_policy ON mesh.resource_export
    FOR SELECT TO mesh_runtime
    USING (
        (
            provider_workspace_id = mesh_ops.current_workspace_id()
            AND provider_network_id = mesh_ops.current_network_id()
        ) OR (
            consumer_workspace_id = mesh_ops.current_workspace_id()
            AND consumer_network_id = mesh_ops.current_network_id()
        )
    );
CREATE POLICY resource_export_constraint_runtime_policy ON mesh.resource_export_constraint
    FOR SELECT TO mesh_runtime
    USING (
        (
            provider_workspace_id = mesh_ops.current_workspace_id()
            AND provider_network_id = mesh_ops.current_network_id()
        ) OR (
            consumer_workspace_id = mesh_ops.current_workspace_id()
            AND consumer_network_id = mesh_ops.current_network_id()
        )
    );
CREATE POLICY share_offer_runtime_policy ON mesh.share_offer
    FOR SELECT TO mesh_runtime
    USING (
        (
            provider_workspace_id = mesh_ops.current_workspace_id()
            AND provider_network_id = mesh_ops.current_network_id()
        ) OR (
            consumer_workspace_id = mesh_ops.current_workspace_id()
            AND consumer_network_id = mesh_ops.current_network_id()
        )
    );
CREATE POLICY trust_contract_runtime_policy ON mesh.trust_contract
    FOR SELECT TO mesh_runtime
    USING (
        (
            provider_workspace_id = mesh_ops.current_workspace_id()
            AND provider_network_id = mesh_ops.current_network_id()
        ) OR (
            consumer_workspace_id = mesh_ops.current_workspace_id()
            AND consumer_network_id = mesh_ops.current_network_id()
        )
    );
CREATE POLICY imported_resource_runtime_policy ON mesh.imported_resource
    FOR SELECT TO mesh_runtime
    USING (
        workspace_id = mesh_ops.current_workspace_id()
        AND network_id = mesh_ops.current_network_id()
    );
CREATE POLICY trust_contract_share_writer_policy ON mesh.trust_contract
    TO mesh_share_writer
    USING (
        provider_workspace_id = mesh_ops.current_share_provider_workspace_id()
        AND provider_network_id = mesh_ops.current_share_provider_network_id()
        AND consumer_workspace_id = mesh_ops.current_share_consumer_workspace_id()
        AND consumer_network_id = mesh_ops.current_share_consumer_network_id()
    )
    WITH CHECK (
        provider_workspace_id = mesh_ops.current_share_provider_workspace_id()
        AND provider_network_id = mesh_ops.current_share_provider_network_id()
        AND consumer_workspace_id = mesh_ops.current_share_consumer_workspace_id()
        AND consumer_network_id = mesh_ops.current_share_consumer_network_id()
    );
CREATE POLICY imported_resource_share_writer_policy ON mesh.imported_resource
    TO mesh_share_writer
    USING (
        workspace_id = mesh_ops.current_share_consumer_workspace_id()
        AND network_id = mesh_ops.current_share_consumer_network_id()
    )
    WITH CHECK (
        workspace_id = mesh_ops.current_share_consumer_workspace_id()
        AND network_id = mesh_ops.current_share_consumer_network_id()
    );

CREATE POLICY workspace_share_writer_policy ON mesh.workspace
    FOR SELECT TO mesh_share_writer
    USING (
        id IN (
            mesh_ops.current_share_provider_workspace_id(),
            mesh_ops.current_share_consumer_workspace_id()
        )
    );
CREATE POLICY deployment_share_writer_policy ON mesh.deployment
    FOR SELECT TO mesh_share_writer
    USING (
        EXISTS (
            SELECT 1
            FROM mesh.workspace AS workspace
            WHERE workspace.deployment_id = deployment.id
              AND workspace.id IN (
                  mesh_ops.current_share_provider_workspace_id(),
                  mesh_ops.current_share_consumer_workspace_id()
              )
        )
    );
CREATE POLICY network_share_writer_policy ON mesh.network
    FOR SELECT TO mesh_share_writer
    USING (
        (
            workspace_id = mesh_ops.current_share_provider_workspace_id()
            AND id = mesh_ops.current_share_provider_network_id()
        )
        OR (
            workspace_id = mesh_ops.current_share_consumer_workspace_id()
            AND id = mesh_ops.current_share_consumer_network_id()
        )
    );
CREATE POLICY resource_share_writer_policy ON mesh.resource
    FOR SELECT TO mesh_share_writer
    USING (
        workspace_id = mesh_ops.current_share_provider_workspace_id()
        AND network_id = mesh_ops.current_share_provider_network_id()
    );
CREATE POLICY resource_device_target_share_writer_policy ON mesh.resource_device_target
    FOR SELECT TO mesh_share_writer
    USING (
        workspace_id = mesh_ops.current_share_provider_workspace_id()
        AND network_id = mesh_ops.current_share_provider_network_id()
    );
CREATE POLICY network_revision_share_writer_policy ON mesh_ops.network_revision
    TO mesh_share_writer
    USING (
        (
            workspace_id = mesh_ops.current_share_provider_workspace_id()
            AND network_id = mesh_ops.current_share_provider_network_id()
        )
        OR (
            workspace_id = mesh_ops.current_share_consumer_workspace_id()
            AND network_id = mesh_ops.current_share_consumer_network_id()
        )
    )
    WITH CHECK (
        (
            workspace_id = mesh_ops.current_share_provider_workspace_id()
            AND network_id = mesh_ops.current_share_provider_network_id()
        )
        OR (
            workspace_id = mesh_ops.current_share_consumer_workspace_id()
            AND network_id = mesh_ops.current_share_consumer_network_id()
        )
    );

CREATE FUNCTION mesh_ops.create_resource_share_offer_v1(
    p_provider_workspace_id BIGINT,
    p_provider_network_id BIGINT,
    p_consumer_workspace_id BIGINT,
    p_consumer_network_id BIGINT,
    p_provider_workspace_public_id UUID,
    p_provider_network_public_id UUID,
    p_consumer_workspace_public_id UUID,
    p_consumer_network_public_id UUID,
    p_resource_public_id UUID,
    p_resource_version BIGINT,
    p_target_generation BIGINT,
    p_resource_semantic_hash BYTEA,
    p_export_public_id UUID,
    p_offer_public_id UUID,
    p_constraint_public_ids JSONB,
    p_constraints JSONB,
    p_constraint_hash BYTEA,
    p_nonce_digest BYTEA,
    p_provider_authority_generation BIGINT,
    p_consumer_authority_generation BIGINT,
    p_expected_provider_sharing_revision BIGINT,
    p_expected_consumer_sharing_revision BIGINT,
    p_expires_at TIMESTAMPTZ,
    p_occurred_at TIMESTAMPTZ
)
RETURNS TABLE (
    provider_network_revision BIGINT,
    provider_sharing_revision BIGINT,
    consumer_network_revision BIGINT,
    consumer_sharing_revision BIGINT,
    export_version BIGINT,
    offer_version BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_deployment_id BIGINT;
    resource_internal_id BIGINT;
    export_internal_id BIGINT;
    offer_internal_id BIGINT;
    constraint_count INTEGER;
BEGIN
    PERFORM mesh_ops.set_share_scope_v1(
        p_provider_workspace_id, p_provider_network_id,
        p_consumer_workspace_id, p_consumer_network_id
    );
    IF p_occurred_at IS NULL OR p_expires_at IS NULL
        OR p_expires_at <= p_occurred_at
        OR p_expires_at > p_occurred_at + INTERVAL '30 days'
        OR p_resource_version <= 0 OR p_target_generation <= 0
        OR p_provider_authority_generation <= 0 OR p_consumer_authority_generation <= 0
        OR p_expected_provider_sharing_revision <= 0
        OR p_expected_consumer_sharing_revision <= 0
        OR pg_catalog.octet_length(p_resource_semantic_hash) <> 32
        OR pg_catalog.octet_length(p_constraint_hash) <> 32
        OR pg_catalog.octet_length(p_nonce_digest) <> 32
        OR p_constraints IS NULL OR pg_catalog.jsonb_typeof(p_constraints) <> 'array'
        OR p_constraint_public_ids IS NULL
        OR pg_catalog.jsonb_typeof(p_constraint_public_ids) <> 'array'
        OR pg_catalog.jsonb_array_length(p_constraints) NOT BETWEEN 1 AND 3
        OR pg_catalog.jsonb_array_length(p_constraint_public_ids)
            <> pg_catalog.jsonb_array_length(p_constraints) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource share offer input';
    END IF;
    constraint_count := pg_catalog.jsonb_array_length(p_constraints);
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.jsonb_array_elements(p_constraints) AS item(value)
        WHERE item.value->>'protocol' NOT IN ('tcp', 'udp', 'icmp')
           OR pg_catalog.jsonb_typeof(item.value->'ranges') <> 'array'
           OR (
                item.value->>'protocol' IN ('tcp', 'udp')
                AND pg_catalog.jsonb_array_length(item.value->'ranges') NOT BETWEEN 1 AND 64
           )
           OR (
                item.value->>'protocol' = 'icmp'
                AND pg_catalog.jsonb_array_length(item.value->'ranges') <> 0
           )
    ) OR (
        SELECT pg_catalog.count(DISTINCT item.value->>'protocol') <> constraint_count
        FROM pg_catalog.jsonb_array_elements(p_constraints) AS item(value)
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.jsonb_array_elements(p_constraints) AS item(value)
        CROSS JOIN LATERAL pg_catalog.jsonb_array_elements(item.value->'ranges') AS range_row(value)
        WHERE pg_catalog.jsonb_typeof(range_row.value) <> 'object'
           OR (range_row.value->>'first') !~ '^[0-9]{1,5}$'
           OR (range_row.value->>'last') !~ '^[0-9]{1,5}$'
           OR (range_row.value->>'first')::BIGINT NOT BETWEEN 1 AND 65535
           OR (range_row.value->>'last')::BIGINT NOT BETWEEN 1 AND 65535
           OR (range_row.value->>'last')::BIGINT < (range_row.value->>'first')::BIGINT
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource share traffic constraints';
    END IF;

    -- This pair is the serialization lock used by every Network authority
    -- mutation. Hold it before reading Workspace, Network, or Resource
    -- authority so their snapshots cannot change before the sharing write.
    PERFORM revision.network_id
    FROM mesh_ops.network_revision AS revision
    WHERE (
        revision.workspace_id = p_provider_workspace_id
        AND revision.network_id = p_provider_network_id
    ) OR (
        revision.workspace_id = p_consumer_workspace_id
        AND revision.network_id = p_consumer_network_id
    )
    ORDER BY revision.workspace_id, revision.network_id
    FOR UPDATE;
    IF NOT EXISTS (
        SELECT 1 FROM mesh_ops.network_revision AS revision
        WHERE revision.workspace_id = p_provider_workspace_id
          AND revision.network_id = p_provider_network_id
          AND revision.sharing_revision = p_expected_provider_sharing_revision
    ) OR NOT EXISTS (
        SELECT 1 FROM mesh_ops.network_revision AS revision
        WHERE revision.workspace_id = p_consumer_workspace_id
          AND revision.network_id = p_consumer_network_id
          AND revision.sharing_revision = p_expected_consumer_sharing_revision
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'sharing revision changed';
    END IF;

    PERFORM workspace.id
    FROM mesh.workspace AS workspace
    WHERE workspace.id IN (p_provider_workspace_id, p_consumer_workspace_id)
      AND workspace.public_id IN (p_provider_workspace_public_id, p_consumer_workspace_public_id)
      AND workspace.state = 'active';
    SELECT provider_workspace.deployment_id
    INTO scoped_deployment_id
    FROM mesh.workspace AS provider_workspace
    JOIN mesh.workspace AS consumer_workspace
      ON consumer_workspace.id = p_consumer_workspace_id
     AND consumer_workspace.public_id = p_consumer_workspace_public_id
     AND consumer_workspace.deployment_id = provider_workspace.deployment_id
     AND consumer_workspace.state = 'active'
    WHERE provider_workspace.id = p_provider_workspace_id
      AND provider_workspace.public_id = p_provider_workspace_public_id
      AND provider_workspace.state = 'active';
    IF scoped_deployment_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'sharing scope is unavailable';
    END IF;
    PERFORM network.id
    FROM mesh.network AS network
    WHERE (
        network.workspace_id = p_provider_workspace_id
        AND network.id = p_provider_network_id
        AND network.public_id = p_provider_network_public_id
    ) OR (
        network.workspace_id = p_consumer_workspace_id
        AND network.id = p_consumer_network_id
        AND network.public_id = p_consumer_network_public_id
    );
    IF (
        SELECT pg_catalog.count(*) FROM mesh.network AS network
        WHERE network.state = 'active' AND (
            (
                network.workspace_id = p_provider_workspace_id
                AND network.id = p_provider_network_id
                AND network.public_id = p_provider_network_public_id
                AND network.authority_generation = p_provider_authority_generation
            ) OR (
                network.workspace_id = p_consumer_workspace_id
                AND network.id = p_consumer_network_id
                AND network.public_id = p_consumer_network_public_id
                AND network.authority_generation = p_consumer_authority_generation
            )
        )
    ) <> 2 THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'sharing authority changed';
    END IF;
    SELECT resource.id INTO resource_internal_id
    FROM mesh.resource AS resource
    JOIN mesh.resource_device_target AS target
      ON target.workspace_id = resource.workspace_id
     AND target.network_id = resource.network_id
     AND target.resource_id = resource.id
     AND target.target_generation = resource.target_generation
     AND target.state = 'active'
    WHERE resource.workspace_id = p_provider_workspace_id
      AND resource.network_id = p_provider_network_id
      AND resource.public_id = p_resource_public_id
      AND resource.version = p_resource_version
      AND resource.target_generation = p_target_generation
      AND resource.semantic_hash = p_resource_semantic_hash
      AND resource.state = 'active'
      AND resource.deleted_at IS NULL;
    IF resource_internal_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Resource export authority changed';
    END IF;

    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        sharing_revision = revision.sharing_revision + 1,
        updated_at = pg_catalog.clock_timestamp()
    WHERE (
        revision.workspace_id = p_provider_workspace_id
        AND revision.network_id = p_provider_network_id
    ) OR (
        revision.workspace_id = p_consumer_workspace_id
        AND revision.network_id = p_consumer_network_id
    );

    INSERT INTO mesh.resource_export (
        public_id, deployment_id,
        provider_workspace_id, provider_network_id,
        consumer_workspace_id, consumer_network_id,
        resource_id, resource_public_id, resource_version, target_generation,
        resource_semantic_hash, constraint_hash,
        provider_authority_generation, expires_at, state, created_at, updated_at
    ) VALUES (
        p_export_public_id, scoped_deployment_id,
        p_provider_workspace_id, p_provider_network_id,
        p_consumer_workspace_id, p_consumer_network_id,
        resource_internal_id, p_resource_public_id, p_resource_version, p_target_generation,
        p_resource_semantic_hash, p_constraint_hash,
        p_provider_authority_generation, p_expires_at, 'active', p_occurred_at, p_occurred_at
    ) RETURNING id, version INTO export_internal_id, export_version;

    INSERT INTO mesh.resource_export_constraint (
        public_id,
        provider_workspace_id, provider_network_id,
        consumer_workspace_id, consumer_network_id,
        resource_export_id, protocol, destination_ports, created_at
    )
    SELECT
        (p_constraint_public_ids->>((item.ordinality - 1)::INTEGER))::UUID,
        p_provider_workspace_id, p_provider_network_id,
        p_consumer_workspace_id, p_consumer_network_id,
        export_internal_id,
        item.value->>'protocol',
        CASE
            WHEN item.value->>'protocol' = 'icmp' THEN '{}'::INT4MULTIRANGE
            ELSE (
                SELECT pg_catalog.range_agg(INT4RANGE(
                    (range_row.value->>'first')::INTEGER,
                    (range_row.value->>'last')::INTEGER + 1,
                    '[)'
                ))
                FROM pg_catalog.jsonb_array_elements(item.value->'ranges') AS range_row(value)
            )
        END,
        p_occurred_at
    FROM pg_catalog.jsonb_array_elements(p_constraints) WITH ORDINALITY AS item(value, ordinality);

    INSERT INTO mesh.share_offer (
        public_id, deployment_id,
        provider_workspace_id, provider_network_id,
        consumer_workspace_id, consumer_network_id,
        resource_export_id, nonce_digest, constraint_hash,
        expires_at, state, created_at, updated_at
    ) VALUES (
        p_offer_public_id, scoped_deployment_id,
        p_provider_workspace_id, p_provider_network_id,
        p_consumer_workspace_id, p_consumer_network_id,
        export_internal_id, p_nonce_digest, p_constraint_hash,
        p_expires_at, 'offered', p_occurred_at, p_occurred_at
    ) RETURNING id, version INTO offer_internal_id, offer_version;

    INSERT INTO mesh.share_offer_locator (
        local_workspace_id, local_network_id, offer_id, offer_public_id,
        provider_workspace_id, provider_network_id,
        consumer_workspace_id, consumer_network_id,
        provider_workspace_public_id, provider_network_public_id,
        consumer_workspace_public_id, consumer_network_public_id,
        direction, state, created_at
    ) VALUES
    (
        p_provider_workspace_id, p_provider_network_id, offer_internal_id, p_offer_public_id,
        p_provider_workspace_id, p_provider_network_id,
        p_consumer_workspace_id, p_consumer_network_id,
        p_provider_workspace_public_id, p_provider_network_public_id,
        p_consumer_workspace_public_id, p_consumer_network_public_id,
        'outgoing', 'offered', p_occurred_at
    ),
    (
        p_consumer_workspace_id, p_consumer_network_id, offer_internal_id, p_offer_public_id,
        p_provider_workspace_id, p_provider_network_id,
        p_consumer_workspace_id, p_consumer_network_id,
        p_provider_workspace_public_id, p_provider_network_public_id,
        p_consumer_workspace_public_id, p_consumer_network_public_id,
        'incoming', 'offered', p_occurred_at
    );

    SELECT revision.network_revision, revision.sharing_revision
    INTO provider_network_revision, provider_sharing_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = p_provider_workspace_id
      AND revision.network_id = p_provider_network_id;
    SELECT revision.network_revision, revision.sharing_revision
    INTO consumer_network_revision, consumer_sharing_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = p_consumer_workspace_id
      AND revision.network_id = p_consumer_network_id;
    RETURN NEXT;
END;
$function$;

CREATE FUNCTION mesh_ops.decide_resource_share_offer_v1(
    p_provider_workspace_id BIGINT,
    p_provider_network_id BIGINT,
    p_consumer_workspace_id BIGINT,
    p_consumer_network_id BIGINT,
    p_provider_workspace_public_id UUID,
    p_provider_network_public_id UUID,
    p_consumer_workspace_public_id UUID,
    p_consumer_network_public_id UUID,
    p_offer_public_id UUID,
    p_expected_offer_version BIGINT,
    p_nonce_digest BYTEA,
    p_action TEXT,
    p_contract_public_id UUID,
    p_imported_resource_public_id UUID,
    p_imported_display_name TEXT,
    p_provider_authority_generation BIGINT,
    p_consumer_authority_generation BIGINT,
    p_recovery_epoch BIGINT,
    p_expected_provider_sharing_revision BIGINT,
    p_expected_consumer_sharing_revision BIGINT,
    p_occurred_at TIMESTAMPTZ
)
RETURNS TABLE (
    provider_network_revision BIGINT,
    provider_sharing_revision BIGINT,
    consumer_network_revision BIGINT,
    consumer_sharing_revision BIGINT,
    offer_version BIGINT,
    contract_version BIGINT,
    imported_resource_version BIGINT,
    contract_state TEXT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_deployment_id BIGINT;
    offer_row mesh.share_offer%ROWTYPE;
    export_row mesh.resource_export%ROWTYPE;
    contract_internal_id BIGINT;
BEGIN
    PERFORM mesh_ops.set_share_scope_v1(
        p_provider_workspace_id, p_provider_network_id,
        p_consumer_workspace_id, p_consumer_network_id
    );
    IF p_occurred_at IS NULL OR p_expected_offer_version <= 0
        OR pg_catalog.octet_length(p_nonce_digest) <> 32
        OR p_action NOT IN ('accept', 'reject', 'revoke')
        OR p_provider_authority_generation <= 0
        OR p_consumer_authority_generation <= 0
        OR p_recovery_epoch <= 0
        OR p_expected_provider_sharing_revision <= 0
        OR p_expected_consumer_sharing_revision <= 0 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Share Offer decision input';
    END IF;
    IF p_action = 'accept' AND (
        p_contract_public_id IS NULL OR p_imported_resource_public_id IS NULL
        OR p_imported_display_name IS NULL
        OR pg_catalog.char_length(p_imported_display_name) NOT BETWEEN 1 AND 128
        OR p_imported_display_name <> pg_catalog.btrim(p_imported_display_name)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Share Offer acceptance input';
    END IF;
    IF p_action <> 'accept' AND (
        p_contract_public_id IS NOT NULL OR p_imported_resource_public_id IS NOT NULL
        OR p_imported_display_name IS NOT NULL
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Share Offer terminal input';
    END IF;

    SELECT provider_workspace.deployment_id
    INTO scoped_deployment_id
    FROM mesh.workspace AS provider_workspace
    JOIN mesh.workspace AS consumer_workspace
      ON consumer_workspace.id = p_consumer_workspace_id
     AND consumer_workspace.public_id = p_consumer_workspace_public_id
     AND consumer_workspace.deployment_id = provider_workspace.deployment_id
     AND consumer_workspace.state = 'active'
    WHERE provider_workspace.id = p_provider_workspace_id
      AND provider_workspace.public_id = p_provider_workspace_public_id
      AND provider_workspace.state = 'active';
    IF scoped_deployment_id IS NULL OR NOT EXISTS (
        SELECT 1
        FROM mesh.deployment AS deployment
        WHERE deployment.id = scoped_deployment_id
          AND deployment.recovery_epoch = p_recovery_epoch
          AND deployment.deleted_at IS NULL
    ) OR (
        SELECT pg_catalog.count(*) FROM mesh.network AS network
        WHERE network.state = 'active' AND (
            (
                network.workspace_id = p_provider_workspace_id
                AND network.id = p_provider_network_id
                AND network.public_id = p_provider_network_public_id
                AND network.authority_generation = p_provider_authority_generation
            ) OR (
                network.workspace_id = p_consumer_workspace_id
                AND network.id = p_consumer_network_id
                AND network.public_id = p_consumer_network_public_id
                AND network.authority_generation = p_consumer_authority_generation
            )
        )
    ) <> 2 THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'sharing authority changed';
    END IF;

    PERFORM revision.network_id
    FROM mesh_ops.network_revision AS revision
    WHERE (
        revision.workspace_id = p_provider_workspace_id
        AND revision.network_id = p_provider_network_id
    ) OR (
        revision.workspace_id = p_consumer_workspace_id
        AND revision.network_id = p_consumer_network_id
    )
    ORDER BY revision.workspace_id, revision.network_id
    FOR UPDATE;
    IF NOT EXISTS (
        SELECT 1 FROM mesh_ops.network_revision AS revision
        WHERE revision.workspace_id = p_provider_workspace_id
          AND revision.network_id = p_provider_network_id
          AND revision.sharing_revision = p_expected_provider_sharing_revision
    ) OR NOT EXISTS (
        SELECT 1 FROM mesh_ops.network_revision AS revision
        WHERE revision.workspace_id = p_consumer_workspace_id
          AND revision.network_id = p_consumer_network_id
          AND revision.sharing_revision = p_expected_consumer_sharing_revision
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'sharing revision changed';
    END IF;

    SELECT offer.* INTO offer_row
    FROM mesh.share_offer AS offer
    WHERE offer.provider_workspace_id = p_provider_workspace_id
      AND offer.provider_network_id = p_provider_network_id
      AND offer.consumer_workspace_id = p_consumer_workspace_id
      AND offer.consumer_network_id = p_consumer_network_id
      AND offer.public_id = p_offer_public_id
    FOR UPDATE;
    IF offer_row.id IS NULL OR offer_row.state <> 'offered'
        OR offer_row.version <> p_expected_offer_version
        OR offer_row.nonce_digest <> p_nonce_digest
        OR NOT p_occurred_at < offer_row.expires_at THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Share Offer changed or is unavailable';
    END IF;
    SELECT export.* INTO export_row
    FROM mesh.resource_export AS export
    WHERE export.id = offer_row.resource_export_id
      AND export.state = 'active'
      AND p_occurred_at < export.expires_at
      AND export.provider_authority_generation = p_provider_authority_generation
    FOR UPDATE;
    IF export_row.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Resource Export changed or is unavailable';
    END IF;

    IF p_action = 'accept' THEN
        IF NOT EXISTS (
            SELECT 1 FROM mesh.resource AS resource
            JOIN mesh.resource_device_target AS target
              ON target.workspace_id = resource.workspace_id
             AND target.network_id = resource.network_id
             AND target.resource_id = resource.id
             AND target.target_generation = resource.target_generation
             AND target.state = 'active'
            WHERE resource.id = export_row.resource_id
              AND resource.version = export_row.resource_version
              AND resource.target_generation = export_row.target_generation
              AND resource.semantic_hash = export_row.resource_semantic_hash
              AND resource.state = 'active'
              AND resource.deleted_at IS NULL
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Resource share target changed';
        END IF;
        INSERT INTO mesh.trust_contract (
            public_id, imported_resource_public_id, deployment_id,
            provider_workspace_id, provider_network_id,
            consumer_workspace_id, consumer_network_id,
            share_offer_id, resource_export_id, resource_id,
            resource_version, target_generation, resource_semantic_hash, constraint_hash,
            provider_authority_generation, consumer_authority_generation,
            recovery_epoch, expires_at, state, created_at, updated_at
        ) VALUES (
            p_contract_public_id, p_imported_resource_public_id, scoped_deployment_id,
            p_provider_workspace_id, p_provider_network_id,
            p_consumer_workspace_id, p_consumer_network_id,
            offer_row.id, export_row.id, export_row.resource_id,
            export_row.resource_version, export_row.target_generation,
            export_row.resource_semantic_hash, export_row.constraint_hash,
            p_provider_authority_generation, p_consumer_authority_generation,
            p_recovery_epoch, LEAST(offer_row.expires_at, export_row.expires_at),
            'activating', p_occurred_at, p_occurred_at
        ) RETURNING id, version, state
        INTO contract_internal_id, contract_version, contract_state;
        INSERT INTO mesh.imported_resource (
            public_id, deployment_id, workspace_id, network_id,
            trust_contract_id, display_name, name_key, state, created_at, updated_at
        ) VALUES (
            p_imported_resource_public_id, scoped_deployment_id,
            p_consumer_workspace_id, p_consumer_network_id,
            contract_internal_id, p_imported_display_name,
            pg_catalog.lower(p_imported_display_name), 'activating', p_occurred_at, p_occurred_at
        ) RETURNING version INTO imported_resource_version;
        UPDATE mesh.share_offer
        SET state = 'accepted', accepted_contract_public_id = p_contract_public_id,
            version = version + 1, updated_at = p_occurred_at, decided_at = p_occurred_at
        WHERE id = offer_row.id
        RETURNING version INTO offer_version;
    ELSE
        UPDATE mesh.share_offer
        SET state = CASE WHEN p_action = 'reject' THEN 'rejected' ELSE 'revoked' END,
            version = version + 1, updated_at = p_occurred_at, decided_at = p_occurred_at
        WHERE id = offer_row.id
        RETURNING version INTO offer_version;
        contract_version := 0;
        imported_resource_version := 0;
        contract_state := '';
    END IF;

    UPDATE mesh.share_offer_locator AS locator
    SET state = CASE
        WHEN p_action = 'accept' THEN 'accepted'
        WHEN p_action = 'reject' THEN 'rejected'
        ELSE 'revoked'
    END
    WHERE locator.offer_id = offer_row.id
      AND locator.provider_workspace_id = p_provider_workspace_id
      AND locator.provider_network_id = p_provider_network_id
      AND locator.consumer_workspace_id = p_consumer_workspace_id
      AND locator.consumer_network_id = p_consumer_network_id;
    IF NOT FOUND OR (
        SELECT pg_catalog.count(*)
        FROM mesh.share_offer_locator AS locator
        WHERE locator.offer_id = offer_row.id
          AND locator.provider_workspace_id = p_provider_workspace_id
          AND locator.provider_network_id = p_provider_network_id
          AND locator.consumer_workspace_id = p_consumer_workspace_id
          AND locator.consumer_network_id = p_consumer_network_id
    ) <> 2 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Share Offer locator authority is unavailable';
    END IF;

    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        sharing_revision = revision.sharing_revision + 1,
        updated_at = pg_catalog.clock_timestamp()
    WHERE (
        revision.workspace_id = p_provider_workspace_id
        AND revision.network_id = p_provider_network_id
    ) OR (
        revision.workspace_id = p_consumer_workspace_id
        AND revision.network_id = p_consumer_network_id
    );
    SELECT revision.network_revision, revision.sharing_revision
    INTO provider_network_revision, provider_sharing_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = p_provider_workspace_id
      AND revision.network_id = p_provider_network_id;
    SELECT revision.network_revision, revision.sharing_revision
    INTO consumer_network_revision, consumer_sharing_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = p_consumer_workspace_id
      AND revision.network_id = p_consumer_network_id;
    RETURN NEXT;
END;
$function$;

CREATE FUNCTION mesh_ops.activate_resource_share_v1(
    p_provider_workspace_id BIGINT,
    p_provider_network_id BIGINT,
    p_consumer_workspace_id BIGINT,
    p_consumer_network_id BIGINT,
    p_contract_public_id UUID,
    p_expected_contract_version BIGINT,
    p_expected_provider_sharing_revision BIGINT,
    p_expected_consumer_sharing_revision BIGINT,
    p_occurred_at TIMESTAMPTZ
)
RETURNS TABLE (
    provider_network_revision BIGINT,
    provider_sharing_revision BIGINT,
    consumer_network_revision BIGINT,
    consumer_sharing_revision BIGINT,
    contract_version BIGINT,
    imported_resource_version BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    contract_row mesh.trust_contract%ROWTYPE;
BEGIN
    PERFORM mesh_ops.set_share_scope_v1(
        p_provider_workspace_id, p_provider_network_id,
        p_consumer_workspace_id, p_consumer_network_id
    );
    IF p_expected_contract_version <= 0
        OR p_expected_provider_sharing_revision <= 0
        OR p_expected_consumer_sharing_revision <= 0
        OR p_occurred_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Trust Contract activation input';
    END IF;

    PERFORM revision.network_id
    FROM mesh_ops.network_revision AS revision
    WHERE (
        revision.workspace_id = p_provider_workspace_id
        AND revision.network_id = p_provider_network_id
    ) OR (
        revision.workspace_id = p_consumer_workspace_id
        AND revision.network_id = p_consumer_network_id
    )
    ORDER BY revision.workspace_id, revision.network_id
    FOR UPDATE;
    IF NOT EXISTS (
        SELECT 1 FROM mesh_ops.network_revision AS revision
        WHERE revision.workspace_id = p_provider_workspace_id
          AND revision.network_id = p_provider_network_id
          AND revision.sharing_revision = p_expected_provider_sharing_revision
    ) OR NOT EXISTS (
        SELECT 1 FROM mesh_ops.network_revision AS revision
        WHERE revision.workspace_id = p_consumer_workspace_id
          AND revision.network_id = p_consumer_network_id
          AND revision.sharing_revision = p_expected_consumer_sharing_revision
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'sharing revision changed';
    END IF;

    SELECT contract.* INTO contract_row
    FROM mesh.trust_contract AS contract
    WHERE contract.public_id = p_contract_public_id
      AND contract.provider_workspace_id = p_provider_workspace_id
      AND contract.provider_network_id = p_provider_network_id
      AND contract.consumer_workspace_id = p_consumer_workspace_id
      AND contract.consumer_network_id = p_consumer_network_id
      AND contract.version = p_expected_contract_version
      AND contract.state = 'activating'
    FOR UPDATE;
    IF contract_row.id IS NULL OR NOT p_occurred_at < contract_row.expires_at THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Trust Contract changed or is unavailable';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM mesh.deployment AS deployment
        JOIN mesh.workspace AS provider_workspace
          ON provider_workspace.deployment_id = deployment.id
         AND provider_workspace.id = p_provider_workspace_id
         AND provider_workspace.state = 'active'
        JOIN mesh.workspace AS consumer_workspace
          ON consumer_workspace.deployment_id = deployment.id
         AND consumer_workspace.id = p_consumer_workspace_id
         AND consumer_workspace.state = 'active'
        JOIN mesh.network AS provider_network
          ON provider_network.workspace_id = provider_workspace.id
         AND provider_network.id = p_provider_network_id
         AND provider_network.state = 'active'
         AND provider_network.authority_generation = contract_row.provider_authority_generation
        JOIN mesh.network AS consumer_network
          ON consumer_network.workspace_id = consumer_workspace.id
         AND consumer_network.id = p_consumer_network_id
         AND consumer_network.state = 'active'
         AND consumer_network.authority_generation = contract_row.consumer_authority_generation
        WHERE deployment.id = contract_row.deployment_id
          AND deployment.state = 'active'
          AND deployment.recovery_state = 'verified'
          AND deployment.recovery_epoch = contract_row.recovery_epoch
          AND deployment.deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'sharing authority changed';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM mesh.resource_export AS export
        JOIN mesh.resource AS resource
          ON resource.workspace_id = export.provider_workspace_id
         AND resource.network_id = export.provider_network_id
         AND resource.id = export.resource_id
         AND resource.version = export.resource_version
         AND resource.target_generation = export.target_generation
         AND resource.semantic_hash = export.resource_semantic_hash
         AND resource.state = 'active'
         AND resource.deleted_at IS NULL
        JOIN mesh.resource_device_target AS target
          ON target.workspace_id = resource.workspace_id
         AND target.network_id = resource.network_id
         AND target.resource_id = resource.id
         AND target.target_generation = resource.target_generation
         AND target.state = 'active'
        WHERE export.id = contract_row.resource_export_id
          AND export.provider_workspace_id = p_provider_workspace_id
          AND export.provider_network_id = p_provider_network_id
          AND export.consumer_workspace_id = p_consumer_workspace_id
          AND export.consumer_network_id = p_consumer_network_id
          AND export.resource_id = contract_row.resource_id
          AND export.resource_version = contract_row.resource_version
          AND export.target_generation = contract_row.target_generation
          AND export.resource_semantic_hash = contract_row.resource_semantic_hash
          AND export.constraint_hash = contract_row.constraint_hash
          AND export.provider_authority_generation = contract_row.provider_authority_generation
          AND export.state = 'active'
          AND p_occurred_at < export.expires_at
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Resource share target changed';
    END IF;

    UPDATE mesh.trust_contract
    SET state = 'active', version = version + 1, updated_at = p_occurred_at
    WHERE id = contract_row.id
    RETURNING version INTO contract_version;
    UPDATE mesh.imported_resource
    SET state = 'active', version = version + 1, updated_at = p_occurred_at
    WHERE trust_contract_id = contract_row.id
      AND state = 'activating'
    RETURNING version INTO imported_resource_version;
    IF imported_resource_version IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Imported Resource changed or is unavailable';
    END IF;

    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        sharing_revision = revision.sharing_revision + 1,
        updated_at = pg_catalog.clock_timestamp()
    WHERE (
        revision.workspace_id = p_provider_workspace_id
        AND revision.network_id = p_provider_network_id
    ) OR (
        revision.workspace_id = p_consumer_workspace_id
        AND revision.network_id = p_consumer_network_id
    );
    SELECT revision.network_revision, revision.sharing_revision
    INTO provider_network_revision, provider_sharing_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = p_provider_workspace_id
      AND revision.network_id = p_provider_network_id;
    SELECT revision.network_revision, revision.sharing_revision
    INTO consumer_network_revision, consumer_sharing_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = p_consumer_workspace_id
      AND revision.network_id = p_consumer_network_id;
    RETURN NEXT;
END;
$function$;

CREATE FUNCTION mesh_ops.revoke_resource_share_v1(
    p_provider_workspace_id BIGINT,
    p_provider_network_id BIGINT,
    p_consumer_workspace_id BIGINT,
    p_consumer_network_id BIGINT,
    p_contract_public_id UUID,
    p_expected_contract_version BIGINT,
    p_expected_provider_sharing_revision BIGINT,
    p_expected_consumer_sharing_revision BIGINT,
    p_occurred_at TIMESTAMPTZ
)
RETURNS TABLE (
    provider_network_revision BIGINT,
    provider_sharing_revision BIGINT,
    consumer_network_revision BIGINT,
    consumer_sharing_revision BIGINT,
    contract_version BIGINT,
    imported_resource_version BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    contract_internal_id BIGINT;
    contract_expires_at TIMESTAMPTZ;
BEGIN
    PERFORM mesh_ops.set_share_scope_v1(
        p_provider_workspace_id, p_provider_network_id,
        p_consumer_workspace_id, p_consumer_network_id
    );
    IF p_expected_contract_version <= 0
        OR p_expected_provider_sharing_revision <= 0
        OR p_expected_consumer_sharing_revision <= 0
        OR p_occurred_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Trust Contract revocation input';
    END IF;
    PERFORM revision.network_id
    FROM mesh_ops.network_revision AS revision
    WHERE (
        revision.workspace_id = p_provider_workspace_id
        AND revision.network_id = p_provider_network_id
    ) OR (
        revision.workspace_id = p_consumer_workspace_id
        AND revision.network_id = p_consumer_network_id
    )
    ORDER BY revision.workspace_id, revision.network_id
    FOR UPDATE;
    IF NOT EXISTS (
        SELECT 1 FROM mesh_ops.network_revision AS revision
        WHERE revision.workspace_id = p_provider_workspace_id
          AND revision.network_id = p_provider_network_id
          AND revision.sharing_revision = p_expected_provider_sharing_revision
    ) OR NOT EXISTS (
        SELECT 1 FROM mesh_ops.network_revision AS revision
        WHERE revision.workspace_id = p_consumer_workspace_id
          AND revision.network_id = p_consumer_network_id
          AND revision.sharing_revision = p_expected_consumer_sharing_revision
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'sharing revision changed';
    END IF;
    SELECT contract.id, contract.expires_at
    INTO contract_internal_id, contract_expires_at
    FROM mesh.trust_contract AS contract
    WHERE contract.public_id = p_contract_public_id
      AND contract.provider_workspace_id = p_provider_workspace_id
      AND contract.provider_network_id = p_provider_network_id
      AND contract.consumer_workspace_id = p_consumer_workspace_id
      AND contract.consumer_network_id = p_consumer_network_id
      AND contract.version = p_expected_contract_version
      AND contract.state IN ('activating', 'active')
    FOR UPDATE;
    IF contract_internal_id IS NULL OR NOT p_occurred_at < contract_expires_at THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Trust Contract changed or is unavailable';
    END IF;
    UPDATE mesh.trust_contract
    SET state = 'revoked', version = version + 1,
        updated_at = p_occurred_at, ended_at = p_occurred_at
    WHERE id = contract_internal_id
    RETURNING version INTO contract_version;
    UPDATE mesh.imported_resource
    SET state = 'revoked', version = version + 1,
        updated_at = p_occurred_at, ended_at = p_occurred_at
    WHERE trust_contract_id = contract_internal_id
      AND state IN ('activating', 'active')
    RETURNING version INTO imported_resource_version;
    IF imported_resource_version IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Imported Resource authority is unavailable';
    END IF;
    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        sharing_revision = revision.sharing_revision + 1,
        updated_at = pg_catalog.clock_timestamp()
    WHERE (
        revision.workspace_id = p_provider_workspace_id
        AND revision.network_id = p_provider_network_id
    ) OR (
        revision.workspace_id = p_consumer_workspace_id
        AND revision.network_id = p_consumer_network_id
    );
    SELECT revision.network_revision, revision.sharing_revision
    INTO provider_network_revision, provider_sharing_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = p_provider_workspace_id
      AND revision.network_id = p_provider_network_id;
    SELECT revision.network_revision, revision.sharing_revision
    INTO consumer_network_revision, consumer_sharing_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = p_consumer_workspace_id
      AND revision.network_id = p_consumer_network_id;
    RETURN NEXT;
END;
$function$;

REVOKE ALL ON
    mesh.resource_export,
    mesh.resource_export_constraint,
    mesh.share_offer,
    mesh.share_offer_locator,
    mesh.trust_contract,
    mesh.imported_resource
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
REVOKE ALL ON SEQUENCE
    mesh.resource_export_id_seq,
    mesh.resource_export_constraint_id_seq,
    mesh.share_offer_id_seq,
    mesh.trust_contract_id_seq,
    mesh.imported_resource_id_seq
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;

GRANT USAGE ON SCHEMA mesh, mesh_ops TO mesh_share_writer;
GRANT SELECT ON
    mesh.deployment,
    mesh.workspace,
    mesh.network,
    mesh.resource,
    mesh.resource_device_target
    TO mesh_share_writer;
GRANT SELECT, UPDATE ON mesh_ops.network_revision TO mesh_share_writer;
GRANT SELECT, INSERT, UPDATE ON
    mesh.resource_export,
    mesh.resource_export_constraint,
    mesh.share_offer,
    mesh.trust_contract,
    mesh.imported_resource
TO mesh_share_writer;
GRANT SELECT, INSERT, UPDATE ON mesh.share_offer_locator TO mesh_share_writer;
GRANT SELECT ON
    mesh.resource_export,
    mesh.resource_export_constraint,
    mesh.share_offer,
    mesh.share_offer_locator,
    mesh.trust_contract,
    mesh.imported_resource
TO mesh_runtime;
GRANT USAGE, SELECT ON SEQUENCE
    mesh.resource_export_id_seq,
    mesh.resource_export_constraint_id_seq,
    mesh.share_offer_id_seq,
    mesh.trust_contract_id_seq,
    mesh.imported_resource_id_seq
TO mesh_share_writer;

REVOKE ALL ON FUNCTION mesh_ops.current_share_provider_workspace_id()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
REVOKE ALL ON FUNCTION mesh_ops.current_share_provider_network_id()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
REVOKE ALL ON FUNCTION mesh_ops.current_share_consumer_workspace_id()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
REVOKE ALL ON FUNCTION mesh_ops.current_share_consumer_network_id()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.current_share_provider_workspace_id() TO mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.current_share_provider_network_id() TO mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.current_share_consumer_workspace_id() TO mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.current_share_consumer_network_id() TO mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.current_workspace_id() TO mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.current_network_id() TO mesh_share_writer;

REVOKE ALL ON FUNCTION mesh_ops.set_share_scope_v1(BIGINT, BIGINT, BIGINT, BIGINT)
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
REVOKE ALL ON FUNCTION mesh_ops.create_resource_share_offer_v1(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID,
    BIGINT, BIGINT, BYTEA, UUID, UUID, JSONB, JSONB,
    BYTEA, BYTEA, BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
REVOKE ALL ON FUNCTION mesh_ops.decide_resource_share_offer_v1(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID, BIGINT, BYTEA, TEXT,
    UUID, UUID, TEXT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
REVOKE ALL ON FUNCTION mesh_ops.activate_resource_share_v1(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
REVOKE ALL ON FUNCTION mesh_ops.revoke_resource_share_v1(
    BIGINT, BIGINT, BIGINT, BIGINT, UUID, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
