DO $database_privileges$
BEGIN
    EXECUTE pg_catalog.format(
        'REVOKE ALL ON DATABASE %I FROM PUBLIC',
        pg_catalog.current_database()
    );
END;
$database_privileges$;

ALTER TABLE mesh.identity_subject
    ADD CONSTRAINT identity_subject_provider_principal_id_unique
    UNIQUE (deployment_id, identity_provider_id, principal_id, id);

CREATE TABLE mesh.auth_transaction (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT,
    identity_provider_id BIGINT NOT NULL,
    identity_provider_client_id BIGINT NOT NULL,
    principal_id BIGINT,
    flow_kind TEXT NOT NULL,
    operation_kind TEXT NOT NULL,
    operation_semantic_hash BYTEA,
    state_digest_algorithm TEXT NOT NULL,
    state_digest_key_id TEXT NOT NULL,
    state_digest BYTEA NOT NULL,
    nonce_digest_algorithm TEXT NOT NULL,
    nonce_digest_key_id TEXT NOT NULL,
    nonce_digest BYTEA NOT NULL,
    pkce_verifier_encryption_algorithm TEXT,
    pkce_verifier_encryption_key_id TEXT,
    pkce_verifier_ciphertext BYTEA,
    redirect_id TEXT,
    return_route_id TEXT NOT NULL,
    expected_organization_digest_algorithm TEXT,
    expected_organization_digest_key_id TEXT,
    expected_organization_digest BYTEA,
    provider_generation BIGINT NOT NULL CHECK (provider_generation > 0),
    deployment_recovery_epoch BIGINT NOT NULL CHECK (deployment_recovery_epoch > 0),
    account_session_generation BIGINT,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    consumed_result_kind TEXT,
    consumed_result_public_id UUID,
    failure_class TEXT,
    state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT auth_transaction_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT auth_transaction_flow_kind_check CHECK (
        flow_kind IN (
            'browser_authorization_code',
            'cli_loopback_authorization_code',
            'cli_device_authorization'
        )
    ),
    CONSTRAINT auth_transaction_operation_check CHECK (
        (
            operation_kind = 'login'
            AND principal_id IS NULL
            AND account_session_generation IS NULL
            AND operation_semantic_hash IS NULL
        )
        OR (
            operation_kind IN ('step_up', 'identity_link')
            AND principal_id IS NOT NULL
            AND account_session_generation IS NOT NULL
            AND account_session_generation > 0
            AND operation_semantic_hash IS NOT NULL
            AND pg_catalog.octet_length(operation_semantic_hash) = 32
        )
    ),
    CONSTRAINT auth_transaction_state_digest_algorithm_check CHECK (
        state_digest_algorithm = 'hmac-sha256-v1'
    ),
    CONSTRAINT auth_transaction_state_digest_key_id_check CHECK (
        pg_catalog.char_length(state_digest_key_id) BETWEEN 1 AND 128
        AND state_digest_key_id = pg_catalog.btrim(state_digest_key_id)
        AND state_digest_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    CONSTRAINT auth_transaction_state_digest_check CHECK (
        pg_catalog.octet_length(state_digest) = 32
    ),
    CONSTRAINT auth_transaction_nonce_digest_algorithm_check CHECK (
        nonce_digest_algorithm = 'hmac-sha256-v1'
    ),
    CONSTRAINT auth_transaction_nonce_digest_key_id_check CHECK (
        pg_catalog.char_length(nonce_digest_key_id) BETWEEN 1 AND 128
        AND nonce_digest_key_id = pg_catalog.btrim(nonce_digest_key_id)
        AND nonce_digest_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    CONSTRAINT auth_transaction_nonce_digest_check CHECK (
        pg_catalog.octet_length(nonce_digest) = 32
    ),
    CONSTRAINT auth_transaction_pkce_check CHECK (
        (
            flow_kind IN ('browser_authorization_code', 'cli_loopback_authorization_code')
            AND state IN ('pending', 'consuming')
            AND pkce_verifier_encryption_algorithm IS NOT NULL
            AND pkce_verifier_encryption_algorithm = 'aead-aes-256-gcm-v1'
            AND pkce_verifier_encryption_key_id IS NOT NULL
            AND pkce_verifier_ciphertext IS NOT NULL
            AND pg_catalog.char_length(pkce_verifier_encryption_key_id) BETWEEN 1 AND 128
            AND pkce_verifier_encryption_key_id =
                pg_catalog.btrim(pkce_verifier_encryption_key_id)
            AND pkce_verifier_encryption_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
            AND pg_catalog.octet_length(pkce_verifier_ciphertext) BETWEEN 1 AND 4096
            AND redirect_id IS NOT NULL
        )
        OR (
            (
                flow_kind = 'cli_device_authorization'
                OR state IN ('succeeded', 'failed', 'expired')
            )
            AND pkce_verifier_encryption_algorithm IS NULL
            AND pkce_verifier_encryption_key_id IS NULL
            AND pkce_verifier_ciphertext IS NULL
            AND (
                flow_kind <> 'cli_device_authorization'
                OR redirect_id IS NULL
            )
        )
    ),
    CONSTRAINT auth_transaction_redirect_id_check CHECK (
        redirect_id IS NULL
        OR (
            pg_catalog.char_length(redirect_id) BETWEEN 1 AND 128
            AND redirect_id = pg_catalog.btrim(redirect_id)
            AND redirect_id ~ '^[a-z][a-z0-9._:-]*$'
        )
    ),
    CONSTRAINT auth_transaction_return_route_id_check CHECK (
        pg_catalog.char_length(return_route_id) BETWEEN 1 AND 128
        AND return_route_id = pg_catalog.btrim(return_route_id)
        AND return_route_id ~ '^[a-z][a-z0-9._:-]*$'
    ),
    CONSTRAINT auth_transaction_expected_organization_digest_check CHECK (
        (
            expected_organization_digest_algorithm IS NULL
            AND expected_organization_digest_key_id IS NULL
            AND expected_organization_digest IS NULL
        )
        OR (
            expected_organization_digest_algorithm IS NOT NULL
            AND expected_organization_digest_algorithm = 'hmac-sha256-v1'
            AND expected_organization_digest_key_id IS NOT NULL
            AND expected_organization_digest IS NOT NULL
            AND pg_catalog.char_length(expected_organization_digest_key_id)
                BETWEEN 1 AND 128
            AND expected_organization_digest_key_id =
                pg_catalog.btrim(expected_organization_digest_key_id)
            AND expected_organization_digest_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
            AND pg_catalog.octet_length(expected_organization_digest) = 32
        )
    ),
    CONSTRAINT auth_transaction_state_check CHECK (
        state IN ('pending', 'consuming', 'succeeded', 'failed', 'expired')
    ),
    CONSTRAINT auth_transaction_result_check CHECK (
        (
            state = 'pending'
            AND consumed_at IS NULL
            AND consumed_result_kind IS NULL
            AND consumed_result_public_id IS NULL
            AND failure_class IS NULL
        )
        OR (
            state = 'consuming'
            AND consumed_at IS NOT NULL
            AND consumed_result_kind IS NULL
            AND consumed_result_public_id IS NULL
            AND failure_class IS NULL
        )
        OR (
            state = 'succeeded'
            AND consumed_at IS NOT NULL
            AND consumed_result_kind IS NOT NULL
            AND consumed_result_kind IN ('account_session', 'step_up', 'identity_proof')
            AND consumed_result_public_id IS NOT NULL
            AND pg_catalog.get_byte(
                pg_catalog.uuid_send(consumed_result_public_id),
                6
            ) >> 4 = 7
            AND failure_class IS NULL
        )
        OR (
            state IN ('failed', 'expired')
            AND consumed_at IS NOT NULL
            AND consumed_result_kind IS NULL
            AND consumed_result_public_id IS NULL
            AND failure_class IS NOT NULL
            AND pg_catalog.char_length(failure_class) BETWEEN 1 AND 64
            AND failure_class = pg_catalog.btrim(failure_class)
            AND failure_class ~ '^[a-z][a-z0-9_]*$'
        )
    ),
    CONSTRAINT auth_transaction_workspace_scope_fk FOREIGN KEY (
        deployment_id,
        workspace_id
    ) REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT auth_transaction_provider_generation_fk FOREIGN KEY (
        deployment_id,
        identity_provider_id,
        provider_generation
    ) REFERENCES mesh.identity_provider_generation (
        deployment_id,
        identity_provider_id,
        generation
    ) ON DELETE RESTRICT,
    CONSTRAINT auth_transaction_provider_client_fk FOREIGN KEY (
        deployment_id,
        identity_provider_id,
        identity_provider_client_id
    ) REFERENCES mesh.identity_provider_client (
        deployment_id,
        identity_provider_id,
        id
    ) ON DELETE RESTRICT,
    CONSTRAINT auth_transaction_account_scope_fk FOREIGN KEY (
        deployment_id,
        principal_id
    ) REFERENCES mesh.account (deployment_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT auth_transaction_timestamps_check CHECK (
        expires_at > created_at
        AND updated_at >= created_at
        AND (consumed_at IS NULL OR consumed_at >= created_at)
    ),
    UNIQUE (deployment_id, identity_provider_id, id),
    UNIQUE (
        deployment_id,
        state_digest_algorithm,
        state_digest_key_id,
        state_digest
    ),
    UNIQUE (
        deployment_id,
        nonce_digest_algorithm,
        nonce_digest_key_id,
        nonce_digest
    )
);

CREATE INDEX auth_transaction_pending_expiry_idx
    ON mesh.auth_transaction (expires_at, id)
    WHERE state = 'pending';

CREATE INDEX auth_transaction_principal_state_idx
    ON mesh.auth_transaction (deployment_id, principal_id, state, id)
    WHERE principal_id IS NOT NULL;

CREATE TABLE mesh.account_session (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    principal_id BIGINT NOT NULL,
    identity_provider_id BIGINT NOT NULL,
    identity_subject_id BIGINT NOT NULL,
    identity_provider_client_id BIGINT NOT NULL,
    login_workspace_id BIGINT,
    token_digest_algorithm TEXT NOT NULL,
    token_digest_key_id TEXT NOT NULL,
    token_digest BYTEA NOT NULL,
    provider_generation BIGINT NOT NULL CHECK (provider_generation > 0),
    provider_sid_digest_algorithm TEXT,
    provider_sid_digest_key_id TEXT,
    provider_sid_digest BYTEA,
    authentication_time TIMESTAMPTZ NOT NULL,
    acr TEXT,
    amr TEXT[] NOT NULL,
    principal_authority_generation BIGINT NOT NULL
        CHECK (principal_authority_generation > 0),
    account_session_generation BIGINT NOT NULL CHECK (account_session_generation > 0),
    deployment_recovery_epoch BIGINT NOT NULL CHECK (deployment_recovery_epoch > 0),
    issued_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ NOT NULL,
    idle_expires_at TIMESTAMPTZ NOT NULL,
    absolute_expires_at TIMESTAMPTZ NOT NULL,
    ended_at TIMESTAMPTZ,
    end_reason TEXT,
    state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT account_session_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT account_session_token_digest_algorithm_check CHECK (
        token_digest_algorithm = 'hmac-sha256-v1'
    ),
    CONSTRAINT account_session_token_digest_key_id_check CHECK (
        pg_catalog.char_length(token_digest_key_id) BETWEEN 1 AND 128
        AND token_digest_key_id = pg_catalog.btrim(token_digest_key_id)
        AND token_digest_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    CONSTRAINT account_session_token_digest_check CHECK (
        pg_catalog.octet_length(token_digest) = 32
    ),
    CONSTRAINT account_session_provider_sid_digest_check CHECK (
        (
            provider_sid_digest_algorithm IS NULL
            AND provider_sid_digest_key_id IS NULL
            AND provider_sid_digest IS NULL
        )
        OR (
            provider_sid_digest_algorithm IS NOT NULL
            AND provider_sid_digest_algorithm = 'hmac-sha256-v1'
            AND provider_sid_digest_key_id IS NOT NULL
            AND provider_sid_digest IS NOT NULL
            AND pg_catalog.char_length(provider_sid_digest_key_id) BETWEEN 1 AND 128
            AND provider_sid_digest_key_id = pg_catalog.btrim(provider_sid_digest_key_id)
            AND provider_sid_digest_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
            AND pg_catalog.octet_length(provider_sid_digest) = 32
        )
    ),
    CONSTRAINT account_session_acr_check CHECK (
        acr IS NULL
        OR (
            pg_catalog.char_length(acr) BETWEEN 1 AND 256
            AND acr = pg_catalog.btrim(acr)
        )
    ),
    CONSTRAINT account_session_amr_check CHECK (
        COALESCE(pg_catalog.array_ndims(amr), 1) = 1
        AND pg_catalog.cardinality(amr) BETWEEN 0 AND 16
        AND pg_catalog.array_position(amr, NULL) IS NULL
        AND pg_catalog.octet_length(pg_catalog.array_to_string(amr, ',')) <= 1024
    ),
    CONSTRAINT account_session_state_check CHECK (
        state IN ('active', 'revoked', 'expired')
    ),
    CONSTRAINT account_session_end_check CHECK (
        (
            state = 'active'
            AND ended_at IS NULL
            AND end_reason IS NULL
        )
        OR (
            state = 'revoked'
            AND ended_at IS NOT NULL
            AND end_reason IS NOT NULL
            AND end_reason IN (
                'local_logout',
                'logout_all',
                'account_suspended',
                'membership_removed',
                'identity_unlinked',
                'privilege_changed',
                'provider_logout',
                'provider_recovery',
                'deployment_recovery',
                'administrative'
            )
        )
        OR (
            state = 'expired'
            AND ended_at IS NOT NULL
            AND end_reason IS NOT NULL
            AND end_reason IN ('idle_expired', 'absolute_expired')
        )
    ),
    CONSTRAINT account_session_account_scope_fk FOREIGN KEY (
        deployment_id,
        principal_id
    ) REFERENCES mesh.account (deployment_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT account_session_subject_scope_fk FOREIGN KEY (
        deployment_id,
        identity_provider_id,
        principal_id,
        identity_subject_id
    ) REFERENCES mesh.identity_subject (
        deployment_id,
        identity_provider_id,
        principal_id,
        id
    ) ON DELETE RESTRICT,
    CONSTRAINT account_session_provider_generation_fk FOREIGN KEY (
        deployment_id,
        identity_provider_id,
        provider_generation
    ) REFERENCES mesh.identity_provider_generation (
        deployment_id,
        identity_provider_id,
        generation
    ) ON DELETE RESTRICT,
    CONSTRAINT account_session_provider_client_fk FOREIGN KEY (
        deployment_id,
        identity_provider_id,
        identity_provider_client_id
    ) REFERENCES mesh.identity_provider_client (
        deployment_id,
        identity_provider_id,
        id
    ) ON DELETE RESTRICT,
    CONSTRAINT account_session_workspace_scope_fk FOREIGN KEY (
        deployment_id,
        login_workspace_id
    ) REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT account_session_timestamps_check CHECK (
        authentication_time <= issued_at
        AND issued_at <= last_used_at
        AND last_used_at < idle_expires_at
        AND idle_expires_at <= absolute_expires_at
        AND created_at <= issued_at
        AND updated_at >= created_at
        AND (ended_at IS NULL OR ended_at >= issued_at)
    ),
    UNIQUE (deployment_id, principal_id, id),
    UNIQUE (
        deployment_id,
        token_digest_algorithm,
        token_digest_key_id,
        token_digest
    )
);

CREATE INDEX account_session_principal_state_expiry_idx
    ON mesh.account_session (
        deployment_id,
        principal_id,
        state,
        absolute_expires_at,
        id
    );

CREATE INDEX account_session_provider_sid_idx
    ON mesh.account_session (
        deployment_id,
        identity_provider_id,
        provider_sid_digest_key_id,
        provider_sid_digest
    )
    WHERE provider_sid_digest IS NOT NULL AND state = 'active';

CREATE INDEX account_session_active_idle_expiry_idx
    ON mesh.account_session (idle_expires_at, id)
    WHERE state = 'active';

CREATE TABLE mesh.identity_link_request (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    current_principal_id BIGINT NOT NULL,
    candidate_identity_provider_id BIGINT NOT NULL,
    candidate_subject_digest_algorithm TEXT NOT NULL,
    candidate_subject_digest_key_id TEXT NOT NULL,
    candidate_subject_digest BYTEA NOT NULL,
    current_proof_account_session_id BIGINT,
    candidate_proof_auth_transaction_id BIGINT NOT NULL,
    proof_kind TEXT NOT NULL,
    operation_semantic_hash BYTEA NOT NULL,
    approval_evidence_reference TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    resolved_at TIMESTAMPTZ,
    result_identity_subject_id BIGINT,
    state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT identity_link_request_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT identity_link_request_subject_digest_algorithm_check CHECK (
        candidate_subject_digest_algorithm = 'hmac-sha256-v1'
    ),
    CONSTRAINT identity_link_request_subject_digest_key_id_check CHECK (
        pg_catalog.char_length(candidate_subject_digest_key_id) BETWEEN 1 AND 128
        AND candidate_subject_digest_key_id =
            pg_catalog.btrim(candidate_subject_digest_key_id)
        AND candidate_subject_digest_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    CONSTRAINT identity_link_request_subject_digest_check CHECK (
        pg_catalog.octet_length(candidate_subject_digest) = 32
    ),
    CONSTRAINT identity_link_request_proof_check CHECK (
        (
            proof_kind = 'dual_authentication'
            AND current_proof_account_session_id IS NOT NULL
            AND approval_evidence_reference IS NULL
        )
        OR (
            proof_kind = 'approved_recovery'
            AND approval_evidence_reference IS NOT NULL
            AND pg_catalog.char_length(approval_evidence_reference) BETWEEN 1 AND 512
            AND approval_evidence_reference =
                pg_catalog.btrim(approval_evidence_reference)
            AND approval_evidence_reference ~ '^[A-Za-z][A-Za-z0-9+.-]*://[A-Za-z0-9][A-Za-z0-9._:/-]*$'
        )
    ),
    CONSTRAINT identity_link_request_operation_hash_check CHECK (
        pg_catalog.octet_length(operation_semantic_hash) = 32
    ),
    CONSTRAINT identity_link_request_state_check CHECK (
        state IN ('pending', 'linked', 'rejected', 'expired')
    ),
    CONSTRAINT identity_link_request_result_check CHECK (
        (
            state = 'pending'
            AND resolved_at IS NULL
            AND result_identity_subject_id IS NULL
        )
        OR (
            state = 'linked'
            AND resolved_at IS NOT NULL
            AND result_identity_subject_id IS NOT NULL
        )
        OR (
            state IN ('rejected', 'expired')
            AND resolved_at IS NOT NULL
            AND result_identity_subject_id IS NULL
        )
    ),
    CONSTRAINT identity_link_request_account_scope_fk FOREIGN KEY (
        deployment_id,
        current_principal_id
    ) REFERENCES mesh.account (deployment_id, principal_id) ON DELETE RESTRICT,
    CONSTRAINT identity_link_request_current_proof_fk FOREIGN KEY (
        deployment_id,
        current_principal_id,
        current_proof_account_session_id
    ) REFERENCES mesh.account_session (
        deployment_id,
        principal_id,
        id
    ) ON DELETE RESTRICT,
    CONSTRAINT identity_link_request_candidate_provider_fk FOREIGN KEY (
        deployment_id,
        candidate_identity_provider_id
    ) REFERENCES mesh.identity_provider (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT identity_link_request_candidate_proof_fk FOREIGN KEY (
        deployment_id,
        candidate_identity_provider_id,
        candidate_proof_auth_transaction_id
    ) REFERENCES mesh.auth_transaction (
        deployment_id,
        identity_provider_id,
        id
    ) ON DELETE RESTRICT,
    CONSTRAINT identity_link_request_result_subject_fk FOREIGN KEY (
        deployment_id,
        candidate_identity_provider_id,
        current_principal_id,
        result_identity_subject_id
    ) REFERENCES mesh.identity_subject (
        deployment_id,
        identity_provider_id,
        principal_id,
        id
    ) ON DELETE RESTRICT,
    CONSTRAINT identity_link_request_timestamps_check CHECK (
        expires_at > created_at
        AND updated_at >= created_at
        AND (resolved_at IS NULL OR resolved_at >= created_at)
    ),
    UNIQUE (deployment_id, id)
);

CREATE UNIQUE INDEX identity_link_request_pending_subject_uidx
    ON mesh.identity_link_request (
        deployment_id,
        candidate_identity_provider_id,
        candidate_subject_digest_key_id,
        candidate_subject_digest
    )
    WHERE state = 'pending';

CREATE INDEX identity_link_request_principal_state_idx
    ON mesh.identity_link_request (
        deployment_id,
        current_principal_id,
        state,
        expires_at,
        id
    );

CREATE TABLE mesh.oidc_logout_replay (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    identity_provider_id BIGINT NOT NULL,
    identity_provider_client_id BIGINT NOT NULL,
    jti_digest_algorithm TEXT NOT NULL,
    jti_digest_key_id TEXT NOT NULL,
    jti_digest BYTEA NOT NULL,
    sid_digest_algorithm TEXT,
    sid_digest_key_id TEXT,
    sid_digest BYTEA,
    subject_digest_algorithm TEXT,
    subject_digest_key_id TEXT,
    subject_digest BYTEA,
    issued_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    processed_at TIMESTAMPTZ,
    processing_result TEXT,
    state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT oidc_logout_replay_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT oidc_logout_replay_jti_digest_algorithm_check CHECK (
        jti_digest_algorithm = 'hmac-sha256-v1'
    ),
    CONSTRAINT oidc_logout_replay_jti_digest_key_id_check CHECK (
        pg_catalog.char_length(jti_digest_key_id) BETWEEN 1 AND 128
        AND jti_digest_key_id = pg_catalog.btrim(jti_digest_key_id)
        AND jti_digest_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    CONSTRAINT oidc_logout_replay_jti_digest_check CHECK (
        pg_catalog.octet_length(jti_digest) = 32
    ),
    CONSTRAINT oidc_logout_replay_sid_digest_check CHECK (
        (
            sid_digest_algorithm IS NULL
            AND sid_digest_key_id IS NULL
            AND sid_digest IS NULL
        )
        OR (
            sid_digest_algorithm IS NOT NULL
            AND sid_digest_algorithm = 'hmac-sha256-v1'
            AND sid_digest_key_id IS NOT NULL
            AND sid_digest IS NOT NULL
            AND pg_catalog.char_length(sid_digest_key_id) BETWEEN 1 AND 128
            AND sid_digest_key_id = pg_catalog.btrim(sid_digest_key_id)
            AND sid_digest_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
            AND pg_catalog.octet_length(sid_digest) = 32
        )
    ),
    CONSTRAINT oidc_logout_replay_subject_digest_check CHECK (
        (
            subject_digest_algorithm IS NULL
            AND subject_digest_key_id IS NULL
            AND subject_digest IS NULL
        )
        OR (
            subject_digest_algorithm IS NOT NULL
            AND subject_digest_algorithm = 'hmac-sha256-v1'
            AND subject_digest_key_id IS NOT NULL
            AND subject_digest IS NOT NULL
            AND pg_catalog.char_length(subject_digest_key_id) BETWEEN 1 AND 128
            AND subject_digest_key_id = pg_catalog.btrim(subject_digest_key_id)
            AND subject_digest_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
            AND pg_catalog.octet_length(subject_digest) = 32
        )
    ),
    CONSTRAINT oidc_logout_replay_target_check CHECK (
        sid_digest IS NOT NULL OR subject_digest IS NOT NULL
    ),
    CONSTRAINT oidc_logout_replay_state_check CHECK (
        state IN ('processing', 'completed', 'failed')
    ),
    CONSTRAINT oidc_logout_replay_result_check CHECK (
        (
            state = 'processing'
            AND processed_at IS NULL
            AND processing_result IS NULL
        )
        OR (
            state = 'completed'
            AND processed_at IS NOT NULL
            AND processing_result IS NOT NULL
            AND processing_result IN ('sessions_revoked', 'no_matching_session')
        )
        OR (
            state = 'failed'
            AND processed_at IS NOT NULL
            AND processing_result IS NOT NULL
            AND processing_result = 'processing_failed'
        )
    ),
    CONSTRAINT oidc_logout_replay_provider_client_fk FOREIGN KEY (
        deployment_id,
        identity_provider_id,
        identity_provider_client_id
    ) REFERENCES mesh.identity_provider_client (
        deployment_id,
        identity_provider_id,
        id
    ) ON DELETE RESTRICT,
    CONSTRAINT oidc_logout_replay_timestamps_check CHECK (
        issued_at < expires_at
        AND updated_at >= created_at
        AND (processed_at IS NULL OR processed_at >= created_at)
    ),
    UNIQUE (deployment_id, id),
    UNIQUE (
        deployment_id,
        identity_provider_id,
        jti_digest_algorithm,
        jti_digest_key_id,
        jti_digest
    )
);

CREATE INDEX oidc_logout_replay_expiry_idx
    ON mesh.oidc_logout_replay (expires_at, id);

CREATE FUNCTION mesh_ops.enforce_human_auth_state_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'human authentication history cannot be deleted';
    END IF;

    IF TG_OP = 'INSERT' THEN
        IF (TG_TABLE_NAME = 'auth_transaction' AND NEW.state <> 'pending')
            OR (TG_TABLE_NAME = 'account_session' AND NEW.state <> 'active')
            OR (TG_TABLE_NAME = 'identity_link_request' AND NEW.state <> 'pending')
            OR (TG_TABLE_NAME = 'oidc_logout_replay' AND NEW.state <> 'processing') THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'invalid initial human authentication state';
        END IF;
        RETURN NEW;
    END IF;

    IF NEW.version <> OLD.version + 1 OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'invalid human authentication row version transition';
    END IF;

    IF TG_TABLE_NAME = 'auth_transaction' THEN
        IF (pg_catalog.to_jsonb(NEW) - ARRAY[
                'state',
                'consumed_at',
                'consumed_result_kind',
                'consumed_result_public_id',
                'failure_class',
                'pkce_verifier_encryption_algorithm',
                'pkce_verifier_encryption_key_id',
                'pkce_verifier_ciphertext',
                'version',
                'updated_at'
            ]::TEXT[]) IS DISTINCT FROM
            (pg_catalog.to_jsonb(OLD) - ARRAY[
                'state',
                'consumed_at',
                'consumed_result_kind',
                'consumed_result_public_id',
                'failure_class',
                'pkce_verifier_encryption_algorithm',
                'pkce_verifier_encryption_key_id',
                'pkce_verifier_ciphertext',
                'version',
                'updated_at'
            ]::TEXT[]) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'authentication transaction binding is immutable';
        END IF;
        IF NOT (
            (OLD.state = 'pending' AND NEW.state IN ('consuming', 'failed', 'expired'))
            OR (
                OLD.state = 'consuming'
                AND NEW.state IN ('succeeded', 'failed', 'expired')
            )
        ) THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'invalid authentication transaction state transition';
        END IF;
    ELSIF TG_TABLE_NAME = 'account_session' THEN
        IF (pg_catalog.to_jsonb(NEW) - ARRAY[
                'state',
                'last_used_at',
                'idle_expires_at',
                'ended_at',
                'end_reason',
                'version',
                'updated_at'
            ]::TEXT[]) IS DISTINCT FROM
            (pg_catalog.to_jsonb(OLD) - ARRAY[
                'state',
                'last_used_at',
                'idle_expires_at',
                'ended_at',
                'end_reason',
                'version',
                'updated_at'
            ]::TEXT[])
            OR NEW.last_used_at < OLD.last_used_at
            OR NEW.idle_expires_at < OLD.idle_expires_at THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'account session binding is immutable';
        END IF;
        IF OLD.state <> 'active'
            OR NEW.state NOT IN ('active', 'revoked', 'expired') THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'invalid account session state transition';
        END IF;
    ELSIF TG_TABLE_NAME = 'identity_link_request' THEN
        IF (pg_catalog.to_jsonb(NEW) - ARRAY[
                'state',
                'resolved_at',
                'result_identity_subject_id',
                'version',
                'updated_at'
            ]::TEXT[]) IS DISTINCT FROM
            (pg_catalog.to_jsonb(OLD) - ARRAY[
                'state',
                'resolved_at',
                'result_identity_subject_id',
                'version',
                'updated_at'
            ]::TEXT[])
            OR OLD.state <> 'pending'
            OR NEW.state NOT IN ('linked', 'rejected', 'expired') THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'invalid identity link request transition';
        END IF;
    ELSIF TG_TABLE_NAME = 'oidc_logout_replay' THEN
        IF (pg_catalog.to_jsonb(NEW) - ARRAY[
                'state',
                'processed_at',
                'processing_result',
                'version',
                'updated_at'
            ]::TEXT[]) IS DISTINCT FROM
            (pg_catalog.to_jsonb(OLD) - ARRAY[
                'state',
                'processed_at',
                'processing_result',
                'version',
                'updated_at'
            ]::TEXT[])
            OR OLD.state <> 'processing'
            OR NEW.state NOT IN ('completed', 'failed') THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'invalid OIDC logout replay transition';
        END IF;
    ELSE
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'invalid human authentication trigger configuration';
    END IF;

    RETURN NEW;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.enforce_human_auth_state_transition() FROM PUBLIC;

CREATE TRIGGER auth_transaction_state_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.auth_transaction
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_human_auth_state_transition();

CREATE TRIGGER account_session_state_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.account_session
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_human_auth_state_transition();

CREATE TRIGGER identity_link_request_state_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.identity_link_request
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_human_auth_state_transition();

CREATE TRIGGER oidc_logout_replay_state_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.oidc_logout_replay
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_human_auth_state_transition();

CREATE FUNCTION mesh_ops.resolve_account_session(
    p_token_digest_algorithm TEXT,
    p_token_digest_key_id TEXT,
    p_token_digest BYTEA
)
RETURNS TABLE (
    session_public_id UUID,
    principal_public_id UUID,
    identity_subject_public_id UUID,
    login_workspace_public_id UUID,
    authentication_time TIMESTAMPTZ,
    acr TEXT,
    amr TEXT[],
    session_version BIGINT,
    principal_authority_generation BIGINT,
    account_session_generation BIGINT,
    provider_generation BIGINT,
    deployment_recovery_epoch BIGINT,
    idle_expires_at TIMESTAMPTZ,
    absolute_expires_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    resolved_workspace_id BIGINT;
    previous_workspace_id TEXT;
BEGIN
    IF p_token_digest_algorithm IS NULL
        OR p_token_digest_algorithm <> 'hmac-sha256-v1'
        OR p_token_digest_key_id IS NULL
        OR pg_catalog.char_length(p_token_digest_key_id) NOT BETWEEN 1 AND 128
        OR p_token_digest_key_id <> pg_catalog.btrim(p_token_digest_key_id)
        OR p_token_digest_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        OR p_token_digest IS NULL
        OR pg_catalog.octet_length(p_token_digest) <> 32 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid account session digest';
    END IF;

    SELECT session.login_workspace_id
    INTO resolved_workspace_id
    FROM mesh.account_session AS session
    WHERE session.token_digest_algorithm = p_token_digest_algorithm
      AND session.token_digest_key_id = p_token_digest_key_id
      AND session.token_digest = p_token_digest;

    previous_workspace_id := pg_catalog.current_setting('mesh.workspace_id', TRUE);
    PERFORM pg_catalog.set_config(
        'mesh.workspace_id',
        COALESCE(resolved_workspace_id::TEXT, ''),
        TRUE
    );

    BEGIN
        RETURN QUERY
        SELECT
            session.public_id,
            principal.public_id,
            subject.public_id,
            workspace.public_id,
            session.authentication_time,
            session.acr,
            session.amr,
            session.version,
            session.principal_authority_generation,
            session.account_session_generation,
            session.provider_generation,
            session.deployment_recovery_epoch,
            session.idle_expires_at,
            session.absolute_expires_at
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
        LEFT JOIN mesh.workspace AS workspace
          ON workspace.deployment_id = session.deployment_id
         AND workspace.id = session.login_workspace_id
        WHERE session.token_digest_algorithm = p_token_digest_algorithm
          AND session.token_digest_key_id = p_token_digest_key_id
          AND session.token_digest = p_token_digest
          AND session.state = 'active'
          AND session.idle_expires_at > pg_catalog.transaction_timestamp()
          AND session.absolute_expires_at > pg_catalog.transaction_timestamp()
          AND deployment.state = 'active'
          AND deployment.recovery_state = 'verified'
          AND deployment.recovery_epoch = session.deployment_recovery_epoch
          AND principal.state = 'active'
          AND principal.authority_generation = session.principal_authority_generation
          AND account.recovery_state = 'verified'
          AND account.session_generation = session.account_session_generation
          AND subject.state = 'active'
          AND provider.state = 'active'
          AND provider.recovery_state = 'verified'
          AND provider.current_generation = session.provider_generation
          AND client.state = 'active'
          AND (
              session.login_workspace_id IS NULL
              OR workspace.state = 'active'
          );
    EXCEPTION
        WHEN OTHERS THEN
            PERFORM pg_catalog.set_config(
                'mesh.workspace_id',
                COALESCE(previous_workspace_id, ''),
                TRUE
            );
            RAISE;
    END;

    PERFORM pg_catalog.set_config(
        'mesh.workspace_id',
        COALESCE(previous_workspace_id, ''),
        TRUE
    );
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.resolve_account_session(TEXT, TEXT, BYTEA) FROM PUBLIC;

CREATE FUNCTION mesh_ops.revoke_account_session(
    p_token_digest_algorithm TEXT,
    p_token_digest_key_id TEXT,
    p_token_digest BYTEA,
    p_end_reason TEXT
)
RETURNS TABLE (
    session_public_id UUID,
    session_version BIGINT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
BEGIN
    IF p_token_digest_algorithm IS NULL
        OR p_token_digest_algorithm <> 'hmac-sha256-v1'
        OR p_token_digest_key_id IS NULL
        OR pg_catalog.char_length(p_token_digest_key_id) NOT BETWEEN 1 AND 128
        OR p_token_digest_key_id <> pg_catalog.btrim(p_token_digest_key_id)
        OR p_token_digest_key_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
        OR p_token_digest IS NULL
        OR pg_catalog.octet_length(p_token_digest) <> 32
        OR p_end_reason IS NULL
        OR p_end_reason NOT IN (
            'local_logout',
            'logout_all',
            'account_suspended',
            'membership_removed',
            'identity_unlinked',
            'privilege_changed',
            'provider_logout',
            'provider_recovery',
            'deployment_recovery',
            'administrative'
        ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid account session revocation input';
    END IF;

    RETURN QUERY
    UPDATE mesh.account_session AS session
    SET
        state = 'revoked',
        ended_at = pg_catalog.transaction_timestamp(),
        end_reason = p_end_reason,
        version = session.version + 1,
        updated_at = pg_catalog.transaction_timestamp()
    WHERE session.token_digest_algorithm = p_token_digest_algorithm
      AND session.token_digest_key_id = p_token_digest_key_id
      AND session.token_digest = p_token_digest
      AND session.state = 'active'
    RETURNING session.public_id, session.version;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.revoke_account_session(TEXT, TEXT, BYTEA, TEXT)
    FROM PUBLIC;

CREATE TRIGGER auth_transaction_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.auth_transaction
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation(
    'auth_transaction',
    'public_id'
);

CREATE TRIGGER account_session_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.account_session
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation(
    'account_session',
    'public_id'
);

CREATE TRIGGER identity_link_request_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.identity_link_request
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation(
    'identity_link_request',
    'public_id'
);

CREATE TRIGGER oidc_logout_replay_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.oidc_logout_replay
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation(
    'oidc_logout_replay',
    'public_id'
);

REVOKE ALL ON ALL TABLES IN SCHEMA mesh FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA mesh FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA mesh, mesh_ops, mesh_audit FROM PUBLIC;

REVOKE ALL ON
    mesh.auth_transaction,
    mesh.account_session,
    mesh.identity_link_request,
    mesh.oidc_logout_replay
    FROM mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

GRANT EXECUTE ON FUNCTION mesh_ops.resolve_account_session(TEXT, TEXT, BYTEA)
    TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.revoke_account_session(TEXT, TEXT, BYTEA, TEXT)
    TO mesh_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
