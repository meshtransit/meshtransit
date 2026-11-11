-- Schema 288: the verified email of an Account, shown on its own Devices
-- (docs/device-logout-s4c-account-email.md). Display data only: it never
-- identifies, links or authorizes anyone; sign-in still matches the provider
-- subject.
--
-- The email lives in mesh.account_email, not in mesh.account: every change to
-- an Account row bumps its version (account_authority_mutation), and session
-- issuance compares that version, so writing the email there would fail a
-- sign-in of the same Account running at the same time.
--
-- record_account_verified_email_v1 is bound to the exact consuming browser
-- login of the route, like sign_up_account_v1 (schema 131), with the
-- predicates subject resolution (schema 101) applies, so it writes only for a
-- sign-in that can resolve: an active, verified deployment, provider and
-- client; a subject that is unique across every state; and for a
-- Workspace-bound login, an active member of a Workspace that routes this
-- provider and client. A sign-in that cannot resolve returns no row. It
-- writes only when the email differs from the stored one; two first
-- sign-ins of one Account at once insert one row and the other compares
-- against it. The caller appends the evidence; it never carries the email or
-- a hash of it.
--
-- read_map_self_identity_v2 is v1 (schema 287) plus the owner's email. v1
-- stays for rollback.
--
-- An email is 3-254 printable ASCII characters without '"', '<' or '>', with
-- exactly one '@' and text on both sides. Core checks this in Go (stricter: it
-- also wants a dot in the domain) and in the function before the row is
-- written, so the CHECK never fails (a failing CHECK would print the row in
-- the server log).

CREATE TABLE mesh.account_email (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL REFERENCES mesh.deployment (id) ON DELETE RESTRICT,
    account_id BIGINT NOT NULL UNIQUE REFERENCES mesh.account (id) ON DELETE RESTRICT,
    email TEXT NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL,
    version BIGINT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT account_email_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT account_email_email_check CHECK (
        pg_catalog.char_length(email) BETWEEN 3 AND 254
        AND pg_catalog.octet_length(email) = pg_catalog.char_length(email)
        AND email ~ '^[!#-;=?-~]+$'
        AND email ~ '^[^@]+@[^@]+$'
    ),
    CONSTRAINT account_email_version_check CHECK (version > 0),
    CONSTRAINT account_email_time_check CHECK (updated_at >= created_at AND verified_at <= updated_at)
);
CREATE INDEX account_email_deployment_idx ON mesh.account_email (deployment_id, account_id);
ALTER TABLE mesh.account_email ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.account_email FORCE ROW LEVEL SECURITY;
CREATE POLICY account_email_migrator_policy ON mesh.account_email
    FOR ALL TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.account_email
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE TRIGGER account_email_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.account_email
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('account_email', 'public_id');

-- Errors: 22023 invalid input, 42501 the sign-in does not match. No row: the
-- sign-in cannot resolve to one active Account (none yet, ambiguous, or not a
-- member of the Workspace it is bound to).
CREATE FUNCTION mesh_ops.record_account_verified_email_v1(
    p_deployment_public_id UUID, p_provider_public_id UUID, p_client_public_id UUID,
    p_provider_generation BIGINT, p_recovery_epoch BIGINT,
    p_transaction_public_id UUID, p_transaction_version BIGINT, p_binding_hash BYTEA,
    p_consumed_at TIMESTAMPTZ, p_subject_algorithm TEXT, p_active_key_id TEXT, p_active_digest BYTEA,
    p_previous_key_id TEXT, p_previous_digest BYTEA, p_email TEXT,
    p_row_public_id UUID, p_change_public_id UUID
)
RETURNS TABLE (
    changed BOOLEAN, principal_public_id UUID, account_email_public_id UUID,
    account_email_version BIGINT, verified_at TIMESTAMPTZ
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_auth RECORD;
    v_matched BIGINT;
    v_principal BIGINT;
    v_principal_public UUID;
    v_account BIGINT;
    v_row mesh.account_email%ROWTYPE;
BEGIN
    IF p_subject_algorithm IS DISTINCT FROM 'hmac-sha256-v1' OR p_active_key_id IS NULL
        OR p_active_digest IS NULL OR pg_catalog.octet_length(p_active_digest) <> 32
        OR (p_previous_key_id IS NULL) <> (p_previous_digest IS NULL)
        OR p_email IS NULL OR pg_catalog.char_length(p_email) NOT BETWEEN 3 AND 254
        OR pg_catalog.octet_length(p_email) <> pg_catalog.char_length(p_email)
        OR p_email !~ '^[!#-;=?-~]+$' OR p_email !~ '^[^@]+@[^@]+$'
        OR p_row_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_row_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'account email input is invalid';
    END IF;
    -- The exact consuming browser login of this route.
    SELECT auth.deployment_id, auth.identity_provider_id, auth.identity_provider_client_id, auth.workspace_id
    INTO v_auth
    FROM mesh.auth_transaction AS auth
    JOIN mesh.deployment AS deployment ON deployment.id = auth.deployment_id
    JOIN mesh.identity_provider AS provider
      ON provider.deployment_id = auth.deployment_id AND provider.id = auth.identity_provider_id
    JOIN mesh.identity_provider_client AS client
      ON client.deployment_id = auth.deployment_id AND client.id = auth.identity_provider_client_id
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND deployment.state = 'active' AND deployment.recovery_state = 'verified'
      AND deployment.deleted_at IS NULL AND deployment.recovery_epoch = p_recovery_epoch
      AND provider.public_id = p_provider_public_id AND provider.current_generation = p_provider_generation
      AND provider.state = 'active' AND provider.recovery_state = 'verified' AND provider.deleted_at IS NULL
      AND client.public_id = p_client_public_id AND client.state = 'active' AND client.deleted_at IS NULL
      AND auth.public_id = p_transaction_public_id
      AND auth.state = 'consuming' AND auth.version = p_transaction_version
      AND auth.flow_kind = 'browser_authorization_code' AND auth.operation_kind = 'login'
      AND auth.provider_generation = p_provider_generation
      AND auth.deployment_recovery_epoch = p_recovery_epoch
      AND auth.principal_id IS NULL AND auth.binding_semantic_hash = p_binding_hash
      AND auth.consumed_at = p_consumed_at AND auth.consumed_at <= v_now AND auth.expires_at > v_now
      AND auth.consumed_result_kind IS NULL AND auth.failure_class IS NULL;
    IF v_auth.deployment_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'sign-in transaction does not match';
    END IF;

    -- Unique across every state, as subject resolution counts it.
    SELECT pg_catalog.count(*) INTO v_matched
    FROM mesh.identity_subject AS subject
    WHERE subject.deployment_id = v_auth.deployment_id
      AND subject.identity_provider_id = v_auth.identity_provider_id
      AND subject.subject_digest_algorithm = p_subject_algorithm
      AND ((subject.subject_digest_key_id = p_active_key_id AND subject.subject_digest = p_active_digest)
           OR (subject.subject_digest_key_id = p_previous_key_id AND subject.subject_digest = p_previous_digest));
    IF v_matched <> 1 THEN
        RETURN;
    END IF;
    SELECT principal.id, principal.public_id, account.id INTO v_principal, v_principal_public, v_account
    FROM mesh.identity_subject AS subject
    JOIN mesh.principal AS principal
      ON principal.deployment_id = subject.deployment_id AND principal.id = subject.principal_id
    JOIN mesh.account AS account
      ON account.deployment_id = principal.deployment_id AND account.principal_id = principal.id
    WHERE subject.deployment_id = v_auth.deployment_id
      AND subject.identity_provider_id = v_auth.identity_provider_id
      AND subject.subject_digest_algorithm = p_subject_algorithm
      AND subject.state = 'active' AND subject.deleted_at IS NULL
      AND ((subject.subject_digest_key_id = p_active_key_id AND subject.subject_digest = p_active_digest)
           OR (subject.subject_digest_key_id = p_previous_key_id AND subject.subject_digest = p_previous_digest))
      AND principal.kind = 'account' AND principal.state = 'active' AND principal.deleted_at IS NULL
      AND account.recovery_state = 'verified';
    IF v_account IS NULL THEN
        RETURN;
    END IF;
    -- A Workspace-bound login counts only for an active member of an active
    -- Workspace that routes this provider and client.
    IF v_auth.workspace_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM mesh.workspace_membership AS membership
        JOIN mesh.workspace AS workspace
          ON workspace.deployment_id = membership.deployment_id AND workspace.id = membership.workspace_id
        JOIN mesh.workspace_identity_provider AS workspace_provider
          ON workspace_provider.deployment_id = workspace.deployment_id
         AND workspace_provider.workspace_id = workspace.id
         AND workspace_provider.identity_provider_id = v_auth.identity_provider_id
         AND workspace_provider.identity_provider_client_id = v_auth.identity_provider_client_id
        WHERE membership.deployment_id = v_auth.deployment_id
          AND membership.workspace_id = v_auth.workspace_id
          AND membership.principal_id = v_principal
          AND membership.state = 'active' AND membership.valid_from <= v_now
          AND (membership.expires_at IS NULL OR membership.expires_at > v_now)
          AND workspace.state = 'active' AND workspace.deleted_at IS NULL
          AND workspace_provider.state = 'active' AND workspace_provider.deleted_at IS NULL
    ) THEN
        RETURN;
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    -- The first sign-in inserts; one at the same time finds that row below.
    INSERT INTO mesh.account_email AS stored (
        public_id, deployment_id, account_id, email, verified_at, version, created_at, updated_at
    ) VALUES (p_row_public_id, v_auth.deployment_id, v_account, p_email, v_now, 1, v_now, v_now)
    ON CONFLICT (account_id) DO NOTHING
    RETURNING * INTO v_row;
    IF v_row.id IS NOT NULL THEN
        RETURN QUERY SELECT TRUE, v_principal_public, v_row.public_id, v_row.version, v_row.verified_at;
        RETURN;
    END IF;
    SELECT * INTO v_row FROM mesh.account_email AS stored
    WHERE stored.account_id = v_account FOR UPDATE;
    IF v_row.email = p_email THEN
        RETURN QUERY SELECT FALSE, v_principal_public, v_row.public_id, v_row.version, v_row.verified_at;
        RETURN;
    END IF;
    UPDATE mesh.account_email AS stored
    SET email = p_email, verified_at = v_now, version = stored.version + 1,
        updated_at = GREATEST(v_now, stored.updated_at)
    WHERE stored.id = v_row.id
    RETURNING * INTO v_row;
    RETURN QUERY SELECT TRUE, v_principal_public, v_row.public_id, v_row.version, v_row.verified_at;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.record_account_verified_email_v1(
    UUID, UUID, UUID, BIGINT, BIGINT, UUID, BIGINT, BYTEA, TIMESTAMPTZ, TEXT, TEXT, BYTEA, TEXT, BYTEA, TEXT,
    UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.record_account_verified_email_v1(
    UUID, UUID, UUID, BIGINT, BIGINT, UUID, BIGINT, BYTEA, TIMESTAMPTZ, TEXT, TEXT, BYTEA, TEXT, BYTEA, TEXT,
    UUID, UUID
) TO mesh_runtime;

CREATE FUNCTION mesh_ops.read_map_self_identity_v2(p_machine_fingerprint BYTEA, p_node_key BYTEA)
RETURNS TABLE (workspace_display_name TEXT, ownership TEXT, owner_display_name TEXT, owner_email TEXT)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT := mesh_ops.current_workspace_id();
    scoped_network_id BIGINT := mesh_ops.current_network_id();
BEGIN
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map self identity scope is unavailable';
    END IF;
    IF p_machine_fingerprint IS NULL OR p_node_key IS NULL THEN
        RETURN;
    END IF;

    RETURN QUERY
    SELECT workspace.display_name,
        device.ownership,
        CASE WHEN device.ownership = 'member' THEN account.display_name END,
        CASE WHEN device.ownership = 'member' THEN account_email.email END
    FROM mesh.device AS device
    JOIN mesh.workspace AS workspace
      ON workspace.id = device.workspace_id
    JOIN mesh.network AS network
      ON network.workspace_id = device.workspace_id
     AND network.id = device.network_id
    JOIN mesh.device_machine_key_epoch AS machine
      ON machine.workspace_id = device.workspace_id
     AND machine.network_id = device.network_id
     AND machine.device_id = device.id
    JOIN mesh.device_node_key_epoch AS node_key
      ON node_key.workspace_id = device.workspace_id
     AND node_key.network_id = device.network_id
     AND node_key.device_id = device.id
    LEFT JOIN mesh.account AS account
      ON account.deployment_id = workspace.deployment_id
     AND account.principal_id = device.owner_principal_id
    LEFT JOIN mesh.account_email AS account_email
      ON account_email.deployment_id = account.deployment_id
     AND account_email.account_id = account.id
    WHERE device.workspace_id = scoped_workspace_id
      AND device.network_id = scoped_network_id
      AND workspace.state = 'active'
      AND workspace.deleted_at IS NULL
      AND machine.fingerprint = p_machine_fingerprint
      AND machine.state = 'active'
      AND machine.epoch = device.current_machine_key_epoch
      AND node_key.public_key = p_node_key
      AND node_key.state = 'active'
      AND node_key.epoch = device.current_node_key_epoch
      AND network.state = 'active'
      AND network.deleted_at IS NULL
      AND device.state = 'active'
      AND device.deleted_at IS NULL
      AND device.expires_at > pg_catalog.transaction_timestamp();
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.read_map_self_identity_v2(BYTEA, BYTEA)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_map_self_identity_v2(BYTEA, BYTEA) TO mesh_runtime;
