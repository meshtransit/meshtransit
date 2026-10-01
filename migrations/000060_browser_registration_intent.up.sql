-- A browser intent exists before the human has selected a Network. No runtime
-- role receives direct table access; purpose-specific functions must admit it.
CREATE TABLE mesh.browser_registration_intent (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    issued_recovery_epoch BIGINT NOT NULL CHECK (issued_recovery_epoch > 0),
    machine_key BYTEA NOT NULL,
    machine_key_fingerprint BYTEA NOT NULL,
    requested_node_key BYTEA NOT NULL,
    requested_hostname TEXT NOT NULL,
    token_nonce BYTEA NOT NULL,
    token_key_id TEXT NOT NULL,
    token_digest_algorithm TEXT NOT NULL,
    token_digest BYTEA NOT NULL UNIQUE,
    pending_registration_public_id UUID UNIQUE,
    state TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.now(),
    CONSTRAINT browser_registration_intent_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT browser_registration_intent_machine_key_check CHECK (
        pg_catalog.octet_length(machine_key) = 32
        AND machine_key <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        AND pg_catalog.octet_length(machine_key_fingerprint) = 32
    ),
    CONSTRAINT browser_registration_intent_node_key_check CHECK (
        pg_catalog.octet_length(requested_node_key) = 32
        AND requested_node_key <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
    ),
    CONSTRAINT browser_registration_intent_hostname_check CHECK (
        pg_catalog.char_length(requested_hostname) BETWEEN 1 AND 253
        AND requested_hostname = pg_catalog.btrim(requested_hostname)
    ),
    CONSTRAINT browser_registration_intent_nonce_check CHECK (
        pg_catalog.octet_length(token_nonce) = 32
        AND token_nonce <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
    ),
    CONSTRAINT browser_registration_intent_token_key_check CHECK (
        pg_catalog.char_length(token_key_id) BETWEEN 1 AND 128
        AND token_key_id = pg_catalog.btrim(token_key_id)
        AND token_key_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    CONSTRAINT browser_registration_intent_digest_check CHECK (
        token_digest_algorithm = 'sha256-domain-v1'
        AND pg_catalog.octet_length(token_digest) = 32
        AND token_digest <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
    ),
    CONSTRAINT browser_registration_intent_state_check CHECK (
        state IN ('pending', 'approved', 'completed', 'rejected', 'expired')
    ),
    CONSTRAINT browser_registration_intent_result_check CHECK (
        (state = 'pending' AND pending_registration_public_id IS NULL)
        OR (state IN ('approved', 'completed') AND pending_registration_public_id IS NOT NULL)
        OR state IN ('rejected', 'expired')
    ),
    CONSTRAINT browser_registration_intent_deployment_fk FOREIGN KEY (deployment_id)
        REFERENCES mesh.deployment (id) ON DELETE RESTRICT,
    CONSTRAINT browser_registration_intent_registration_fk FOREIGN KEY (
        pending_registration_public_id
    ) REFERENCES mesh.pending_registration (public_id) ON DELETE RESTRICT,
    CONSTRAINT browser_registration_intent_timestamps_check CHECK (
        expires_at > created_at AND updated_at >= created_at
    ),
    UNIQUE (deployment_id, id)
);

CREATE UNIQUE INDEX browser_registration_intent_active_machine_uidx
    ON mesh.browser_registration_intent (deployment_id, machine_key_fingerprint)
    WHERE state IN ('pending', 'approved');
CREATE INDEX browser_registration_intent_expiry_idx
    ON mesh.browser_registration_intent (state, expires_at, id)
    WHERE state IN ('pending', 'approved');

CREATE FUNCTION mesh_ops.enforce_browser_registration_intent_transition()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'browser registration intent is retained';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'pending' OR NEW.pending_registration_public_id IS NOT NULL THEN
            RAISE EXCEPTION USING
                ERRCODE = '23514',
                MESSAGE = 'invalid initial browser registration intent';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.public_id <> NEW.public_id
        OR OLD.deployment_id <> NEW.deployment_id
        OR OLD.issued_recovery_epoch <> NEW.issued_recovery_epoch
        OR OLD.machine_key <> NEW.machine_key
        OR OLD.machine_key_fingerprint <> NEW.machine_key_fingerprint
        OR OLD.requested_node_key <> NEW.requested_node_key
        OR OLD.requested_hostname <> NEW.requested_hostname
        OR OLD.token_nonce <> NEW.token_nonce
        OR OLD.token_key_id <> NEW.token_key_id
        OR OLD.token_digest_algorithm <> NEW.token_digest_algorithm
        OR OLD.token_digest <> NEW.token_digest
        OR OLD.expires_at <> NEW.expires_at
        OR NEW.version <> OLD.version + 1
        OR NEW.updated_at < OLD.updated_at
        OR OLD.state IN ('completed', 'rejected', 'expired')
        OR (OLD.pending_registration_public_id IS NOT NULL
            AND OLD.pending_registration_public_id IS DISTINCT FROM NEW.pending_registration_public_id)
        OR (OLD.state = 'approved' AND NEW.state = 'pending') THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'invalid browser registration intent transition';
    END IF;
    RETURN NEW;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.enforce_browser_registration_intent_transition() FROM PUBLIC;

CREATE TRIGGER browser_registration_intent_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.browser_registration_intent
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_browser_registration_intent_transition();

CREATE TRIGGER browser_registration_intent_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.browser_registration_intent
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation(
    'browser_registration_intent',
    'public_id'
);

ALTER TABLE mesh.browser_registration_intent ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.browser_registration_intent FORCE ROW LEVEL SECURITY;
CREATE POLICY browser_registration_intent_migrator_policy
    ON mesh.browser_registration_intent
    TO mesh_migrator
    USING (TRUE)
    WITH CHECK (TRUE);

REVOKE ALL ON TABLE mesh.browser_registration_intent
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
