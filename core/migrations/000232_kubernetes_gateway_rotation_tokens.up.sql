-- Schema 232 (K1.1a, docs/k8s-k1-1a-sa-token.md): a Kubernetes gateway
-- proves it is its pod, by a pod-bound ServiceAccount token, when it joins
-- and when it rotates a key. Core verifies the token in Go against the
-- cluster's signing trust; the database keeps the trust, binds each gateway
-- Device to the pod named at its join, and refuses a gateway's new key epoch
-- unless the same transaction recorded a verified token for it. Core binaries
-- older than 232 record none, so they rotate no gateway key (fail closed).
--
-- Errors: 22023 invalid input, 42501 no scope, P0002 no proven gateway
-- session, MTK14 the replica must join again with its signing keys (its
-- request has no trust), MTK15 its signing keys differ from the cluster's,
-- MTK16 another live Device or approval holds its pod, MTK17 the token was
-- used for this key, MTK18 the cluster's trust
-- changed or is missing, MTK19 a gateway key rotation without a token, MTK20
-- the token is not valid now by the database's clock.

-- Formats the Go side checks too (shared/kubejoin): the CHECKs repeat them so
-- both refuse the same values.
CREATE FUNCTION mesh_ops.kubernetes_issuer_is_valid_v1(p_issuer TEXT)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT p_issuer IS NOT NULL AND pg_catalog.octet_length(p_issuer) <= 255
        AND p_issuer ~ '^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[!-~]*)?$'
        AND pg_catalog.translate(p_issuer, '?#@\', '') = p_issuer
$function$;

-- An RFC 1123 subdomain as Kubernetes names ServiceAccounts, pods and
-- StatefulSets: 253 characters in all, no limit per label.
CREATE FUNCTION mesh_ops.kubernetes_name_is_valid_v1(p_name TEXT)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT p_name IS NOT NULL AND pg_catalog.octet_length(p_name) <= 253
        AND p_name ~ '^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$'
$function$;

-- An RFC 1123 label as Kubernetes names namespaces.
CREATE FUNCTION mesh_ops.kubernetes_namespace_is_valid_v1(p_namespace TEXT)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT p_namespace IS NOT NULL AND pg_catalog.octet_length(p_namespace) <= 63
        AND p_namespace ~ '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$'
$function$;

-- One to eight SHA-256 thumbprints.
CREATE FUNCTION mesh_ops.kubernetes_thumbprints_are_valid_v1(p_thumbprints BYTEA[])
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT p_thumbprints IS NOT NULL AND pg_catalog.array_ndims(p_thumbprints) = 1
        AND pg_catalog.cardinality(p_thumbprints) BETWEEN 1 AND 8
        AND pg_catalog.array_position(p_thumbprints, NULL) IS NULL
        AND pg_catalog.cardinality(p_thumbprints) = pg_catalog.cardinality(ARRAY(
            SELECT DISTINCT thumbprint FROM pg_catalog.unnest(p_thumbprints) AS thumbprint
            WHERE pg_catalog.octet_length(thumbprint) = 32))
$function$;

-- A replica's trust digest (design §6.2), as shared/kubejoin.TrustDigest
-- computes it: lengths big-endian before each value, the JWKS canonical.
CREATE FUNCTION mesh_ops.kubernetes_trust_digest_v1(
    p_issuer TEXT, p_jwks BYTEA, p_namespace TEXT, p_service_account TEXT, p_pod_name TEXT
)
RETURNS BYTEA
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.sha256(pg_catalog.convert_to('meshtransit/kube-sa-trust/v1', 'UTF8')
        || pg_catalog.decode('00', 'hex')
        || pg_catalog.int2send(pg_catalog.octet_length(p_issuer)::SMALLINT) || pg_catalog.convert_to(p_issuer, 'UTF8')
        || pg_catalog.int4send(pg_catalog.octet_length(p_jwks)) || p_jwks
        || pg_catalog.int2send(pg_catalog.octet_length(p_namespace)::SMALLINT) || pg_catalog.convert_to(p_namespace, 'UTF8')
        || pg_catalog.int2send(pg_catalog.octet_length(p_service_account)::SMALLINT)
        || pg_catalog.convert_to(p_service_account, 'UTF8')
        || pg_catalog.int2send(pg_catalog.octet_length(p_pod_name)::SMALLINT) || pg_catalog.convert_to(p_pod_name, 'UTF8'))
$function$;

-- The join code v2's 50 bits (shared/kubejoin.ComputeV2), first character
-- in the highest bits, as schema 224 compares v1 codes.
CREATE FUNCTION mesh_ops.kubernetes_join_code_v2(
    p_machine_key BYTEA, p_node_key BYTEA, p_cluster_public_id UUID, p_request_nonce BYTEA, p_trust_digest BYTEA
)
RETURNS BIGINT
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT (pg_catalog.get_byte(digest, 0)::BIGINT << 42) | (pg_catalog.get_byte(digest, 1)::BIGINT << 34)
        | (pg_catalog.get_byte(digest, 2)::BIGINT << 26) | (pg_catalog.get_byte(digest, 3)::BIGINT << 18)
        | (pg_catalog.get_byte(digest, 4)::BIGINT << 10) | (pg_catalog.get_byte(digest, 5)::BIGINT << 2)
        | (pg_catalog.get_byte(digest, 6)::BIGINT >> 6)
    FROM (SELECT pg_catalog.sha256(pg_catalog.convert_to('meshtransit/kube-join-code/v2', 'UTF8')
        || pg_catalog.decode('00', 'hex') || p_machine_key || p_node_key
        || pg_catalog.uuid_send(p_cluster_public_id) || p_request_nonce || p_trust_digest) AS digest) AS computed
$function$;

REVOKE ALL ON FUNCTION mesh_ops.kubernetes_trust_digest_v1(TEXT, BYTEA, TEXT, TEXT, TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_join_code_v2(BYTEA, BYTEA, UUID, BYTEA, BYTEA) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_issuer_is_valid_v1(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_name_is_valid_v1(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_namespace_is_valid_v1(TEXT) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_thumbprints_are_valid_v1(BYTEA[]) FROM PUBLIC;

-- A replica's trust as its pod sent it at join (design §6.3). Requests opened
-- before 232, or by an older Core, are code_version 1 and carry none.
ALTER TABLE mesh.kubernetes_replica_request
    ADD COLUMN code_version SMALLINT NOT NULL DEFAULT 1,
    ADD COLUMN sa_issuer TEXT,
    ADD COLUMN sa_jwks BYTEA,
    ADD COLUMN sa_key_thumbprints BYTEA[],
    ADD COLUMN sa_namespace TEXT,
    ADD COLUMN sa_service_account TEXT,
    ADD COLUMN sa_statefulset TEXT,
    ADD COLUMN sa_pod_name TEXT,
    ADD COLUMN sa_join_key_thumbprint BYTEA,
    ADD COLUMN sa_digest BYTEA;
ALTER TABLE mesh.kubernetes_replica_request
    -- COALESCE: a CHECK passes on NULL, and a NULL trust column would make
    -- the version 2 branch NULL rather than false.
    ADD CONSTRAINT kubernetes_replica_request_trust_check CHECK (COALESCE(
        (code_version = 1 AND sa_issuer IS NULL AND sa_jwks IS NULL AND sa_key_thumbprints IS NULL
            AND sa_namespace IS NULL AND sa_service_account IS NULL AND sa_statefulset IS NULL
            AND sa_pod_name IS NULL AND sa_join_key_thumbprint IS NULL AND sa_digest IS NULL)
        OR (code_version = 2
            AND mesh_ops.kubernetes_issuer_is_valid_v1(sa_issuer)
            AND pg_catalog.octet_length(sa_jwks) BETWEEN 2 AND 16384
            AND mesh_ops.kubernetes_thumbprints_are_valid_v1(sa_key_thumbprints)
            AND mesh_ops.kubernetes_namespace_is_valid_v1(sa_namespace)
            AND mesh_ops.kubernetes_name_is_valid_v1(sa_service_account)
            AND mesh_ops.kubernetes_name_is_valid_v1(sa_statefulset)
            AND mesh_ops.kubernetes_name_is_valid_v1(sa_pod_name)
            AND pg_catalog.starts_with(sa_pod_name, sa_statefulset || '-')
            AND pg_catalog.substr(sa_pod_name, pg_catalog.length(sa_statefulset) + 2) ~ '^(0|[1-9][0-9]*)$'
            AND pg_catalog.octet_length(sa_join_key_thumbprint) = 32
            AND sa_join_key_thumbprint = ANY (sa_key_thumbprints)
            -- The digest the code binds is exactly the stored trust's.
            AND sa_digest = mesh_ops.kubernetes_trust_digest_v1(sa_issuer, sa_jwks, sa_namespace,
                sa_service_account, sa_pod_name)), FALSE)
    ) NOT VALID;
ALTER TABLE mesh.kubernetes_replica_request VALIDATE CONSTRAINT kubernetes_replica_request_trust_check;
-- Each gateway Device has exactly one completed request, which names its
-- pod (design §6.5).
CREATE UNIQUE INDEX kubernetes_replica_request_device_uidx
    ON mesh.kubernetes_replica_request (device_id) WHERE device_id IS NOT NULL;
CREATE INDEX kubernetes_replica_request_pod_idx
    ON mesh.kubernetes_replica_request (kubernetes_cluster_id, sa_pod_name)
    WHERE sa_pod_name IS NOT NULL AND state IN ('approved', 'completed');

-- Schema 224's transition guard, with the trust columns immutable too. They
-- are nullable, so they compare with IS DISTINCT FROM: <> would let NULL turn
-- into a value.
CREATE OR REPLACE FUNCTION mesh_ops.enforce_kubernetes_replica_request_transition_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'replica requests are never removed';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'pending' OR NEW.version <> 1 OR NEW.failed_code_attempts <> 0 THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid new replica request';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.public_id <> OLD.public_id OR NEW.workspace_id <> OLD.workspace_id
        OR NEW.network_id <> OLD.network_id OR NEW.kubernetes_cluster_id <> OLD.kubernetes_cluster_id
        OR NEW.enrollment_credential_id <> OLD.enrollment_credential_id
        OR NEW.machine_key <> OLD.machine_key OR NEW.node_key <> OLD.node_key
        OR NEW.node_key_fingerprint <> OLD.node_key_fingerprint OR NEW.hostname <> OLD.hostname
        OR NEW.machine_key_fingerprint <> OLD.machine_key_fingerprint OR NEW.reported <> OLD.reported
        -- Schema 232: the trust the pod sent never changes.
        OR NEW.code_version IS DISTINCT FROM OLD.code_version
        OR NEW.sa_issuer IS DISTINCT FROM OLD.sa_issuer OR NEW.sa_jwks IS DISTINCT FROM OLD.sa_jwks
        OR NEW.sa_key_thumbprints IS DISTINCT FROM OLD.sa_key_thumbprints
        OR NEW.sa_namespace IS DISTINCT FROM OLD.sa_namespace
        OR NEW.sa_service_account IS DISTINCT FROM OLD.sa_service_account
        OR NEW.sa_statefulset IS DISTINCT FROM OLD.sa_statefulset
        OR NEW.sa_pod_name IS DISTINCT FROM OLD.sa_pod_name
        OR NEW.sa_join_key_thumbprint IS DISTINCT FROM OLD.sa_join_key_thumbprint
        OR NEW.sa_digest IS DISTINCT FROM OLD.sa_digest
        -- What an approval set never changes afterwards.
        OR (OLD.approved_at IS NOT NULL AND (
            NEW.approved_at IS DISTINCT FROM OLD.approved_at
            OR NEW.approved_by_principal_id IS DISTINCT FROM OLD.approved_by_principal_id
            OR NEW.completion_deadline IS DISTINCT FROM OLD.completion_deadline
            OR NEW.reserved_ordinal IS DISTINCT FROM OLD.reserved_ordinal
            OR NEW.reserved_hostname IS DISTINCT FROM OLD.reserved_hostname))
        -- A request expires only past its deadline.
        OR (NEW.state = 'expired' AND OLD.state = 'pending'
            AND OLD.expires_at > pg_catalog.transaction_timestamp())
        OR (NEW.state = 'expired' AND OLD.state = 'approved'
            AND OLD.completion_deadline > pg_catalog.transaction_timestamp())
        OR NEW.request_nonce <> OLD.request_nonce OR NEW.expires_at <> OLD.expires_at
        OR NEW.created_at <> OLD.created_at OR NEW.version <> OLD.version + 1
        OR NEW.failed_code_attempts < OLD.failed_code_attempts
        OR NOT (
            (OLD.state = 'pending' AND NEW.state IN ('pending', 'approved', 'rejected', 'cancelled', 'expired'))
            OR (OLD.state = 'approved' AND NEW.state IN ('completed', 'cancelled', 'expired'))
        ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid replica request transition';
    END IF;
    RETURN NEW;
END;
$function$;

-- A cluster's signing trust (design §5.1): one row per cluster, apart from
-- the cluster row so that setting it never bumps the cluster's version.
-- Written only by definer functions: a replica's approval (schema 232) or an
-- administrator's paste (K1.1b).
CREATE TABLE mesh.kubernetes_cluster_signing_trust (
    kubernetes_cluster_id BIGINT PRIMARY KEY,
    -- Names the trust in the authority journal; a new one at every set.
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'pinned' CHECK (mode = 'pinned'),
    issuer TEXT NOT NULL CHECK (mesh_ops.kubernetes_issuer_is_valid_v1(issuer)),
    jwks BYTEA NOT NULL CHECK (pg_catalog.octet_length(jwks) BETWEEN 2 AND 16384),
    key_thumbprints BYTEA[] NOT NULL CHECK (mesh_ops.kubernetes_thumbprints_are_valid_v1(key_thumbprints)),
    namespace TEXT NOT NULL CHECK (mesh_ops.kubernetes_namespace_is_valid_v1(namespace)),
    service_account TEXT NOT NULL CHECK (mesh_ops.kubernetes_name_is_valid_v1(service_account)),
    statefulset TEXT NOT NULL CHECK (mesh_ops.kubernetes_name_is_valid_v1(statefulset)),
    version BIGINT NOT NULL CHECK (version > 0),
    source TEXT NOT NULL CHECK (source IN ('replica_approval', 'admin_paste')),
    source_request_id BIGINT,
    set_by_principal_id BIGINT NOT NULL,
    set_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT kubernetes_cluster_signing_trust_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT kubernetes_cluster_signing_trust_source_request_check CHECK (
        (source = 'replica_approval') = (source_request_id IS NOT NULL)
    ),
    CONSTRAINT kubernetes_cluster_signing_trust_cluster_fk FOREIGN KEY (workspace_id, network_id, kubernetes_cluster_id)
        REFERENCES mesh.kubernetes_cluster (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT kubernetes_cluster_signing_trust_request_fk FOREIGN KEY (workspace_id, network_id, source_request_id)
        REFERENCES mesh.kubernetes_replica_request (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT kubernetes_cluster_signing_trust_principal_fk FOREIGN KEY (set_by_principal_id)
        REFERENCES mesh.principal (id) ON DELETE RESTRICT
);
ALTER TABLE mesh.kubernetes_cluster_signing_trust ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.kubernetes_cluster_signing_trust FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_cluster_signing_trust_migrator_policy ON mesh.kubernetes_cluster_signing_trust
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.kubernetes_cluster_signing_trust
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER kubernetes_cluster_signing_trust_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.kubernetes_cluster_signing_trust
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('kubernetes_cluster_signing_trust', 'public_id');

-- One use of a verified token (design §7.5): per cluster, jti, purpose and
-- the key the rotation replaces (the machine key's fingerprint, or the node
-- key itself). xact_id names the transaction that used it, which the epoch
-- trigger below requires to be its own.
CREATE TABLE mesh_ops.kubernetes_gateway_token_use (
    kubernetes_cluster_id BIGINT NOT NULL,
    jti TEXT NOT NULL CHECK (pg_catalog.octet_length(jti) BETWEEN 1 AND 128 AND jti ~ '^[!-~]+$'),
    purpose TEXT NOT NULL CHECK (purpose IN ('machine_key', 'node_key')),
    replaced_key BYTEA NOT NULL CHECK (pg_catalog.octet_length(replaced_key) = 32),
    device_id BIGINT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    xact_id XID8 NOT NULL,
    used_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (kubernetes_cluster_id, jti, purpose, replaced_key)
);
CREATE INDEX kubernetes_gateway_token_use_xact_idx
    ON mesh_ops.kubernetes_gateway_token_use (device_id, purpose, xact_id);
CREATE INDEX kubernetes_gateway_token_use_expiry_idx ON mesh_ops.kubernetes_gateway_token_use (expires_at);
ALTER TABLE mesh_ops.kubernetes_gateway_token_use ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.kubernetes_gateway_token_use FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_gateway_token_use_migrator_policy ON mesh_ops.kubernetes_gateway_token_use
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh_ops.kubernetes_gateway_token_use
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- K11-I1: a gateway Device's second and later key epochs, of either kind,
-- enter only in a transaction that recorded a verified token for that Device
-- and kind. Epoch 1 is the join's (one per Device and kind, by the epoch
-- tables' unique keys). The trigger runs as its owner, so neither the
-- caller's row security nor its settings change what it sees.
CREATE FUNCTION mesh_ops.require_kubernetes_gateway_rotation_token_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_purpose TEXT := TG_ARGV[0];
    v_kind TEXT;
BEGIN
    IF NEW.epoch = 1 THEN
        RETURN NEW;
    END IF;
    SELECT device.kind INTO v_kind FROM mesh.device AS device WHERE device.id = NEW.device_id;
    IF v_kind IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'a key epoch names no Device';
    END IF;
    IF v_kind <> 'kubernetes_gateway' THEN
        RETURN NEW;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM mesh_ops.kubernetes_gateway_token_use AS use
        WHERE use.device_id = NEW.device_id AND use.purpose = v_purpose
          AND use.xact_id = pg_catalog.pg_current_xact_id()
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK19', MESSAGE = 'a gateway key rotation needs a verified pod token';
    END IF;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.require_kubernetes_gateway_rotation_token_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE TRIGGER device_machine_key_epoch_gateway_token
BEFORE INSERT ON mesh.device_machine_key_epoch
FOR EACH ROW EXECUTE FUNCTION mesh_ops.require_kubernetes_gateway_rotation_token_v1('machine_key');
CREATE TRIGGER device_node_key_epoch_gateway_token
BEFORE INSERT ON mesh.device_node_key_epoch
FOR EACH ROW EXECUTE FUNCTION mesh_ops.require_kubernetes_gateway_rotation_token_v1('node_key');

-- What a gateway's rotation token must match (design §8.3): the gateway the
-- session proved (schema 226's mark, in this transaction), its cluster's
-- trust and the pod its join named. No row: not a proven gateway session.
-- Trust or pod NULL: the cluster has no trust, or the Device joined before
-- 232; Core refuses its rotations (trust_missing).
CREATE FUNCTION mesh_ops.read_kubernetes_gateway_rotation_trust_v1(p_machine_fingerprint BYTEA, p_node_key BYTEA)
RETURNS TABLE (
    device_public_id UUID, cluster_public_id UUID, trust_version BIGINT, issuer TEXT, jwks BYTEA,
    namespace TEXT, service_account TEXT, pod_name TEXT
)
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT device.public_id, cluster.public_id, trust.version, trust.issuer, trust.jwks,
        trust.namespace, trust.service_account, request.sa_pod_name
    FROM mesh.device AS device
    JOIN mesh.device_machine_key_epoch AS machine
      ON machine.workspace_id = device.workspace_id AND machine.network_id = device.network_id
     AND machine.device_id = device.id AND machine.epoch = device.current_machine_key_epoch
    JOIN mesh.device_node_key_epoch AS node_key
      ON node_key.workspace_id = device.workspace_id AND node_key.network_id = device.network_id
     AND node_key.device_id = device.id AND node_key.epoch = device.current_node_key_epoch
    JOIN mesh.kubernetes_cluster AS cluster
      ON cluster.workspace_id = device.workspace_id AND cluster.network_id = device.network_id
     AND cluster.id = device.kubernetes_cluster_id AND cluster.state = 'active'
    LEFT JOIN mesh.kubernetes_cluster_signing_trust AS trust ON trust.kubernetes_cluster_id = cluster.id
    LEFT JOIN mesh.kubernetes_replica_request AS request
      ON request.device_id = device.id AND request.state = 'completed'
    WHERE p_machine_fingerprint IS NOT NULL AND pg_catalog.octet_length(p_machine_fingerprint) = 32
      AND p_node_key IS NOT NULL AND pg_catalog.octet_length(p_node_key) = 32
      AND mesh_ops.session_proven_node_key_matches_v1(p_machine_fingerprint, p_node_key)
      AND machine.fingerprint = p_machine_fingerprint AND machine.state = 'active'
      AND node_key.public_key = p_node_key AND node_key.state = 'active'
      AND device.kind = 'kubernetes_gateway' AND device.state = 'active' AND device.deleted_at IS NULL
      AND device.expires_at > pg_catalog.transaction_timestamp()
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_kubernetes_gateway_rotation_trust_v1(BYTEA, BYTEA)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_kubernetes_gateway_rotation_trust_v1(BYTEA, BYTEA) TO mesh_runtime;

-- Records one use of a verified token for a rotation of the gateway the
-- session proved, in the transaction's Network (design §8.4). The replaced
-- key is the machine key's fingerprint or the current node key. Lock order:
-- the caller holds the Network revision; then the Device (FOR UPDATE, again
-- if the caller holds it), the trust (FOR SHARE), the use.
CREATE FUNCTION mesh_ops.consume_kubernetes_gateway_rotation_token_v1(
    p_device_public_id UUID, p_machine_fingerprint BYTEA, p_node_key BYTEA, p_purpose TEXT,
    p_trust_version BIGINT, p_jti TEXT, p_expires_at TIMESTAMPTZ
)
RETURNS VOID
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_device mesh.device%ROWTYPE;
    v_trust mesh.kubernetes_cluster_signing_trust%ROWTYPE;
    v_replaced BYTEA;
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_device_public_id IS NULL OR p_machine_fingerprint IS NULL
        OR pg_catalog.octet_length(p_machine_fingerprint) <> 32
        OR p_node_key IS NULL OR pg_catalog.octet_length(p_node_key) <> 32
        OR p_purpose IS NULL OR p_purpose NOT IN ('machine_key', 'node_key')
        OR p_trust_version IS NULL OR p_trust_version < 1
        OR p_jti IS NULL OR pg_catalog.octet_length(p_jti) NOT BETWEEN 1 AND 128 OR p_jti !~ '^[!-~]+$'
        OR p_expires_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'gateway rotation token is invalid';
    END IF;
    IF NOT mesh_ops.session_proven_node_key_matches_v1(p_machine_fingerprint, p_node_key) THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'no proven gateway session';
    END IF;
    SELECT device.* INTO v_device
    FROM mesh.device AS device
    JOIN mesh.device_machine_key_epoch AS machine
      ON machine.workspace_id = device.workspace_id AND machine.network_id = device.network_id
     AND machine.device_id = device.id AND machine.epoch = device.current_machine_key_epoch
    JOIN mesh.device_node_key_epoch AS node_key
      ON node_key.workspace_id = device.workspace_id AND node_key.network_id = device.network_id
     AND node_key.device_id = device.id AND node_key.epoch = device.current_node_key_epoch
    WHERE device.workspace_id = v_workspace AND device.network_id = v_network
      AND device.public_id = p_device_public_id
      AND machine.fingerprint = p_machine_fingerprint AND machine.state = 'active'
      AND node_key.public_key = p_node_key AND node_key.state = 'active'
      AND device.kind = 'kubernetes_gateway' AND device.state = 'active' AND device.deleted_at IS NULL
      AND device.expires_at > v_now
    FOR UPDATE OF device;
    IF v_device.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'no proven gateway session';
    END IF;
    -- The pod the Device's join named, and the trust the token was checked
    -- against, both still as Core read them.
    SELECT trust.* INTO v_trust
    FROM mesh.kubernetes_cluster_signing_trust AS trust
    WHERE trust.kubernetes_cluster_id = v_device.kubernetes_cluster_id
      AND trust.workspace_id = v_workspace AND trust.network_id = v_network
    FOR SHARE OF trust;
    IF v_trust.kubernetes_cluster_id IS NULL OR v_trust.version <> p_trust_version
        OR NOT EXISTS (SELECT 1 FROM mesh.kubernetes_replica_request AS request
                       WHERE request.device_id = v_device.id AND request.state = 'completed'
                         AND request.sa_pod_name IS NOT NULL) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK18', MESSAGE = 'the cluster''s signing trust changed or is missing';
    END IF;
    -- Core checked the token by its own clock; the database checks again by
    -- its own, so skew between them opens no replay window (design §7.5).
    IF p_expires_at <= v_now OR p_expires_at > v_now + INTERVAL '15 minutes 30 seconds' THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK20', MESSAGE = 'the gateway token is not valid now';
    END IF;
    v_replaced := CASE p_purpose WHEN 'machine_key' THEN p_machine_fingerprint ELSE p_node_key END;
    INSERT INTO mesh_ops.kubernetes_gateway_token_use (
        kubernetes_cluster_id, jti, purpose, replaced_key, device_id, expires_at, xact_id, used_at
    ) VALUES (
        v_device.kubernetes_cluster_id, p_jti, p_purpose, v_replaced, v_device.id, p_expires_at,
        pg_catalog.pg_current_xact_id(), v_now
    )
    ON CONFLICT DO NOTHING;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK17', MESSAGE = 'the gateway token was used for this key';
    END IF;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.consume_kubernetes_gateway_rotation_token_v1(
    UUID, BYTEA, BYTEA, TEXT, BIGINT, TEXT, TIMESTAMPTZ)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.consume_kubernetes_gateway_rotation_token_v1(
    UUID, BYTEA, BYTEA, TEXT, BIGINT, TEXT, TIMESTAMPTZ) TO mesh_runtime;

-- Schema 227's rotation with a verified token: the token's use is recorded
-- first, under the Device lock, so the epoch trigger admits the new key.
-- Same outputs and errors as v1, plus consume's. A rotation past the budget
-- returns limited_until and the caller rolls back, the use with it.
CREATE FUNCTION mesh_ops.rotate_kubernetes_gateway_machine_key_v2(
    p_machine_fingerprint BYTEA, p_node_key BYTEA, p_new_machine_key BYTEA, p_new_fingerprint BYTEA,
    p_epoch_public_id UUID, p_change_public_id UUID,
    p_device_public_id UUID, p_trust_version BIGINT, p_jti TEXT, p_expires_at TIMESTAMPTZ
)
RETURNS TABLE (
    device_public_id UUID, previous_device_version BIGINT, device_version BIGINT,
    machine_key_epoch BIGINT, session_generation BIGINT, limited_until TIMESTAMPTZ
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    PERFORM mesh_ops.consume_kubernetes_gateway_rotation_token_v1(p_device_public_id, p_machine_fingerprint,
        p_node_key, 'machine_key', p_trust_version, p_jti, p_expires_at);
    RETURN QUERY SELECT * FROM mesh_ops.rotate_kubernetes_gateway_machine_key_v1(p_machine_fingerprint,
        p_node_key, p_new_machine_key, p_new_fingerprint, p_epoch_public_id, p_change_public_id);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.rotate_kubernetes_gateway_machine_key_v2(
    BYTEA, BYTEA, BYTEA, BYTEA, UUID, UUID, UUID, BIGINT, TEXT, TIMESTAMPTZ)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.rotate_kubernetes_gateway_machine_key_v2(
    BYTEA, BYTEA, BYTEA, BYTEA, UUID, UUID, UUID, BIGINT, TEXT, TIMESTAMPTZ) TO mesh_runtime;

-- Removes uses whose token expired more than five minutes ago, oldest first,
-- at most p_limit, in one installation: an expired token is refused anyway,
-- and the margin covers clock skew between Core and the database.
CREATE FUNCTION mesh_ops.prune_kubernetes_gateway_token_uses_v1(p_deployment_public_id UUID, p_limit INTEGER)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_deployment_id BIGINT;
    v_removed INTEGER;
BEGIN
    IF p_deployment_public_id IS NULL OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 10000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes gateway token retention input';
    END IF;
    SELECT deployment.id INTO v_deployment_id
    FROM mesh.deployment AS deployment
    WHERE deployment.installation_public_id = p_deployment_public_id;
    IF v_deployment_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Kubernetes gateway token installation is unavailable';
    END IF;
    -- Workspaces are visible to the owner only while the scan is on (schema
    -- 134), as for schema 229's pruning.
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    WITH doomed AS (
        SELECT use.kubernetes_cluster_id, use.jti, use.purpose, use.replaced_key
        FROM mesh_ops.kubernetes_gateway_token_use AS use
        JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = use.kubernetes_cluster_id
        JOIN mesh.workspace AS workspace ON workspace.id = cluster.workspace_id
        WHERE workspace.deployment_id = v_deployment_id
          AND use.expires_at < pg_catalog.clock_timestamp() - INTERVAL '5 minutes'
        ORDER BY use.expires_at
        LIMIT p_limit
    )
    DELETE FROM mesh_ops.kubernetes_gateway_token_use AS use
    USING doomed
    WHERE use.kubernetes_cluster_id = doomed.kubernetes_cluster_id AND use.jti = doomed.jti
      AND use.purpose = doomed.purpose AND use.replaced_key = doomed.replaced_key;
    GET DIAGNOSTICS v_removed = ROW_COUNT;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', '', TRUE);
    RETURN v_removed;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.prune_kubernetes_gateway_token_uses_v1(UUID, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.prune_kubernetes_gateway_token_uses_v1(UUID, INTEGER) TO mesh_worker;

-- ---- Join v2 (design §6) ----

-- Opens a replica's request with the trust its pod sent (schema 225's v1
-- plus trust). The same keys asking again get their request back with
-- trust_conflict when it is waiting or approved and holds other signing
-- material, so Core answers CONFLICT with the request's nonce; a completed
-- request is never a conflict (its Device reconnects after the cluster's
-- keys rotated); a request without trust still waiting
-- is cancelled and a new one opened. Errors as v1.
CREATE FUNCTION mesh_ops.open_kubernetes_replica_request_v2(
    p_credential_public_id UUID, p_request_public_id UUID, p_machine_key BYTEA,
    p_machine_key_fingerprint BYTEA, p_node_key BYTEA, p_node_key_fingerprint BYTEA, p_hostname TEXT,
    p_reported JSONB, p_request_nonce BYTEA, p_change_public_id UUID,
    p_sa_issuer TEXT, p_sa_jwks BYTEA, p_sa_key_thumbprints BYTEA[], p_sa_namespace TEXT,
    p_sa_service_account TEXT, p_sa_statefulset TEXT, p_sa_pod_name TEXT, p_sa_join_key_thumbprint BYTEA,
    p_sa_digest BYTEA
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_credential mesh.enrollment_credential%ROWTYPE;
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_epoch BIGINT;
    v_request mesh.kubernetes_replica_request%ROWTYPE;
    v_waiting BIGINT;
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_credential_public_id IS NULL OR p_request_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_request_public_id), 6) >> 4 <> 7
        OR p_machine_key IS NULL OR p_machine_key_fingerprint IS NULL OR p_node_key IS NULL
        OR p_node_key_fingerprint IS NULL
        OR p_hostname IS NULL OR p_reported IS NULL OR p_request_nonce IS NULL
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR p_sa_digest IS NULL OR pg_catalog.octet_length(p_sa_digest) <> 32 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'replica request is invalid';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    SELECT credential.* INTO v_credential FROM mesh.enrollment_credential AS credential
    WHERE credential.workspace_id = v_workspace AND credential.network_id = v_network
      AND credential.public_id = p_credential_public_id
    FOR UPDATE;
    SELECT cluster.* INTO v_cluster FROM mesh.kubernetes_cluster AS cluster
    JOIN mesh.enrollment_profile AS profile ON profile.kubernetes_cluster_id = cluster.id
    WHERE profile.id = v_credential.enrollment_profile_id AND profile.device_kind = 'kubernetes_gateway'
      AND profile.deleted_at IS NULL AND cluster.state = 'active';
    SELECT deployment.recovery_epoch INTO v_epoch FROM mesh.workspace AS workspace
    JOIN mesh.deployment AS deployment ON deployment.id = workspace.deployment_id
    WHERE workspace.id = v_workspace;
    -- The same replica asking again gets its request back whatever its key
    -- has become since, waiting, approved or completed: approvals consume
    -- the key's uses, and a reconnecting replica must still find its way.
    IF v_credential.id IS NOT NULL THEN
        PERFORM mesh_ops.expire_kubernetes_replica_requests_internal_v1(
            v_credential.id, NULL, p_machine_key_fingerprint, p_node_key);
        SELECT request.* INTO v_request FROM mesh.kubernetes_replica_request AS request
        WHERE request.machine_key_fingerprint = p_machine_key_fingerprint
          AND request.enrollment_credential_id = v_credential.id
          AND request.state IN ('pending', 'approved', 'completed')
        ORDER BY request.id DESC
        LIMIT 1;
        IF FOUND AND v_request.node_key = p_node_key AND v_request.machine_key = p_machine_key THEN
            -- Schema 232: a request opened without trust, still waiting, is
            -- cancelled and the replica opens one with trust. Any other comes
            -- back, saying whether it holds other signing material.
            IF v_request.code_version = 1 AND v_request.state = 'pending' THEN
                UPDATE mesh.kubernetes_replica_request AS request
                SET state = 'cancelled', version = request.version + 1,
                    updated_at = GREATEST(v_now, request.updated_at)
                WHERE request.id = v_request.id AND request.state = 'pending';
            ELSE
                RETURN pg_catalog.jsonb_build_object(
                    'created', FALSE,
                    'trust_conflict', v_request.code_version = 2 AND v_request.sa_digest <> p_sa_digest
                        AND v_request.state IN ('pending', 'approved'),
                    'request', mesh_ops.kubernetes_replica_request_document_internal_v1(v_request),
                    'request_nonce', pg_catalog.encode(v_request.request_nonce, 'hex')
                );
            END IF;
        END IF;
        v_request := NULL;
    END IF;
    IF v_credential.id IS NULL OR v_cluster.id IS NULL OR v_credential.state <> 'active'
        OR v_credential.issued_recovery_epoch IS DISTINCT FROM v_epoch
        OR v_credential.valid_from > v_now OR v_credential.expires_at <= v_now
        OR v_credential.used_count >= v_credential.max_uses THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK04', MESSAGE = 'the join key is not usable';
    END IF;
    -- Past-deadline requests of this key, or holding these keys under
    -- another key, are moved to expired first. Those other requests are
    -- taken out of the usual lock order; a deadlock with another key's
    -- approval is possible only over two stale rows, and PostgreSQL resolves
    -- it (40P01, a conflict the caller retries).
    PERFORM mesh_ops.expire_kubernetes_replica_requests_internal_v1(
        v_credential.id, NULL, p_machine_key_fingerprint, p_node_key);

    SELECT request.* INTO v_request FROM mesh.kubernetes_replica_request AS request
    WHERE request.machine_key_fingerprint = p_machine_key_fingerprint
      AND request.state IN ('pending', 'approved');
    IF FOUND THEN
        IF v_request.node_key <> p_node_key OR v_request.enrollment_credential_id <> v_credential.id
            OR v_request.machine_key <> p_machine_key THEN
            RAISE EXCEPTION USING ERRCODE = 'MTK06', MESSAGE = 'the keys are already in use';
        END IF;
        IF v_request.code_version = 1 AND v_request.state = 'pending' THEN
            UPDATE mesh.kubernetes_replica_request AS request
            SET state = 'cancelled', version = request.version + 1,
                updated_at = GREATEST(v_now, request.updated_at)
            WHERE request.id = v_request.id AND request.state = 'pending';
        ELSE
            RETURN pg_catalog.jsonb_build_object(
                'created', FALSE,
                'trust_conflict', v_request.code_version = 2 AND v_request.sa_digest <> p_sa_digest
                    AND v_request.state IN ('pending', 'approved'),
                'request', mesh_ops.kubernetes_replica_request_document_internal_v1(v_request),
                'request_nonce', pg_catalog.encode(v_request.request_nonce, 'hex')
            );
        END IF;
    END IF;
    IF EXISTS (SELECT 1 FROM mesh.device_machine_key_epoch AS epoch
               WHERE epoch.fingerprint = p_machine_key_fingerprint)
        OR EXISTS (SELECT 1 FROM mesh.device_node_key_epoch AS epoch WHERE epoch.public_key = p_node_key)
        OR EXISTS (SELECT 1 FROM mesh.kubernetes_replica_request AS request
                   WHERE request.node_key = p_node_key AND request.state IN ('pending', 'approved'))
        OR EXISTS (SELECT 1 FROM mesh.pending_registration AS pending
                   WHERE pending.state IN ('pending', 'authorized') AND pending.requested_node_key = p_node_key)
        OR EXISTS (SELECT 1 FROM mesh.pending_registration AS pending
                   WHERE pending.state IN ('pending', 'authorized')
                     AND pending.machine_key_fingerprint = p_machine_key_fingerprint)
        OR EXISTS (SELECT 1 FROM mesh.browser_registration_intent AS intent
                   WHERE intent.state IN ('pending', 'approved') AND intent.requested_node_key = p_node_key)
        OR EXISTS (SELECT 1 FROM mesh.browser_registration_intent AS intent
                   JOIN mesh.workspace AS workspace ON workspace.deployment_id = intent.deployment_id
                   WHERE workspace.id = v_workspace AND intent.state IN ('pending', 'approved')
                     AND intent.machine_key_fingerprint = p_machine_key_fingerprint) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK06', MESSAGE = 'the keys are already in use';
    END IF;
    SELECT pg_catalog.count(*) INTO v_waiting FROM mesh.kubernetes_replica_request AS request
    WHERE request.enrollment_credential_id = v_credential.id AND request.state = 'pending';
    IF v_waiting >= 2 * v_credential.max_uses THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK03', MESSAGE = 'too many replicas are waiting for this join key';
    END IF;
    INSERT INTO mesh.kubernetes_replica_request (
        public_id, workspace_id, network_id, kubernetes_cluster_id, enrollment_credential_id,
        machine_key, machine_key_fingerprint, node_key, node_key_fingerprint, hostname, request_nonce, reported,
        expires_at, created_at, updated_at, code_version, sa_issuer, sa_jwks, sa_key_thumbprints, sa_namespace,
        sa_service_account, sa_statefulset, sa_pod_name, sa_join_key_thumbprint, sa_digest
    ) VALUES (
        p_request_public_id, v_workspace, v_network, v_cluster.id, v_credential.id,
        p_machine_key, p_machine_key_fingerprint, p_node_key, p_node_key_fingerprint, p_hostname, p_request_nonce,
        p_reported,
        v_credential.expires_at, v_now, v_now, 2, p_sa_issuer, p_sa_jwks, p_sa_key_thumbprints, p_sa_namespace,
        p_sa_service_account, p_sa_statefulset, p_sa_pod_name, p_sa_join_key_thumbprint, p_sa_digest
    ) RETURNING * INTO v_request;
    RETURN pg_catalog.jsonb_build_object(
        'created', TRUE,
        'trust_conflict', FALSE,
        'key_issuer_principal_id', (SELECT issuer.public_id FROM mesh.principal AS issuer
                                    WHERE issuer.id = v_credential.issuer_principal_id),
        'network_id', (SELECT network.public_id FROM mesh.network AS network
                       WHERE network.workspace_id = v_workspace AND network.id = v_network),
        'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(v_workspace, v_network),
        'request', mesh_ops.kubernetes_replica_request_document_internal_v1(v_request),
        'request_nonce', pg_catalog.encode(v_request.request_nonce, 'hex')
    );
END;
$function$;

-- Schema 224's lock for an approval, with the request's code version and
-- trust digest, which the code v2 binds.
CREATE FUNCTION mesh_ops.lock_kubernetes_replica_request_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_request_public_id UUID, p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_grant RECORD;
    v_request mesh.kubernetes_replica_request%ROWTYPE;
BEGIN
    IF p_cluster_public_id IS NULL OR p_request_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'replica request is invalid';
    END IF;
    -- Moving a request past its deadline to expired is a change too.
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    SELECT * INTO v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'kubernetes_cluster.approve');
    v_request := mesh_ops.lock_kubernetes_replica_request_internal_v1(
        v_grant.workspace_id, v_grant.network_id, p_cluster_public_id, p_request_public_id);
    RETURN pg_catalog.jsonb_build_object(
        'request', mesh_ops.kubernetes_replica_request_document_internal_v1(v_request),
        'machine_key', pg_catalog.encode(v_request.machine_key, 'hex'),
        'node_key', pg_catalog.encode(v_request.node_key, 'hex'),
        'request_nonce', pg_catalog.encode(v_request.request_nonce, 'hex'),
        'code_version', v_request.code_version,
        'trust_digest', pg_catalog.encode(v_request.sa_digest, 'hex')
    );
END;
$function$;

-- Approves a waiting request (schema 224's v1) after Go matched the code v2.
-- A request without trust is cancelled instead (outcome cancelled, as for an
-- unusable key). The first replica's trust becomes the cluster's; a later
-- one must match it (MTK15). A pod another live Device or approval holds is
-- refused (MTK16).
CREATE FUNCTION mesh_ops.approve_kubernetes_replica_request_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_request_public_id UUID, p_code BIGINT, p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_grant RECORD;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_before mesh.kubernetes_replica_request%ROWTYPE;
    v_request mesh.kubernetes_replica_request%ROWTYPE;
    v_credential mesh.enrollment_credential%ROWTYPE;
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_epoch BIGINT;
    v_ordinal SMALLINT;
    v_hostname TEXT;
    v_trust mesh.kubernetes_cluster_signing_trust%ROWTYPE;
    v_trust_set JSONB;
    v_trust_public_id UUID;
BEGIN
    IF p_cluster_public_id IS NULL OR p_request_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'replica request is invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'kubernetes_cluster.approve');
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    v_before := mesh_ops.lock_kubernetes_replica_request_internal_v1(
        v_grant.workspace_id, v_grant.network_id, p_cluster_public_id, p_request_public_id);
    IF v_before.state <> 'pending' THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK02', MESSAGE = 'the replica request is not waiting';
    END IF;
    SELECT cluster.* INTO STRICT v_cluster FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.id = v_before.kubernetes_cluster_id;
    -- Schema 232: a request opened without trust is cancelled, never
    -- approved; the replica joins again with its signing keys.
    IF v_before.code_version = 1 THEN
        UPDATE mesh.kubernetes_replica_request AS request
        SET state = 'cancelled', version = request.version + 1, updated_at = GREATEST(v_now, request.updated_at)
        WHERE request.id = v_before.id
        RETURNING * INTO v_request;
        RETURN pg_catalog.jsonb_build_object(
            'outcome', 'cancelled',
            'network_id', p_network_public_id,
            'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(
                v_grant.workspace_id, v_grant.network_id),
            'before', mesh_ops.kubernetes_replica_request_document_internal_v1(v_before),
            'request', mesh_ops.kubernetes_replica_request_document_internal_v1(v_request),
            'authority', v_grant.authority
        );
    END IF;
    -- The code v2 is checked here too, not only by Core: it binds the keys,
    -- the cluster, the nonce and the trust digest (shared/kubejoin).
    IF p_code IS DISTINCT FROM mesh_ops.kubernetes_join_code_v2(v_before.machine_key, v_before.node_key,
        v_cluster.public_id, v_before.request_nonce, v_before.sa_digest) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK09', MESSAGE = 'the code does not match the request';
    END IF;
    SELECT credential.* INTO v_credential FROM mesh.enrollment_credential AS credential
    WHERE credential.id = v_before.enrollment_credential_id;
    SELECT deployment.recovery_epoch INTO v_epoch FROM mesh.deployment AS deployment
    WHERE deployment.id = v_grant.deployment_id;
    IF v_credential.state <> 'active' OR v_credential.expires_at <= v_now OR v_credential.valid_from > v_now
        OR v_credential.used_count >= v_credential.max_uses
        OR v_credential.issued_recovery_epoch IS DISTINCT FROM v_epoch THEN
        UPDATE mesh.kubernetes_replica_request AS request
        SET state = 'cancelled', version = request.version + 1, updated_at = GREATEST(v_now, request.updated_at)
        WHERE request.id = v_before.id
        RETURNING * INTO v_request;
        RETURN pg_catalog.jsonb_build_object(
            'outcome', 'cancelled',
            'network_id', p_network_public_id,
            'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(
                v_grant.workspace_id, v_grant.network_id),
            'before', mesh_ops.kubernetes_replica_request_document_internal_v1(v_before),
            'request', mesh_ops.kubernetes_replica_request_document_internal_v1(v_request),
            'authority', v_grant.authority
        );
    END IF;
    -- Requests of this cluster past their deadline expire first, so an
    -- approval that lapsed holds its pod no longer.
    PERFORM mesh_ops.expire_kubernetes_replica_requests_internal_v1(NULL, v_cluster.id, NULL, NULL);
    -- Schema 232: the first replica's trust becomes the cluster's; later
    -- replicas must match it (design §6.4). The cluster's row lock, taken
    -- above, orders approvals of one cluster, so the trust is only read.
    SELECT trust.* INTO v_trust FROM mesh.kubernetes_cluster_signing_trust AS trust
    WHERE trust.kubernetes_cluster_id = v_cluster.id
    FOR SHARE;
    IF v_trust.kubernetes_cluster_id IS NULL THEN
        v_trust_public_id := pg_catalog.uuidv7();
        INSERT INTO mesh.kubernetes_cluster_signing_trust (
            kubernetes_cluster_id, public_id, workspace_id, network_id, issuer, jwks, key_thumbprints, namespace,
            service_account, statefulset, version, source, source_request_id, set_by_principal_id, set_at
        ) VALUES (
            v_cluster.id, v_trust_public_id, v_cluster.workspace_id, v_cluster.network_id, v_before.sa_issuer,
            v_before.sa_jwks, v_before.sa_key_thumbprints, v_before.sa_namespace, v_before.sa_service_account,
            v_before.sa_statefulset, 1, 'replica_approval', v_before.id, v_grant.actor_id, v_now
        );
        -- What the approval anchored, for its audit event.
        v_trust_set := pg_catalog.jsonb_build_object(
            'trust_id', v_trust_public_id, 'version', 1, 'issuer', v_before.sa_issuer,
            'namespace', v_before.sa_namespace, 'service_account', v_before.sa_service_account,
            'statefulset', v_before.sa_statefulset,
            'key_thumbprints', pg_catalog.to_jsonb(ARRAY(
                SELECT pg_catalog.encode(thumbprint, 'hex')
                FROM pg_catalog.unnest(v_before.sa_key_thumbprints) AS thumbprint))
        );
    ELSIF v_trust.issuer <> v_before.sa_issuer OR v_trust.namespace <> v_before.sa_namespace
        OR v_trust.service_account <> v_before.sa_service_account
        OR v_trust.statefulset <> v_before.sa_statefulset
        OR NOT (v_before.sa_join_key_thumbprint = ANY (v_trust.key_thumbprints)) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK15', MESSAGE = 'the replica''s signing keys differ from the cluster''s';
    END IF;
    -- One Device per pod: none alive bound to it, and no other approval.
    IF EXISTS (SELECT 1 FROM mesh.kubernetes_replica_request AS other
               JOIN mesh.device AS device ON device.id = other.device_id
               WHERE other.kubernetes_cluster_id = v_cluster.id AND other.state = 'completed'
                 AND other.sa_pod_name = v_before.sa_pod_name AND device.deleted_at IS NULL)
        OR EXISTS (SELECT 1 FROM mesh.kubernetes_replica_request AS other
                   WHERE other.kubernetes_cluster_id = v_cluster.id AND other.state = 'approved'
                     AND other.completion_deadline > v_now
                     AND other.sa_pod_name = v_before.sa_pod_name AND other.id <> v_before.id) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK16', MESSAGE = 'a Device or an approval already holds this pod';
    END IF;
    -- Ordinals of one cluster are reserved under its row lock, taken above.
    SELECT candidate.ordinal INTO v_ordinal
    FROM pg_catalog.generate_series(0, 63) AS candidate(ordinal)
    WHERE NOT EXISTS (
        SELECT 1 FROM mesh.device AS device
        WHERE device.workspace_id = v_cluster.workspace_id AND device.network_id = v_cluster.network_id
          AND device.kubernetes_cluster_id = v_cluster.id AND device.deleted_at IS NULL
          AND device.kubernetes_ordinal = candidate.ordinal
    ) AND NOT EXISTS (
        SELECT 1 FROM mesh.kubernetes_replica_request AS request
        WHERE request.kubernetes_cluster_id = v_cluster.id AND request.state = 'approved'
          AND request.reserved_ordinal = candidate.ordinal
    )
    ORDER BY candidate.ordinal
    LIMIT 1;
    IF v_ordinal IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK07', MESSAGE = 'the Kubernetes cluster has 64 replicas';
    END IF;
    v_hostname := v_cluster.name || '-' || v_ordinal::TEXT;
    UPDATE mesh.enrollment_credential AS credential
    SET used_count = credential.used_count + 1, version = credential.version + 1,
        updated_at = GREATEST(v_now, credential.updated_at)
    WHERE credential.id = v_credential.id;
    UPDATE mesh.kubernetes_replica_request AS request
    SET state = 'approved', approved_by_principal_id = v_grant.actor_id, approved_at = v_now,
        completion_deadline = v_now + INTERVAL '15 minutes', reserved_ordinal = v_ordinal,
        reserved_hostname = v_hostname, version = request.version + 1,
        updated_at = GREATEST(v_now, request.updated_at)
    WHERE request.id = v_before.id
    RETURNING * INTO v_request;
    RETURN pg_catalog.jsonb_build_object(
        'outcome', 'approved',
        'trust_set', v_trust_set,
        'network_id', p_network_public_id,
        'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(v_grant.workspace_id, v_grant.network_id),
        'before', mesh_ops.kubernetes_replica_request_document_internal_v1(v_before),
        'request', mesh_ops.kubernetes_replica_request_document_internal_v1(v_request),
        'authority', v_grant.authority
    );
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.approve_kubernetes_replica_request_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_request_public_id UUID, p_code BIGINT, p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    -- Schema 232: approvals go through v2, which checks the code v2 and the
    -- trust; Core 231 approves nothing on this schema.
    RAISE EXCEPTION USING ERRCODE = 'MTK14', MESSAGE = 'the replica must join again with its signing keys';
END;
$function$;

CREATE OR REPLACE FUNCTION mesh_ops.complete_kubernetes_replica_request_v1(
    p_request_internal_id BIGINT, p_device_internal_id BIGINT, p_credential_use_public_id UUID,
    p_network_revision BIGINT, p_occurred_at TIMESTAMPTZ
)
RETURNS BOOLEAN
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_request mesh.kubernetes_replica_request%ROWTYPE;
    v_trusted mesh.kubernetes_replica_request%ROWTYPE;
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    IF p_request_internal_id IS NULL OR p_device_internal_id IS NULL OR p_credential_use_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_credential_use_public_id), 6) >> 4 <> 7
        OR p_network_revision IS NULL OR p_network_revision <= 0 OR p_occurred_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'replica completion is invalid';
    END IF;
    -- Schema 232: only a request with trust completes, and only while no
    -- other live Device holds its pod (the caller holds the cluster lock).
    SELECT request.* INTO v_trusted FROM mesh.kubernetes_replica_request AS request
    WHERE request.id = p_request_internal_id AND request.workspace_id = v_workspace
      AND request.network_id = v_network;
    IF v_trusted.code_version = 1 THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK14', MESSAGE = 'the replica must join again with its signing keys';
    END IF;
    IF EXISTS (SELECT 1 FROM mesh.kubernetes_replica_request AS other
               JOIN mesh.device AS device ON device.id = other.device_id
               WHERE other.kubernetes_cluster_id = v_trusted.kubernetes_cluster_id AND other.state = 'completed'
                 AND other.sa_pod_name = v_trusted.sa_pod_name AND device.deleted_at IS NULL) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK16', MESSAGE = 'a Device already holds this pod';
    END IF;
    UPDATE mesh.kubernetes_replica_request AS request
    SET state = 'completed', device_id = p_device_internal_id, completed_network_revision = p_network_revision,
        version = request.version + 1, updated_at = GREATEST(p_occurred_at, request.updated_at)
    FROM mesh.device AS device
    WHERE request.id = p_request_internal_id AND request.workspace_id = v_workspace
      AND request.network_id = v_network AND request.state = 'approved'
      AND device.workspace_id = v_workspace AND device.network_id = v_network
      AND device.id = p_device_internal_id AND device.kind = 'kubernetes_gateway'
      AND device.kubernetes_cluster_id = request.kubernetes_cluster_id
      AND device.kubernetes_ordinal = request.reserved_ordinal
    RETURNING request.* INTO v_request;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK10', MESSAGE = 'the replica request cannot complete';
    END IF;
    -- The Device holds exactly the keys the administrator's code bound.
    PERFORM 1 FROM mesh.device_machine_key_epoch AS epoch
    WHERE epoch.device_id = p_device_internal_id AND epoch.state = 'active'
      AND epoch.public_key = v_request.machine_key AND epoch.fingerprint = v_request.machine_key_fingerprint;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK10', MESSAGE = 'the Device does not hold the approved machine key';
    END IF;
    PERFORM 1 FROM mesh.device_node_key_epoch AS epoch
    WHERE epoch.device_id = p_device_internal_id AND epoch.state = 'active'
      AND epoch.public_key = v_request.node_key;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK10', MESSAGE = 'the Device does not hold the approved node key';
    END IF;
    -- Schema 226: a gateway's machine keys are never used again, by any
    -- gateway; its first one enters the history here.
    INSERT INTO mesh_ops.kubernetes_gateway_machine_key_history (fingerprint, device_id, created_at)
    VALUES (v_request.machine_key_fingerprint, p_device_internal_id, p_occurred_at)
    ON CONFLICT (fingerprint) DO NOTHING;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK10', MESSAGE = 'the machine key was used by a gateway before';
    END IF;
    INSERT INTO mesh.enrollment_credential_use (
        public_id, workspace_id, network_id, enrollment_credential_id, pending_registration_id,
        kubernetes_replica_request_id, device_id, machine_key_fingerprint, result, used_at, created_at
    ) VALUES (
        p_credential_use_public_id, v_workspace, v_network, v_request.enrollment_credential_id, NULL,
        v_request.id, p_device_internal_id, v_request.machine_key_fingerprint, 'created', p_occurred_at,
        p_occurred_at
    );
    RETURN TRUE;
END;
$function$;

-- Schema 224's wrong-code counter, unchanged, for Core 232: v1 below
-- refuses requests with trust, which Core 231 cannot check.
CREATE FUNCTION mesh_ops.record_kubernetes_join_code_failure_v2(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_request_public_id UUID, p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_grant RECORD;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_before mesh.kubernetes_replica_request%ROWTYPE;
    v_request mesh.kubernetes_replica_request%ROWTYPE;
BEGIN
    IF p_cluster_public_id IS NULL OR p_request_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'replica request is invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'kubernetes_cluster.approve');
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    v_before := mesh_ops.lock_kubernetes_replica_request_internal_v1(
        v_grant.workspace_id, v_grant.network_id, p_cluster_public_id, p_request_public_id);
    IF v_before.state <> 'pending' THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK02', MESSAGE = 'the replica request is not waiting';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    UPDATE mesh.kubernetes_replica_request AS request
    SET failed_code_attempts = request.failed_code_attempts + 1,
        state = CASE WHEN request.failed_code_attempts + 1 >= 5 THEN 'cancelled' ELSE request.state END,
        version = request.version + 1, updated_at = GREATEST(v_now, request.updated_at)
    WHERE request.id = v_before.id
    RETURNING * INTO v_request;
    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id,
        'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(v_grant.workspace_id, v_grant.network_id),
        'before', mesh_ops.kubernetes_replica_request_document_internal_v1(v_before),
        'request', mesh_ops.kubernetes_replica_request_document_internal_v1(v_request),
        'authority', v_grant.authority
    );
END;
$function$;

-- Schema 224's wrong-code counter, refusing a request with trust (Core 231
-- on this schema).
CREATE OR REPLACE FUNCTION mesh_ops.record_kubernetes_join_code_failure_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_request_public_id UUID, p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_grant RECORD;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_before mesh.kubernetes_replica_request%ROWTYPE;
    v_request mesh.kubernetes_replica_request%ROWTYPE;
BEGIN
    IF p_cluster_public_id IS NULL OR p_request_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'replica request is invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'kubernetes_cluster.approve');
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    v_before := mesh_ops.lock_kubernetes_replica_request_internal_v1(
        v_grant.workspace_id, v_grant.network_id, p_cluster_public_id, p_request_public_id);
    IF v_before.state <> 'pending' THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK02', MESSAGE = 'the replica request is not waiting';
    END IF;
    -- Schema 232: Core 231 compares a code v1, which never matches a request
    -- with trust; nothing is counted against it.
    IF v_before.code_version = 2 THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK14', MESSAGE = 'the replica request is approved with a code v2';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    UPDATE mesh.kubernetes_replica_request AS request
    SET failed_code_attempts = request.failed_code_attempts + 1,
        state = CASE WHEN request.failed_code_attempts + 1 >= 5 THEN 'cancelled' ELSE request.state END,
        version = request.version + 1, updated_at = GREATEST(v_now, request.updated_at)
    WHERE request.id = v_before.id
    RETURNING * INTO v_request;
    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id,
        'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(v_grant.workspace_id, v_grant.network_id),
        'before', mesh_ops.kubernetes_replica_request_document_internal_v1(v_before),
        'request', mesh_ops.kubernetes_replica_request_document_internal_v1(v_request),
        'authority', v_grant.authority
    );
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.open_kubernetes_replica_request_v2(
    UUID, UUID, BYTEA, BYTEA, BYTEA, BYTEA, TEXT, JSONB, BYTEA, UUID,
    TEXT, BYTEA, BYTEA[], TEXT, TEXT, TEXT, TEXT, BYTEA, BYTEA
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.open_kubernetes_replica_request_v2(
    UUID, UUID, BYTEA, BYTEA, BYTEA, BYTEA, TEXT, JSONB, BYTEA, UUID,
    TEXT, BYTEA, BYTEA[], TEXT, TEXT, TEXT, TEXT, BYTEA, BYTEA
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.lock_kubernetes_replica_request_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.lock_kubernetes_replica_request_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.approve_kubernetes_replica_request_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, BIGINT, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.approve_kubernetes_replica_request_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, BIGINT, UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.record_kubernetes_join_code_failure_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.record_kubernetes_join_code_failure_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, UUID
) TO mesh_runtime;
