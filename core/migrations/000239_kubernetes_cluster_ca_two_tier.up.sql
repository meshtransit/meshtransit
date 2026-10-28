-- Schema 239 (K1a4a a2, docs/k8s-k1a4-ca-quarantine-design.md §17, owner
-- decisions Q21–Q28): two CA tiers per Kubernetes cluster, data keys that
-- can be wrapped again and replaced, the DNS suffix as a database fact, and
-- worker heartbeats that say what the worker can do.
--
-- Schema 238 kept one CA tier with immutable data key wrappings. Nothing
-- has used those tables yet (no worker job before this step), so this
-- migration drops them and their functions and builds the two-tier model in
-- their place; it refuses to run if any row exists. The schedule, its
-- triggers and the work, schedule and postpone functions of 238 stay.
--
-- - A cluster has a root (ten years, rotated only when its key is
--   compromised, its name changes or it nears its end) that clients trust,
--   and an intermediate (30 days) that the root signs and that signs
--   replica certificates. Both carry the cluster's name constraint.
-- - Each Network has data keys; a data key has wrappings, one active. A
--   wrapping is replaced without touching the CAs (rewrap), and a data key
--   is replaced for new CAs while old CAs still open under the old one.
-- - The DNS suffix the worker names clusters under is recorded once per
--   installation; a worker configured with another suffix does no CA work.
-- - Every CA and data key change is one change with one sealed audit event
--   on the Network's stream, bound to the Network revision. An operator's
--   change names the operator and the change record (permission
--   system.operator); the worker's own is system.reconcile.

DO $guard$
BEGIN
    IF EXISTS (SELECT 1 FROM mesh.kubernetes_cluster_ca) OR EXISTS (SELECT 1 FROM mesh.kubernetes_ca_data_key) THEN
        RAISE EXCEPTION USING ERRCODE = '55000',
            MESSAGE = 'schema 239 rebuilds Kubernetes cluster CAs and needs schema 238 tables empty';
    END IF;
END;
$guard$;

DROP FUNCTION mesh_ops.lock_kubernetes_ca_network_v1(UUID, UUID, UUID);
DROP FUNCTION mesh_ops.add_kubernetes_ca_data_key_v1(UUID, UUID, UUID, UUID, TEXT, TEXT, BYTEA);
DROP FUNCTION mesh_ops.create_kubernetes_cluster_ca_v1(
    UUID, UUID, UUID, UUID, UUID, UUID, TEXT, TEXT, UUID, BYTEA, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, BYTEA);
DROP FUNCTION mesh_ops.move_kubernetes_cluster_ca_v1(UUID, UUID, UUID, UUID, UUID, BIGINT, TEXT, TEXT);
DROP FUNCTION mesh_ops.append_kubernetes_cluster_ca_evidence_v1(
    UUID, BIGINT, BIGINT, BYTEA, BYTEA, UUID, UUID, JSONB, BIGINT);
DROP FUNCTION mesh_ops.kubernetes_cluster_ca_proof_internal_v1(BIGINT, TEXT);
DROP FUNCTION mesh_ops.kubernetes_cluster_ca_payload_internal_v1(BIGINT);
DROP FUNCTION mesh_ops.kubernetes_cluster_ca_action_internal_v1(TEXT, TEXT);
DROP FUNCTION mesh_ops.beat_kubernetes_ca_worker_v1(UUID, UUID, BOOLEAN, TEXT, TEXT);
DROP TABLE mesh.kubernetes_cluster_ca;
DROP TABLE mesh.kubernetes_ca_data_key;
DROP FUNCTION mesh_ops.guard_kubernetes_ca_row_v1();

-- The DNS suffix of each installation, as the first worker that named a
-- cluster recorded it.
CREATE TABLE mesh_ops.kubernetes_ca_dns_suffix (
    deployment_id BIGINT PRIMARY KEY REFERENCES mesh.deployment (id) ON DELETE RESTRICT,
    -- At most 160 bytes, so the longest cluster name (60 + ".kube." + two
    -- 12-digit codes) still fits in 253.
    suffix TEXT NOT NULL CHECK (
        pg_catalog.octet_length(suffix) BETWEEN 3 AND 160
        AND suffix ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'
    ),
    recorded_at TIMESTAMPTZ NOT NULL
);

-- A Network's data keys. One is active and seals new CAs; a retired one
-- still opens the CAs it sealed until they retire.
CREATE TABLE mesh.kubernetes_ca_data_key (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active', 'retired')),
    -- What the last change was, which names its audit action.
    last_change TEXT NOT NULL CHECK (last_change IN ('created', 'rewrapped', 'retired')),
    created_at TIMESTAMPTZ NOT NULL,
    retired_at TIMESTAMPTZ,
    changed_by TEXT CHECK (pg_catalog.octet_length(changed_by) BETWEEN 1 AND 128 AND changed_by ~ '^[ -~]+$'),
    change_ref TEXT CHECK (pg_catalog.octet_length(change_ref) BETWEEN 1 AND 128 AND change_ref ~ '^[ -~]+$'),
    CONSTRAINT kubernetes_ca_data_key_retired_change_check CHECK (last_change <> 'retired' OR state = 'retired'),
    CONSTRAINT kubernetes_ca_data_key_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT kubernetes_ca_data_key_lifecycle_check CHECK (
        (state = 'active' AND retired_at IS NULL)
        OR (state = 'retired' AND retired_at IS NOT NULL AND retired_at >= created_at)
    ),
    CONSTRAINT kubernetes_ca_data_key_actor_check CHECK ((changed_by IS NULL) = (change_ref IS NULL)),
    CONSTRAINT kubernetes_ca_data_key_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    UNIQUE (workspace_id, network_id, id)
);
CREATE UNIQUE INDEX kubernetes_ca_data_key_active_idx
    ON mesh.kubernetes_ca_data_key (workspace_id, network_id) WHERE state = 'active';

-- A data key as a custody wrapped it. One wrapping of a key is active;
-- rewrapping adds one and retires the other.
CREATE TABLE mesh.kubernetes_ca_data_key_wrapping (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    data_key_id BIGINT NOT NULL,
    custody TEXT NOT NULL CHECK (custody IN ('file', 'kms')),
    key_id TEXT NOT NULL CHECK (pg_catalog.octet_length(key_id) BETWEEN 1 AND 2048 AND key_id ~ '^[!-~]+$'),
    ciphertext BYTEA NOT NULL CHECK (pg_catalog.octet_length(ciphertext) BETWEEN 16 AND 6144),
    state TEXT NOT NULL CHECK (state IN ('active', 'retired')),
    created_at TIMESTAMPTZ NOT NULL,
    retired_at TIMESTAMPTZ,
    CONSTRAINT kubernetes_ca_data_key_wrapping_lifecycle_check CHECK (
        (state = 'active' AND retired_at IS NULL)
        OR (state = 'retired' AND retired_at IS NOT NULL AND retired_at >= created_at)
    ),
    CONSTRAINT kubernetes_ca_data_key_wrapping_key_fk FOREIGN KEY (workspace_id, network_id, data_key_id)
        REFERENCES mesh.kubernetes_ca_data_key (workspace_id, network_id, id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX kubernetes_ca_data_key_wrapping_active_idx
    ON mesh.kubernetes_ca_data_key_wrapping (data_key_id) WHERE state = 'active';

-- A cluster's CAs. Roots: at most one next (published, not yet signing),
-- one active and one retiring. Intermediates: at most one active, signed
-- by a root of the same cluster; any number retiring while certificates
-- they signed may live. A CA that stops signing drops its sealed key.
CREATE TABLE mesh.kubernetes_cluster_ca (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    kubernetes_cluster_id BIGINT NOT NULL,
    data_key_id BIGINT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('root', 'intermediate')),
    issuer_ca_id BIGINT,
    state TEXT NOT NULL CHECK (state IN ('next', 'active', 'retiring', 'retired')),
    reason TEXT NOT NULL CHECK (
        reason IN ('initial', 'scheduled', 'name_changed', 'admin', 'emergency', 'compromise')
    ),
    state_reason TEXT NOT NULL CHECK (
        state_reason IN (
            'initial', 'scheduled', 'name_changed', 'admin', 'emergency', 'compromise', 'cluster_deleted', 'expired'
        )
    ),
    certificate BYTEA NOT NULL CHECK (pg_catalog.octet_length(certificate) BETWEEN 64 AND 8192),
    fingerprint BYTEA NOT NULL UNIQUE CHECK (fingerprint = pg_catalog.sha256(certificate)),
    cluster_dns_name TEXT NOT NULL CHECK (
        pg_catalog.octet_length(cluster_dns_name) BETWEEN 1 AND 253
        AND cluster_dns_name ~ '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$'
    ),
    not_before TIMESTAMPTZ NOT NULL,
    not_after TIMESTAMPTZ NOT NULL,
    private_key_ciphertext BYTEA CHECK (pg_catalog.octet_length(private_key_ciphertext) BETWEEN 32 AND 1024),
    created_at TIMESTAMPTZ NOT NULL,
    activated_at TIMESTAMPTZ,
    retiring_at TIMESTAMPTZ,
    retired_at TIMESTAMPTZ,
    changed_by TEXT CHECK (pg_catalog.octet_length(changed_by) BETWEEN 1 AND 128 AND changed_by ~ '^[ -~]+$'),
    change_ref TEXT CHECK (pg_catalog.octet_length(change_ref) BETWEEN 1 AND 128 AND change_ref ~ '^[ -~]+$'),
    CONSTRAINT kubernetes_cluster_ca_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT kubernetes_cluster_ca_tier_check CHECK (
        (kind = 'root' AND issuer_ca_id IS NULL
            AND not_after <= not_before + INTERVAL '15 years 2 days')
        OR (kind = 'intermediate' AND issuer_ca_id IS NOT NULL AND state <> 'next'
            AND not_after <= not_before + INTERVAL '92 days')
    ),
    CONSTRAINT kubernetes_cluster_ca_validity_check CHECK (not_after > not_before),
    CONSTRAINT kubernetes_cluster_ca_lifecycle_check CHECK (
        (state = 'next' AND activated_at IS NULL AND retiring_at IS NULL AND retired_at IS NULL
            AND private_key_ciphertext IS NOT NULL)
        OR (state = 'active' AND activated_at IS NOT NULL AND activated_at >= created_at AND retiring_at IS NULL
            AND retired_at IS NULL AND private_key_ciphertext IS NOT NULL)
        OR (state = 'retiring' AND activated_at IS NOT NULL AND retiring_at IS NOT NULL
            AND retiring_at >= activated_at AND retired_at IS NULL AND private_key_ciphertext IS NULL)
        OR (state = 'retired' AND retired_at IS NOT NULL AND retired_at >= created_at
            AND private_key_ciphertext IS NULL)
    ),
    CONSTRAINT kubernetes_cluster_ca_actor_check CHECK ((changed_by IS NULL) = (change_ref IS NULL)),
    CONSTRAINT kubernetes_cluster_ca_cluster_fk FOREIGN KEY (workspace_id, network_id, kubernetes_cluster_id)
        REFERENCES mesh.kubernetes_cluster (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT kubernetes_cluster_ca_data_key_fk FOREIGN KEY (workspace_id, network_id, data_key_id)
        REFERENCES mesh.kubernetes_ca_data_key (workspace_id, network_id, id) ON DELETE RESTRICT,
    UNIQUE (workspace_id, network_id, kubernetes_cluster_id, id),
    CONSTRAINT kubernetes_cluster_ca_issuer_fk FOREIGN KEY (workspace_id, network_id, kubernetes_cluster_id, issuer_ca_id)
        REFERENCES mesh.kubernetes_cluster_ca (workspace_id, network_id, kubernetes_cluster_id, id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX kubernetes_cluster_ca_root_next_idx
    ON mesh.kubernetes_cluster_ca (kubernetes_cluster_id) WHERE kind = 'root' AND state = 'next';
CREATE UNIQUE INDEX kubernetes_cluster_ca_root_active_idx
    ON mesh.kubernetes_cluster_ca (kubernetes_cluster_id) WHERE kind = 'root' AND state = 'active';
CREATE UNIQUE INDEX kubernetes_cluster_ca_root_retiring_idx
    ON mesh.kubernetes_cluster_ca (kubernetes_cluster_id) WHERE kind = 'root' AND state = 'retiring';
CREATE UNIQUE INDEX kubernetes_cluster_ca_intermediate_active_idx
    ON mesh.kubernetes_cluster_ca (kubernetes_cluster_id) WHERE kind = 'intermediate' AND state = 'active';
CREATE INDEX kubernetes_cluster_ca_live_idx
    ON mesh.kubernetes_cluster_ca (workspace_id, network_id, kubernetes_cluster_id) WHERE state <> 'retired';
CREATE INDEX kubernetes_cluster_ca_data_key_idx ON mesh.kubernetes_cluster_ca (data_key_id);
CREATE INDEX kubernetes_cluster_ca_issuer_idx ON mesh.kubernetes_cluster_ca (issuer_ca_id)
    WHERE issuer_ca_id IS NOT NULL;

ALTER TABLE mesh_ops.kubernetes_ca_worker_heartbeat
    ADD COLUMN capabilities TEXT[] NOT NULL DEFAULT '{}'::TEXT[]
        CHECK (pg_catalog.cardinality(capabilities) <= 16);

ALTER TABLE mesh_ops.kubernetes_ca_dns_suffix ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.kubernetes_ca_dns_suffix FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_ca_dns_suffix_migrator_policy ON mesh_ops.kubernetes_ca_dns_suffix
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
ALTER TABLE mesh.kubernetes_ca_data_key ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.kubernetes_ca_data_key FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_ca_data_key_migrator_policy ON mesh.kubernetes_ca_data_key
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
ALTER TABLE mesh.kubernetes_ca_data_key_wrapping ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.kubernetes_ca_data_key_wrapping FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_ca_data_key_wrapping_migrator_policy ON mesh.kubernetes_ca_data_key_wrapping
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
ALTER TABLE mesh.kubernetes_cluster_ca ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.kubernetes_cluster_ca FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_cluster_ca_migrator_policy ON mesh.kubernetes_cluster_ca
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh_ops.kubernetes_ca_dns_suffix, mesh.kubernetes_ca_data_key, mesh.kubernetes_ca_data_key_wrapping,
    mesh.kubernetes_cluster_ca
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE TRIGGER kubernetes_ca_data_key_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.kubernetes_ca_data_key
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('kubernetes_ca_data_key', 'public_id');
CREATE TRIGGER kubernetes_cluster_ca_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.kubernetes_cluster_ca
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('kubernetes_cluster_ca', 'public_id');

-- Rows are never deleted. A data key changes only by a rewrap (version,
-- actor) or by retiring; a wrapping only by retiring; a CA only moves
-- forward (roots next → active → retiring → retired, intermediates active
-- → retiring → retired, or straight to retired), dropping its sealed key
-- when it stops signing.
CREATE FUNCTION mesh_ops.guard_kubernetes_ca_row_v2()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Kubernetes CA rows are never deleted';
    END IF;
    IF TG_TABLE_NAME = 'kubernetes_ca_data_key' THEN
        IF NEW.id IS DISTINCT FROM OLD.id OR NEW.public_id IS DISTINCT FROM OLD.public_id
            OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR NEW.network_id IS DISTINCT FROM OLD.network_id
            OR NEW.created_at IS DISTINCT FROM OLD.created_at
            OR (OLD.retired_at IS NOT NULL AND NEW.retired_at IS DISTINCT FROM OLD.retired_at)
            OR (OLD.state, NEW.state, NEW.last_change) NOT IN (
                ('active', 'active', 'rewrapped'), ('active', 'retired', 'retired'),
                ('retired', 'retired', 'rewrapped')
            ) THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Kubernetes CA data key change';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_TABLE_NAME = 'kubernetes_ca_data_key_wrapping' THEN
        IF NEW.id IS DISTINCT FROM OLD.id OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id
            OR NEW.network_id IS DISTINCT FROM OLD.network_id OR NEW.data_key_id IS DISTINCT FROM OLD.data_key_id
            OR NEW.custody IS DISTINCT FROM OLD.custody OR NEW.key_id IS DISTINCT FROM OLD.key_id
            OR NEW.ciphertext IS DISTINCT FROM OLD.ciphertext OR NEW.created_at IS DISTINCT FROM OLD.created_at
            OR NOT (OLD.state = 'active' AND NEW.state = 'retired') THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Kubernetes CA data key wrapping change';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.public_id IS DISTINCT FROM OLD.public_id
        OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR NEW.network_id IS DISTINCT FROM OLD.network_id
        OR NEW.kubernetes_cluster_id IS DISTINCT FROM OLD.kubernetes_cluster_id
        OR NEW.data_key_id IS DISTINCT FROM OLD.data_key_id OR NEW.kind IS DISTINCT FROM OLD.kind
        OR NEW.issuer_ca_id IS DISTINCT FROM OLD.issuer_ca_id OR NEW.reason IS DISTINCT FROM OLD.reason
        OR NEW.certificate IS DISTINCT FROM OLD.certificate OR NEW.fingerprint IS DISTINCT FROM OLD.fingerprint
        OR NEW.cluster_dns_name IS DISTINCT FROM OLD.cluster_dns_name
        OR NEW.not_before IS DISTINCT FROM OLD.not_before OR NEW.not_after IS DISTINCT FROM OLD.not_after
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
        OR (OLD.activated_at IS NOT NULL AND NEW.activated_at IS DISTINCT FROM OLD.activated_at)
        OR (OLD.retiring_at IS NOT NULL AND NEW.retiring_at IS DISTINCT FROM OLD.retiring_at)
        OR (NEW.private_key_ciphertext IS NOT NULL
            AND NEW.private_key_ciphertext IS DISTINCT FROM OLD.private_key_ciphertext)
        OR (OLD.state, NEW.state) NOT IN (
            ('next', 'active'), ('next', 'retired'), ('active', 'retiring'), ('active', 'retired'),
            ('retiring', 'retired')
        ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Kubernetes cluster CA change';
    END IF;
    RETURN NEW;
END;
$function$;
CREATE TRIGGER kubernetes_ca_data_key_guard
BEFORE UPDATE OR DELETE ON mesh.kubernetes_ca_data_key
FOR EACH ROW EXECUTE FUNCTION mesh_ops.guard_kubernetes_ca_row_v2();
CREATE TRIGGER kubernetes_ca_data_key_wrapping_guard
BEFORE UPDATE OR DELETE ON mesh.kubernetes_ca_data_key_wrapping
FOR EACH ROW EXECUTE FUNCTION mesh_ops.guard_kubernetes_ca_row_v2();
CREATE TRIGGER kubernetes_cluster_ca_guard
BEFORE UPDATE OR DELETE ON mesh.kubernetes_cluster_ca
FOR EACH ROW EXECUTE FUNCTION mesh_ops.guard_kubernetes_ca_row_v2();
REVOKE ALL ON FUNCTION mesh_ops.guard_kubernetes_ca_row_v2() FROM PUBLIC;

-- The internal ids of a Network of the installation, without a lock.
CREATE FUNCTION mesh_ops.kubernetes_ca_scope_internal_v1(
    p_deployment_public_id UUID, p_workspace_public_id UUID, p_network_public_id UUID,
    OUT workspace_id BIGINT, OUT network_id BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_deployment_id BIGINT := mesh_ops.kubernetes_ca_deployment_internal_v1(p_deployment_public_id);
    v_scan TEXT := pg_catalog.current_setting('mesh.access_ledger_scan', TRUE);
BEGIN
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    SELECT workspace.id, network.id INTO workspace_id, network_id
    FROM mesh.workspace AS workspace
    JOIN mesh.network AS network ON network.workspace_id = workspace.id
    WHERE workspace.public_id = p_workspace_public_id AND network.public_id = p_network_public_id
      AND workspace.deployment_id = v_deployment_id;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', COALESCE(v_scan, ''), TRUE);
    IF workspace_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Kubernetes CA Network is unavailable';
    END IF;
END;
$function$;

-- Records the installation's DNS suffix the first time, and says whether
-- the worker's suffix is the recorded one. A worker whose suffix differs
-- names no cluster and does no CA work (§17.1 C2).
CREATE FUNCTION mesh_ops.claim_kubernetes_ca_dns_suffix_v1(p_deployment_public_id UUID, p_suffix TEXT)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_deployment_id BIGINT := mesh_ops.kubernetes_ca_deployment_internal_v1(p_deployment_public_id);
    v_recorded TEXT;
    v_inserted BOOLEAN;
BEGIN
    IF p_suffix IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes CA DNS suffix';
    END IF;
    INSERT INTO mesh_ops.kubernetes_ca_dns_suffix (deployment_id, suffix, recorded_at)
    VALUES (v_deployment_id, p_suffix, pg_catalog.clock_timestamp())
    ON CONFLICT (deployment_id) DO NOTHING;
    v_inserted := FOUND;
    SELECT stored.suffix INTO STRICT v_recorded
    FROM mesh_ops.kubernetes_ca_dns_suffix AS stored WHERE stored.deployment_id = v_deployment_id;
    RETURN pg_catalog.jsonb_build_object(
        'outcome', CASE WHEN v_inserted THEN 'recorded' WHEN v_recorded = p_suffix THEN 'matched' ELSE 'mismatched' END,
        'suffix', v_recorded
    );
END;
$function$;

-- What the worker decides from: the tenant codes that name the clusters,
-- the data keys with their active wrapping, and the 96 scheduled clusters
-- due first (64 active at most, and deleted ones until their CAs retire)
-- with their CAs that are not retired.
CREATE FUNCTION mesh_ops.kubernetes_ca_network_snapshot_internal_v1(
    p_workspace_id BIGINT, p_network_id BIGINT, p_workspace_public_id UUID, p_network_public_id UUID
)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'now', pg_catalog.clock_timestamp(),
        'workspace_code', (SELECT display.display_code FROM mesh_ops.tenant_display_identity AS display
            WHERE display.workspace_public_id = p_workspace_public_id),
        'network_code', (SELECT display.display_code FROM mesh_ops.tenant_display_identity AS display
            WHERE display.network_public_id = p_network_public_id),
        'data_keys', COALESCE((
            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                'id', data_key.public_id, 'version', data_key.version, 'active', data_key.state = 'active',
                'custody', wrapping.custody, 'key_id', wrapping.key_id,
                'ciphertext', pg_catalog.encode(wrapping.ciphertext, 'hex')
            ) ORDER BY data_key.id)
            FROM mesh.kubernetes_ca_data_key AS data_key
            JOIN mesh.kubernetes_ca_data_key_wrapping AS wrapping
              ON wrapping.data_key_id = data_key.id AND wrapping.state = 'active'
            WHERE data_key.workspace_id = p_workspace_id AND data_key.network_id = p_network_id
              AND (data_key.state = 'active' OR EXISTS (
                  SELECT 1 FROM mesh.kubernetes_cluster_ca AS ca
                  WHERE ca.data_key_id = data_key.id AND ca.private_key_ciphertext IS NOT NULL))
        ), '[]'::JSONB),
        'clusters', COALESCE((
            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                'id', cluster.public_id, 'name', cluster.name, 'state', cluster.state,
                'next_action_at', schedule.next_action_at, 'failures', schedule.failures,
                'cas', COALESCE((
                    SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                        'id', ca.public_id, 'version', ca.version, 'kind', ca.kind, 'issuer_id', issuer.public_id,
                        'state', ca.state, 'reason', ca.reason, 'data_key_id', data_key.public_id,
                        'certificate', pg_catalog.encode(ca.certificate, 'hex'),
                        'cluster_dns_name', ca.cluster_dns_name,
                        'not_before', ca.not_before, 'not_after', ca.not_after,
                        'sealed_key', pg_catalog.encode(ca.private_key_ciphertext, 'hex'),
                        'created_at', ca.created_at, 'activated_at', ca.activated_at, 'retiring_at', ca.retiring_at
                    ) ORDER BY ca.id)
                    FROM mesh.kubernetes_cluster_ca AS ca
                    JOIN mesh.kubernetes_ca_data_key AS data_key ON data_key.id = ca.data_key_id
                    LEFT JOIN mesh.kubernetes_cluster_ca AS issuer ON issuer.id = ca.issuer_ca_id
                    WHERE ca.workspace_id = cluster.workspace_id AND ca.network_id = cluster.network_id
                      AND ca.kubernetes_cluster_id = cluster.id AND ca.state <> 'retired'
                ), '[]'::JSONB)
            ) ORDER BY schedule.next_action_at, cluster.id)
            FROM (
                SELECT listed.* FROM mesh_ops.kubernetes_cluster_ca_schedule AS listed
                WHERE listed.workspace_id = p_workspace_id AND listed.network_id = p_network_id
                ORDER BY listed.next_action_at, listed.kubernetes_cluster_id
                LIMIT 96
            ) AS schedule
            JOIN mesh.kubernetes_cluster AS cluster
              ON cluster.workspace_id = schedule.workspace_id AND cluster.network_id = schedule.network_id
             AND cluster.id = schedule.kubernetes_cluster_id
        ), '[]'::JSONB)
    )
$function$;

-- Reads a Network without its lock: the worker prepares keys from it,
-- outside any transaction that holds a lock (§17.3).
CREATE FUNCTION mesh_ops.read_kubernetes_ca_network_v1(
    p_deployment_public_id UUID, p_workspace_public_id UUID, p_network_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_scope RECORD;
BEGIN
    SELECT * INTO STRICT v_scope
    FROM mesh_ops.kubernetes_ca_scope_internal_v1(p_deployment_public_id, p_workspace_public_id, p_network_public_id);
    RETURN pg_catalog.jsonb_build_object('outcome', 'read') || mesh_ops.kubernetes_ca_network_snapshot_internal_v1(
        v_scope.workspace_id, v_scope.network_id, p_workspace_public_id, p_network_public_id);
END;
$function$;

-- Takes the Network's CA lock and reads it again; outcome is 'busy' when
-- another worker holds the Network.
CREATE FUNCTION mesh_ops.lock_kubernetes_ca_network_v2(
    p_deployment_public_id UUID, p_workspace_public_id UUID, p_network_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_scope RECORD;
BEGIN
    SELECT * INTO STRICT v_scope
    FROM mesh_ops.kubernetes_ca_network_internal_v1(p_deployment_public_id, p_workspace_public_id, p_network_public_id);
    IF v_scope.busy THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'busy');
    END IF;
    RETURN pg_catalog.jsonb_build_object('outcome', 'locked') || mesh_ops.kubernetes_ca_network_snapshot_internal_v1(
        v_scope.workspace_id, v_scope.network_id, p_workspace_public_id, p_network_public_id);
END;
$function$;

-- The audit action of a change to a CA or data key row this transaction
-- made.
CREATE FUNCTION mesh_ops.kubernetes_ca_action_internal_v1(p_aggregate TEXT, p_operation TEXT, p_row_id BIGINT)
RETURNS TEXT
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT CASE
        WHEN p_aggregate = 'kubernetes_cluster_ca' THEN (
            SELECT CASE
                WHEN p_operation = 'insert' THEN 'kubernetes_cluster.ca_created'
                WHEN p_operation = 'update' AND ca.state = 'active' THEN 'kubernetes_cluster.ca_activated'
                WHEN p_operation = 'update' AND ca.state = 'retiring' THEN 'kubernetes_cluster.ca_retiring'
                WHEN p_operation = 'update' AND ca.state = 'retired' THEN 'kubernetes_cluster.ca_retired'
            END
            FROM mesh.kubernetes_cluster_ca AS ca WHERE ca.id = p_row_id)
        WHEN p_aggregate = 'kubernetes_ca_data_key' THEN (
            SELECT CASE
                WHEN p_operation = 'insert' AND data_key.last_change = 'created' THEN 'kubernetes_ca_data_key.created'
                WHEN p_operation = 'update' AND data_key.last_change IN ('rewrapped', 'retired')
                    THEN 'kubernetes_ca_data_key.' || data_key.last_change
            END
            FROM mesh.kubernetes_ca_data_key AS data_key WHERE data_key.id = p_row_id)
    END
$function$;

-- What a CA's or data key's audit event says: never key material.
CREATE FUNCTION mesh_ops.kubernetes_ca_payload_internal_v1(p_aggregate TEXT, p_row_id BIGINT)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT CASE
        WHEN p_aggregate = 'kubernetes_cluster_ca' THEN (
            SELECT pg_catalog.jsonb_build_object(
                'format', 'kubernetes-cluster-ca/v2',
                'ca_id', ca.public_id,
                'cluster_id', cluster.public_id,
                'kind', ca.kind,
                'issuer_id', issuer.public_id,
                'state', ca.state,
                'reason', ca.reason,
                'state_reason', ca.state_reason,
                'fingerprint', pg_catalog.encode(ca.fingerprint, 'hex'),
                'cluster_dns_name', ca.cluster_dns_name,
                'not_before', ca.not_before,
                'not_after', ca.not_after,
                'data_key_id', data_key.public_id,
                'version', ca.version,
                'changed_by', ca.changed_by,
                'change_ref', ca.change_ref
            )
            FROM mesh.kubernetes_cluster_ca AS ca
            JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = ca.kubernetes_cluster_id
            JOIN mesh.kubernetes_ca_data_key AS data_key ON data_key.id = ca.data_key_id
            LEFT JOIN mesh.kubernetes_cluster_ca AS issuer ON issuer.id = ca.issuer_ca_id
            WHERE ca.id = p_row_id)
        WHEN p_aggregate = 'kubernetes_ca_data_key' THEN (
            SELECT pg_catalog.jsonb_build_object(
                'format', 'kubernetes-ca-data-key/v1',
                'data_key_id', data_key.public_id,
                'state', data_key.state,
                'custody', wrapping.custody,
                'key_id', wrapping.key_id,
                'version', data_key.version,
                'changed_by', data_key.changed_by,
                'change_ref', data_key.change_ref
            )
            FROM mesh.kubernetes_ca_data_key AS data_key
            JOIN mesh.kubernetes_ca_data_key_wrapping AS wrapping
              ON wrapping.data_key_id = data_key.id AND wrapping.state = 'active'
            WHERE data_key.id = p_row_id)
    END
$function$;

-- The head of the Network's audit stream and the payload of a CA or data
-- key row this transaction changed, for the worker to hash and append.
CREATE FUNCTION mesh_ops.kubernetes_ca_proof_internal_v1(p_aggregate TEXT, p_row_id BIGINT, p_operation TEXT)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_row RECORD;
    v_revision BIGINT;
    v_stream RECORD;
    v_payload JSONB;
    v_scan TEXT := pg_catalog.current_setting('mesh.access_ledger_scan', TRUE);
BEGIN
    IF p_aggregate = 'kubernetes_cluster_ca' THEN
        SELECT ca.public_id, ca.version, ca.workspace_id, ca.network_id, ca.changed_by INTO STRICT v_row
        FROM mesh.kubernetes_cluster_ca AS ca WHERE ca.id = p_row_id;
    ELSE
        SELECT data_key.public_id, data_key.version, data_key.workspace_id, data_key.network_id,
            data_key.changed_by INTO STRICT v_row
        FROM mesh.kubernetes_ca_data_key AS data_key WHERE data_key.id = p_row_id;
    END IF;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    SELECT revision.network_revision INTO v_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_row.workspace_id AND revision.network_id = v_row.network_id;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', COALESCE(v_scan, ''), TRUE);
    IF v_revision IS NULL OR v_revision < 1 THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Network revision is unavailable';
    END IF;
    SELECT stream.id, stream.next_sequence, stream.latest_event_hash INTO v_stream
    FROM mesh_audit.audit_stream AS stream
    WHERE stream.scope_kind = 'network'
      AND stream.workspace_id = v_row.workspace_id AND stream.network_id = v_row.network_id
    FOR UPDATE;
    IF v_stream.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Network audit stream is unavailable';
    END IF;
    v_payload := mesh_ops.kubernetes_ca_payload_internal_v1(p_aggregate, p_row_id);
    RETURN pg_catalog.jsonb_build_object(
        'outcome', 'changed',
        'aggregate', p_aggregate,
        'action', mesh_ops.kubernetes_ca_action_internal_v1(p_aggregate, p_operation, p_row_id),
        'permission', CASE WHEN v_row.changed_by IS NULL THEN 'system.reconcile' ELSE 'system.operator' END,
        'row_id', v_row.public_id,
        'version', v_row.version,
        'network_revision', v_revision,
        'semantic_hash', pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(v_payload::TEXT, 'UTF8')), 'hex'),
        'stream_id', v_stream.id,
        'sequence', v_stream.next_sequence,
        'previous_hash', pg_catalog.encode(v_stream.latest_event_hash, 'hex'),
        'payload', v_payload::TEXT
    );
END;
$function$;

-- Checks the change id and the operator's name and change record: both or
-- neither.
CREATE FUNCTION mesh_ops.kubernetes_ca_change_valid_internal_v1(
    p_change_public_id UUID, p_actor TEXT, p_change_ref TEXT, VARIADIC p_others UUID[]
)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT p_change_public_id IS NOT NULL
        AND pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 = 7
        AND NOT (p_change_public_id = ANY (p_others))
        AND (p_actor IS NULL) = (p_change_ref IS NULL)
        AND (p_actor IS NULL OR (pg_catalog.octet_length(p_actor) BETWEEN 1 AND 128 AND p_actor ~ '^[ -~]+$'
            AND pg_catalog.octet_length(p_change_ref) BETWEEN 1 AND 128 AND p_change_ref ~ '^[ -~]+$'))
$function$;

-- Stores a new active data key for the Network, wrapped by the custody,
-- as one change; outcome 'existing' when the Network has one already.
CREATE FUNCTION mesh_ops.add_kubernetes_ca_data_key_v2(
    p_deployment_public_id UUID, p_workspace_public_id UUID, p_network_public_id UUID,
    p_data_key_public_id UUID, p_change_public_id UUID, p_custody TEXT, p_key_id TEXT, p_ciphertext BYTEA,
    p_actor TEXT, p_change_ref TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_scope RECORD;
    v_row_id BIGINT;
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
BEGIN
    IF p_data_key_public_id IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(p_data_key_public_id), 6) >> 4 <> 7
        OR NOT mesh_ops.kubernetes_ca_change_valid_internal_v1(p_change_public_id, p_actor, p_change_ref,
            p_data_key_public_id) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes CA data key';
    END IF;
    SELECT * INTO STRICT v_scope
    FROM mesh_ops.kubernetes_ca_network_internal_v1(p_deployment_public_id, p_workspace_public_id, p_network_public_id);
    IF v_scope.busy THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'busy');
    END IF;
    IF EXISTS (
        SELECT 1 FROM mesh.kubernetes_ca_data_key AS data_key
        WHERE data_key.workspace_id = v_scope.workspace_id AND data_key.network_id = v_scope.network_id
          AND data_key.state = 'active'
    ) THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'existing');
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    INSERT INTO mesh.kubernetes_ca_data_key (
        public_id, workspace_id, network_id, state, last_change, created_at, changed_by, change_ref
    ) VALUES (
        p_data_key_public_id, v_scope.workspace_id, v_scope.network_id, 'active', 'created', v_now, p_actor,
        p_change_ref
    )
    RETURNING id INTO v_row_id;
    INSERT INTO mesh.kubernetes_ca_data_key_wrapping (
        workspace_id, network_id, data_key_id, custody, key_id, ciphertext, state, created_at
    ) VALUES (v_scope.workspace_id, v_scope.network_id, v_row_id, p_custody, p_key_id, p_ciphertext, 'active', v_now);
    RETURN mesh_ops.kubernetes_ca_proof_internal_v1('kubernetes_ca_data_key', v_row_id, 'insert');
END;
$function$;

-- Wraps a data key again, under another custody key, as one change: the
-- data key and the CAs it sealed do not change (§17.1 C1). Outcome
-- 'stale' when the key is no longer at p_version.
CREATE FUNCTION mesh_ops.rewrap_kubernetes_ca_data_key_v1(
    p_deployment_public_id UUID, p_workspace_public_id UUID, p_network_public_id UUID,
    p_data_key_public_id UUID, p_version BIGINT, p_change_public_id UUID, p_custody TEXT, p_key_id TEXT,
    p_ciphertext BYTEA, p_actor TEXT, p_change_ref TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_scope RECORD;
    v_key mesh.kubernetes_ca_data_key%ROWTYPE;
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
BEGIN
    IF p_data_key_public_id IS NULL OR p_version IS NULL OR p_version < 1
        OR NOT mesh_ops.kubernetes_ca_change_valid_internal_v1(p_change_public_id, p_actor, p_change_ref,
            p_data_key_public_id) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes CA data key rewrap';
    END IF;
    SELECT * INTO STRICT v_scope
    FROM mesh_ops.kubernetes_ca_network_internal_v1(p_deployment_public_id, p_workspace_public_id, p_network_public_id);
    IF v_scope.busy THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'busy');
    END IF;
    SELECT data_key.* INTO v_key
    FROM mesh.kubernetes_ca_data_key AS data_key
    WHERE data_key.workspace_id = v_scope.workspace_id AND data_key.network_id = v_scope.network_id
      AND data_key.public_id = p_data_key_public_id
    FOR UPDATE;
    IF v_key.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Kubernetes CA data key is unavailable';
    END IF;
    IF v_key.version <> p_version THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'stale');
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    UPDATE mesh.kubernetes_ca_data_key_wrapping AS wrapping
    SET state = 'retired', retired_at = v_now
    WHERE wrapping.data_key_id = v_key.id AND wrapping.state = 'active';
    INSERT INTO mesh.kubernetes_ca_data_key_wrapping (
        workspace_id, network_id, data_key_id, custody, key_id, ciphertext, state, created_at
    ) VALUES (v_key.workspace_id, v_key.network_id, v_key.id, p_custody, p_key_id, p_ciphertext, 'active', v_now);
    UPDATE mesh.kubernetes_ca_data_key AS data_key
    SET version = data_key.version + 1, last_change = 'rewrapped', changed_by = p_actor, change_ref = p_change_ref
    WHERE data_key.id = v_key.id;
    RETURN mesh_ops.kubernetes_ca_proof_internal_v1('kubernetes_ca_data_key', v_key.id, 'update');
END;
$function$;

-- Retires the Network's active data key as one change: new CAs then need a
-- new one; CAs it sealed still open under it until they retire.
CREATE FUNCTION mesh_ops.retire_kubernetes_ca_data_key_v1(
    p_deployment_public_id UUID, p_workspace_public_id UUID, p_network_public_id UUID,
    p_data_key_public_id UUID, p_version BIGINT, p_change_public_id UUID, p_actor TEXT, p_change_ref TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_scope RECORD;
    v_key mesh.kubernetes_ca_data_key%ROWTYPE;
BEGIN
    IF p_data_key_public_id IS NULL OR p_version IS NULL OR p_version < 1
        OR NOT mesh_ops.kubernetes_ca_change_valid_internal_v1(p_change_public_id, p_actor, p_change_ref,
            p_data_key_public_id) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes CA data key retirement';
    END IF;
    SELECT * INTO STRICT v_scope
    FROM mesh_ops.kubernetes_ca_network_internal_v1(p_deployment_public_id, p_workspace_public_id, p_network_public_id);
    IF v_scope.busy THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'busy');
    END IF;
    SELECT data_key.* INTO v_key
    FROM mesh.kubernetes_ca_data_key AS data_key
    WHERE data_key.workspace_id = v_scope.workspace_id AND data_key.network_id = v_scope.network_id
      AND data_key.public_id = p_data_key_public_id AND data_key.state = 'active'
    FOR UPDATE;
    IF v_key.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Kubernetes CA data key is unavailable';
    END IF;
    IF v_key.version <> p_version THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'stale');
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    UPDATE mesh.kubernetes_ca_data_key AS data_key
    SET version = data_key.version + 1, state = 'retired', last_change = 'retired',
        retired_at = pg_catalog.clock_timestamp(), changed_by = p_actor, change_ref = p_change_ref
    WHERE data_key.id = v_key.id;
    RETURN mesh_ops.kubernetes_ca_proof_internal_v1('kubernetes_ca_data_key', v_key.id, 'update');
END;
$function$;

-- Creates a cluster's CA as one change: a root (active or next) of an
-- active cluster, or an active intermediate signed by the cluster's active
-- root, for the root's name and ending no later than it. The data key is
-- the Network's active one; the fingerprint is computed here. Returns the
-- proof to append, or outcome 'busy'.
CREATE FUNCTION mesh_ops.create_kubernetes_cluster_ca_v2(
    p_deployment_public_id UUID, p_workspace_public_id UUID, p_network_public_id UUID,
    p_cluster_public_id UUID, p_ca_public_id UUID, p_change_public_id UUID, p_kind TEXT, p_issuer_public_id UUID,
    p_state TEXT, p_reason TEXT, p_data_key_public_id UUID, p_certificate BYTEA, p_cluster_dns_name TEXT,
    p_not_before TIMESTAMPTZ, p_not_after TIMESTAMPTZ, p_sealed_key BYTEA, p_actor TEXT, p_change_ref TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_scope RECORD;
    v_cluster_id BIGINT;
    v_data_key_id BIGINT;
    v_issuer mesh.kubernetes_cluster_ca%ROWTYPE;
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_row_id BIGINT;
BEGIN
    IF p_ca_public_id IS NULL OR p_cluster_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_ca_public_id), 6) >> 4 <> 7
        OR NOT mesh_ops.kubernetes_ca_change_valid_internal_v1(p_change_public_id, p_actor, p_change_ref,
            p_ca_public_id)
        OR NOT ((p_kind = 'root' AND p_issuer_public_id IS NULL AND p_state IN ('active', 'next'))
            OR (p_kind = 'intermediate' AND p_issuer_public_id IS NOT NULL AND p_state = 'active'))
        OR p_reason IS NULL OR p_reason NOT IN ('initial', 'scheduled', 'name_changed', 'admin', 'emergency', 'compromise')
        OR p_certificate IS NULL OR p_sealed_key IS NULL OR p_not_before IS NULL OR p_not_after IS NULL
        OR p_not_after <= v_now THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes cluster CA';
    END IF;
    SELECT * INTO STRICT v_scope
    FROM mesh_ops.kubernetes_ca_network_internal_v1(p_deployment_public_id, p_workspace_public_id, p_network_public_id);
    IF v_scope.busy THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'busy');
    END IF;
    SELECT cluster.id INTO v_cluster_id
    FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.workspace_id = v_scope.workspace_id AND cluster.network_id = v_scope.network_id
      AND cluster.public_id = p_cluster_public_id AND cluster.state = 'active'
    FOR SHARE;
    SELECT data_key.id INTO v_data_key_id
    FROM mesh.kubernetes_ca_data_key AS data_key
    WHERE data_key.workspace_id = v_scope.workspace_id AND data_key.network_id = v_scope.network_id
      AND data_key.public_id = p_data_key_public_id AND data_key.state = 'active';
    IF v_cluster_id IS NULL OR v_data_key_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Kubernetes cluster or CA data key is unavailable';
    END IF;
    -- A CA signs only under the installation's recorded suffix (§17.1 C2).
    -- The scope resolution checked the Network is the installation's.
    IF NOT EXISTS (
        SELECT 1 FROM mesh_ops.kubernetes_ca_dns_suffix AS recorded
        WHERE recorded.deployment_id = mesh_ops.kubernetes_ca_deployment_internal_v1(p_deployment_public_id)
          AND pg_catalog.right(p_cluster_dns_name, pg_catalog.length(recorded.suffix) + 1) = '.' || recorded.suffix
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Kubernetes cluster CA is not under the recorded suffix';
    END IF;
    -- Intermediates retire a day after they hand over; more than eight
    -- still retiring means a runaway (§17.3).
    IF p_kind = 'intermediate' AND (
        SELECT pg_catalog.count(*) FROM mesh.kubernetes_cluster_ca AS ca
        WHERE ca.kubernetes_cluster_id = v_cluster_id AND ca.kind = 'intermediate' AND ca.state = 'retiring'
    ) >= 8 THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Kubernetes cluster has too many retiring intermediates';
    END IF;
    IF p_kind = 'intermediate' THEN
        SELECT ca.* INTO v_issuer
        FROM mesh.kubernetes_cluster_ca AS ca
        WHERE ca.kubernetes_cluster_id = v_cluster_id AND ca.public_id = p_issuer_public_id
          AND ca.kind = 'root' AND ca.state = 'active'
        FOR SHARE;
        IF v_issuer.id IS NULL OR v_issuer.cluster_dns_name <> p_cluster_dns_name
            OR p_not_after > v_issuer.not_after OR p_not_before < v_issuer.not_before THEN
            RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Kubernetes cluster root is unavailable';
        END IF;
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    INSERT INTO mesh.kubernetes_cluster_ca (
        public_id, workspace_id, network_id, kubernetes_cluster_id, data_key_id, kind, issuer_ca_id, state, reason,
        state_reason, certificate, fingerprint, cluster_dns_name, not_before, not_after, private_key_ciphertext,
        created_at, activated_at, changed_by, change_ref
    ) VALUES (
        p_ca_public_id, v_scope.workspace_id, v_scope.network_id, v_cluster_id, v_data_key_id, p_kind, v_issuer.id,
        p_state, p_reason, p_reason, p_certificate, pg_catalog.sha256(p_certificate), p_cluster_dns_name,
        p_not_before, p_not_after, p_sealed_key, v_now, CASE WHEN p_state = 'active' THEN v_now END,
        p_actor, p_change_ref
    )
    RETURNING id INTO v_row_id;
    RETURN mesh_ops.kubernetes_ca_proof_internal_v1('kubernetes_cluster_ca', v_row_id, 'insert');
END;
$function$;

-- Moves a CA forward as one change, if it is still at p_version. A root
-- becomes active only for an active cluster, steps down only once no
-- intermediate of it is active, and retires only once every intermediate
-- of it has. Returns the proof to append, or outcome 'busy' or 'stale'.
CREATE FUNCTION mesh_ops.move_kubernetes_cluster_ca_v2(
    p_deployment_public_id UUID, p_workspace_public_id UUID, p_network_public_id UUID,
    p_ca_public_id UUID, p_change_public_id UUID, p_version BIGINT, p_state TEXT, p_reason TEXT,
    p_actor TEXT, p_change_ref TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_scope RECORD;
    v_ca mesh.kubernetes_cluster_ca%ROWTYPE;
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
BEGIN
    IF p_ca_public_id IS NULL OR p_version IS NULL OR p_version < 1
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_ca_public_id), 6) >> 4 <> 7
        OR NOT mesh_ops.kubernetes_ca_change_valid_internal_v1(p_change_public_id, p_actor, p_change_ref,
            p_ca_public_id)
        OR p_state IS NULL OR p_state NOT IN ('active', 'retiring', 'retired')
        OR p_reason IS NULL OR p_reason NOT IN (
            'scheduled', 'name_changed', 'admin', 'emergency', 'compromise', 'cluster_deleted', 'expired'
        )
        OR (p_state = 'active' AND p_reason NOT IN ('scheduled', 'admin', 'name_changed')) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes cluster CA move';
    END IF;
    SELECT * INTO STRICT v_scope
    FROM mesh_ops.kubernetes_ca_network_internal_v1(p_deployment_public_id, p_workspace_public_id, p_network_public_id);
    IF v_scope.busy THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'busy');
    END IF;
    SELECT ca.* INTO v_ca
    FROM mesh.kubernetes_cluster_ca AS ca
    WHERE ca.workspace_id = v_scope.workspace_id AND ca.network_id = v_scope.network_id
      AND ca.public_id = p_ca_public_id
    FOR UPDATE;
    IF v_ca.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Kubernetes cluster CA is unavailable';
    END IF;
    IF v_ca.version <> p_version THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'stale');
    END IF;
    IF p_state = 'active' THEN
        PERFORM 1 FROM mesh.kubernetes_cluster AS cluster
        WHERE cluster.id = v_ca.kubernetes_cluster_id AND cluster.state = 'active'
        FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Kubernetes cluster is unavailable';
        END IF;
    END IF;
    IF v_ca.kind = 'root' AND EXISTS (
        SELECT 1 FROM mesh.kubernetes_cluster_ca AS below
        WHERE below.issuer_ca_id = v_ca.id
          AND (below.state = 'active' OR (p_state = 'retired' AND below.state <> 'retired'))
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Kubernetes cluster root still has intermediates';
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    UPDATE mesh.kubernetes_cluster_ca AS ca
    SET version = ca.version + 1,
        state = p_state,
        state_reason = p_reason,
        activated_at = CASE WHEN p_state = 'active' THEN v_now ELSE ca.activated_at END,
        retiring_at = CASE WHEN p_state = 'retiring' THEN v_now ELSE ca.retiring_at END,
        retired_at = CASE WHEN p_state = 'retired' THEN v_now ELSE ca.retired_at END,
        private_key_ciphertext = CASE WHEN p_state = 'active' THEN ca.private_key_ciphertext END,
        changed_by = p_actor,
        change_ref = p_change_ref
    WHERE ca.id = v_ca.id;
    RETURN mesh_ops.kubernetes_ca_proof_internal_v1('kubernetes_cluster_ca', v_ca.id, 'update');
END;
$function$;

-- Appends the audit event of the CA or data key change this transaction
-- and change made, bound to the Network revision the proof read: another
-- writer that moved it since makes the worker redo the whole change.
CREATE FUNCTION mesh_ops.append_kubernetes_ca_evidence_v1(
    p_aggregate TEXT,
    p_row_public_id UUID,
    p_stream_id BIGINT,
    p_sequence BIGINT,
    p_previous_hash BYTEA,
    p_event_hash BYTEA,
    p_audit_event_public_id UUID,
    p_outbox_public_id UUID,
    p_payload JSONB,
    p_network_revision BIGINT
)
RETURNS BIGINT
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops, mesh_audit
AS $function$
DECLARE
    v_change UUID;
    v_transaction BIGINT := (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT;
    v_row RECORD;
    v_operation TEXT;
    v_action TEXT;
    v_revision BIGINT;
    v_scan TEXT := pg_catalog.current_setting('mesh.access_ledger_scan', TRUE);
BEGIN
    BEGIN
        v_change := NULLIF(pg_catalog.current_setting('mesh.change_public_id', TRUE), '')::UUID;
    EXCEPTION WHEN invalid_text_representation THEN
        v_change := NULL;
    END;
    IF v_change IS NULL OR p_aggregate IS NULL OR p_aggregate NOT IN ('kubernetes_cluster_ca', 'kubernetes_ca_data_key')
        OR p_row_public_id IS NULL OR p_stream_id IS NULL OR p_sequence IS NULL OR p_sequence <= 0
        OR p_previous_hash IS NULL OR pg_catalog.octet_length(p_previous_hash) <> 32
        OR p_event_hash IS NULL OR pg_catalog.octet_length(p_event_hash) <> 32
        OR p_audit_event_public_id IS NULL OR p_outbox_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_audit_event_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_outbox_public_id), 6) >> 4 <> 7
        OR p_audit_event_public_id = p_outbox_public_id
        OR p_audit_event_public_id IN (v_change, p_row_public_id)
        OR p_outbox_public_id IN (v_change, p_row_public_id) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Kubernetes CA evidence';
    END IF;
    -- The change is exactly this row's one mutation, at its current version.
    SELECT mutation.operation INTO v_operation
    FROM mesh_audit.authority_mutation AS mutation
    WHERE mutation.change_public_id = v_change AND mutation.transaction_id = v_transaction
      AND mutation.aggregate_kind = p_aggregate AND mutation.row_public_id = p_row_public_id;
    IF p_aggregate = 'kubernetes_cluster_ca' THEN
        SELECT ca.id, ca.public_id, ca.version, ca.workspace_id, ca.network_id, ca.changed_by INTO v_row
        FROM mesh.kubernetes_cluster_ca AS ca WHERE ca.public_id = p_row_public_id;
    ELSE
        SELECT data_key.id, data_key.public_id, data_key.version, data_key.workspace_id, data_key.network_id,
            data_key.changed_by INTO v_row
        FROM mesh.kubernetes_ca_data_key AS data_key WHERE data_key.public_id = p_row_public_id;
    END IF;
    IF v_row.id IS NULL OR v_operation IS NULL OR v_operation NOT IN ('insert', 'update')
        OR NOT EXISTS (
            SELECT 1 FROM mesh_audit.authority_mutation AS mutation
            WHERE mutation.change_public_id = v_change AND mutation.transaction_id = v_transaction
              AND mutation.aggregate_kind = p_aggregate AND mutation.row_public_id = p_row_public_id
              AND mutation.after_version = v_row.version)
        OR NOT EXISTS (
            SELECT 1 FROM mesh_audit.audit_stream AS stream
            WHERE stream.id = p_stream_id AND stream.scope_kind = 'network'
              AND stream.workspace_id = v_row.workspace_id AND stream.network_id = v_row.network_id)
        OR (SELECT pg_catalog.count(*) FROM mesh_audit.authority_mutation AS mutation
            WHERE mutation.change_public_id = v_change AND mutation.transaction_id = v_transaction) <> 1
        OR p_payload IS DISTINCT FROM mesh_ops.kubernetes_ca_payload_internal_v1(p_aggregate, v_row.id) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Kubernetes CA evidence';
    END IF;
    v_action := mesh_ops.kubernetes_ca_action_internal_v1(p_aggregate, v_operation, v_row.id);
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    SELECT revision.network_revision INTO STRICT v_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_row.workspace_id AND revision.network_id = v_row.network_id;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', COALESCE(v_scan, ''), TRUE);
    IF p_network_revision IS DISTINCT FROM v_revision THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Network revision changed';
    END IF;
    RETURN mesh_audit.append_authority_evidence(
        p_stream_id, p_audit_event_public_id, p_outbox_public_id, p_sequence, p_previous_hash, p_event_hash,
        p_aggregate, v_row.public_id, v_row.version, v_revision, NULL::UUID,
        v_action, CASE WHEN v_row.changed_by IS NULL THEN 'system.reconcile' ELSE 'system.operator' END,
        NULL::UUID, NULL::BYTEA,
        pg_catalog.sha256(pg_catalog.convert_to(p_payload::TEXT, 'UTF8')),
        p_payload, v_action, p_payload
    );
END;
$function$;

-- A worker process says what it can do and whether it can sign for the
-- next 90 s, and drops the beats of processes gone for a day.
CREATE FUNCTION mesh_ops.beat_kubernetes_ca_worker_v2(
    p_deployment_public_id UUID, p_instance_public_id UUID, p_ready BOOLEAN, p_worker_version TEXT,
    p_custody TEXT, p_capabilities TEXT[]
)
RETURNS TIMESTAMPTZ
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_deployment_id BIGINT;
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_ready_until TIMESTAMPTZ;
BEGIN
    IF p_instance_public_id IS NULL OR p_ready IS NULL OR p_capabilities IS NULL
        OR (p_ready AND p_custody = 'none')
        OR EXISTS (SELECT 1 FROM pg_catalog.unnest(p_capabilities) AS capability
            WHERE capability IS NULL OR capability !~ '^[a-z][a-z0-9_.]{0,31}$') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes CA worker heartbeat';
    END IF;
    v_deployment_id := mesh_ops.kubernetes_ca_deployment_internal_v1(p_deployment_public_id);
    v_ready_until := CASE WHEN p_ready THEN v_now + INTERVAL '90 seconds' ELSE v_now END;
    INSERT INTO mesh_ops.kubernetes_ca_worker_heartbeat AS beat (
        deployment_id, instance_public_id, ready_until, worker_version, custody, updated_at, capabilities
    ) VALUES (v_deployment_id, p_instance_public_id, v_ready_until, p_worker_version, p_custody, v_now,
        p_capabilities)
    ON CONFLICT (deployment_id, instance_public_id) DO UPDATE
    SET ready_until = EXCLUDED.ready_until, worker_version = EXCLUDED.worker_version,
        custody = EXCLUDED.custody, updated_at = EXCLUDED.updated_at, capabilities = EXCLUDED.capabilities;
    DELETE FROM mesh_ops.kubernetes_ca_worker_heartbeat AS beat
    WHERE beat.deployment_id = v_deployment_id AND beat.updated_at < v_now - INTERVAL '1 day';
    RETURN v_ready_until;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.kubernetes_ca_scope_internal_v1(UUID, UUID, UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_ca_network_snapshot_internal_v1(BIGINT, BIGINT, UUID, UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_ca_action_internal_v1(TEXT, TEXT, BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_ca_payload_internal_v1(TEXT, BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_ca_proof_internal_v1(TEXT, BIGINT, TEXT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_ca_change_valid_internal_v1(UUID, TEXT, TEXT, UUID[])
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.claim_kubernetes_ca_dns_suffix_v1(UUID, TEXT)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.read_kubernetes_ca_network_v1(UUID, UUID, UUID)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.lock_kubernetes_ca_network_v2(UUID, UUID, UUID)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.add_kubernetes_ca_data_key_v2(UUID, UUID, UUID, UUID, UUID, TEXT, TEXT, BYTEA, TEXT, TEXT)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.rewrap_kubernetes_ca_data_key_v1(
    UUID, UUID, UUID, UUID, BIGINT, UUID, TEXT, TEXT, BYTEA, TEXT, TEXT
) FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.retire_kubernetes_ca_data_key_v1(UUID, UUID, UUID, UUID, BIGINT, UUID, TEXT, TEXT)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.create_kubernetes_cluster_ca_v2(
    UUID, UUID, UUID, UUID, UUID, UUID, TEXT, UUID, TEXT, TEXT, UUID, BYTEA, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, BYTEA,
    TEXT, TEXT
) FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.move_kubernetes_cluster_ca_v2(
    UUID, UUID, UUID, UUID, UUID, BIGINT, TEXT, TEXT, TEXT, TEXT
) FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.append_kubernetes_ca_evidence_v1(
    TEXT, UUID, BIGINT, BIGINT, BYTEA, BYTEA, UUID, UUID, JSONB, BIGINT
) FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.beat_kubernetes_ca_worker_v2(UUID, UUID, BOOLEAN, TEXT, TEXT, TEXT[])
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
-- Only the worker keeps the CAs (K1a4 Q3); operator commands run as it.
GRANT EXECUTE ON FUNCTION mesh_ops.claim_kubernetes_ca_dns_suffix_v1(UUID, TEXT) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.read_kubernetes_ca_network_v1(UUID, UUID, UUID) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.lock_kubernetes_ca_network_v2(UUID, UUID, UUID) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.add_kubernetes_ca_data_key_v2(UUID, UUID, UUID, UUID, UUID, TEXT, TEXT, BYTEA, TEXT, TEXT)
    TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.rewrap_kubernetes_ca_data_key_v1(
    UUID, UUID, UUID, UUID, BIGINT, UUID, TEXT, TEXT, BYTEA, TEXT, TEXT
) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.retire_kubernetes_ca_data_key_v1(UUID, UUID, UUID, UUID, BIGINT, UUID, TEXT, TEXT)
    TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.create_kubernetes_cluster_ca_v2(
    UUID, UUID, UUID, UUID, UUID, UUID, TEXT, UUID, TEXT, TEXT, UUID, BYTEA, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, BYTEA,
    TEXT, TEXT
) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.move_kubernetes_cluster_ca_v2(
    UUID, UUID, UUID, UUID, UUID, BIGINT, TEXT, TEXT, TEXT, TEXT
) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.append_kubernetes_ca_evidence_v1(
    TEXT, UUID, BIGINT, BIGINT, BYTEA, BYTEA, UUID, UUID, JSONB, BIGINT
) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.beat_kubernetes_ca_worker_v2(UUID, UUID, BOOLEAN, TEXT, TEXT, TEXT[])
    TO mesh_worker;
