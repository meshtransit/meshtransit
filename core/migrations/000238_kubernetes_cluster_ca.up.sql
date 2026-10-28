-- Schema 238 (K1a4a a1b, docs/k8s-k1a4-ca-quarantine-design.md §3, §15,
-- §16.1; ADR-053): the CA of each Kubernetes cluster, the data key that
-- wraps its private key, when the worker should next look at a cluster, and
-- the worker's heartbeat.
--
-- Only the worker writes here, through the functions below, each bound to
-- its installation. A CA's private key is stored only sealed (AES-256-GCM
-- under the Network's data key, AAD bound to deployment, cluster, CA and
-- certificate fingerprint); the data key is stored only wrapped by the
-- custody (a key file or AWS KMS). Every CA row change is one change with
-- one sealed audit event on the Network's stream, as in schema 229.
--
-- The CA set in gateway maps, the Network revision a CA change bumps, the
-- signing queue and the certificate ledger come with a3 (schema 239). Until
-- then nothing reads these rows but the worker.

-- One data key per Network wraps the private keys of its clusters' CAs. A
-- retired key still opens the CAs it sealed until they are retired.
CREATE TABLE mesh.kubernetes_ca_data_key (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    custody TEXT NOT NULL CHECK (custody IN ('file', 'kms')),
    key_id TEXT NOT NULL CHECK (pg_catalog.octet_length(key_id) BETWEEN 1 AND 2048 AND key_id ~ '^[!-~]+$'),
    ciphertext BYTEA NOT NULL CHECK (pg_catalog.octet_length(ciphertext) BETWEEN 16 AND 6144),
    state TEXT NOT NULL CHECK (state IN ('active', 'retired')),
    created_at TIMESTAMPTZ NOT NULL,
    retired_at TIMESTAMPTZ,
    CONSTRAINT kubernetes_ca_data_key_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT kubernetes_ca_data_key_lifecycle_check CHECK (
        (state = 'active' AND retired_at IS NULL)
        OR (state = 'retired' AND retired_at IS NOT NULL AND retired_at >= created_at)
    ),
    CONSTRAINT kubernetes_ca_data_key_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    UNIQUE (workspace_id, network_id, id)
);
CREATE UNIQUE INDEX kubernetes_ca_data_key_active_idx
    ON mesh.kubernetes_ca_data_key (workspace_id, network_id) WHERE state = 'active';

-- A cluster's CAs: at most one next (published, not yet signing), one
-- active (signing) and one retiring (still trusted) at a time. A CA that
-- stops signing drops its sealed private key: retiring and retired rows
-- keep only the certificate. Rows are never deleted; the audit trail names
-- them.
CREATE TABLE mesh.kubernetes_cluster_ca (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    kubernetes_cluster_id BIGINT NOT NULL,
    data_key_id BIGINT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('next', 'active', 'retiring', 'retired')),
    reason TEXT NOT NULL CHECK (
        reason IN ('initial', 'scheduled', 'name_changed', 'admin', 'emergency', 'compromise')
    ),
    state_reason TEXT NOT NULL CHECK (
        state_reason IN (
            'initial', 'scheduled', 'name_changed', 'admin', 'emergency', 'compromise', 'cluster_deleted', 'expired'
        )
    ),
    issuer_kind TEXT NOT NULL DEFAULT 'self' CHECK (issuer_kind = 'self'),
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
    CONSTRAINT kubernetes_cluster_ca_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT kubernetes_cluster_ca_validity_check CHECK (
        not_after > not_before AND not_after <= not_before + INTERVAL '1830 days'
    ),
    CONSTRAINT kubernetes_cluster_ca_lifecycle_check CHECK (
        (state = 'next' AND activated_at IS NULL AND retiring_at IS NULL AND retired_at IS NULL
            AND private_key_ciphertext IS NOT NULL)
        OR (state = 'active' AND activated_at IS NOT NULL AND activated_at >= created_at AND retiring_at IS NULL AND retired_at IS NULL
            AND private_key_ciphertext IS NOT NULL)
        OR (state = 'retiring' AND activated_at IS NOT NULL AND retiring_at IS NOT NULL
            AND retiring_at >= activated_at AND retired_at IS NULL
            AND private_key_ciphertext IS NULL)
        OR (state = 'retired' AND retired_at IS NOT NULL AND retired_at >= created_at
            AND private_key_ciphertext IS NULL)
    ),
    CONSTRAINT kubernetes_cluster_ca_cluster_fk FOREIGN KEY (workspace_id, network_id, kubernetes_cluster_id)
        REFERENCES mesh.kubernetes_cluster (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT kubernetes_cluster_ca_data_key_fk FOREIGN KEY (workspace_id, network_id, data_key_id)
        REFERENCES mesh.kubernetes_ca_data_key (workspace_id, network_id, id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX kubernetes_cluster_ca_next_idx
    ON mesh.kubernetes_cluster_ca (kubernetes_cluster_id) WHERE state = 'next';
CREATE UNIQUE INDEX kubernetes_cluster_ca_active_idx
    ON mesh.kubernetes_cluster_ca (kubernetes_cluster_id) WHERE state = 'active';
CREATE UNIQUE INDEX kubernetes_cluster_ca_retiring_idx
    ON mesh.kubernetes_cluster_ca (kubernetes_cluster_id) WHERE state = 'retiring';
CREATE INDEX kubernetes_cluster_ca_live_idx
    ON mesh.kubernetes_cluster_ca (workspace_id, network_id, kubernetes_cluster_id) WHERE state <> 'retired';
CREATE INDEX kubernetes_cluster_ca_data_key_idx ON mesh.kubernetes_cluster_ca (data_key_id);

-- When the worker should next look at a cluster: due now when the cluster
-- is created or deleted, otherwise when the worker scheduled it (at most a
-- day ahead). The row goes once a deleted cluster has no CA left.
CREATE TABLE mesh_ops.kubernetes_cluster_ca_schedule (
    kubernetes_cluster_id BIGINT PRIMARY KEY,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    next_action_at TIMESTAMPTZ NOT NULL,
    failures INTEGER NOT NULL DEFAULT 0 CHECK (failures BETWEEN 0 AND 1000000),
    last_failure_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT kubernetes_cluster_ca_schedule_failure_check CHECK ((failures = 0) = (last_failure_at IS NULL)),
    CONSTRAINT kubernetes_cluster_ca_schedule_cluster_fk FOREIGN KEY (workspace_id, network_id, kubernetes_cluster_id)
        REFERENCES mesh.kubernetes_cluster (workspace_id, network_id, id) ON DELETE RESTRICT
);
CREATE INDEX kubernetes_cluster_ca_schedule_due_idx
    ON mesh_ops.kubernetes_cluster_ca_schedule (next_action_at, workspace_id, network_id);
CREATE INDEX kubernetes_cluster_ca_schedule_network_idx
    ON mesh_ops.kubernetes_cluster_ca_schedule (workspace_id, network_id);

-- Each worker process that can sign beats every 30 s; control offers
-- certificates only while some beat is fresh (a3). A worker without its
-- custody beats not ready.
CREATE TABLE mesh_ops.kubernetes_ca_worker_heartbeat (
    deployment_id BIGINT NOT NULL REFERENCES mesh.deployment (id) ON DELETE RESTRICT,
    instance_public_id UUID NOT NULL,
    ready_until TIMESTAMPTZ NOT NULL,
    worker_version TEXT NOT NULL CHECK (
        pg_catalog.octet_length(worker_version) BETWEEN 1 AND 64 AND worker_version ~ '^[!-~]+$'
    ),
    custody TEXT NOT NULL CHECK (custody IN ('file', 'kms', 'none')),
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (deployment_id, instance_public_id),
    CONSTRAINT kubernetes_ca_worker_heartbeat_ready_check CHECK (
        ready_until >= updated_at AND ready_until <= updated_at + INTERVAL '5 minutes'
        AND (custody <> 'none' OR ready_until = updated_at)
    )
);

ALTER TABLE mesh.kubernetes_ca_data_key ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.kubernetes_ca_data_key FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_ca_data_key_migrator_policy ON mesh.kubernetes_ca_data_key
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
ALTER TABLE mesh.kubernetes_cluster_ca ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.kubernetes_cluster_ca FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_cluster_ca_migrator_policy ON mesh.kubernetes_cluster_ca
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
ALTER TABLE mesh_ops.kubernetes_cluster_ca_schedule ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.kubernetes_cluster_ca_schedule FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_cluster_ca_schedule_migrator_policy ON mesh_ops.kubernetes_cluster_ca_schedule
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
ALTER TABLE mesh_ops.kubernetes_ca_worker_heartbeat ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.kubernetes_ca_worker_heartbeat FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_ca_worker_heartbeat_migrator_policy ON mesh_ops.kubernetes_ca_worker_heartbeat
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.kubernetes_ca_data_key, mesh.kubernetes_cluster_ca,
    mesh_ops.kubernetes_cluster_ca_schedule, mesh_ops.kubernetes_ca_worker_heartbeat
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE TRIGGER kubernetes_cluster_ca_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.kubernetes_cluster_ca
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('kubernetes_cluster_ca', 'public_id');

-- A data key changes only from active to retired; a CA only moves forward
-- (next → active → retiring → retired, or straight to retired), dropping
-- its sealed key when it stops signing. Neither is ever deleted.
CREATE FUNCTION mesh_ops.guard_kubernetes_ca_row_v1()
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
            OR NEW.custody IS DISTINCT FROM OLD.custody OR NEW.key_id IS DISTINCT FROM OLD.key_id
            OR NEW.ciphertext IS DISTINCT FROM OLD.ciphertext OR NEW.created_at IS DISTINCT FROM OLD.created_at
            OR NOT (OLD.state = 'active' AND NEW.state = 'retired') THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Kubernetes CA data key change';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.id IS DISTINCT FROM OLD.id OR NEW.public_id IS DISTINCT FROM OLD.public_id
        OR NEW.workspace_id IS DISTINCT FROM OLD.workspace_id OR NEW.network_id IS DISTINCT FROM OLD.network_id
        OR NEW.kubernetes_cluster_id IS DISTINCT FROM OLD.kubernetes_cluster_id
        OR NEW.data_key_id IS DISTINCT FROM OLD.data_key_id OR NEW.reason IS DISTINCT FROM OLD.reason
        OR NEW.issuer_kind IS DISTINCT FROM OLD.issuer_kind OR NEW.certificate IS DISTINCT FROM OLD.certificate
        OR NEW.fingerprint IS DISTINCT FROM OLD.fingerprint
        OR NEW.cluster_dns_name IS DISTINCT FROM OLD.cluster_dns_name
        OR NEW.not_before IS DISTINCT FROM OLD.not_before OR NEW.not_after IS DISTINCT FROM OLD.not_after
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
        OR (OLD.activated_at IS NOT NULL AND NEW.activated_at IS DISTINCT FROM OLD.activated_at)
        OR (OLD.retiring_at IS NOT NULL AND NEW.retiring_at IS DISTINCT FROM OLD.retiring_at)
        OR NEW.private_key_ciphertext IS NOT NULL AND NEW.private_key_ciphertext IS DISTINCT FROM OLD.private_key_ciphertext
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
FOR EACH ROW EXECUTE FUNCTION mesh_ops.guard_kubernetes_ca_row_v1();
CREATE TRIGGER kubernetes_cluster_ca_guard
BEFORE UPDATE OR DELETE ON mesh.kubernetes_cluster_ca
FOR EACH ROW EXECUTE FUNCTION mesh_ops.guard_kubernetes_ca_row_v1();

-- A cluster created or deleted is due now. The trigger runs as its owner:
-- the runtime that writes clusters has no right on the schedule.
CREATE FUNCTION mesh_ops.schedule_kubernetes_cluster_ca_change_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
BEGIN
    INSERT INTO mesh_ops.kubernetes_cluster_ca_schedule AS schedule (
        kubernetes_cluster_id, workspace_id, network_id, next_action_at, updated_at
    ) VALUES (NEW.id, NEW.workspace_id, NEW.network_id, v_now, v_now)
    ON CONFLICT (kubernetes_cluster_id) DO UPDATE
    SET next_action_at = LEAST(schedule.next_action_at, EXCLUDED.next_action_at),
        updated_at = EXCLUDED.updated_at;
    RETURN NULL;
END;
$function$;
CREATE TRIGGER kubernetes_cluster_ca_schedule_created
AFTER INSERT ON mesh.kubernetes_cluster
FOR EACH ROW EXECUTE FUNCTION mesh_ops.schedule_kubernetes_cluster_ca_change_v1();
CREATE TRIGGER kubernetes_cluster_ca_schedule_state
AFTER UPDATE OF state ON mesh.kubernetes_cluster
FOR EACH ROW WHEN (OLD.state IS DISTINCT FROM NEW.state)
EXECUTE FUNCTION mesh_ops.schedule_kubernetes_cluster_ca_change_v1();

-- Every active cluster is due once the worker can run.
INSERT INTO mesh_ops.kubernetes_cluster_ca_schedule (
    kubernetes_cluster_id, workspace_id, network_id, next_action_at, updated_at
)
SELECT cluster.id, cluster.workspace_id, cluster.network_id, pg_catalog.transaction_timestamp(),
    pg_catalog.transaction_timestamp()
FROM mesh.kubernetes_cluster AS cluster
WHERE cluster.state = 'active';

-- The installation the worker names, or an error.
CREATE FUNCTION mesh_ops.kubernetes_ca_deployment_internal_v1(p_deployment_public_id UUID)
RETURNS BIGINT
LANGUAGE plpgsql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_deployment_id BIGINT;
BEGIN
    SELECT deployment.id INTO v_deployment_id
    FROM mesh.deployment AS deployment
    WHERE deployment.installation_public_id = p_deployment_public_id;
    IF v_deployment_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Kubernetes CA installation is unavailable';
    END IF;
    RETURN v_deployment_id;
END;
$function$;

-- The internal ids of a Network of the installation, with the Network
-- lock of the CA lifecycle held by this transaction: taken here, or held
-- already (advisory locks re-enter). busy is true when another transaction
-- holds it; no id is returned then.
CREATE FUNCTION mesh_ops.kubernetes_ca_network_internal_v1(
    p_deployment_public_id UUID, p_workspace_public_id UUID, p_network_public_id UUID,
    OUT workspace_id BIGINT, OUT network_id BIGINT, OUT busy BOOLEAN
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
    busy := NOT pg_catalog.pg_try_advisory_xact_lock(
        pg_catalog.hashtextextended('meshtransit/kubernetes-ca/' || p_network_public_id::TEXT, 0));
    IF busy THEN
        workspace_id := NULL;
        network_id := NULL;
    END IF;
END;
$function$;

-- The Networks of the installation with a cluster due, earliest first.
CREATE FUNCTION mesh_ops.read_kubernetes_ca_work_v1(p_deployment_public_id UUID, p_limit INTEGER)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_deployment_id BIGINT;
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_networks JSONB;
    v_scan TEXT := pg_catalog.current_setting('mesh.access_ledger_scan', TRUE);
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes CA work limit';
    END IF;
    v_deployment_id := mesh_ops.kubernetes_ca_deployment_internal_v1(p_deployment_public_id);
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    WITH due AS (
        SELECT schedule.workspace_id, schedule.network_id, pg_catalog.min(schedule.next_action_at) AS due_at
        FROM mesh_ops.kubernetes_cluster_ca_schedule AS schedule
        WHERE schedule.next_action_at <= v_now
        GROUP BY schedule.workspace_id, schedule.network_id
    ), listed AS (
        SELECT workspace.public_id AS workspace_public_id, network.public_id AS network_public_id, due.due_at
        FROM due
        JOIN mesh.workspace AS workspace ON workspace.id = due.workspace_id
        JOIN mesh.network AS network ON network.workspace_id = due.workspace_id AND network.id = due.network_id
        WHERE workspace.deployment_id = v_deployment_id
        ORDER BY due.due_at, network.public_id
        LIMIT p_limit
    )
    SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'workspace_id', listed.workspace_public_id, 'network_id', listed.network_public_id
    ) ORDER BY listed.due_at, listed.network_public_id), '[]'::JSONB) INTO v_networks
    FROM listed;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', COALESCE(v_scan, ''), TRUE);
    RETURN pg_catalog.jsonb_build_object('now', v_now, 'networks', v_networks);
END;
$function$;

-- Takes the Network's CA lock and reads what the worker decides from: the
-- tenant codes that name the clusters, the data keys, and the 96 scheduled
-- clusters due first (64 active at most, and deleted ones until their CAs
-- retire) with their CAs that are not retired. outcome is 'busy' when another
-- worker holds the Network.
CREATE FUNCTION mesh_ops.lock_kubernetes_ca_network_v1(
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
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
BEGIN
    SELECT * INTO STRICT v_scope
    FROM mesh_ops.kubernetes_ca_network_internal_v1(p_deployment_public_id, p_workspace_public_id, p_network_public_id);
    IF v_scope.busy THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'busy');
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'outcome', 'locked',
        'now', v_now,
        'workspace_code', (SELECT display.display_code FROM mesh_ops.tenant_display_identity AS display
            WHERE display.workspace_public_id = p_workspace_public_id),
        'network_code', (SELECT display.display_code FROM mesh_ops.tenant_display_identity AS display
            WHERE display.network_public_id = p_network_public_id),
        'data_keys', COALESCE((
            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                'id', data_key.public_id, 'custody', data_key.custody, 'key_id', data_key.key_id,
                'ciphertext', pg_catalog.encode(data_key.ciphertext, 'hex'), 'active', data_key.state = 'active'
            ) ORDER BY data_key.id)
            FROM mesh.kubernetes_ca_data_key AS data_key
            WHERE data_key.workspace_id = v_scope.workspace_id AND data_key.network_id = v_scope.network_id
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
                        'id', ca.public_id, 'version', ca.version, 'state', ca.state, 'reason', ca.reason,
                        'data_key_id', data_key.public_id,
                        'certificate', pg_catalog.encode(ca.certificate, 'hex'),
                        'cluster_dns_name', ca.cluster_dns_name,
                        'not_before', ca.not_before, 'not_after', ca.not_after,
                        'sealed_key', pg_catalog.encode(ca.private_key_ciphertext, 'hex'),
                        'created_at', ca.created_at, 'activated_at', ca.activated_at, 'retiring_at', ca.retiring_at
                    ) ORDER BY ca.id)
                    FROM mesh.kubernetes_cluster_ca AS ca
                    JOIN mesh.kubernetes_ca_data_key AS data_key ON data_key.id = ca.data_key_id
                    WHERE ca.workspace_id = cluster.workspace_id AND ca.network_id = cluster.network_id
                      AND ca.kubernetes_cluster_id = cluster.id AND ca.state <> 'retired'
                ), '[]'::JSONB)
            ) ORDER BY schedule.next_action_at, cluster.id)
            FROM (
                SELECT listed.* FROM mesh_ops.kubernetes_cluster_ca_schedule AS listed
                WHERE listed.workspace_id = v_scope.workspace_id AND listed.network_id = v_scope.network_id
                ORDER BY listed.next_action_at, listed.kubernetes_cluster_id
                LIMIT 96
            ) AS schedule
            JOIN mesh.kubernetes_cluster AS cluster
              ON cluster.workspace_id = schedule.workspace_id AND cluster.network_id = schedule.network_id
             AND cluster.id = schedule.kubernetes_cluster_id
        ), '[]'::JSONB)
    );
END;
$function$;

-- Stores the Network's first data key, wrapped by the custody, unless
-- another worker stored one first; returns the active key either way.
CREATE FUNCTION mesh_ops.add_kubernetes_ca_data_key_v1(
    p_deployment_public_id UUID, p_workspace_public_id UUID, p_network_public_id UUID,
    p_data_key_public_id UUID, p_custody TEXT, p_key_id TEXT, p_ciphertext BYTEA
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
    v_key RECORD;
BEGIN
    IF p_data_key_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_data_key_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes CA data key';
    END IF;
    SELECT * INTO STRICT v_scope
    FROM mesh_ops.kubernetes_ca_network_internal_v1(p_deployment_public_id, p_workspace_public_id, p_network_public_id);
    IF v_scope.busy THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'busy');
    END IF;
    INSERT INTO mesh.kubernetes_ca_data_key (
        public_id, workspace_id, network_id, custody, key_id, ciphertext, state, created_at
    ) VALUES (
        p_data_key_public_id, v_scope.workspace_id, v_scope.network_id, p_custody, p_key_id, p_ciphertext, 'active',
        pg_catalog.clock_timestamp()
    )
    ON CONFLICT (workspace_id, network_id) WHERE state = 'active' DO NOTHING;
    SELECT data_key.public_id, data_key.custody, data_key.key_id, data_key.ciphertext INTO STRICT v_key
    FROM mesh.kubernetes_ca_data_key AS data_key
    WHERE data_key.workspace_id = v_scope.workspace_id AND data_key.network_id = v_scope.network_id
      AND data_key.state = 'active';
    RETURN pg_catalog.jsonb_build_object(
        'outcome', CASE WHEN v_key.public_id = p_data_key_public_id THEN 'added' ELSE 'existing' END,
        'id', v_key.public_id, 'custody', v_key.custody, 'key_id', v_key.key_id,
        'ciphertext', pg_catalog.encode(v_key.ciphertext, 'hex')
    );
END;
$function$;

-- The audit action of a CA row change.
CREATE FUNCTION mesh_ops.kubernetes_cluster_ca_action_internal_v1(p_operation TEXT, p_state TEXT)
RETURNS TEXT
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT CASE
        WHEN p_operation = 'insert' THEN 'kubernetes_cluster.ca_created'
        WHEN p_operation = 'update' AND p_state = 'active' THEN 'kubernetes_cluster.ca_activated'
        WHEN p_operation = 'update' AND p_state = 'retiring' THEN 'kubernetes_cluster.ca_retiring'
        WHEN p_operation = 'update' AND p_state = 'retired' THEN 'kubernetes_cluster.ca_retired'
    END
$function$;

-- What a CA's audit event says: never key material.
CREATE FUNCTION mesh_ops.kubernetes_cluster_ca_payload_internal_v1(p_ca_id BIGINT)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'format', 'kubernetes-cluster-ca/v1',
        'ca_id', ca.public_id,
        'cluster_id', cluster.public_id,
        'state', ca.state,
        'reason', ca.reason,
        'state_reason', ca.state_reason,
        'issuer_kind', ca.issuer_kind,
        'fingerprint', pg_catalog.encode(ca.fingerprint, 'hex'),
        'cluster_dns_name', ca.cluster_dns_name,
        'not_before', ca.not_before,
        'not_after', ca.not_after,
        'custody', data_key.custody,
        'data_key_id', data_key.public_id,
        'version', ca.version
    )
    FROM mesh.kubernetes_cluster_ca AS ca
    JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = ca.kubernetes_cluster_id
    JOIN mesh.kubernetes_ca_data_key AS data_key ON data_key.id = ca.data_key_id
    WHERE ca.id = p_ca_id
$function$;

-- The head of the Network's audit stream and the payload of a CA row this
-- transaction changed, for the worker to hash and append.
CREATE FUNCTION mesh_ops.kubernetes_cluster_ca_proof_internal_v1(p_ca_id BIGINT, p_operation TEXT)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_ca mesh.kubernetes_cluster_ca%ROWTYPE;
    v_revision BIGINT;
    v_stream RECORD;
    v_payload JSONB;
    v_scan TEXT := pg_catalog.current_setting('mesh.access_ledger_scan', TRUE);
BEGIN
    SELECT ca.* INTO STRICT v_ca FROM mesh.kubernetes_cluster_ca AS ca WHERE ca.id = p_ca_id;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    SELECT revision.network_revision INTO v_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_ca.workspace_id AND revision.network_id = v_ca.network_id;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', COALESCE(v_scan, ''), TRUE);
    IF v_revision IS NULL OR v_revision < 1 THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Network revision is unavailable';
    END IF;
    SELECT stream.id, stream.next_sequence, stream.latest_event_hash INTO v_stream
    FROM mesh_audit.audit_stream AS stream
    WHERE stream.scope_kind = 'network'
      AND stream.workspace_id = v_ca.workspace_id AND stream.network_id = v_ca.network_id
    FOR UPDATE;
    IF v_stream.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Network audit stream is unavailable';
    END IF;
    v_payload := mesh_ops.kubernetes_cluster_ca_payload_internal_v1(v_ca.id);
    RETURN pg_catalog.jsonb_build_object(
        'outcome', 'changed',
        'action', mesh_ops.kubernetes_cluster_ca_action_internal_v1(p_operation, v_ca.state),
        'ca_id', v_ca.public_id,
        'version', v_ca.version,
        'network_revision', v_revision,
        'semantic_hash', pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(v_payload::TEXT, 'UTF8')), 'hex'),
        'stream_id', v_stream.id,
        'sequence', v_stream.next_sequence,
        'previous_hash', pg_catalog.encode(v_stream.latest_event_hash, 'hex'),
        'payload', v_payload::TEXT
    );
END;
$function$;

-- Creates a cluster's CA, active or next, as one change. The cluster must
-- be active and the data key the Network's active one; the fingerprint is
-- computed here. Returns the proof to append, or outcome 'busy'.
CREATE FUNCTION mesh_ops.create_kubernetes_cluster_ca_v1(
    p_deployment_public_id UUID, p_workspace_public_id UUID, p_network_public_id UUID,
    p_cluster_public_id UUID, p_ca_public_id UUID, p_change_public_id UUID,
    p_state TEXT, p_reason TEXT, p_data_key_public_id UUID, p_certificate BYTEA, p_cluster_dns_name TEXT,
    p_not_before TIMESTAMPTZ, p_not_after TIMESTAMPTZ, p_sealed_key BYTEA
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
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_row_id BIGINT;
BEGIN
    IF p_ca_public_id IS NULL OR p_change_public_id IS NULL OR p_cluster_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_ca_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR p_ca_public_id = p_change_public_id
        OR p_state IS NULL OR p_state NOT IN ('active', 'next')
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

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    INSERT INTO mesh.kubernetes_cluster_ca (
        public_id, workspace_id, network_id, kubernetes_cluster_id, data_key_id, state, reason, state_reason,
        certificate, fingerprint, cluster_dns_name, not_before, not_after, private_key_ciphertext,
        created_at, activated_at
    ) VALUES (
        p_ca_public_id, v_scope.workspace_id, v_scope.network_id, v_cluster_id, v_data_key_id, p_state, p_reason,
        p_reason, p_certificate, pg_catalog.sha256(p_certificate), p_cluster_dns_name, p_not_before, p_not_after,
        p_sealed_key, v_now, CASE WHEN p_state = 'active' THEN v_now END
    )
    RETURNING id INTO v_row_id;
    RETURN mesh_ops.kubernetes_cluster_ca_proof_internal_v1(v_row_id, 'insert');
END;
$function$;

-- Moves a CA forward as one change, if it is still at p_version: next to
-- active, active to retiring, or any to retired. Returns the proof to
-- append, or outcome 'busy' or 'stale'.
CREATE FUNCTION mesh_ops.move_kubernetes_cluster_ca_v1(
    p_deployment_public_id UUID, p_workspace_public_id UUID, p_network_public_id UUID,
    p_ca_public_id UUID, p_change_public_id UUID, p_version BIGINT, p_state TEXT, p_reason TEXT
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
    IF p_ca_public_id IS NULL OR p_change_public_id IS NULL OR p_version IS NULL OR p_version < 1
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_ca_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR p_ca_public_id = p_change_public_id
        OR p_state IS NULL OR p_state NOT IN ('active', 'retiring', 'retired')
        OR p_reason IS NULL OR p_reason NOT IN (
            'scheduled', 'name_changed', 'admin', 'emergency', 'compromise', 'cluster_deleted', 'expired'
        ) THEN
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
    -- A next CA becomes active only while its cluster is.
    IF p_state = 'active' THEN
        PERFORM 1 FROM mesh.kubernetes_cluster AS cluster
        WHERE cluster.id = v_ca.kubernetes_cluster_id AND cluster.state = 'active'
        FOR SHARE;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Kubernetes cluster is unavailable';
        END IF;
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    UPDATE mesh.kubernetes_cluster_ca AS ca
    SET version = ca.version + 1,
        state = p_state,
        state_reason = p_reason,
        activated_at = CASE WHEN p_state = 'active' THEN v_now ELSE ca.activated_at END,
        retiring_at = CASE WHEN p_state = 'retiring' THEN v_now ELSE ca.retiring_at END,
        retired_at = CASE WHEN p_state = 'retired' THEN v_now ELSE ca.retired_at END,
        private_key_ciphertext = CASE WHEN p_state = 'active' THEN ca.private_key_ciphertext END
    WHERE ca.id = v_ca.id;
    RETURN mesh_ops.kubernetes_cluster_ca_proof_internal_v1(v_ca.id, 'update');
END;
$function$;

-- Appends the audit event of the CA row change create_ or
-- move_kubernetes_cluster_ca_v1 made in this transaction and change.
CREATE FUNCTION mesh_ops.append_kubernetes_cluster_ca_evidence_v1(
    p_ca_public_id UUID,
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
    v_ca mesh.kubernetes_cluster_ca%ROWTYPE;
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
    IF v_change IS NULL OR p_ca_public_id IS NULL OR p_stream_id IS NULL
        OR p_sequence IS NULL OR p_sequence <= 0
        OR p_previous_hash IS NULL OR pg_catalog.octet_length(p_previous_hash) <> 32
        OR p_event_hash IS NULL OR pg_catalog.octet_length(p_event_hash) <> 32
        OR p_audit_event_public_id IS NULL OR p_outbox_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_audit_event_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_outbox_public_id), 6) >> 4 <> 7
        OR p_audit_event_public_id = p_outbox_public_id
        OR p_audit_event_public_id IN (v_change, p_ca_public_id)
        OR p_outbox_public_id IN (v_change, p_ca_public_id) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Kubernetes cluster CA evidence';
    END IF;
    -- The change is exactly this CA's one mutation, at its current version.
    SELECT mutation.operation INTO v_operation
    FROM mesh_audit.authority_mutation AS mutation
    WHERE mutation.change_public_id = v_change AND mutation.transaction_id = v_transaction
      AND mutation.aggregate_kind = 'kubernetes_cluster_ca' AND mutation.row_public_id = p_ca_public_id;
    SELECT ca.* INTO v_ca
    FROM mesh.kubernetes_cluster_ca AS ca
    JOIN mesh_audit.authority_mutation AS mutation
      ON mutation.change_public_id = v_change AND mutation.transaction_id = v_transaction
     AND mutation.aggregate_kind = 'kubernetes_cluster_ca' AND mutation.row_public_id = ca.public_id
     AND mutation.operation IN ('insert', 'update') AND mutation.after_version = ca.version
    JOIN mesh_audit.audit_stream AS stream
      ON stream.id = p_stream_id AND stream.scope_kind = 'network'
     AND stream.workspace_id = ca.workspace_id AND stream.network_id = ca.network_id
    WHERE ca.public_id = p_ca_public_id;
    IF v_ca.id IS NULL
        OR (SELECT pg_catalog.count(*) FROM mesh_audit.authority_mutation AS mutation
            WHERE mutation.change_public_id = v_change AND mutation.transaction_id = v_transaction) <> 1
        OR p_payload IS DISTINCT FROM mesh_ops.kubernetes_cluster_ca_payload_internal_v1(v_ca.id) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Kubernetes cluster CA evidence';
    END IF;
    v_action := mesh_ops.kubernetes_cluster_ca_action_internal_v1(v_operation, v_ca.state);
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    SELECT revision.network_revision INTO STRICT v_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_ca.workspace_id AND revision.network_id = v_ca.network_id;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', COALESCE(v_scan, ''), TRUE);
    -- The event hash covers the revision the proof read: another writer
    -- that moved it since makes the worker redo the whole change.
    IF p_network_revision IS DISTINCT FROM v_revision THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Network revision changed';
    END IF;
    RETURN mesh_audit.append_authority_evidence(
        p_stream_id, p_audit_event_public_id, p_outbox_public_id, p_sequence, p_previous_hash, p_event_hash,
        'kubernetes_cluster_ca', v_ca.public_id, v_ca.version, v_revision, NULL::UUID,
        v_action, 'system.reconcile', NULL::UUID, NULL::BYTEA,
        pg_catalog.sha256(pg_catalog.convert_to(p_payload::TEXT, 'UTF8')),
        p_payload, v_action, p_payload
    );
END;
$function$;

-- Sets when the worker should next look at a cluster: no earlier than now,
-- no later than a day ahead. failed counts a failed look. A null time ends
-- the schedule of a deleted cluster that has no CA left.
CREATE FUNCTION mesh_ops.schedule_kubernetes_cluster_ca_v1(
    p_deployment_public_id UUID, p_workspace_public_id UUID, p_network_public_id UUID,
    p_cluster_public_id UUID, p_next_action_at TIMESTAMPTZ, p_failed BOOLEAN
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
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_at TIMESTAMPTZ;
BEGIN
    IF p_cluster_public_id IS NULL OR p_failed IS NULL OR (p_next_action_at IS NULL AND p_failed) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes CA schedule';
    END IF;
    SELECT * INTO STRICT v_scope
    FROM mesh_ops.kubernetes_ca_network_internal_v1(p_deployment_public_id, p_workspace_public_id, p_network_public_id);
    IF v_scope.busy THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'busy');
    END IF;
    -- Locked, so a delete committed while the worker planned is seen here.
    SELECT cluster.* INTO v_cluster
    FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.workspace_id = v_scope.workspace_id AND cluster.network_id = v_scope.network_id
      AND cluster.public_id = p_cluster_public_id
    FOR SHARE;
    IF v_cluster.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Kubernetes cluster is unavailable';
    END IF;
    IF p_next_action_at IS NULL THEN
        IF v_cluster.state <> 'deleted' OR EXISTS (
            SELECT 1 FROM mesh.kubernetes_cluster_ca AS ca
            WHERE ca.kubernetes_cluster_id = v_cluster.id AND ca.state <> 'retired'
        ) THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Kubernetes cluster still has CAs to keep';
        END IF;
        DELETE FROM mesh_ops.kubernetes_cluster_ca_schedule AS schedule
        WHERE schedule.kubernetes_cluster_id = v_cluster.id;
        RETURN pg_catalog.jsonb_build_object('outcome', 'done');
    END IF;
    v_at := GREATEST(v_now, LEAST(p_next_action_at, v_now + INTERVAL '1 day'));
    -- A deleted cluster's CAs retire at once (K1a4 §15.11).
    IF v_cluster.state = 'deleted' AND EXISTS (
        SELECT 1 FROM mesh.kubernetes_cluster_ca AS ca
        WHERE ca.kubernetes_cluster_id = v_cluster.id AND ca.state <> 'retired'
    ) THEN
        v_at := v_now;
    END IF;
    INSERT INTO mesh_ops.kubernetes_cluster_ca_schedule AS schedule (
        kubernetes_cluster_id, workspace_id, network_id, next_action_at, failures, last_failure_at, updated_at
    ) VALUES (
        v_cluster.id, v_cluster.workspace_id, v_cluster.network_id, v_at,
        CASE WHEN p_failed THEN 1 ELSE 0 END, CASE WHEN p_failed THEN v_now END, v_now
    )
    ON CONFLICT (kubernetes_cluster_id) DO UPDATE
    SET next_action_at = EXCLUDED.next_action_at,
        failures = CASE WHEN p_failed THEN LEAST(schedule.failures + 1, 1000000) ELSE 0 END,
        last_failure_at = EXCLUDED.last_failure_at,
        updated_at = EXCLUDED.updated_at;
    RETURN pg_catalog.jsonb_build_object('outcome', 'scheduled', 'next_action_at', v_at);
END;
$function$;

-- Postpones a Network's due clusters after a failed look, without the
-- worker reading them: no earlier than a minute, no later than a day.
CREATE FUNCTION mesh_ops.postpone_kubernetes_ca_network_v1(
    p_deployment_public_id UUID, p_workspace_public_id UUID, p_network_public_id UUID, p_until TIMESTAMPTZ
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
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_postponed INTEGER;
BEGIN
    IF p_until IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes CA postponement';
    END IF;
    SELECT * INTO STRICT v_scope
    FROM mesh_ops.kubernetes_ca_network_internal_v1(p_deployment_public_id, p_workspace_public_id, p_network_public_id);
    IF v_scope.busy THEN
        RETURN pg_catalog.jsonb_build_object('outcome', 'busy');
    END IF;
    UPDATE mesh_ops.kubernetes_cluster_ca_schedule AS schedule
    SET next_action_at = GREATEST(v_now + INTERVAL '1 minute', LEAST(p_until, v_now + INTERVAL '1 day')),
        failures = LEAST(schedule.failures + 1, 1000000),
        last_failure_at = v_now,
        updated_at = v_now
    WHERE schedule.workspace_id = v_scope.workspace_id AND schedule.network_id = v_scope.network_id
      AND schedule.next_action_at <= v_now;
    GET DIAGNOSTICS v_postponed = ROW_COUNT;
    RETURN pg_catalog.jsonb_build_object('outcome', 'postponed', 'clusters', v_postponed);
END;
$function$;

-- A worker process says whether it can sign for the next 90 s, and drops
-- the beats of processes gone for a day.
CREATE FUNCTION mesh_ops.beat_kubernetes_ca_worker_v1(
    p_deployment_public_id UUID, p_instance_public_id UUID, p_ready BOOLEAN, p_worker_version TEXT,
    p_custody TEXT
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
    IF p_instance_public_id IS NULL OR p_ready IS NULL OR (p_ready AND p_custody = 'none') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes CA worker heartbeat';
    END IF;
    v_deployment_id := mesh_ops.kubernetes_ca_deployment_internal_v1(p_deployment_public_id);
    v_ready_until := CASE WHEN p_ready THEN v_now + INTERVAL '90 seconds' ELSE v_now END;
    INSERT INTO mesh_ops.kubernetes_ca_worker_heartbeat AS beat (
        deployment_id, instance_public_id, ready_until, worker_version, custody, updated_at
    ) VALUES (v_deployment_id, p_instance_public_id, v_ready_until, p_worker_version, p_custody, v_now)
    ON CONFLICT (deployment_id, instance_public_id) DO UPDATE
    SET ready_until = EXCLUDED.ready_until, worker_version = EXCLUDED.worker_version,
        custody = EXCLUDED.custody, updated_at = EXCLUDED.updated_at;
    DELETE FROM mesh_ops.kubernetes_ca_worker_heartbeat AS beat
    WHERE beat.deployment_id = v_deployment_id AND beat.updated_at < v_now - INTERVAL '1 day';
    RETURN v_ready_until;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.guard_kubernetes_ca_row_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.schedule_kubernetes_cluster_ca_change_v1() FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_ca_deployment_internal_v1(UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_ca_network_internal_v1(UUID, UUID, UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_cluster_ca_action_internal_v1(TEXT, TEXT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_cluster_ca_payload_internal_v1(BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_cluster_ca_proof_internal_v1(BIGINT, TEXT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.read_kubernetes_ca_work_v1(UUID, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.lock_kubernetes_ca_network_v1(UUID, UUID, UUID)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.add_kubernetes_ca_data_key_v1(UUID, UUID, UUID, UUID, TEXT, TEXT, BYTEA)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.create_kubernetes_cluster_ca_v1(
    UUID, UUID, UUID, UUID, UUID, UUID, TEXT, TEXT, UUID, BYTEA, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, BYTEA
) FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.move_kubernetes_cluster_ca_v1(UUID, UUID, UUID, UUID, UUID, BIGINT, TEXT, TEXT)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.append_kubernetes_cluster_ca_evidence_v1(
    UUID, BIGINT, BIGINT, BYTEA, BYTEA, UUID, UUID, JSONB, BIGINT
) FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.schedule_kubernetes_cluster_ca_v1(UUID, UUID, UUID, UUID, TIMESTAMPTZ, BOOLEAN)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.postpone_kubernetes_ca_network_v1(UUID, UUID, UUID, TIMESTAMPTZ)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.beat_kubernetes_ca_worker_v1(UUID, UUID, BOOLEAN, TEXT, TEXT)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
-- Only the worker keeps the CAs (K1a4 §3, Q3).
GRANT EXECUTE ON FUNCTION mesh_ops.read_kubernetes_ca_work_v1(UUID, INTEGER) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.lock_kubernetes_ca_network_v1(UUID, UUID, UUID) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.add_kubernetes_ca_data_key_v1(UUID, UUID, UUID, UUID, TEXT, TEXT, BYTEA)
    TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.create_kubernetes_cluster_ca_v1(
    UUID, UUID, UUID, UUID, UUID, UUID, TEXT, TEXT, UUID, BYTEA, TEXT, TIMESTAMPTZ, TIMESTAMPTZ, BYTEA
) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.move_kubernetes_cluster_ca_v1(UUID, UUID, UUID, UUID, UUID, BIGINT, TEXT, TEXT)
    TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.append_kubernetes_cluster_ca_evidence_v1(
    UUID, BIGINT, BIGINT, BYTEA, BYTEA, UUID, UUID, JSONB, BIGINT
) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.schedule_kubernetes_cluster_ca_v1(UUID, UUID, UUID, UUID, TIMESTAMPTZ, BOOLEAN)
    TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.postpone_kubernetes_ca_network_v1(UUID, UUID, UUID, TIMESTAMPTZ)
    TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.beat_kubernetes_ca_worker_v1(UUID, UUID, BOOLEAN, TEXT, TEXT) TO mesh_worker;
