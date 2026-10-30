-- Schema 252 (K1d d2a, docs/k8s-k1d-console-design.md §4.1, Q156-Q163):
-- those who may approve a cluster's replicas ask the CA worker to retire one
-- of its CAs. The API only records the request; the worker retires the CA
-- under the Network's CA lock and marks the request done in the same
-- transaction, or refuses it (expired after an hour, the CA changed, the
-- restore guard is on for a reason other than compromise, the CA is gone).

-- Printable text of at most 256 characters: no control characters, and no
-- invisible format or separator characters that could make a reference
-- look like another in the Console or a SIEM (review d2a L8).
CREATE FUNCTION mesh_ops.kubernetes_ca_retire_text_is_valid_v1(p_text TEXT, p_allow_empty BOOLEAN)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT p_text IS NOT NULL AND p_allow_empty IS NOT NULL
        AND pg_catalog.char_length(p_text) <= 256 AND (p_allow_empty OR p_text <> '')
        AND p_text !~ '[[:cntrl:]]' AND p_text !~ '[\u2028\u2029\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]'
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_ca_retire_text_is_valid_v1(TEXT, BOOLEAN)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE TABLE mesh.kubernetes_ca_retire_request (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    kubernetes_cluster_id BIGINT NOT NULL,
    kubernetes_cluster_ca_id BIGINT NOT NULL,
    ca_version BIGINT NOT NULL CHECK (ca_version > 0),
    reason TEXT NOT NULL CHECK (reason IN ('admin', 'emergency', 'compromise')),
    -- What the person gave: a ticket or incident reference and a short
    -- note, printable text without line breaks (no secrets: the Console
    -- says so).
    change_ref TEXT NOT NULL CHECK (mesh_ops.kubernetes_ca_retire_text_is_valid_v1(change_ref, FALSE)),
    note TEXT NOT NULL CHECK (mesh_ops.kubernetes_ca_retire_text_is_valid_v1(note, TRUE)),
    requested_by_principal_id BIGINT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'done', 'refused')),
    refusal TEXT CHECK (refusal IN ('expired', 'changed', 'guard', 'gone')),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    finished_at TIMESTAMPTZ,
    CONSTRAINT kubernetes_ca_retire_request_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT kubernetes_ca_retire_request_expiry_check CHECK (expires_at = created_at + INTERVAL '1 hour'),
    CONSTRAINT kubernetes_ca_retire_request_finish_check CHECK (
        (state = 'pending') = (finished_at IS NULL) AND (state = 'refused') = (refusal IS NOT NULL)
        AND (finished_at IS NULL OR finished_at >= created_at)
    ),
    CONSTRAINT kubernetes_ca_retire_request_cluster_fk FOREIGN KEY (workspace_id, network_id, kubernetes_cluster_id)
        REFERENCES mesh.kubernetes_cluster (workspace_id, network_id, id) ON DELETE CASCADE,
    CONSTRAINT kubernetes_ca_retire_request_ca_fk
        FOREIGN KEY (workspace_id, network_id, kubernetes_cluster_id, kubernetes_cluster_ca_id)
        REFERENCES mesh.kubernetes_cluster_ca (workspace_id, network_id, kubernetes_cluster_id, id) ON DELETE CASCADE
);
-- One waiting request a CA (Q158).
CREATE UNIQUE INDEX kubernetes_ca_retire_request_pending_idx
    ON mesh.kubernetes_ca_retire_request (kubernetes_cluster_ca_id) WHERE state = 'pending';
-- Requests a person made in the last hour (Q157).
CREATE INDEX kubernetes_ca_retire_request_requester_idx
    ON mesh.kubernetes_ca_retire_request (workspace_id, requested_by_principal_id, created_at);
-- The worker's queue, oldest first.
CREATE INDEX kubernetes_ca_retire_request_queue_idx
    ON mesh.kubernetes_ca_retire_request (created_at, id) WHERE state = 'pending';
-- A cluster's requests, newest first.
CREATE INDEX kubernetes_ca_retire_request_cluster_idx
    ON mesh.kubernetes_ca_retire_request (kubernetes_cluster_id, created_at DESC, public_id DESC);
-- A request is an authority change of its own; the worker's outcome is a
-- transition the CA's sealed events record, so only the insert is captured.
CREATE TRIGGER kubernetes_ca_retire_request_authority_capture
AFTER INSERT ON mesh.kubernetes_ca_retire_request
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('kubernetes_ca_retire_request', 'public_id');
ALTER TABLE mesh.kubernetes_ca_retire_request ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.kubernetes_ca_retire_request FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_ca_retire_request_migrator_policy ON mesh.kubernetes_ca_retire_request
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.kubernetes_ca_retire_request
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- A request as the API and the Console read it.
CREATE FUNCTION mesh_ops.kubernetes_ca_retire_request_document_internal_v1(
    p_request mesh.kubernetes_ca_retire_request
)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'request_id', p_request.public_id,
        'ca_id', (SELECT ca.public_id FROM mesh.kubernetes_cluster_ca AS ca WHERE ca.id = p_request.kubernetes_cluster_ca_id),
        'ca_version', p_request.ca_version,
        'reason', p_request.reason,
        'change_ref', p_request.change_ref,
        'note', p_request.note,
        'requested_by_principal_id', (SELECT principal.public_id FROM mesh.principal AS principal
                                      WHERE principal.id = p_request.requested_by_principal_id),
        'state', p_request.state,
        'refusal', p_request.refusal,
        'created_at', p_request.created_at,
        'expires_at', p_request.expires_at,
        'finished_at', p_request.finished_at
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_ca_retire_request_document_internal_v1(mesh.kubernetes_ca_retire_request)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Records a request to retire a CA of an active cluster (kubernetes_cluster.approve).
-- A waiting request for the same CA with the same reason is returned
-- unchanged (created false), another reason is MTK41. A retired CA is
-- MTK40; a CA that moved past p_ca_version is 40001; a person's sixth
-- request within the hour is MTK42.
CREATE FUNCTION mesh_ops.request_kubernetes_ca_retire_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_ca_public_id UUID, p_ca_version BIGINT, p_reason TEXT, p_change_ref TEXT, p_note TEXT,
    p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_grant RECORD;
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
    v_ca mesh.kubernetes_cluster_ca%ROWTYPE;
    v_waiting mesh.kubernetes_ca_retire_request%ROWTYPE;
    v_request mesh.kubernetes_ca_retire_request%ROWTYPE;
    v_recent INTEGER;
BEGIN
    IF p_cluster_public_id IS NULL OR p_ca_public_id IS NULL OR p_ca_version IS NULL OR p_ca_version < 1
        OR p_reason IS NULL OR p_reason NOT IN ('admin', 'emergency', 'compromise')
        OR NOT mesh_ops.kubernetes_ca_retire_text_is_valid_v1(p_change_ref, FALSE)
        OR NOT mesh_ops.kubernetes_ca_retire_text_is_valid_v1(p_note, TRUE)
        OR p_change_public_id IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes CA retire request is invalid';
    END IF;
    SELECT * INTO v_grant FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'kubernetes_cluster.approve');
    SELECT * INTO v_cluster FROM mesh.kubernetes_cluster AS cluster
    WHERE cluster.workspace_id = v_grant.workspace_id AND cluster.network_id = v_grant.network_id
      AND cluster.public_id = p_cluster_public_id AND cluster.state = 'active'
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes cluster';
    END IF;
    SELECT * INTO v_ca FROM mesh.kubernetes_cluster_ca AS ca
    WHERE ca.workspace_id = v_cluster.workspace_id AND ca.network_id = v_cluster.network_id
      AND ca.kubernetes_cluster_id = v_cluster.id AND ca.public_id = p_ca_public_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes CA';
    END IF;
    IF v_ca.state = 'retired' THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK40', MESSAGE = 'the Kubernetes CA is already retired';
    END IF;
    -- Requests of one person, then of one CA, go one at a time (always in
    -- that order): the hourly count and the waiting request are read with
    -- no other request of theirs in flight (review d2a M3, L5).
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        'meshtransit/kubernetes-ca-retire/actor/' || v_grant.actor_id::TEXT, 0));
    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(
        'meshtransit/kubernetes-ca-retire/ca/' || v_ca.public_id::TEXT, 0));
    SELECT * INTO v_waiting FROM mesh.kubernetes_ca_retire_request AS request
    WHERE request.kubernetes_cluster_ca_id = v_ca.id AND request.state = 'pending'
    FOR UPDATE;
    -- A request past its hour no worker took holds nothing: it ends
    -- expired, as the worker would end it (review d2a L7).
    IF FOUND AND v_waiting.expires_at <= v_now THEN
        UPDATE mesh.kubernetes_ca_retire_request AS request
        SET state = 'refused', refusal = 'expired', finished_at = v_now, version = request.version + 1
        WHERE request.id = v_waiting.id;
        v_waiting := NULL;
    END IF;
    IF v_waiting.id IS NOT NULL THEN
        IF v_waiting.reason <> p_reason THEN
            RAISE EXCEPTION USING ERRCODE = 'MTK41', MESSAGE = 'another request to retire the CA is waiting';
        END IF;
        RETURN pg_catalog.jsonb_build_object(
            'network_id', p_network_public_id, 'cluster_id', p_cluster_public_id, 'created', FALSE,
            'request', mesh_ops.kubernetes_ca_retire_request_document_internal_v1(v_waiting));
    END IF;
    IF v_ca.version <> p_ca_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'the Kubernetes CA changed';
    END IF;
    SELECT pg_catalog.count(*) INTO v_recent FROM (
        SELECT 1 FROM mesh.kubernetes_ca_retire_request AS request
        WHERE request.workspace_id = v_grant.workspace_id AND request.requested_by_principal_id = v_grant.actor_id
          AND request.created_at > v_now - INTERVAL '1 hour'
        LIMIT 5) AS counted;
    IF v_recent >= 5 THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK42', MESSAGE = 'too many requests to retire CAs in the last hour';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    INSERT INTO mesh.kubernetes_ca_retire_request (
        public_id, workspace_id, network_id, kubernetes_cluster_id, kubernetes_cluster_ca_id, ca_version, reason,
        change_ref, note, requested_by_principal_id, state, created_at, expires_at)
    VALUES (pg_catalog.uuidv7(), v_cluster.workspace_id, v_cluster.network_id, v_cluster.id, v_ca.id, v_ca.version,
        p_reason, p_change_ref, p_note, v_grant.actor_id, 'pending', v_now, v_now + INTERVAL '1 hour')
    RETURNING * INTO v_request;
    RETURN pg_catalog.jsonb_build_object(
        'network_id', p_network_public_id,
        'network_revision', mesh_ops.kubernetes_network_revision_internal_v1(v_grant.workspace_id, v_grant.network_id),
        'cluster_id', p_cluster_public_id,
        'created', TRUE,
        'request', mesh_ops.kubernetes_ca_retire_request_document_internal_v1(v_request),
        'authority', v_grant.authority
    );
END;
$function$;

-- Whether the caller may approve the Network's replicas, so ask to retire
-- a CA: the CA page's can_retire, so the Console never guesses (Q163). It
-- grants nothing and is looser than the request, which also checks the
-- member's scope and the account principal: a rare caller may see the
-- button and get 403.
CREATE FUNCTION mesh_ops.kubernetes_cluster_can_approve_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT EXISTS (SELECT 1 FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        'kubernetes_cluster.approve', pg_catalog.transaction_timestamp()))
$function$;

-- A page of a cluster's requests, newest first, for those who approve its
-- replicas or read the audit of its Workspace or Network (Q163): up to
-- p_limit + 1 rows, so the caller knows whether more follow.
CREATE FUNCTION mesh_ops.list_kubernetes_ca_retire_requests_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_cluster_public_id UUID,
    p_after_at TIMESTAMPTZ, p_after_id UUID, p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    v_cluster mesh.kubernetes_cluster%ROWTYPE;
BEGIN
    IF p_cluster_public_id IS NULL OR (p_after_at IS NULL) <> (p_after_id IS NULL)
        OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes CA retire request page is invalid';
    END IF;
    BEGIN
        PERFORM 1 FROM mesh_ops.kubernetes_cluster_grant_internal_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
            p_session_version, p_principal_authority_generation, p_account_session_generation,
            p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
            'kubernetes_cluster.approve');
    EXCEPTION WHEN insufficient_privilege THEN
        PERFORM 1 FROM mesh_ops.resolve_workspace_permission_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
            p_session_version, p_principal_authority_generation, p_account_session_generation,
            p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, 'audit.read', v_now);
        IF NOT FOUND THEN
            PERFORM 1 FROM mesh_ops.resolve_network_permission_v2(
                p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
                p_session_version, p_principal_authority_generation, p_account_session_generation,
                p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
                'audit.read', v_now);
            IF NOT FOUND THEN
                RAISE EXCEPTION USING ERRCODE = '42501',
                    MESSAGE = 'kubernetes_cluster.approve or audit.read required';
            END IF;
        END IF;
    END;
    SELECT cluster.* INTO v_cluster FROM mesh.kubernetes_cluster AS cluster
    JOIN mesh.workspace AS workspace ON workspace.id = cluster.workspace_id
    JOIN mesh.network AS network ON network.workspace_id = cluster.workspace_id AND network.id = cluster.network_id
    WHERE workspace.public_id = p_workspace_public_id AND network.public_id = p_network_public_id
      AND cluster.public_id = p_cluster_public_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'unknown Kubernetes cluster';
    END IF;
    RETURN COALESCE((
        SELECT pg_catalog.jsonb_agg(
            mesh_ops.kubernetes_ca_retire_request_document_internal_v1(listed)
            ORDER BY listed.created_at DESC, listed.public_id DESC)
        FROM (
            SELECT request.* FROM mesh.kubernetes_ca_retire_request AS request
            WHERE request.kubernetes_cluster_id = v_cluster.id
              AND (p_after_at IS NULL OR (request.created_at, request.public_id) < (p_after_at, p_after_id))
            ORDER BY request.created_at DESC, request.public_id DESC
            LIMIT p_limit + 1
        ) AS listed
    ), '[]'::JSONB);
END;
$function$;

-- The worker's queue: the oldest waiting requests of the installation,
-- with what it needs to act (Q159), the CA's state included: the Network's
-- locked read holds at most 96 clusters, so a CA missing from it is gone
-- only when this says it is retired. Its clock is the database's.
CREATE FUNCTION mesh_ops.read_kubernetes_ca_retire_work_v1(p_deployment_public_id UUID, p_limit INTEGER)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_deployment_id BIGINT;
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_requests JSONB;
    v_scan TEXT := pg_catalog.current_setting('mesh.access_ledger_scan', TRUE);
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 64 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes CA retire work limit';
    END IF;
    v_deployment_id := mesh_ops.kubernetes_ca_deployment_internal_v1(p_deployment_public_id);
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
        'workspace_id', listed.workspace_public_id, 'network_id', listed.network_public_id,
        'cluster_id', listed.cluster_public_id, 'request_id', listed.public_id, 'ca_id', listed.ca_public_id,
        'ca_version', listed.ca_version, 'ca_state', listed.ca_state, 'reason', listed.reason,
        'expires_at', listed.expires_at
    ) ORDER BY listed.reason = 'compromise' DESC, listed.created_at, listed.id), '[]'::JSONB) INTO v_requests
    FROM (
        SELECT request.id, request.public_id, request.created_at, request.expires_at, request.ca_version,
            request.reason, workspace.public_id AS workspace_public_id, network.public_id AS network_public_id,
            cluster.public_id AS cluster_public_id, ca.public_id AS ca_public_id, ca.state AS ca_state
        FROM mesh.kubernetes_ca_retire_request AS request
        JOIN mesh.workspace AS workspace ON workspace.id = request.workspace_id
        JOIN mesh.network AS network
            ON network.workspace_id = request.workspace_id AND network.id = request.network_id
        JOIN mesh.kubernetes_cluster AS cluster ON cluster.id = request.kubernetes_cluster_id
        JOIN mesh.kubernetes_cluster_ca AS ca ON ca.id = request.kubernetes_cluster_ca_id
        WHERE request.state = 'pending' AND workspace.deployment_id = v_deployment_id
        -- A compromise goes first: older requests that wait cannot hold it
        -- back (review d2a M4).
        ORDER BY request.reason = 'compromise' DESC, request.created_at, request.id
        LIMIT p_limit
    ) AS listed;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', COALESCE(v_scan, ''), TRUE);
    RETURN pg_catalog.jsonb_build_object('now', v_now, 'requests', v_requests);
END;
$function$;

-- The waiting request of the installation's Network, locked, or none.
CREATE FUNCTION mesh_ops.kubernetes_ca_retire_request_waiting_internal_v1(
    p_deployment_public_id UUID, p_workspace_public_id UUID, p_network_public_id UUID, p_request_public_id UUID
)
RETURNS mesh.kubernetes_ca_retire_request
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_deployment_id BIGINT;
    v_request mesh.kubernetes_ca_retire_request%ROWTYPE;
BEGIN
    IF p_workspace_public_id IS NULL OR p_network_public_id IS NULL OR p_request_public_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Kubernetes CA retire request is invalid';
    END IF;
    v_deployment_id := mesh_ops.kubernetes_ca_deployment_internal_v1(p_deployment_public_id);
    SELECT request.* INTO v_request FROM mesh.kubernetes_ca_retire_request AS request
    JOIN mesh.workspace AS workspace ON workspace.id = request.workspace_id
    JOIN mesh.network AS network ON network.workspace_id = request.workspace_id AND network.id = request.network_id
    WHERE workspace.deployment_id = v_deployment_id AND workspace.public_id = p_workspace_public_id
      AND network.public_id = p_network_public_id AND request.public_id = p_request_public_id
      AND request.state = 'pending'
    FOR UPDATE OF request;
    RETURN v_request;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_ca_retire_request_waiting_internal_v1(UUID, UUID, UUID, UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Marks a waiting request done. The worker calls it inside the transaction
-- that retired the CA, under the Network's CA lock (Q159); FALSE when the
-- request no longer waits.
CREATE FUNCTION mesh_ops.complete_kubernetes_ca_retire_request_v1(
    p_deployment_public_id UUID, p_workspace_public_id UUID, p_network_public_id UUID, p_request_public_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_request mesh.kubernetes_ca_retire_request%ROWTYPE;
    v_scan TEXT := pg_catalog.current_setting('mesh.access_ledger_scan', TRUE);
BEGIN
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    v_request := mesh_ops.kubernetes_ca_retire_request_waiting_internal_v1(
        p_deployment_public_id, p_workspace_public_id, p_network_public_id, p_request_public_id);
    -- A restore marked since the worker read the guard stops all but a
    -- compromise here too: the CA rows let any operator's change through
    -- (review d2a M2). The change rolls back; the next pass refuses it.
    IF v_request.id IS NOT NULL AND v_request.reason <> 'compromise'
        AND mesh_ops.kubernetes_ca_guard_suspected_internal_v1(
            mesh_ops.kubernetes_ca_deployment_internal_v1(p_deployment_public_id)) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTK30', MESSAGE = 'Kubernetes CA work is stopped: a database restore is suspected';
    END IF;
    IF v_request.id IS NOT NULL THEN
        UPDATE mesh.kubernetes_ca_retire_request AS request
        SET state = 'done', finished_at = GREATEST(pg_catalog.clock_timestamp(), request.created_at),
            version = request.version + 1
        WHERE request.id = v_request.id;
    END IF;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', COALESCE(v_scan, ''), TRUE);
    RETURN v_request.id IS NOT NULL;
END;
$function$;

-- Refuses a waiting request with the worker's reason; FALSE when it no
-- longer waits.
CREATE FUNCTION mesh_ops.refuse_kubernetes_ca_retire_request_v1(
    p_deployment_public_id UUID, p_workspace_public_id UUID, p_network_public_id UUID, p_request_public_id UUID,
    p_refusal TEXT
)
RETURNS BOOLEAN
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_request mesh.kubernetes_ca_retire_request%ROWTYPE;
    v_scan TEXT := pg_catalog.current_setting('mesh.access_ledger_scan', TRUE);
BEGIN
    IF p_refusal IS NULL OR p_refusal NOT IN ('expired', 'changed', 'guard', 'gone') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Kubernetes CA retire refusal';
    END IF;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    v_request := mesh_ops.kubernetes_ca_retire_request_waiting_internal_v1(
        p_deployment_public_id, p_workspace_public_id, p_network_public_id, p_request_public_id);
    IF v_request.id IS NOT NULL THEN
        UPDATE mesh.kubernetes_ca_retire_request AS request
        SET state = 'refused', refusal = p_refusal,
            finished_at = GREATEST(pg_catalog.clock_timestamp(), request.created_at),
            version = request.version + 1
        WHERE request.id = v_request.id;
    END IF;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', COALESCE(v_scan, ''), TRUE);
    RETURN v_request.id IS NOT NULL;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.request_kubernetes_ca_retire_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, BIGINT, TEXT, TEXT, TEXT, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.request_kubernetes_ca_retire_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, UUID, BIGINT, TEXT, TEXT, TEXT, UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_cluster_can_approve_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.kubernetes_cluster_can_approve_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.list_kubernetes_ca_retire_requests_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TIMESTAMPTZ, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_kubernetes_ca_retire_requests_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, TIMESTAMPTZ, UUID, INTEGER
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.read_kubernetes_ca_retire_work_v1(UUID, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_kubernetes_ca_retire_work_v1(UUID, INTEGER) TO mesh_worker;
REVOKE ALL ON FUNCTION mesh_ops.complete_kubernetes_ca_retire_request_v1(UUID, UUID, UUID, UUID)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.complete_kubernetes_ca_retire_request_v1(UUID, UUID, UUID, UUID) TO mesh_worker;
REVOKE ALL ON FUNCTION mesh_ops.refuse_kubernetes_ca_retire_request_v1(UUID, UUID, UUID, UUID, TEXT)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.refuse_kubernetes_ca_retire_request_v1(UUID, UUID, UUID, UUID, TEXT) TO mesh_worker;
