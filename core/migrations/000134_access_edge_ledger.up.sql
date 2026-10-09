-- Schema 134 (R1-68): the access edge ledger answers "who could reach what
-- at time T, through which rule, and since when".
--
-- network_revision_history keeps the time of every Network revision; a
-- trigger on the revision counter writes it, so no writer can skip it.
--
-- The access-ledger worker computes, after each revision, the effective edge
-- set of a Network from the same sources as the Access Graph (compiled
-- Device rules with their Resource provenance, group, identity-group and tag
-- rules at current membership, and Imported Resources on the consumer side),
-- keeping only edges whose Devices are active and unexpired and whose share
-- is active. It diffs the set against the open edges: a new edge opens at the
-- revision and its time, a vanished edge closes there, an unchanged edge is
-- not written. Each edge keeps the earliest expiry of its endpoints, so a
-- Device that expires between two revisions is excluded at query time.
--
-- Every recorded change writes a snapshot with the edge count and a digest of
-- the whole set, sealed as the audit event access_graph.recorded on the
-- Network stream. The worker runs in one REPEATABLE READ transaction, so the
-- edge set is the one of the revision it records. Known limits: the ledger
-- lags the change by the poll interval, and a state that lasts less than one
-- interval (changed and changed back) may not be recorded. A revision's time
-- is taken when its counter is written, so it can precede the commit by the
-- length of the writing transaction.
--
-- Retention is fixed at 13 months like audit: closed edges, snapshots and
-- revision times older than that are pruned, except the latest of each
-- Network.

CREATE TABLE mesh_ops.network_revision_history (
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    network_revision BIGINT NOT NULL CHECK (network_revision > 0),
    policy_revision BIGINT NOT NULL CHECK (policy_revision > 0),
    recorded_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (workspace_id, network_id, network_revision),
    CONSTRAINT network_revision_history_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT
);
CREATE INDEX network_revision_history_time_idx
    ON mesh_ops.network_revision_history (workspace_id, network_id, recorded_at DESC);

CREATE TABLE mesh_ops.access_edge_history (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    edge_key BYTEA NOT NULL,
    access_rule_public_id UUID NOT NULL,
    selector_kind TEXT NOT NULL,
    source_device_public_id UUID NOT NULL,
    destination_device_public_id UUID,
    destination_imported_resource_public_id UUID,
    trust_contract_public_id UUID,
    destination_resource_public_id UUID,
    destination_resource_group_public_id UUID,
    source_selector_kind TEXT,
    source_selector_public_id UUID,
    destination_selector_kind TEXT,
    destination_selector_public_id UUID,
    protocol TEXT NOT NULL,
    destination_ports INT4MULTIRANGE NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    valid_from_revision BIGINT NOT NULL CHECK (valid_from_revision > 0),
    valid_from_at TIMESTAMPTZ NOT NULL,
    valid_to_revision BIGINT,
    valid_to_at TIMESTAMPTZ,
    CONSTRAINT access_edge_history_key_check CHECK (pg_catalog.octet_length(edge_key) = 32),
    CONSTRAINT access_edge_history_kind_check CHECK (
        (selector_kind IN ('device', 'resource', 'resource_group')
            AND destination_device_public_id IS NOT NULL
            AND destination_imported_resource_public_id IS NULL AND trust_contract_public_id IS NULL)
        OR (selector_kind = 'imported_resource'
            AND destination_device_public_id IS NULL
            AND destination_imported_resource_public_id IS NOT NULL AND trust_contract_public_id IS NOT NULL)
    ),
    CONSTRAINT access_edge_history_protocol_check CHECK (protocol IN ('tcp', 'udp', 'icmp')),
    CONSTRAINT access_edge_history_interval_check CHECK (
        (valid_to_revision IS NULL AND valid_to_at IS NULL)
        OR (valid_to_revision > valid_from_revision AND valid_to_at >= valid_from_at)
    ),
    CONSTRAINT access_edge_history_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX access_edge_history_open_uidx
    ON mesh_ops.access_edge_history (workspace_id, network_id, edge_key)
    WHERE valid_to_revision IS NULL;
CREATE INDEX access_edge_history_key_idx
    ON mesh_ops.access_edge_history (workspace_id, network_id, edge_key, valid_from_at);
CREATE INDEX access_edge_history_closed_idx
    ON mesh_ops.access_edge_history (valid_to_at)
    WHERE valid_to_at IS NOT NULL;

-- One row per recorded change. version and public_id let the authority
-- mutation trigger cover the insert, so the snapshot cannot be written
-- without its audit event in the same transaction.
CREATE TABLE mesh_ops.access_edge_snapshot (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version = 1),
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    network_revision BIGINT NOT NULL CHECK (network_revision > 0),
    policy_revision BIGINT NOT NULL CHECK (policy_revision > 0),
    effective_at TIMESTAMPTZ NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    edge_count INTEGER NOT NULL CHECK (edge_count >= 0),
    opened_count INTEGER NOT NULL CHECK (opened_count >= 0),
    closed_count INTEGER NOT NULL CHECK (closed_count >= 0),
    digest BYTEA NOT NULL CHECK (pg_catalog.octet_length(digest) = 32),
    UNIQUE (workspace_id, network_id, network_revision),
    CONSTRAINT access_edge_snapshot_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT access_edge_snapshot_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT
);
CREATE INDEX access_edge_snapshot_time_idx
    ON mesh_ops.access_edge_snapshot (workspace_id, network_id, effective_at DESC);

CREATE TABLE mesh_ops.access_ledger_cursor (
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    recorded_network_revision BIGINT NOT NULL CHECK (recorded_network_revision > 0),
    first_recorded_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (workspace_id, network_id),
    CONSTRAINT access_ledger_cursor_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT
);

ALTER TABLE mesh_ops.network_revision_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.network_revision_history FORCE ROW LEVEL SECURITY;
CREATE POLICY network_revision_history_migrator_policy ON mesh_ops.network_revision_history
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
ALTER TABLE mesh_ops.access_edge_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.access_edge_history FORCE ROW LEVEL SECURITY;
CREATE POLICY access_edge_history_migrator_policy ON mesh_ops.access_edge_history
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
ALTER TABLE mesh_ops.access_edge_snapshot ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.access_edge_snapshot FORCE ROW LEVEL SECURITY;
CREATE POLICY access_edge_snapshot_migrator_policy ON mesh_ops.access_edge_snapshot
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
ALTER TABLE mesh_ops.access_ledger_cursor ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.access_ledger_cursor FORCE ROW LEVEL SECURITY;
CREATE POLICY access_ledger_cursor_migrator_policy ON mesh_ops.access_ledger_cursor
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);

-- The worker discovers Networks across the installation. Workspace, Network
-- and revision rows are readable by the function owner only while
-- mesh.access_ledger_scan is on, which the ledger functions set around their
-- discovery and scope resolution and clear before returning.
CREATE POLICY workspace_access_ledger_scan ON mesh.workspace
    FOR SELECT TO mesh_migrator
    USING (pg_catalog.current_setting('mesh.access_ledger_scan', TRUE) = 'on');
CREATE POLICY network_access_ledger_scan ON mesh.network
    FOR SELECT TO mesh_migrator
    USING (pg_catalog.current_setting('mesh.access_ledger_scan', TRUE) = 'on');
CREATE POLICY network_revision_access_ledger_scan ON mesh_ops.network_revision
    FOR SELECT TO mesh_migrator
    USING (pg_catalog.current_setting('mesh.access_ledger_scan', TRUE) = 'on');

CREATE TRIGGER access_edge_snapshot_authority_mutation
AFTER INSERT ON mesh_ops.access_edge_snapshot
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('access_edge_snapshot', 'public_id');

-- Revision times. Every writer advances the counter, so the trigger covers
-- them all; a revision written twice in one transaction keeps its first time.
CREATE FUNCTION mesh_ops.record_network_revision_history_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
BEGIN
    IF TG_OP = 'INSERT' OR NEW.network_revision <> OLD.network_revision THEN
        INSERT INTO mesh_ops.network_revision_history (
            workspace_id, network_id, network_revision, policy_revision, recorded_at
        ) VALUES (
            NEW.workspace_id, NEW.network_id, NEW.network_revision, NEW.policy_revision,
            pg_catalog.clock_timestamp()
        )
        ON CONFLICT (workspace_id, network_id, network_revision) DO NOTHING;
    END IF;
    RETURN NULL;
END;
$function$;

CREATE TRIGGER network_revision_history_record
AFTER INSERT OR UPDATE OF network_revision ON mesh_ops.network_revision
FOR EACH ROW EXECUTE FUNCTION mesh_ops.record_network_revision_history_v1();

-- History starts now: the current revision of each Network, at its last update.
DO $backfill$
BEGIN
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    INSERT INTO mesh_ops.network_revision_history (
        workspace_id, network_id, network_revision, policy_revision, recorded_at
    )
    SELECT revision.workspace_id, revision.network_id, revision.network_revision,
        revision.policy_revision, revision.updated_at
    FROM mesh_ops.network_revision AS revision;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', '', TRUE);
END;
$backfill$;

-- The effective edge set of the Network bound to this transaction. Callers
-- bind mesh.workspace_id and mesh.network_id first: the group resolver reads
-- them. Not granted to any role.
CREATE FUNCTION mesh_ops.access_edges_internal_v1(
    p_workspace_id BIGINT,
    p_network_id BIGINT,
    p_policy_revision BIGINT,
    p_now TIMESTAMPTZ
)
RETURNS TABLE (
    edge_key BYTEA,
    access_rule_public_id UUID,
    selector_kind TEXT,
    source_device_public_id UUID,
    destination_device_public_id UUID,
    destination_imported_resource_public_id UUID,
    trust_contract_public_id UUID,
    destination_resource_public_id UUID,
    destination_resource_group_public_id UUID,
    source_selector_kind TEXT,
    source_selector_public_id UUID,
    destination_selector_kind TEXT,
    destination_selector_public_id UUID,
    protocol TEXT,
    destination_ports INT4MULTIRANGE,
    expires_at TIMESTAMPTZ
)
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    v_release_id BIGINT;
BEGIN
    IF p_workspace_id IS NULL OR p_network_id IS NULL OR p_now IS NULL
        OR mesh_ops.current_workspace_id() IS DISTINCT FROM p_workspace_id
        OR mesh_ops.current_network_id() IS DISTINCT FROM p_network_id THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'access edge scope is unavailable';
    END IF;
    SELECT release.id INTO v_release_id
    FROM mesh.policy_release AS release
    WHERE release.workspace_id = p_workspace_id
      AND release.network_id = p_network_id
      AND release.policy_revision = p_policy_revision
      AND release.state = 'active';
    IF v_release_id IS NULL THEN
        RETURN;
    END IF;

    RETURN QUERY
    WITH local_edge AS (
        SELECT rule.access_rule_public_id AS rule_id,
            CASE
                WHEN group_provenance.id IS NOT NULL THEN 'resource_group'
                WHEN resource_provenance.id IS NOT NULL THEN 'resource'
                ELSE 'device'
            END AS kind,
            source.public_id AS source_id,
            destination.public_id AS destination_id,
            NULL::UUID AS imported_id,
            NULL::UUID AS contract_id,
            COALESCE(member.public_id, direct_resource.public_id) AS resource_id,
            resource_group.public_id AS group_id,
            NULL::TEXT AS source_selector,
            NULL::UUID AS source_selector_id,
            NULL::TEXT AS destination_selector,
            NULL::UUID AS destination_selector_id,
            rule.protocol,
            rule.destination_ports,
            LEAST(source.expires_at, destination.expires_at) AS expiry
        FROM mesh.compiled_policy_rule AS rule
        JOIN mesh.device AS source
          ON source.workspace_id = rule.workspace_id AND source.network_id = rule.network_id
         AND source.id = rule.source_device_id
        JOIN mesh.device AS destination
          ON destination.workspace_id = rule.workspace_id AND destination.network_id = rule.network_id
         AND destination.id = rule.destination_device_id
        LEFT JOIN mesh.compiled_policy_resource_destination AS resource_provenance
          ON resource_provenance.workspace_id = rule.workspace_id
         AND resource_provenance.network_id = rule.network_id
         AND resource_provenance.compiled_policy_rule_id = rule.id
        LEFT JOIN mesh.resource AS direct_resource
          ON direct_resource.workspace_id = rule.workspace_id
         AND direct_resource.network_id = rule.network_id
         AND direct_resource.id = resource_provenance.destination_resource_id
        LEFT JOIN mesh.compiled_policy_resource_group_destination AS group_provenance
          ON group_provenance.workspace_id = rule.workspace_id
         AND group_provenance.network_id = rule.network_id
         AND group_provenance.compiled_policy_rule_id = rule.id
        LEFT JOIN mesh.resource AS member
          ON member.workspace_id = rule.workspace_id
         AND member.network_id = rule.network_id
         AND member.id = group_provenance.destination_resource_id
        LEFT JOIN mesh.resource_group AS resource_group
          ON resource_group.workspace_id = rule.workspace_id
         AND resource_group.network_id = rule.network_id
         AND resource_group.id = group_provenance.destination_resource_group_id
        WHERE rule.workspace_id = p_workspace_id
          AND rule.network_id = p_network_id
          AND rule.policy_release_id = v_release_id
          AND rule.policy_revision = p_policy_revision
          AND source.state = 'active' AND source.expires_at > p_now
          AND destination.state = 'active' AND destination.expires_at > p_now
    ),
    imported_edge AS (
        SELECT rule.access_rule_public_id,
            'imported_resource'::TEXT,
            source.public_id,
            NULL::UUID,
            imported.public_id,
            contract.public_id,
            NULL::UUID,
            NULL::UUID,
            NULL::TEXT,
            NULL::UUID,
            NULL::TEXT,
            NULL::UUID,
            rule.protocol,
            rule.destination_ports,
            LEAST(source.expires_at, contract.expires_at)
        FROM mesh.compiled_policy_imported_resource_destination AS rule
        JOIN mesh.device AS source
          ON source.workspace_id = rule.workspace_id AND source.network_id = rule.network_id
         AND source.id = rule.source_device_id
        JOIN mesh.imported_resource AS imported
          ON imported.workspace_id = rule.workspace_id AND imported.network_id = rule.network_id
         AND imported.id = rule.imported_resource_id
        JOIN mesh.trust_contract AS contract
          ON contract.id = rule.trust_contract_id
         AND contract.consumer_workspace_id = p_workspace_id
         AND contract.consumer_network_id = p_network_id
        WHERE rule.workspace_id = p_workspace_id
          AND rule.network_id = p_network_id
          AND rule.policy_release_id = v_release_id
          AND rule.policy_revision = p_policy_revision
          AND source.state = 'active' AND source.expires_at > p_now
          AND imported.state = 'active'
          AND contract.state = 'active' AND contract.expires_at > p_now
    ),
    group_edge AS (
        SELECT edge.access_rule_public_id,
            'device'::TEXT,
            source.public_id,
            destination.public_id,
            NULL::UUID,
            NULL::UUID,
            NULL::UUID,
            NULL::UUID,
            edge.source_selector_kind,
            edge.source_selector_public_id,
            edge.destination_selector_kind,
            edge.destination_selector_public_id,
            edge.protocol,
            edge.destination_ports,
            LEAST(source.expires_at, destination.expires_at)
        FROM mesh_ops.resolve_group_policy_edges_v2(NULL) AS edge
        JOIN mesh.device AS source
          ON source.workspace_id = p_workspace_id AND source.network_id = p_network_id
         AND source.id = edge.source_device_id
        JOIN mesh.device AS destination
          ON destination.workspace_id = p_workspace_id AND destination.network_id = p_network_id
         AND destination.id = edge.destination_device_id
        WHERE source.state = 'active' AND source.expires_at > p_now
          AND destination.state = 'active' AND destination.expires_at > p_now
    ),
    keyed AS (
        SELECT pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.concat_ws('|',
                'access-edge/v1', edge.kind, edge.rule_id::TEXT, edge.source_id::TEXT,
                COALESCE(edge.destination_id::TEXT, '-'), COALESCE(edge.imported_id::TEXT, '-'),
                COALESCE(edge.contract_id::TEXT, '-'), COALESCE(edge.resource_id::TEXT, '-'),
                COALESCE(edge.group_id::TEXT, '-'), COALESCE(edge.source_selector, '-'),
                COALESCE(edge.source_selector_id::TEXT, '-'), COALESCE(edge.destination_selector, '-'),
                COALESCE(edge.destination_selector_id::TEXT, '-'), edge.protocol,
                edge.destination_ports::TEXT,
                ((EXTRACT(EPOCH FROM edge.expiry) * 1000000)::BIGINT)::TEXT
            ), 'UTF8')) AS key,
            edge.*
        FROM (
            SELECT * FROM local_edge
            UNION ALL SELECT * FROM imported_edge
            UNION ALL SELECT * FROM group_edge
        ) AS edge
    )
    SELECT DISTINCT ON (keyed.key)
        keyed.key, keyed.rule_id, keyed.kind, keyed.source_id, keyed.destination_id,
        keyed.imported_id, keyed.contract_id, keyed.resource_id, keyed.group_id,
        keyed.source_selector, keyed.source_selector_id, keyed.destination_selector,
        keyed.destination_selector_id, keyed.protocol, keyed.destination_ports, keyed.expiry
    FROM keyed
    ORDER BY keyed.key;
END;
$function$;

-- Networks whose revision is newer than the ledger, oldest change first.
CREATE FUNCTION mesh_ops.list_access_ledger_due_v1(p_deployment_public_id UUID, p_limit INTEGER)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    v_result JSONB;
BEGIN
    IF p_deployment_public_id IS NULL OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 128 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid access ledger discovery input';
    END IF;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    SELECT pg_catalog.jsonb_build_object('items', COALESCE(pg_catalog.jsonb_agg(
        pg_catalog.jsonb_build_object('workspace_id', due.workspace_public_id, 'network_id', due.network_public_id)
        ORDER BY due.updated_at, due.network_id), '[]'::JSONB))
    FROM (
        SELECT workspace.public_id AS workspace_public_id, network.public_id AS network_public_id,
            revision.updated_at, network.id AS network_id
        FROM mesh_ops.network_revision AS revision
        JOIN mesh.network AS network
          ON network.workspace_id = revision.workspace_id AND network.id = revision.network_id
        JOIN mesh.workspace AS workspace ON workspace.id = network.workspace_id
        JOIN mesh.deployment AS deployment ON deployment.id = workspace.deployment_id
        LEFT JOIN mesh_ops.access_ledger_cursor AS ledger
          ON ledger.workspace_id = revision.workspace_id AND ledger.network_id = revision.network_id
        WHERE deployment.installation_public_id = p_deployment_public_id
          AND network.state <> 'deleted'
          AND (ledger.recorded_network_revision IS NULL
               OR ledger.recorded_network_revision < revision.network_revision)
        ORDER BY revision.updated_at, network.id
        LIMIT p_limit
    ) AS due
    INTO v_result;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', '', TRUE);
    RETURN v_result;
END;
$function$;

CREATE FUNCTION mesh_ops.access_edge_snapshot_payload_internal_v1(p_snapshot_id BIGINT)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh_ops
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'format', 'access-edges/v1',
        'snapshot_id', snapshot.public_id,
        'network_revision', snapshot.network_revision,
        'policy_revision', snapshot.policy_revision,
        'effective_at', snapshot.effective_at,
        'edge_count', snapshot.edge_count,
        'opened', snapshot.opened_count,
        'closed', snapshot.closed_count,
        'digest', pg_catalog.encode(snapshot.digest, 'hex')
    )
    FROM mesh_ops.access_edge_snapshot AS snapshot
    WHERE snapshot.id = p_snapshot_id
$function$;

-- Records the current revision of one Network. Returns recorded=false when
-- the ledger is already current, another worker holds the Network, or the
-- edge set did not change (the cursor still advances). Otherwise it writes
-- the snapshot under p_change, locks the Network audit stream and returns
-- the head and payload for the caller to hash and append.
CREATE FUNCTION mesh_ops.record_access_edges_v1(
    p_deployment_public_id UUID,
    p_workspace_public_id UUID,
    p_network_public_id UUID,
    p_snapshot_public_id UUID,
    p_change_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops, mesh_audit
AS $function$
DECLARE
    v_workspace_id BIGINT;
    v_network_id BIGINT;
    v_revision BIGINT;
    v_policy_revision BIGINT;
    v_revision_updated TIMESTAMPTZ;
    v_effective_at TIMESTAMPTZ;
    v_recorded BIGINT;
    v_now TIMESTAMPTZ := pg_catalog.clock_timestamp();
    v_edges INTEGER;
    v_opened INTEGER;
    v_closed INTEGER;
    v_digest BYTEA;
    v_snapshot_id BIGINT;
    v_stream RECORD;
BEGIN
    IF p_deployment_public_id IS NULL OR p_workspace_public_id IS NULL OR p_network_public_id IS NULL
        OR p_snapshot_public_id IS NULL OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_snapshot_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR p_snapshot_public_id = p_change_public_id THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid access ledger input';
    END IF;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);
    SELECT network.workspace_id, network.id
    INTO v_workspace_id, v_network_id
    FROM mesh.network AS network
    JOIN mesh.workspace AS workspace ON workspace.id = network.workspace_id
    JOIN mesh.deployment AS deployment ON deployment.id = workspace.deployment_id
    WHERE deployment.installation_public_id = p_deployment_public_id
      AND workspace.public_id = p_workspace_public_id
      AND network.public_id = p_network_public_id
      AND network.state <> 'deleted';
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', '', TRUE);
    IF v_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'access ledger scope is unavailable';
    END IF;
    -- The revision row and the edge sources read through the exact Network scope.
    PERFORM pg_catalog.set_config('mesh.workspace_id', v_workspace_id::TEXT, TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', v_network_id::TEXT, TRUE);
    IF NOT pg_catalog.pg_try_advisory_xact_lock(
        pg_catalog.hashtextextended('meshtransit/access-ledger/' || v_network_id::TEXT, 0)) THEN
        RETURN pg_catalog.jsonb_build_object('recorded', FALSE, 'busy', TRUE);
    END IF;

    SELECT revision.network_revision, revision.policy_revision, revision.updated_at
    INTO v_revision, v_policy_revision, v_revision_updated
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_workspace_id AND revision.network_id = v_network_id;
    SELECT ledger.recorded_network_revision INTO v_recorded
    FROM mesh_ops.access_ledger_cursor AS ledger
    WHERE ledger.workspace_id = v_workspace_id AND ledger.network_id = v_network_id;
    IF v_revision IS NULL OR v_recorded >= v_revision THEN
        RETURN pg_catalog.jsonb_build_object('recorded', FALSE, 'busy', FALSE);
    END IF;
    SELECT history.recorded_at INTO v_effective_at
    FROM mesh_ops.network_revision_history AS history
    WHERE history.workspace_id = v_workspace_id AND history.network_id = v_network_id
      AND history.network_revision = v_revision;
    v_effective_at := COALESCE(v_effective_at, v_revision_updated);

    WITH current_edge AS MATERIALIZED (
        SELECT * FROM mesh_ops.access_edges_internal_v1(v_workspace_id, v_network_id, v_policy_revision, v_now)
    ),
    closed AS (
        UPDATE mesh_ops.access_edge_history AS edge
        SET valid_to_revision = v_revision, valid_to_at = v_effective_at
        WHERE edge.workspace_id = v_workspace_id AND edge.network_id = v_network_id
          AND edge.valid_to_revision IS NULL
          AND NOT EXISTS (SELECT 1 FROM current_edge WHERE current_edge.edge_key = edge.edge_key)
        RETURNING 1
    ),
    opened AS (
        INSERT INTO mesh_ops.access_edge_history (
            workspace_id, network_id, edge_key, access_rule_public_id, selector_kind,
            source_device_public_id, destination_device_public_id,
            destination_imported_resource_public_id, trust_contract_public_id,
            destination_resource_public_id, destination_resource_group_public_id,
            source_selector_kind, source_selector_public_id,
            destination_selector_kind, destination_selector_public_id,
            protocol, destination_ports, expires_at, valid_from_revision, valid_from_at
        )
        SELECT v_workspace_id, v_network_id, current_edge.edge_key, current_edge.access_rule_public_id,
            current_edge.selector_kind, current_edge.source_device_public_id,
            current_edge.destination_device_public_id, current_edge.destination_imported_resource_public_id,
            current_edge.trust_contract_public_id, current_edge.destination_resource_public_id,
            current_edge.destination_resource_group_public_id, current_edge.source_selector_kind,
            current_edge.source_selector_public_id, current_edge.destination_selector_kind,
            current_edge.destination_selector_public_id, current_edge.protocol,
            current_edge.destination_ports, current_edge.expires_at, v_revision, v_effective_at
        FROM current_edge
        WHERE NOT EXISTS (
            SELECT 1 FROM mesh_ops.access_edge_history AS edge
            WHERE edge.workspace_id = v_workspace_id AND edge.network_id = v_network_id
              AND edge.valid_to_revision IS NULL AND edge.edge_key = current_edge.edge_key
        )
        RETURNING 1
    )
    SELECT (SELECT pg_catalog.count(*) FROM current_edge)::INTEGER,
        (SELECT pg_catalog.count(*) FROM opened)::INTEGER,
        (SELECT pg_catalog.count(*) FROM closed)::INTEGER,
        pg_catalog.sha256(
            pg_catalog.convert_to('meshtransit/access-edges/v1', 'UTF8') || '\x00'::BYTEA
            || COALESCE((SELECT pg_catalog.string_agg(current_edge.edge_key, ''::BYTEA ORDER BY current_edge.edge_key)
                         FROM current_edge), ''::BYTEA))
    INTO v_edges, v_opened, v_closed, v_digest;

    INSERT INTO mesh_ops.access_ledger_cursor (
        workspace_id, network_id, recorded_network_revision, first_recorded_at, updated_at
    ) VALUES (v_workspace_id, v_network_id, v_revision, v_now, v_now)
    ON CONFLICT (workspace_id, network_id) DO UPDATE
    SET recorded_network_revision = EXCLUDED.recorded_network_revision, updated_at = EXCLUDED.updated_at;

    -- The first record of a Network is its baseline even when it is empty.
    IF v_opened = 0 AND v_closed = 0 AND v_recorded IS NOT NULL THEN
        RETURN pg_catalog.jsonb_build_object('recorded', FALSE, 'busy', FALSE);
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    INSERT INTO mesh_ops.access_edge_snapshot (
        public_id, workspace_id, network_id, network_revision, policy_revision, effective_at,
        recorded_at, edge_count, opened_count, closed_count, digest
    ) VALUES (
        p_snapshot_public_id, v_workspace_id, v_network_id, v_revision, v_policy_revision, v_effective_at,
        v_now, v_edges, v_opened, v_closed, v_digest
    )
    RETURNING id INTO v_snapshot_id;

    SELECT stream.id, stream.next_sequence, stream.latest_event_hash INTO v_stream
    FROM mesh_audit.audit_stream AS stream
    WHERE stream.scope_kind = 'network'
      AND stream.workspace_id = v_workspace_id AND stream.network_id = v_network_id
    FOR UPDATE;
    IF v_stream.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'Network audit stream is unavailable';
    END IF;

    RETURN pg_catalog.jsonb_build_object(
        'recorded', TRUE,
        'busy', FALSE,
        'snapshot_id', p_snapshot_public_id,
        'network_revision', v_revision,
        'digest', pg_catalog.encode(v_digest, 'hex'),
        'stream_id', v_stream.id,
        'sequence', v_stream.next_sequence,
        'previous_hash', pg_catalog.encode(v_stream.latest_event_hash, 'hex'),
        'payload', mesh_ops.access_edge_snapshot_payload_internal_v1(v_snapshot_id)::TEXT
    );
END;
$function$;

-- Appends access_graph.recorded for the snapshot written by
-- record_access_edges_v1 in this transaction and change.
CREATE FUNCTION mesh_ops.append_access_edge_evidence_v1(
    p_snapshot_public_id UUID,
    p_stream_id BIGINT,
    p_sequence BIGINT,
    p_previous_hash BYTEA,
    p_event_hash BYTEA,
    p_event_public_id UUID,
    p_outbox_public_id UUID,
    p_payload JSONB
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
    v_snapshot mesh_ops.access_edge_snapshot%ROWTYPE;
BEGIN
    BEGIN
        v_change := NULLIF(pg_catalog.current_setting('mesh.change_public_id', TRUE), '')::UUID;
    EXCEPTION WHEN invalid_text_representation THEN
        v_change := NULL;
    END;
    IF v_change IS NULL OR p_snapshot_public_id IS NULL OR p_stream_id IS NULL
        OR p_sequence IS NULL OR p_sequence <= 0
        OR p_previous_hash IS NULL OR pg_catalog.octet_length(p_previous_hash) <> 32
        OR p_event_hash IS NULL OR pg_catalog.octet_length(p_event_hash) <> 32
        OR p_event_public_id IS NULL OR p_outbox_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_event_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_outbox_public_id), 6) >> 4 <> 7
        OR p_event_public_id = p_outbox_public_id
        OR p_event_public_id IN (v_change, p_snapshot_public_id)
        OR p_outbox_public_id IN (v_change, p_snapshot_public_id) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid access ledger evidence';
    END IF;
    SELECT snapshot.* INTO v_snapshot
    FROM mesh_ops.access_edge_snapshot AS snapshot
    JOIN mesh_audit.authority_mutation AS mutation
      ON mutation.change_public_id = v_change AND mutation.transaction_id = v_transaction
     AND mutation.aggregate_kind = 'access_edge_snapshot' AND mutation.row_public_id = snapshot.public_id
     AND mutation.operation = 'insert' AND mutation.after_version = 1
    JOIN mesh_audit.audit_stream AS stream
      ON stream.id = p_stream_id AND stream.scope_kind = 'network'
     AND stream.workspace_id = snapshot.workspace_id AND stream.network_id = snapshot.network_id
    WHERE snapshot.public_id = p_snapshot_public_id;
    IF v_snapshot.id IS NULL
        OR (SELECT pg_catalog.count(*) FROM mesh_audit.authority_mutation AS mutation
            WHERE mutation.change_public_id = v_change AND mutation.transaction_id = v_transaction) <> 1
        OR p_payload IS DISTINCT FROM mesh_ops.access_edge_snapshot_payload_internal_v1(v_snapshot.id) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid access ledger evidence';
    END IF;
    RETURN mesh_audit.append_authority_evidence(
        p_stream_id, p_event_public_id, p_outbox_public_id, p_sequence, p_previous_hash, p_event_hash,
        'access_edge_snapshot', v_snapshot.public_id, 1, v_snapshot.network_revision, NULL::UUID,
        'access_graph.recorded', 'system.reconcile', NULL::UUID, NULL::BYTEA, v_snapshot.digest,
        p_payload, 'access_graph.recorded', p_payload
    );
END;
$function$;

-- Removes ledger rows older than 13 months, keeping the latest snapshot and
-- revision time of each Network. Bounded per call; returns rows removed.
CREATE FUNCTION mesh_ops.prune_access_ledger_v1(p_deployment_public_id UUID, p_limit INTEGER)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    v_cutoff TIMESTAMPTZ := pg_catalog.clock_timestamp() - INTERVAL '13 months';
    v_deployment_id BIGINT;
    v_edges INTEGER;
    v_snapshots INTEGER;
    v_revisions INTEGER;
BEGIN
    IF p_deployment_public_id IS NULL OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 10000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid access ledger retention input';
    END IF;
    SELECT deployment.id INTO v_deployment_id
    FROM mesh.deployment AS deployment
    WHERE deployment.installation_public_id = p_deployment_public_id;
    IF v_deployment_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'access ledger scope is unavailable';
    END IF;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', 'on', TRUE);

    DELETE FROM mesh_ops.access_edge_history AS edge
    WHERE edge.id IN (
        SELECT old.id
        FROM mesh_ops.access_edge_history AS old
        JOIN mesh.workspace AS workspace ON workspace.id = old.workspace_id
        WHERE workspace.deployment_id = v_deployment_id
          AND old.valid_to_at IS NOT NULL AND old.valid_to_at < v_cutoff
        LIMIT p_limit
    );
    GET DIAGNOSTICS v_edges = ROW_COUNT;

    DELETE FROM mesh_ops.access_edge_snapshot AS snapshot
    WHERE snapshot.id IN (
        SELECT old.id
        FROM mesh_ops.access_edge_snapshot AS old
        JOIN mesh.workspace AS workspace ON workspace.id = old.workspace_id
        WHERE workspace.deployment_id = v_deployment_id
          AND old.effective_at < v_cutoff
          AND EXISTS (
              SELECT 1 FROM mesh_ops.access_edge_snapshot AS newer
              WHERE newer.workspace_id = old.workspace_id AND newer.network_id = old.network_id
                AND newer.network_revision > old.network_revision
          )
        LIMIT p_limit
    );
    GET DIAGNOSTICS v_snapshots = ROW_COUNT;

    DELETE FROM mesh_ops.network_revision_history AS history
    WHERE (history.workspace_id, history.network_id, history.network_revision) IN (
        SELECT old.workspace_id, old.network_id, old.network_revision
        FROM mesh_ops.network_revision_history AS old
        JOIN mesh.workspace AS workspace ON workspace.id = old.workspace_id
        WHERE workspace.deployment_id = v_deployment_id
          AND old.recorded_at < v_cutoff
          AND EXISTS (
              SELECT 1 FROM mesh_ops.network_revision_history AS newer
              WHERE newer.workspace_id = old.workspace_id AND newer.network_id = old.network_id
                AND newer.network_revision > old.network_revision
          )
        LIMIT p_limit
    );
    GET DIAGNOSTICS v_revisions = ROW_COUNT;
    PERFORM pg_catalog.set_config('mesh.access_ledger_scan', '', TRUE);
    RETURN v_edges + v_snapshots + v_revisions;
END;
$function$;

-- The edges in effect at p_at in one Network, under the same policy.read and
-- device.read authority as the Access Graph listing. Returns NULL when the
-- scope or authority does not resolve. Edges are ordered by edge key, which
-- also identifies one edge over time. Filters: a Device at either end, an
-- exact source and destination Device, and a protocol.
CREATE FUNCTION mesh_ops.read_access_graph_history_v1(
    p_session_public_id UUID, p_deployment_public_id UUID,
    p_principal_public_id UUID, p_identity_subject_public_id UUID,
    p_session_version BIGINT, p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT, p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT, p_workspace_public_id UUID,
    p_network_public_id UUID, p_evaluated_at TIMESTAMPTZ,
    p_at TIMESTAMPTZ, p_device_public_id UUID, p_source_public_id UUID,
    p_destination_public_id UUID, p_protocol TEXT, p_after_edge_key BYTEA, p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    never_expires CONSTANT TIMESTAMPTZ := TIMESTAMPTZ '2200-01-01 00:00:00+00';
    v_workspace BIGINT;
    v_network BIGINT;
    v_since TIMESTAMPTZ;
    v_revision BIGINT;
    v_snapshot JSONB;
    v_edges JSONB;
BEGIN
    IF p_at IS NULL OR p_evaluated_at IS NULL OR p_at > p_evaluated_at
        OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 501
        OR (p_protocol IS NOT NULL AND p_protocol NOT IN ('tcp', 'udp', 'icmp'))
        OR (p_after_edge_key IS NOT NULL AND pg_catalog.octet_length(p_after_edge_key) <> 32)
        OR (p_device_public_id IS NOT NULL
            AND pg_catalog.get_byte(pg_catalog.uuid_send(p_device_public_id), 6) >> 4 <> 7)
        OR (p_source_public_id IS NOT NULL
            AND pg_catalog.get_byte(pg_catalog.uuid_send(p_source_public_id), 6) >> 4 <> 7)
        OR (p_destination_public_id IS NOT NULL
            AND pg_catalog.get_byte(pg_catalog.uuid_send(p_destination_public_id), 6) >> 4 <> 7) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Access Graph history input';
    END IF;
    BEGIN
        SELECT workspace_internal_id, network_internal_id INTO v_workspace, v_network
        FROM mesh_ops.set_network_scope(p_workspace_public_id, p_network_public_id);
    EXCEPTION WHEN foreign_key_violation OR insufficient_privilege THEN
        RETURN NULL;
    END;
    IF NOT EXISTS (
        SELECT 1 FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, 'policy.read', p_evaluated_at)
    ) OR NOT EXISTS (
        SELECT 1 FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, 'device.read', p_evaluated_at)
    ) THEN
        RETURN NULL;
    END IF;

    SELECT MIN(snapshot.effective_at) INTO v_since
    FROM mesh_ops.access_edge_snapshot AS snapshot
    WHERE snapshot.workspace_id = v_workspace AND snapshot.network_id = v_network;
    SELECT MAX(history.network_revision) INTO v_revision
    FROM mesh_ops.network_revision_history AS history
    WHERE history.workspace_id = v_workspace AND history.network_id = v_network
      AND history.recorded_at <= p_at;
    SELECT pg_catalog.jsonb_build_object(
        'id', snapshot.public_id, 'network_revision', snapshot.network_revision,
        'effective_at', snapshot.effective_at, 'recorded_at', snapshot.recorded_at,
        'edge_count', snapshot.edge_count, 'digest', pg_catalog.encode(snapshot.digest, 'hex'))
    INTO v_snapshot
    FROM mesh_ops.access_edge_snapshot AS snapshot
    WHERE snapshot.workspace_id = v_workspace AND snapshot.network_id = v_network
      AND snapshot.effective_at <= p_at
    ORDER BY snapshot.network_revision DESC
    LIMIT 1;

    SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
            'edge_id', pg_catalog.encode(page.edge_key, 'hex'),
            'access_rule_id', page.access_rule_public_id,
            'selector_kind', page.selector_kind,
            'source_device_id', page.source_device_public_id,
            'source_hostname', source.hostname,
            'destination_device_id', page.destination_device_public_id,
            'destination_hostname', destination.hostname,
            'destination_imported_resource_id', page.destination_imported_resource_public_id,
            'trust_contract_id', page.trust_contract_public_id,
            'destination_resource_id', page.destination_resource_public_id,
            'destination_resource_group_id', page.destination_resource_group_public_id,
            'source_selector_kind', page.source_selector_kind,
            'source_selector_id', page.source_selector_public_id,
            'destination_selector_kind', page.destination_selector_kind,
            'destination_selector_id', page.destination_selector_public_id,
            'protocol', page.protocol,
            'destination_port_range_first', ARRAY(
                SELECT pg_catalog.lower(port_range)::INTEGER
                FROM pg_catalog.unnest(page.destination_ports) AS port_range
                ORDER BY pg_catalog.lower(port_range)),
            'destination_port_range_last', ARRAY(
                SELECT (pg_catalog.upper(port_range) - 1)::INTEGER
                FROM pg_catalog.unnest(page.destination_ports) AS port_range
                ORDER BY pg_catalog.lower(port_range)),
            'valid_from_revision', page.valid_from_revision,
            'valid_from_at', page.valid_from_at,
            'valid_to_revision', page.valid_to_revision,
            'valid_to_at', page.valid_to_at,
            'expires_at', CASE WHEN page.expires_at >= never_expires THEN NULL ELSE page.expires_at END
        ) ORDER BY page.edge_key), '[]'::JSONB)
    INTO v_edges
    FROM (
        SELECT edge.*
        FROM mesh_ops.access_edge_history AS edge
        WHERE edge.workspace_id = v_workspace AND edge.network_id = v_network
          AND v_since IS NOT NULL AND p_at >= v_since
          AND edge.valid_from_at <= p_at
          AND (edge.valid_to_at IS NULL OR edge.valid_to_at > p_at)
          AND edge.expires_at > p_at
          AND (p_after_edge_key IS NULL OR edge.edge_key > p_after_edge_key)
          AND (p_protocol IS NULL OR edge.protocol = p_protocol)
          AND (p_device_public_id IS NULL OR edge.source_device_public_id = p_device_public_id
               OR edge.destination_device_public_id = p_device_public_id)
          AND (p_source_public_id IS NULL OR edge.source_device_public_id = p_source_public_id)
          AND (p_destination_public_id IS NULL OR edge.destination_device_public_id = p_destination_public_id)
        ORDER BY edge.edge_key
        LIMIT p_limit
    ) AS page
    LEFT JOIN mesh.device AS source
      ON source.workspace_id = v_workspace AND source.network_id = v_network
     AND source.public_id = page.source_device_public_id
    LEFT JOIN mesh.device AS destination
      ON destination.workspace_id = v_workspace AND destination.network_id = v_network
     AND destination.public_id = page.destination_device_public_id;

    RETURN pg_catalog.jsonb_build_object(
        'workspace_id', p_workspace_public_id,
        'network_id', p_network_public_id,
        'at', p_at,
        'recorded_since', v_since,
        'network_revision', v_revision,
        'snapshot', v_snapshot,
        'edges', v_edges
    );
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.record_network_revision_history_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.access_edges_internal_v1(BIGINT, BIGINT, BIGINT, TIMESTAMPTZ)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.access_edge_snapshot_payload_internal_v1(BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.list_access_ledger_due_v1(UUID, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.record_access_edges_v1(UUID, UUID, UUID, UUID, UUID)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.append_access_edge_evidence_v1(UUID, BIGINT, BIGINT, BYTEA, BYTEA, UUID, UUID, JSONB)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.prune_access_ledger_v1(UUID, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_access_ledger_due_v1(UUID, INTEGER) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.record_access_edges_v1(UUID, UUID, UUID, UUID, UUID) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.append_access_edge_evidence_v1(UUID, BIGINT, BIGINT, BYTEA, BYTEA, UUID, UUID, JSONB)
    TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.prune_access_ledger_v1(UUID, INTEGER) TO mesh_worker;
REVOKE ALL ON FUNCTION mesh_ops.read_access_graph_history_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ,
    TIMESTAMPTZ, UUID, UUID, UUID, TEXT, BYTEA, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_access_graph_history_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ,
    TIMESTAMPTZ, UUID, UUID, UUID, TEXT, BYTEA, INTEGER
) TO mesh_runtime;
