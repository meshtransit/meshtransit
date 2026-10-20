-- Schema 199: the access edge ledger records rules to Sites (TD-CORE-62).
--
-- access_edges_internal_v2 is v1's edge set plus one edge per active,
-- unexpired Device a route rule of the active release grants a Site to,
-- resolved as the Access Graph lists them (site_graph_edges_internal_v1:
-- current membership, not the Site's own routers). A Site edge names the Site
-- and the prefixes the rule grants; its key is built like v1's, with the Site
-- and prefixes added, so the keys of the other edges do not change and no
-- edge closes and reopens when this schema arrives.
--
-- record_access_edges_v1 keeps its signature and now records v2's set, so
-- every Core version that calls it records the same edges. History reads
-- share one body: read_access_graph_history_v1, which older Cores call and
-- whose decoders know no Site edge, leaves Site edges out; v2 returns them
-- with destination_site_id and destination_prefixes.

ALTER TABLE mesh_ops.access_edge_history
    ADD COLUMN destination_site_public_id UUID,
    ADD COLUMN destination_prefixes CIDR[];
ALTER TABLE mesh_ops.access_edge_history DROP CONSTRAINT access_edge_history_kind_check;
ALTER TABLE mesh_ops.access_edge_history ADD CONSTRAINT access_edge_history_kind_check CHECK (
    (selector_kind IN ('device', 'resource', 'resource_group')
        AND destination_device_public_id IS NOT NULL
        AND destination_imported_resource_public_id IS NULL AND trust_contract_public_id IS NULL
        AND destination_site_public_id IS NULL AND destination_prefixes IS NULL)
    OR (selector_kind = 'imported_resource'
        AND destination_device_public_id IS NULL
        AND destination_imported_resource_public_id IS NOT NULL AND trust_contract_public_id IS NOT NULL
        AND destination_site_public_id IS NULL AND destination_prefixes IS NULL)
    OR (selector_kind = 'site'
        AND destination_device_public_id IS NULL
        AND destination_imported_resource_public_id IS NULL AND trust_contract_public_id IS NULL
        AND destination_site_public_id IS NOT NULL
        AND destination_prefixes IS NOT NULL AND mesh_ops.site_prefixes_valid_internal_v1(destination_prefixes))
);

CREATE FUNCTION mesh_ops.access_edges_internal_v2(
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
    expires_at TIMESTAMPTZ,
    destination_site_public_id UUID,
    destination_prefixes CIDR[]
)
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_release_id BIGINT;
BEGIN
    -- v1 checks the bound scope and returns nothing without an active release.
    RETURN QUERY
    SELECT edge.*, NULL::UUID, NULL::CIDR[]
    FROM mesh_ops.access_edges_internal_v1(p_workspace_id, p_network_id, p_policy_revision, p_now) AS edge;

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
    WITH site_edge AS (
        SELECT rule.access_rule_public_id AS rule_id,
            source.public_id AS source_id,
            edge.source_selector_kind AS source_selector,
            CASE edge.source_selector_kind
                WHEN 'device_group' THEN device_group.public_id
                WHEN 'identity_group' THEN identity_group.public_id
                WHEN 'device_tag' THEN device_tag.public_id
            END AS source_selector_id,
            rule.protocol,
            rule.destination_ports,
            source.expires_at AS expiry,
            network_site.public_id AS site_id,
            rule.prefixes
        FROM mesh_ops.site_graph_edges_internal_v1(
            p_workspace_id, p_network_id, v_release_id, NULL, '{}', '{}', '{}') AS edge
        JOIN mesh.compiled_policy_route_rule AS rule ON rule.id = edge.route_rule_id
        JOIN mesh.network_site AS network_site
          ON network_site.id = rule.destination_site_id AND network_site.state = 'active'
        JOIN mesh.device AS source
          ON source.workspace_id = p_workspace_id AND source.network_id = p_network_id
         AND source.id = edge.source_device_id
        LEFT JOIN mesh.device_group AS device_group ON device_group.id = rule.source_device_group_id
        LEFT JOIN mesh.identity_group AS identity_group ON identity_group.id = rule.source_identity_group_id
        LEFT JOIN mesh.device_tag AS device_tag ON device_tag.id = rule.source_device_tag_id
        WHERE source.state = 'active' AND source.expires_at > p_now
    )
    SELECT DISTINCT ON (keyed.key)
        keyed.key, keyed.rule_id, 'site'::TEXT, keyed.source_id, NULL::UUID, NULL::UUID, NULL::UUID,
        NULL::UUID, NULL::UUID, keyed.source_selector, keyed.source_selector_id, NULL::TEXT, NULL::UUID,
        keyed.protocol, keyed.destination_ports, keyed.expiry, keyed.site_id, keyed.prefixes
    FROM (
        SELECT pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.concat_ws('|',
                'access-edge/v1', 'site', site_edge.rule_id::TEXT, site_edge.source_id::TEXT,
                '-', '-', '-', '-', '-', COALESCE(site_edge.source_selector, '-'),
                COALESCE(site_edge.source_selector_id::TEXT, '-'), '-', '-', site_edge.protocol,
                site_edge.destination_ports::TEXT,
                ((EXTRACT(EPOCH FROM site_edge.expiry) * 1000000)::BIGINT)::TEXT,
                site_edge.site_id::TEXT, site_edge.prefixes::TEXT
            ), 'UTF8')) AS key,
            site_edge.*
        FROM site_edge
    ) AS keyed
    ORDER BY keyed.key;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.access_edges_internal_v2(BIGINT, BIGINT, BIGINT, TIMESTAMPTZ)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE OR REPLACE FUNCTION mesh_ops.record_access_edges_v1(
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
        SELECT * FROM mesh_ops.access_edges_internal_v2(v_workspace_id, v_network_id, v_policy_revision, v_now)
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
            protocol, destination_ports, expires_at, valid_from_revision, valid_from_at,
            destination_site_public_id, destination_prefixes
        )
        SELECT v_workspace_id, v_network_id, current_edge.edge_key, current_edge.access_rule_public_id,
            current_edge.selector_kind, current_edge.source_device_public_id,
            current_edge.destination_device_public_id, current_edge.destination_imported_resource_public_id,
            current_edge.trust_contract_public_id, current_edge.destination_resource_public_id,
            current_edge.destination_resource_group_public_id, current_edge.source_selector_kind,
            current_edge.source_selector_public_id, current_edge.destination_selector_kind,
            current_edge.destination_selector_public_id, current_edge.protocol,
            current_edge.destination_ports, current_edge.expires_at, v_revision, v_effective_at,
            current_edge.destination_site_public_id, current_edge.destination_prefixes
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

-- The body of the history reads. Without p_include_sites, Site edges are
-- left out and the edges carry no Site keys.
CREATE FUNCTION mesh_ops.read_access_graph_history_internal_v1(
    p_session_public_id UUID, p_deployment_public_id UUID,
    p_principal_public_id UUID, p_identity_subject_public_id UUID,
    p_session_version BIGINT, p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT, p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT, p_workspace_public_id UUID,
    p_network_public_id UUID, p_evaluated_at TIMESTAMPTZ,
    p_at TIMESTAMPTZ, p_device_public_id UUID, p_source_public_id UUID,
    p_destination_public_id UUID, p_protocol TEXT, p_after_edge_key BYTEA, p_limit INTEGER,
    p_include_sites BOOLEAN
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
        OR p_include_sites IS NULL
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
        ) || CASE WHEN p_include_sites THEN pg_catalog.jsonb_build_object(
            'destination_site_id', page.destination_site_public_id,
            'destination_prefixes', CASE WHEN page.destination_prefixes IS NULL THEN NULL ELSE ARRAY(
                SELECT prefix::TEXT FROM pg_catalog.unnest(page.destination_prefixes) AS prefix ORDER BY prefix)
                END
        ) ELSE '{}'::JSONB END
        ORDER BY page.edge_key), '[]'::JSONB)
    INTO v_edges
    FROM (
        SELECT edge.*
        FROM mesh_ops.access_edge_history AS edge
        WHERE edge.workspace_id = v_workspace AND edge.network_id = v_network
          AND v_since IS NOT NULL AND p_at >= v_since
          AND edge.valid_from_at <= p_at
          AND (edge.valid_to_at IS NULL OR edge.valid_to_at > p_at)
          AND edge.expires_at > p_at
          AND (p_include_sites OR edge.selector_kind <> 'site')
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

REVOKE ALL ON FUNCTION mesh_ops.read_access_graph_history_internal_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ,
    TIMESTAMPTZ, UUID, UUID, UUID, TEXT, BYTEA, INTEGER, BOOLEAN
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE OR REPLACE FUNCTION mesh_ops.read_access_graph_history_v1(
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
LANGUAGE sql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT mesh_ops.read_access_graph_history_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_evaluated_at, p_at, p_device_public_id, p_source_public_id, p_destination_public_id,
        p_protocol, p_after_edge_key, p_limit, FALSE)
$function$;

CREATE FUNCTION mesh_ops.read_access_graph_history_v2(
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
LANGUAGE sql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT mesh_ops.read_access_graph_history_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_evaluated_at, p_at, p_device_public_id, p_source_public_id, p_destination_public_id,
        p_protocol, p_after_edge_key, p_limit, TRUE)
$function$;

REVOKE ALL ON FUNCTION mesh_ops.read_access_graph_history_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ,
    TIMESTAMPTZ, UUID, UUID, UUID, TEXT, BYTEA, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_access_graph_history_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ,
    TIMESTAMPTZ, UUID, UUID, UUID, TEXT, BYTEA, INTEGER
) TO mesh_runtime;
