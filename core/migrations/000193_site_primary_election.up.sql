-- Schema 193: Core elects each Site's primary router (R2a, design §6.2 and
-- §6.5.3).
--
-- The worker reads, page by page, the facts of every active Site with
-- routers (priority, state, whether each router's Device is live,
-- Workspace-owned and offers the Site's prefixes, and the current primary),
-- adds what Redis holds of the routers' health, and decides in Go. A change
-- is written by prepare and finalize in one transaction, as other
-- reconcilers do: prepare checks the generation the decision was made on
-- (an older decision writes nothing), records the new primary, advances the
-- Network and route revisions (the generation consumers see) and returns
-- the evidence; Go hashes it; finalize appends the audit event
-- site.primary_changed (system.reconcile, no actor) with the revision
-- wakeup that rebuilds the Network's maps.
--
-- Maps read the elected primary with the Sites (load_map_network_sites_v2).
-- A Site without a row keeps the primary by priority until its first
-- election. Lock order: the Network revision, the Site's primary row, the
-- audit head.

CREATE TABLE mesh.site_primary (
    site_id BIGINT PRIMARY KEY,
    -- The Site's public ID, which names the aggregate in the audit stream.
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    -- NULL: no router can serve the Site. previous_device_id is the primary
    -- this election replaced, for its evidence.
    device_id BIGINT,
    previous_device_id BIGINT,
    generation BIGINT NOT NULL CHECK (generation > 0),
    reason TEXT NOT NULL CHECK (reason ~ '^[a-z_]{1,32}$'),
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    elected_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT site_primary_site_fk FOREIGN KEY (workspace_id, network_id, site_id)
        REFERENCES mesh.network_site (workspace_id, network_id, id) ON DELETE CASCADE,
    CONSTRAINT site_primary_device_fk FOREIGN KEY (workspace_id, network_id, device_id)
        REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE SET NULL (device_id),
    CONSTRAINT site_primary_previous_device_fk FOREIGN KEY (workspace_id, network_id, previous_device_id)
        REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE SET NULL (previous_device_id)
);

CREATE INDEX site_primary_device_idx ON mesh.site_primary (device_id) WHERE device_id IS NOT NULL;

CREATE TRIGGER site_primary_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.site_primary
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('site_primary', 'public_id');

ALTER TABLE mesh.site_primary ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.site_primary FORCE ROW LEVEL SECURITY;
CREATE POLICY site_primary_migrator_policy ON mesh.site_primary TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.site_primary FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer,
    mesh_share_writer;

-- The deployment the worker serves.
CREATE FUNCTION mesh_ops.site_election_deployment_internal_v1(p_deployment UUID)
RETURNS BIGINT
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_deployment_id BIGINT;
BEGIN
    SELECT deployment.id INTO v_deployment_id
    FROM mesh.deployment AS deployment
    WHERE deployment.installation_public_id = p_deployment AND deployment.deleted_at IS NULL;
    IF v_deployment_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Site election installation is unavailable';
    END IF;
    RETURN v_deployment_id;
END;
$function$;

-- One page of active Sites with routers, in Site order after p_after_site:
-- each Site's failback setting, its current primary and generation (none
-- before its first election) and its routers with the facts that decide
-- whether they can serve. A discovery read: prepare checks again under
-- locks. Devices, Networks and Workspaces are read in each Site's own scope.
CREATE FUNCTION mesh_ops.list_site_elections_v1(p_deployment UUID, p_after_site UUID, p_limit INTEGER)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_deployment_id BIGINT;
    v_site RECORD;
    v_items JSONB := '[]'::JSONB;
    v_count INTEGER := 0;
BEGIN
    IF p_deployment IS NULL OR p_limit IS NULL OR p_limit < 1 OR p_limit > 64 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Site election page';
    END IF;
    v_deployment_id := mesh_ops.site_election_deployment_internal_v1(p_deployment);
    FOR v_site IN
        SELECT network_site.id, network_site.public_id, network_site.workspace_id, network_site.network_id,
               network_site.failback, site_primary.device_id AS primary_id,
               COALESCE(site_primary.generation, 0) AS generation
        FROM mesh.network_site AS network_site
        LEFT JOIN mesh.site_primary AS site_primary ON site_primary.site_id = network_site.id
        WHERE network_site.deployment_id = v_deployment_id AND network_site.state = 'active'
          AND (p_after_site IS NULL OR network_site.public_id > p_after_site)
          AND EXISTS (SELECT 1 FROM mesh.network_site_router AS any_router WHERE any_router.site_id = network_site.id)
        ORDER BY network_site.public_id
        LIMIT p_limit + 1
    LOOP
        v_count := v_count + 1;
        EXIT WHEN v_count > p_limit;
        PERFORM pg_catalog.set_config('mesh.workspace_id', v_site.workspace_id::TEXT, TRUE);
        PERFORM pg_catalog.set_config('mesh.network_id', v_site.network_id::TEXT, TRUE);
        v_items := v_items || pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object(
            'site_id', v_site.public_id,
            'workspace_id', (SELECT workspace.public_id FROM mesh.workspace AS workspace
                             WHERE workspace.id = v_site.workspace_id),
            'network_id', (SELECT network.public_id FROM mesh.network AS network
                           WHERE network.workspace_id = v_site.workspace_id AND network.id = v_site.network_id),
            'failback', v_site.failback,
            'primary_device_id', (SELECT device.public_id FROM mesh.device AS device
                                  WHERE device.workspace_id = v_site.workspace_id
                                    AND device.network_id = v_site.network_id AND device.id = v_site.primary_id),
            'generation', v_site.generation,
            'routers', (
                SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                    'device_id', device.public_id,
                    'priority', router.priority,
                    'state', router.state,
                    'live', device.state = 'active' AND device.expires_at > pg_catalog.transaction_timestamp(),
                    'workspace_owned', device.ownership = 'workspace',
                    'covers', mesh_ops.offer_covers_internal_v1(COALESCE(offer.prefixes, '{}'::CIDR[]),
                        network_site.prefixes)
                ) ORDER BY router.priority, device.public_id)
                FROM mesh.network_site_router AS router
                JOIN mesh.network_site AS network_site ON network_site.id = router.site_id
                JOIN mesh.device AS device
                  ON device.workspace_id = router.workspace_id AND device.network_id = router.network_id
                 AND device.id = router.device_id
                LEFT JOIN mesh.device_route_advertisement AS offer ON offer.device_id = router.device_id
                WHERE router.site_id = v_site.id
            )
        ));
    END LOOP;
    RETURN pg_catalog.jsonb_build_object('items', v_items, 'done', v_count <= p_limit);
END;
$function$;

-- The audit and outbox payloads of a primary change, as prepare returns and
-- finalize recomputes them.
CREATE FUNCTION mesh_ops.site_primary_payloads_internal_v1(
    p_site UUID, p_device UUID, p_previous UUID, p_reason TEXT, p_generation BIGINT,
    p_network_revision BIGINT, p_route_revision BIGINT
)
RETURNS TABLE (audit_payload JSONB, outbox_payload JSONB)
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
               'site_public_id', p_site, 'device_public_id', p_device,
               'previous_device_public_id', p_previous, 'reason', p_reason, 'generation', p_generation,
               'network_revision', p_network_revision, 'route_revision', p_route_revision),
           pg_catalog.jsonb_build_object(
               'network_revision', p_network_revision, 'subsystem', 'routes',
               'subsystem_revision', p_route_revision)
$function$;

-- Makes p_device (NULL: none) the primary of p_site when its generation is
-- still p_expected_generation (0: never elected) and the Device is still one
-- of its routers, and returns the evidence to hash; otherwise changes
-- nothing.
CREATE FUNCTION mesh_ops.prepare_site_primary_v1(
    p_deployment UUID, p_site UUID, p_expected_generation BIGINT, p_device UUID, p_reason TEXT, p_change UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_unchanged CONSTANT JSONB := '{"changed":false}'::JSONB;
    v_deployment_id BIGINT;
    v_site mesh.network_site%ROWTYPE;
    v_scope RECORD;
    v_current mesh.site_primary%ROWTYPE;
    v_device_id BIGINT;
    v_previous UUID;
    v_revisions RECORD;
    v_head RECORD;
    v_generation BIGINT;
    v_version BIGINT;
    v_payloads RECORD;
BEGIN
    IF p_site IS NULL OR p_change IS NULL OR p_expected_generation IS NULL OR p_expected_generation < 0
        OR p_reason IS NULL OR p_reason !~ '^[a-z_]{1,32}$'
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_site), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Site election';
    END IF;
    v_deployment_id := mesh_ops.site_election_deployment_internal_v1(p_deployment);
    SELECT * INTO v_site FROM mesh.network_site AS network_site
    WHERE network_site.public_id = p_site AND network_site.deployment_id = v_deployment_id
      AND network_site.state = 'active';
    IF v_site.id IS NULL THEN
        RETURN v_unchanged;
    END IF;
    PERFORM pg_catalog.set_config('mesh.workspace_id', v_site.workspace_id::TEXT, TRUE);
    PERFORM pg_catalog.set_config('mesh.network_id', v_site.network_id::TEXT, TRUE);
    SELECT workspace.public_id AS workspace_public_id, network.public_id AS network_public_id INTO v_scope
    FROM mesh.network AS network
    JOIN mesh.workspace AS workspace ON workspace.id = network.workspace_id
    WHERE network.workspace_id = v_site.workspace_id AND network.id = v_site.network_id;
    PERFORM mesh_ops.lock_site_scope_internal_v1(v_site.workspace_id, v_site.network_id);

    SELECT * INTO v_current FROM mesh.site_primary AS site_primary
    WHERE site_primary.site_id = v_site.id FOR UPDATE;
    IF COALESCE(v_current.generation, 0) <> p_expected_generation THEN
        RETURN v_unchanged; -- decided on an older state
    END IF;
    IF p_device IS NOT NULL THEN
        -- Still a router of the Site that can serve it: the facts the
        -- decision was made on may have changed since the list.
        SELECT device.id INTO v_device_id
        FROM mesh.network_site_router AS router
        JOIN mesh.device AS device
          ON device.workspace_id = router.workspace_id AND device.network_id = router.network_id
         AND device.id = router.device_id
        LEFT JOIN mesh.device_route_advertisement AS offer ON offer.device_id = router.device_id
        WHERE router.site_id = v_site.id AND device.public_id = p_device
          AND device.state = 'active' AND device.expires_at > pg_catalog.transaction_timestamp()
          AND device.ownership = 'workspace'
          AND mesh_ops.offer_covers_internal_v1(COALESCE(offer.prefixes, '{}'::CIDR[]), v_site.prefixes);
        IF v_device_id IS NULL THEN
            RETURN v_unchanged; -- no longer a router of the Site that can serve it
        END IF;
    END IF;
    IF v_current.site_id IS NOT NULL AND v_current.device_id IS NOT DISTINCT FROM v_device_id THEN
        RETURN v_unchanged;
    END IF;
    SELECT device.public_id INTO v_previous FROM mesh.device AS device
    WHERE device.workspace_id = v_site.workspace_id AND device.network_id = v_site.network_id
      AND device.id = v_current.device_id;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change::TEXT, TRUE);
    SELECT * INTO STRICT v_revisions FROM mesh_ops.advance_site_revisions_internal_v1(v_site.workspace_id,
        v_site.network_id);
    INSERT INTO mesh.site_primary AS site_primary
        (site_id, public_id, workspace_id, network_id, device_id, previous_device_id, generation, reason, elected_at)
    VALUES (v_site.id, v_site.public_id, v_site.workspace_id, v_site.network_id, v_device_id, NULL, 1, p_reason,
        pg_catalog.transaction_timestamp())
    ON CONFLICT (site_id) DO UPDATE
    SET device_id = EXCLUDED.device_id, previous_device_id = site_primary.device_id,
        generation = site_primary.generation + 1, reason = EXCLUDED.reason,
        version = site_primary.version + 1, elected_at = EXCLUDED.elected_at
    RETURNING site_primary.generation, site_primary.version INTO v_generation, v_version;

    SELECT stream.id, stream.next_sequence, stream.latest_event_hash INTO STRICT v_head
    FROM mesh_audit.audit_stream AS stream
    WHERE stream.workspace_id = v_site.workspace_id AND stream.network_id = v_site.network_id
    FOR UPDATE;
    SELECT * INTO STRICT v_payloads FROM mesh_ops.site_primary_payloads_internal_v1(p_site, p_device, v_previous,
        p_reason, v_generation, v_revisions.network_revision, v_revisions.route_revision);
    RETURN pg_catalog.jsonb_build_object(
        'changed', TRUE,
        'transaction_id', (pg_catalog.pg_current_xact_id()::TEXT),
        'change_id', p_change,
        'site_id', p_site,
        'generation', v_generation,
        'aggregate_version', v_version,
        'event', pg_catalog.jsonb_build_object(
            'workspace_id', v_scope.workspace_public_id,
            'network_id', v_scope.network_public_id,
            'stream_id', v_head.id,
            'sequence', v_head.next_sequence,
            'previous_hash', pg_catalog.encode(v_head.latest_event_hash, 'hex'),
            'network_revision', v_revisions.network_revision,
            'audit_payload', v_payloads.audit_payload::TEXT,
            'outbox_payload', v_payloads.outbox_payload::TEXT
        )
    );
END;
$function$;

-- Records the evidence prepare returned, once MeshCore has hashed it.
-- Everything appended is recomputed here and must match, so only the ids
-- and hash come from the caller.
CREATE FUNCTION mesh_ops.finalize_site_primary_v1(
    p_deployment UUID, p_site UUID, p_change UUID, p_reason TEXT, p_event JSONB
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_deployment_id BIGINT;
    v_primary mesh.site_primary%ROWTYPE;
    v_device UUID;
    v_previous UUID;
    v_revisions RECORD;
    v_head RECORD;
    v_payloads RECORD;
    v_sequence BIGINT;
BEGIN
    IF p_site IS NULL OR p_change IS NULL OR p_reason IS NULL OR p_reason !~ '^[a-z_]{1,32}$'
        OR p_event IS NULL OR pg_catalog.jsonb_typeof(p_event) <> 'object'
        OR pg_catalog.octet_length(p_event::TEXT) > 16384 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Site election evidence';
    END IF;
    IF pg_catalog.current_setting('mesh.change_public_id', TRUE) IS DISTINCT FROM p_change::TEXT THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Site election was not prepared in this transaction';
    END IF;
    v_deployment_id := mesh_ops.site_election_deployment_internal_v1(p_deployment);
    SELECT site_primary.* INTO v_primary
    FROM mesh.site_primary AS site_primary
    JOIN mesh.network_site AS network_site ON network_site.id = site_primary.site_id
    WHERE site_primary.public_id = p_site AND network_site.deployment_id = v_deployment_id;
    IF v_primary.site_id IS NULL OR v_primary.reason <> p_reason OR NOT EXISTS (
        SELECT 1 FROM mesh_audit.authority_mutation AS mutation
        WHERE mutation.transaction_id = (pg_catalog.pg_current_xact_id()::TEXT)::BIGINT
          AND mutation.change_public_id = p_change
          AND mutation.aggregate_kind = 'site_primary'
          AND mutation.row_public_id = v_primary.public_id
          AND mutation.after_version = v_primary.version
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Site election mutation missing';
    END IF;
    SELECT device.public_id INTO v_device FROM mesh.device AS device
    WHERE device.workspace_id = v_primary.workspace_id AND device.network_id = v_primary.network_id
      AND device.id = v_primary.device_id;
    SELECT device.public_id INTO v_previous FROM mesh.device AS device
    WHERE device.workspace_id = v_primary.workspace_id AND device.network_id = v_primary.network_id
      AND device.id = v_primary.previous_device_id;
    SELECT revision.network_revision, revision.route_revision INTO STRICT v_revisions
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_primary.workspace_id AND revision.network_id = v_primary.network_id;
    SELECT stream.id, stream.next_sequence, stream.latest_event_hash INTO STRICT v_head
    FROM mesh_audit.audit_stream AS stream
    WHERE stream.workspace_id = v_primary.workspace_id AND stream.network_id = v_primary.network_id
    FOR UPDATE;
    SELECT * INTO STRICT v_payloads FROM mesh_ops.site_primary_payloads_internal_v1(p_site, v_device, v_previous,
        p_reason, v_primary.generation, v_revisions.network_revision, v_revisions.route_revision);
    IF (p_event ->> 'stream_id')::BIGINT IS DISTINCT FROM v_head.id
        OR (p_event ->> 'sequence')::BIGINT IS DISTINCT FROM v_head.next_sequence
        OR p_event ->> 'previous_hash' IS DISTINCT FROM pg_catalog.encode(v_head.latest_event_hash, 'hex')
        OR (p_event ->> 'network_revision')::BIGINT IS DISTINCT FROM v_revisions.network_revision
        OR p_event ->> 'audit_payload' IS DISTINCT FROM v_payloads.audit_payload::TEXT
        OR p_event ->> 'outbox_payload' IS DISTINCT FROM v_payloads.outbox_payload::TEXT THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Site election evidence mismatch';
    END IF;
    v_sequence := mesh_audit.append_authority_evidence(
        v_head.id,
        (p_event ->> 'event_id')::UUID,
        (p_event ->> 'outbox_id')::UUID,
        v_head.next_sequence,
        v_head.latest_event_hash,
        pg_catalog.decode(p_event ->> 'event_hash', 'hex'),
        'site_primary',
        v_primary.public_id,
        v_primary.version,
        v_revisions.network_revision,
        NULL::UUID,
        'site.primary_changed',
        'system.reconcile',
        NULL::UUID,
        NULL::BYTEA,
        NULL::BYTEA,
        v_payloads.audit_payload,
        'network.revision.advanced',
        v_payloads.outbox_payload
    );
    IF v_sequence <> v_head.next_sequence THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Site election evidence changed';
    END IF;
    RETURN 1;
END;
$function$;

-- The active Sites of the bound scope as v1 reads them, with the elected
-- primary: elected is FALSE before a Site's first election, and
-- primary_device_id NULL when no router can serve it.
CREATE FUNCTION mesh_ops.load_map_network_sites_v2(p_limit INTEGER)
RETURNS TABLE (
    site_id BIGINT,
    site_public_id UUID,
    prefixes CIDR[],
    masquerade BOOLEAN,
    probe_addresses INET[],
    probe_kinds TEXT[],
    probe_ports INTEGER[],
    elected BOOLEAN,
    primary_device_id BIGINT
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
BEGIN
    RETURN QUERY
    SELECT sites.site_id, sites.site_public_id, sites.prefixes, sites.masquerade, sites.probe_addresses,
           sites.probe_kinds, sites.probe_ports, site_primary.site_id IS NOT NULL, site_primary.device_id
    FROM mesh_ops.load_map_network_sites_v1(p_limit) AS sites
    LEFT JOIN mesh.site_primary AS site_primary ON site_primary.site_id = sites.site_id
    ORDER BY sites.site_public_id;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.site_election_deployment_internal_v1(UUID)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.site_primary_payloads_internal_v1(UUID, UUID, UUID, TEXT, BIGINT, BIGINT, BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.list_site_elections_v1(UUID, UUID, INTEGER)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.prepare_site_primary_v1(UUID, UUID, BIGINT, UUID, TEXT, UUID)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.finalize_site_primary_v1(UUID, UUID, UUID, TEXT, JSONB)
    FROM PUBLIC, mesh_runtime, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.load_map_network_sites_v2(INTEGER)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
-- Only the worker role elects primaries; maps read them at runtime.
GRANT EXECUTE ON FUNCTION mesh_ops.list_site_elections_v1(UUID, UUID, INTEGER) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.prepare_site_primary_v1(UUID, UUID, BIGINT, UUID, TEXT, UUID) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.finalize_site_primary_v1(UUID, UUID, UUID, TEXT, JSONB) TO mesh_worker;
GRANT EXECUTE ON FUNCTION mesh_ops.load_map_network_sites_v2(INTEGER) TO mesh_runtime;
