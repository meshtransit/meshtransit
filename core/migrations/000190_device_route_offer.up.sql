-- What a Device offers to forward, from its HostinfoReport (subnet routes,
-- R1.4a; mtcp-v1 §8.2).
--
-- report_device_route_offer_v1 stores the canonical prefixes the node's own
-- configuration offers, authenticated like logout_device_v1 by the machine
-- fingerprint and node key of the session. Go drops entries that are not
-- canonical and sends them sorted. An empty offer keeps the row, empty, so
-- its version only grows.
--
-- An unchanged offer writes nothing and takes no lock, so reconnect storms
-- cost two indexed reads per Device. A changed one serializes with Site,
-- router and policy changes on the Network revision row and is authority:
-- the row carries the Device's public ID and a version, its mutation is
-- captured, and Go seals it with device.route_offer_changed on the Network
-- stream. It moves maps only when it changes whether the Device covers an
-- active Site it routes: it then advances the Network and route revisions
-- (the route revision is the generation consumers see, mtcp-v1 §7.6) and the
-- event wakes map sessions. Any other change grants nothing and moves no map:
-- Core sends routers the Site's prefixes and each router forwards only into
-- what it offers itself.
--
-- Errors: 22023 invalid input, 42501 no Network scope, P0002 no active
-- Device with that machine and node key.

-- Nothing wrote offers before this schema except tests; the table is empty
-- or tiny, and the new columns need no rewrite.
ALTER TABLE mesh.device_route_advertisement
    ADD COLUMN public_id UUID,
    ADD COLUMN version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0);
UPDATE mesh.device_route_advertisement AS offer
SET public_id = device.public_id
FROM mesh.device AS device
WHERE device.id = offer.device_id;
ALTER TABLE mesh.device_route_advertisement
    ALTER COLUMN public_id SET NOT NULL,
    ADD CONSTRAINT device_route_advertisement_public_id_key UNIQUE (public_id),
    ADD CONSTRAINT device_route_advertisement_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    );
CREATE TRIGGER device_route_advertisement_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.device_route_advertisement
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('device_route_advertisement', 'public_id');

-- Whether an offer covers every prefix of a Site, as schema 188 decides a
-- router can serve.
CREATE FUNCTION mesh_ops.offer_covers_internal_v1(p_offer CIDR[], p_wanted CIDR[])
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT NOT EXISTS (
        SELECT 1 FROM pg_catalog.unnest(p_wanted) AS wanted
        WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.unnest(p_offer) AS offered WHERE wanted <<= offered))
$function$;
REVOKE ALL ON FUNCTION mesh_ops.offer_covers_internal_v1(CIDR[], CIDR[])
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE FUNCTION mesh_ops.report_device_route_offer_v1(
    p_machine_fingerprint BYTEA, p_node_key BYTEA, p_prefixes CIDR[], p_change_public_id UUID
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
    v_device mesh.device%ROWTYPE;
    v_before CIDR[];
    v_after CIDR[];
    v_router BOOLEAN;
    v_version BIGINT;
    v_actor UUID;
    v_revisions RECORD;
BEGIN
    IF p_machine_fingerprint IS NULL OR pg_catalog.octet_length(p_machine_fingerprint) <> 32
        OR p_node_key IS NULL OR pg_catalog.octet_length(p_node_key) <> 32
        OR p_prefixes IS NULL OR NOT mesh_ops.advertised_prefixes_valid_internal_v1(p_prefixes)
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'route offer is invalid';
    END IF;
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    v_after := p_prefixes;

    FOR attempt IN 1..2 LOOP
        SELECT device.* INTO v_device
        FROM mesh.device AS device
        JOIN mesh.device_machine_key_epoch AS machine
          ON machine.workspace_id = device.workspace_id AND machine.network_id = device.network_id
         AND machine.device_id = device.id AND machine.epoch = device.current_machine_key_epoch
         AND machine.state = 'active' AND machine.fingerprint = p_machine_fingerprint
        JOIN mesh.device_node_key_epoch AS node_key
          ON node_key.workspace_id = device.workspace_id AND node_key.network_id = device.network_id
         AND node_key.device_id = device.id AND node_key.epoch = device.current_node_key_epoch
         AND node_key.state = 'active' AND node_key.public_key = p_node_key
        WHERE device.workspace_id = v_workspace AND device.network_id = v_network
          AND device.state = 'active' AND device.deleted_at IS NULL;
        IF v_device.id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Device is unavailable';
        END IF;
        SELECT offer.prefixes INTO v_before
        FROM mesh.device_route_advertisement AS offer WHERE offer.device_id = v_device.id;
        v_before := COALESCE(v_before, '{}'::CIDR[]);
        IF v_before = v_after THEN
            RETURN pg_catalog.jsonb_build_object('changed', FALSE);
        END IF;
        EXIT WHEN attempt = 2;
        -- A change: serialize with Site, router and policy changes and with
        -- the Device's own lifecycle, then read again under the lock.
        PERFORM 1 FROM mesh_ops.network_revision AS revision
        WHERE revision.workspace_id = v_workspace AND revision.network_id = v_network
        FOR UPDATE;
    END LOOP;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    INSERT INTO mesh.device_route_advertisement AS offer
        (device_id, workspace_id, network_id, public_id, prefixes, reported_at)
    VALUES (v_device.id, v_workspace, v_network, v_device.public_id, v_after, pg_catalog.transaction_timestamp())
    ON CONFLICT (device_id) DO UPDATE
    SET prefixes = EXCLUDED.prefixes, reported_at = EXCLUDED.reported_at, version = offer.version + 1
    RETURNING offer.version INTO v_version;

    v_router := EXISTS (
        SELECT 1 FROM mesh.network_site_router AS router
        JOIN mesh.network_site AS network_site ON network_site.id = router.site_id AND network_site.state = 'active'
        WHERE router.device_id = v_device.id
          AND mesh_ops.offer_covers_internal_v1(v_before, network_site.prefixes)
              <> mesh_ops.offer_covers_internal_v1(v_after, network_site.prefixes)
    );
    IF v_router THEN
        SELECT * INTO STRICT v_revisions FROM mesh_ops.advance_site_revisions_internal_v1(v_workspace, v_network);
    ELSE
        SELECT revision.network_revision, revision.route_revision INTO STRICT v_revisions
        FROM mesh_ops.network_revision AS revision
        WHERE revision.workspace_id = v_workspace AND revision.network_id = v_network;
    END IF;
    SELECT principal.public_id INTO STRICT v_actor
    FROM mesh.principal AS principal WHERE principal.id = v_device.owner_principal_id;
    RETURN pg_catalog.jsonb_build_object(
        'changed', TRUE, 'moves_maps', v_router,
        'device_id', v_device.public_id, 'hostname', v_device.hostname, 'version', v_version,
        'actor_principal_id', v_actor,
        'before', v_before, 'after', v_after,
        'network_revision', v_revisions.network_revision, 'route_revision', v_revisions.route_revision
    );
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.report_device_route_offer_v1(BYTEA, BYTEA, CIDR[], UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mesh_ops.report_device_route_offer_v1(BYTEA, BYTEA, CIDR[], UUID) TO mesh_runtime;
