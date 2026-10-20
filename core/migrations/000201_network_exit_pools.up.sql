-- Network Exit Pools and their exit nodes (exit node design §5, step E1a).
--
-- An Exit Pool is a group of exit nodes: Devices of the Network that forward
-- other Devices' Internet traffic. It is its own entity, never a kind of
-- Site: a Site is an address space to reach, an Exit Pool a way out to the
-- Internet. Go validates names, limits and the Internet addresses a pool is
-- configured with; these tables keep the bounds and the identities, and the
-- SECURITY DEFINER functions below check the caller's Session and the exact
-- Network permission. Each change returns its document; the caller appends
-- the evidence on the Network stream with the Network and route revisions
-- these functions advance, so maps are rebuilt. A change that changes
-- nothing writes nothing.
--
-- An exit node serves only while its Device is active, owned by the
-- Workspace and offers to be an exit node itself (mesh.device_exit_offer,
-- written from the node's report). Assigning a Device does not need the
-- offer: the pool can be prepared before the exit node is turned on.
-- Documents return those facts; Go decides. A Device is an exit node of one
-- pool at most.
--
-- Errors: 22023 invalid input, 42501 not authorized, P0002 unknown pool or
-- exit node, 40001 stale version, MTX01 name taken, MTX02 pool limit, MTX03
-- exit node limit, MTX04 the Device is not an active, Workspace-owned Device
-- of this Network, MTX05 the Device is an exit node of another pool.
--
-- Pools use the route permissions, as Sites do: route.read lists them;
-- route.approve creates and changes pools and chooses exit nodes;
-- route.withdraw deletes pools and removes exit nodes.

-- Whether an address is on the Internet as an exit node forwards to it; the
-- same set as Go's shared/internet. A guard: Go refuses other addresses
-- first.
CREATE FUNCTION mesh_ops.internet_address_internal_v1(p_address INET)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT p_address IS NOT NULL
       AND pg_catalog.masklen(p_address) = CASE pg_catalog.family(p_address) WHEN 4 THEN 32 ELSE 128 END
       AND (pg_catalog.family(p_address) = 4 OR p_address <<= '2000::/3'::INET)
       AND NOT EXISTS (
           SELECT 1 FROM pg_catalog.unnest(ARRAY[
               '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '168.63.129.16/32',
               '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.31.196.0/24',
               '192.52.193.0/24', '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24',
               '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
               '2001::/32', '2001:2::/48', '2001:10::/28', '2001:20::/28', '2001:db8::/32', '2002::/16',
               '3fff::/20'
           ]::INET[]) AS excluded
           WHERE pg_catalog.family(excluded) = pg_catalog.family(p_address) AND p_address <<= excluded)
$function$;

CREATE FUNCTION mesh_ops.exit_pool_upstreams_valid_internal_v1(p_upstreams INET[])
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.cardinality(p_upstreams) <= 4
       AND NOT EXISTS (
           SELECT 1 FROM pg_catalog.unnest(p_upstreams) AS upstream
           WHERE NOT mesh_ops.internet_address_internal_v1(upstream))
       AND (SELECT pg_catalog.count(DISTINCT upstream) FROM pg_catalog.unnest(p_upstreams) AS upstream)
           = pg_catalog.cardinality(p_upstreams)
$function$;

-- Each probe is an object of an Internet address and a TCP port, at most
-- eight of them, without duplicates.
CREATE FUNCTION mesh_ops.exit_pool_probes_valid_internal_v1(p_probes JSONB)
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_typeof(p_probes) = 'array'
       AND pg_catalog.jsonb_array_length(p_probes) <= 8
       AND NOT EXISTS (
           SELECT 1 FROM pg_catalog.jsonb_array_elements(p_probes) AS probe(item)
           WHERE pg_catalog.jsonb_typeof(probe.item) <> 'object'
              OR (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(probe.item)) <> 2
              OR pg_catalog.jsonb_typeof(probe.item -> 'address') IS DISTINCT FROM 'string'
              OR pg_catalog.jsonb_typeof(probe.item -> 'port') IS DISTINCT FROM 'number'
              OR (probe.item ->> 'port') !~ '^[1-9][0-9]{0,4}$'
              OR (probe.item ->> 'port')::INTEGER > 65535
              OR (probe.item ->> 'address') !~ '^[0-9A-Fa-f.:]{2,39}$'
              OR NOT mesh_ops.internet_address_internal_v1((probe.item ->> 'address')::INET))
       AND (SELECT pg_catalog.count(DISTINCT probe.item) FROM pg_catalog.jsonb_array_elements(p_probes) AS probe(item))
           = pg_catalog.jsonb_array_length(p_probes)
$function$;

CREATE TABLE mesh.network_exit_pool (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    name TEXT NOT NULL,
    name_key TEXT NOT NULL,
    failback BOOLEAN NOT NULL,
    smtp_allowed BOOLEAN NOT NULL,
    conntrack_per_consumer INTEGER NOT NULL,
    dns_upstreams INET[] NOT NULL DEFAULT '{}'::INET[],
    probes JSONB NOT NULL DEFAULT '[]'::JSONB,
    state TEXT NOT NULL DEFAULT 'active',
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ,
    CONSTRAINT network_exit_pool_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT network_exit_pool_name_check CHECK (
        name = pg_catalog.btrim(name)
        AND pg_catalog.char_length(name) BETWEEN 1 AND 64
        AND name !~ '[[:cntrl:]]'
        AND name_key = pg_catalog.lower(name)
    ),
    CONSTRAINT network_exit_pool_conntrack_check CHECK (conntrack_per_consumer BETWEEN 1024 AND 262144),
    CONSTRAINT network_exit_pool_upstreams_check CHECK (
        mesh_ops.exit_pool_upstreams_valid_internal_v1(dns_upstreams)
    ),
    CONSTRAINT network_exit_pool_probes_check CHECK (mesh_ops.exit_pool_probes_valid_internal_v1(probes)),
    CONSTRAINT network_exit_pool_state_check CHECK (
        (state = 'active' AND deleted_at IS NULL) OR (state = 'deleted' AND deleted_at IS NOT NULL)
    ),
    CONSTRAINT network_exit_pool_timestamps_check CHECK (updated_at >= created_at),
    CONSTRAINT network_exit_pool_workspace_fk FOREIGN KEY (deployment_id, workspace_id)
        REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT network_exit_pool_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    UNIQUE (workspace_id, network_id, id)
);

CREATE UNIQUE INDEX network_exit_pool_active_name_uidx
    ON mesh.network_exit_pool (workspace_id, network_id, name_key)
    WHERE state = 'active';

CREATE TABLE mesh.network_exit_node (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    pool_id BIGINT NOT NULL,
    device_id BIGINT NOT NULL,
    priority INTEGER NOT NULL,
    state TEXT NOT NULL,
    added_by_principal_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT network_exit_node_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT network_exit_node_priority_check CHECK (priority BETWEEN 0 AND 999),
    CONSTRAINT network_exit_node_state_check CHECK (state IN ('active', 'draining')),
    CONSTRAINT network_exit_node_timestamps_check CHECK (updated_at >= created_at),
    CONSTRAINT network_exit_node_pool_fk FOREIGN KEY (workspace_id, network_id, pool_id)
        REFERENCES mesh.network_exit_pool (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT network_exit_node_device_fk FOREIGN KEY (workspace_id, network_id, device_id)
        REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE RESTRICT,
    -- One pool per Device: an exit node's way out belongs to one pool.
    CONSTRAINT network_exit_node_device_key UNIQUE (device_id)
);

CREATE INDEX network_exit_node_pool_idx ON mesh.network_exit_node (pool_id);

-- Whether a Device's local configuration offers to be an exit node, from
-- its latest report. A report, not authority: offering grants nothing.
CREATE TABLE mesh.device_exit_offer (
    device_id BIGINT PRIMARY KEY,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    offered BOOLEAN NOT NULL,
    reported_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT device_exit_offer_device_fk FOREIGN KEY (workspace_id, network_id, device_id)
        REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE CASCADE
);

CREATE FUNCTION mesh_ops.enforce_network_exit_pool_transition_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Exit Pools are deleted by state, never removed';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'active' OR NEW.version <> 1 THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid new Exit Pool';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.public_id <> OLD.public_id OR NEW.deployment_id <> OLD.deployment_id
        OR NEW.workspace_id <> OLD.workspace_id OR NEW.network_id <> OLD.network_id
        OR NEW.created_at <> OLD.created_at OR NEW.version <> OLD.version + 1
        OR OLD.state = 'deleted' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Exit Pool transition';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER network_exit_pool_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.network_exit_pool
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_network_exit_pool_transition_v1();
CREATE TRIGGER network_exit_pool_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.network_exit_pool
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('network_exit_pool', 'public_id');
CREATE TRIGGER network_exit_node_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.network_exit_node
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('network_exit_node', 'public_id');

-- A Device that leaves the Network (revoked, logged out, removed) drops its
-- exit offer in the same transaction; a suspended Device keeps it, as it
-- keeps its route offer (schema 200).
CREATE FUNCTION mesh_ops.drop_exit_offer_of_removed_device_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF NEW.deleted_at IS NOT NULL OR NEW.state NOT IN ('active', 'suspended') THEN
        DELETE FROM mesh.device_exit_offer AS offer
        WHERE offer.workspace_id = NEW.workspace_id
          AND offer.network_id = NEW.network_id
          AND offer.device_id = NEW.id;
    END IF;
    RETURN NULL;
END;
$function$;

CREATE TRIGGER device_drop_exit_offer
AFTER UPDATE OF state, deleted_at ON mesh.device
FOR EACH ROW
WHEN (OLD.state IS DISTINCT FROM NEW.state OR OLD.deleted_at IS DISTINCT FROM NEW.deleted_at)
EXECUTE FUNCTION mesh_ops.drop_exit_offer_of_removed_device_v1();

ALTER TABLE mesh.network_exit_pool ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.network_exit_pool FORCE ROW LEVEL SECURITY;
CREATE POLICY network_exit_pool_migrator_policy ON mesh.network_exit_pool
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
ALTER TABLE mesh.network_exit_node ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.network_exit_node FORCE ROW LEVEL SECURITY;
CREATE POLICY network_exit_node_migrator_policy ON mesh.network_exit_node
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
ALTER TABLE mesh.device_exit_offer ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.device_exit_offer FORCE ROW LEVEL SECURITY;
CREATE POLICY device_exit_offer_migrator_policy ON mesh.device_exit_offer
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.network_exit_pool, mesh.network_exit_node, mesh.device_exit_offer
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.internet_address_internal_v1(INET)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.exit_pool_upstreams_valid_internal_v1(INET[])
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.exit_pool_probes_valid_internal_v1(JSONB)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.enforce_network_exit_pool_transition_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.drop_exit_offer_of_removed_device_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The exact Network scope bound by the caller, after one permission check.
-- The permission resolver takes the Workspace lock first (schema 184).
CREATE FUNCTION mesh_ops.authorize_exit_pool_internal_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_permission TEXT
)
RETURNS TABLE (deployment_id BIGINT, workspace_id BIGINT, network_id BIGINT, principal_id BIGINT,
    role_binding_public_id UUID)
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_deployment BIGINT;
    v_principal BIGINT;
    v_binding UUID;
BEGIN
    IF p_workspace_public_id IS NULL OR p_network_public_id IS NULL
        OR p_permission NOT IN ('route.read', 'route.approve', 'route.withdraw') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Exit Pool scope input is invalid';
    END IF;
    SELECT permission.role_binding_public_id INTO v_binding
    FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version,
        p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_permission, pg_catalog.transaction_timestamp()
    ) AS permission;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Exit Pool action is not authorized';
    END IF;
    SELECT workspace.deployment_id INTO v_deployment
    FROM mesh.workspace AS workspace
    JOIN mesh.network AS network ON network.workspace_id = workspace.id
    WHERE workspace.id = v_workspace AND network.id = v_network
      AND workspace.public_id = p_workspace_public_id AND network.public_id = p_network_public_id
      AND workspace.state = 'active' AND workspace.deleted_at IS NULL
      AND network.state = 'active' AND network.deleted_at IS NULL;
    SELECT principal.id INTO v_principal FROM mesh.principal AS principal
    WHERE principal.public_id = p_principal_public_id;
    IF v_deployment IS NULL OR v_principal IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Exit Pool scope is unavailable';
    END IF;
    RETURN QUERY SELECT v_deployment, v_workspace, v_network, v_principal, v_binding;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.authorize_exit_pool_internal_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TEXT
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- One pool with its exit nodes and, for each, the facts Go needs to decide
-- whether it can serve: Device state, ownership and whether its own
-- configuration offers to be an exit node.
CREATE FUNCTION mesh_ops.exit_pool_document_internal_v1(p_pool mesh.network_exit_pool)
RETURNS JSONB
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'pool_id', p_pool.public_id,
        'name', p_pool.name,
        'failback', p_pool.failback,
        'smtp_allowed', p_pool.smtp_allowed,
        'conntrack_per_consumer', p_pool.conntrack_per_consumer,
        'dns_upstreams', COALESCE((
            SELECT pg_catalog.jsonb_agg(pg_catalog.host(upstream) ORDER BY ordinal)
            FROM pg_catalog.unnest(p_pool.dns_upstreams) WITH ORDINALITY AS item(upstream, ordinal)), '[]'::JSONB),
        'probes', p_pool.probes,
        'state', p_pool.state,
        'version', p_pool.version,
        'created_at', p_pool.created_at,
        'updated_at', p_pool.updated_at,
        'nodes', COALESCE((
            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                'device_id', device.public_id,
                'device_name', device.hostname,
                'device_state', device.state,
                'ownership', device.ownership,
                'offered', COALESCE(offer.offered, FALSE),
                'priority', exit_node.priority,
                'state', exit_node.state,
                'added_at', exit_node.created_at
            ) ORDER BY exit_node.priority, device.public_id)
            FROM mesh.network_exit_node AS exit_node
            JOIN mesh.device AS device ON device.id = exit_node.device_id
            LEFT JOIN mesh.device_exit_offer AS offer ON offer.device_id = device.id
            WHERE exit_node.pool_id = p_pool.id
        ), '[]'::JSONB)
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.exit_pool_document_internal_v1(mesh.network_exit_pool)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Whether the Session may create, change and delete pools, without raising.
CREATE FUNCTION mesh_ops.exit_pool_abilities_internal_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID
)
RETURNS JSONB
LANGUAGE sql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'can_manage', EXISTS (SELECT 1 FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, 'route.approve', pg_catalog.transaction_timestamp())),
        'can_delete', EXISTS (SELECT 1 FROM mesh_ops.resolve_network_permission_v2(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id, 'route.withdraw', pg_catalog.transaction_timestamp()))
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.exit_pool_abilities_internal_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- One page of the Network's active pools in (name, pool) order, after the
-- pool p_after_pool_public_id when given.
CREATE FUNCTION mesh_ops.list_exit_pools_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_after_pool_public_id UUID, p_limit INTEGER
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
    v_after_key TEXT;
    v_page JSONB;
    v_count INTEGER;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Exit Pool page is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_exit_pool_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'route.read'
    );
    IF p_after_pool_public_id IS NOT NULL THEN
        SELECT exit_pool.name_key INTO v_after_key FROM mesh.network_exit_pool AS exit_pool
        WHERE exit_pool.workspace_id = v_scope.workspace_id AND exit_pool.network_id = v_scope.network_id
          AND exit_pool.public_id = p_after_pool_public_id;
        IF v_after_key IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Exit Pool page cursor is unknown';
        END IF;
    END IF;
    SELECT pg_catalog.jsonb_agg(mesh_ops.exit_pool_document_internal_v1(page) ORDER BY page.name_key, page.public_id),
           pg_catalog.count(*)
    INTO v_page, v_count
    FROM (
        SELECT * FROM mesh.network_exit_pool AS exit_pool
        WHERE exit_pool.workspace_id = v_scope.workspace_id AND exit_pool.network_id = v_scope.network_id
          AND exit_pool.state = 'active'
          AND (v_after_key IS NULL
               OR (exit_pool.name_key, exit_pool.public_id) > (v_after_key, p_after_pool_public_id))
        ORDER BY exit_pool.name_key, exit_pool.public_id
        LIMIT p_limit + 1
    ) AS page;
    RETURN pg_catalog.jsonb_build_object(
        'pools', CASE WHEN v_count > p_limit
                      THEN v_page - p_limit
                      ELSE COALESCE(v_page, '[]'::JSONB) END,
        'has_more', v_count > p_limit
    ) || mesh_ops.exit_pool_abilities_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.list_exit_pools_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_exit_pools_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, INTEGER
) TO mesh_runtime;

-- One active pool (route.read).
CREATE FUNCTION mesh_ops.read_exit_pool_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_pool_public_id UUID
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
    v_pool mesh.network_exit_pool%ROWTYPE;
BEGIN
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_exit_pool_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'route.read'
    );
    SELECT * INTO v_pool FROM mesh.network_exit_pool AS exit_pool
    WHERE exit_pool.workspace_id = v_scope.workspace_id AND exit_pool.network_id = v_scope.network_id
      AND exit_pool.public_id = p_pool_public_id AND exit_pool.state = 'active';
    IF v_pool.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Exit Pool is unavailable';
    END IF;
    RETURN pg_catalog.jsonb_build_object('pool', mesh_ops.exit_pool_document_internal_v1(v_pool))
        || mesh_ops.exit_pool_abilities_internal_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_exit_pool_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_exit_pool_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) TO mesh_runtime;

-- Creates or changes a pool (route.approve) or deletes it (route.withdraw).
-- p_pool_limit is the Workspace's plan limit, already bounded by Go. An
-- update that changes nothing writes nothing and returns changed = false.
-- Deleting a pool removes its exit nodes. Changes serialize on the Network's
-- revision row and advance the Network and route revisions, as Site changes
-- do (schema 188).
CREATE FUNCTION mesh_ops.change_exit_pool_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_operation TEXT,
    p_pool_public_id UUID, p_expected_version BIGINT, p_name TEXT, p_failback BOOLEAN,
    p_smtp_allowed BOOLEAN, p_conntrack_per_consumer INTEGER, p_dns_upstreams INET[], p_probes JSONB,
    p_pool_limit INTEGER, p_change_public_id UUID
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
    v_pool mesh.network_exit_pool%ROWTYPE;
    v_before JSONB;
    v_revisions RECORD;
    v_constraint TEXT;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_operation NOT IN ('create', 'update', 'delete') OR p_pool_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_pool_public_id), 6) >> 4 <> 7
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR (p_operation <> 'create' AND (p_expected_version IS NULL OR p_expected_version < 1))
        OR (p_operation <> 'delete' AND (p_name IS NULL OR p_failback IS NULL OR p_smtp_allowed IS NULL
            OR p_conntrack_per_consumer IS NULL OR p_dns_upstreams IS NULL OR p_probes IS NULL))
        OR (p_operation = 'create' AND (p_pool_limit IS NULL OR p_pool_limit NOT BETWEEN 1 AND 64)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Exit Pool change is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_exit_pool_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id,
        CASE WHEN p_operation = 'delete' THEN 'route.withdraw' ELSE 'route.approve' END
    );
    PERFORM mesh_ops.lock_site_scope_internal_v1(v_scope.workspace_id, v_scope.network_id);
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    IF p_operation = 'create' THEN
        IF (SELECT pg_catalog.count(*) FROM mesh.network_exit_pool AS exit_pool
            WHERE exit_pool.workspace_id = v_scope.workspace_id
              AND exit_pool.network_id = v_scope.network_id
              AND exit_pool.state = 'active') >= p_pool_limit THEN
            RAISE EXCEPTION USING ERRCODE = 'MTX02', MESSAGE = 'Network already has the maximum Exit Pools';
        END IF;
        BEGIN
            INSERT INTO mesh.network_exit_pool (
                public_id, deployment_id, workspace_id, network_id, name, name_key, failback, smtp_allowed,
                conntrack_per_consumer, dns_upstreams, probes, created_at, updated_at
            ) VALUES (
                p_pool_public_id, v_scope.deployment_id, v_scope.workspace_id, v_scope.network_id,
                p_name, pg_catalog.lower(p_name), p_failback, p_smtp_allowed, p_conntrack_per_consumer,
                p_dns_upstreams, p_probes, v_now, v_now
            ) RETURNING * INTO v_pool;
        EXCEPTION WHEN unique_violation THEN
            GET STACKED DIAGNOSTICS v_constraint = CONSTRAINT_NAME;
            IF v_constraint = 'network_exit_pool_active_name_uidx' THEN
                RAISE EXCEPTION USING ERRCODE = 'MTX01', MESSAGE = 'Exit Pool name is taken';
            END IF;
            RAISE;
        END;
    ELSE
        SELECT * INTO v_pool FROM mesh.network_exit_pool AS exit_pool
        WHERE exit_pool.workspace_id = v_scope.workspace_id AND exit_pool.network_id = v_scope.network_id
          AND exit_pool.public_id = p_pool_public_id AND exit_pool.state = 'active'
        FOR UPDATE;
        IF v_pool.id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Exit Pool is unavailable';
        END IF;
        IF v_pool.version <> p_expected_version THEN
            RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Exit Pool version changed';
        END IF;
        v_before := mesh_ops.exit_pool_document_internal_v1(v_pool);
        IF p_operation = 'update' AND v_pool.name = p_name AND v_pool.failback = p_failback
            AND v_pool.smtp_allowed = p_smtp_allowed AND v_pool.conntrack_per_consumer = p_conntrack_per_consumer
            AND v_pool.dns_upstreams = p_dns_upstreams AND v_pool.probes = p_probes THEN
            RETURN pg_catalog.jsonb_build_object(
                'pool', v_before, 'previous', v_before, 'changed', FALSE,
                'role_binding_id', v_scope.role_binding_public_id);
        END IF;
        IF p_operation = 'update' THEN
            BEGIN
                UPDATE mesh.network_exit_pool
                SET name = p_name, name_key = pg_catalog.lower(p_name), failback = p_failback,
                    smtp_allowed = p_smtp_allowed, conntrack_per_consumer = p_conntrack_per_consumer,
                    dns_upstreams = p_dns_upstreams, probes = p_probes,
                    version = version + 1, updated_at = GREATEST(v_now, updated_at)
                WHERE id = v_pool.id
                RETURNING * INTO v_pool;
            EXCEPTION WHEN unique_violation THEN
                GET STACKED DIAGNOSTICS v_constraint = CONSTRAINT_NAME;
                IF v_constraint = 'network_exit_pool_active_name_uidx' THEN
                    RAISE EXCEPTION USING ERRCODE = 'MTX01', MESSAGE = 'Exit Pool name is taken';
                END IF;
                RAISE;
            END;
        ELSE
            DELETE FROM mesh.network_exit_node WHERE pool_id = v_pool.id;
            UPDATE mesh.network_exit_pool
            SET state = 'deleted', deleted_at = GREATEST(v_now, updated_at),
                version = version + 1, updated_at = GREATEST(v_now, updated_at)
            WHERE id = v_pool.id
            RETURNING * INTO v_pool;
        END IF;
    END IF;
    SELECT * INTO STRICT v_revisions FROM mesh_ops.advance_site_revisions_internal_v1(
        v_scope.workspace_id, v_scope.network_id);
    RETURN pg_catalog.jsonb_build_object(
        'pool', mesh_ops.exit_pool_document_internal_v1(v_pool), 'previous', v_before, 'changed', TRUE,
        'network_revision', v_revisions.network_revision, 'route_revision', v_revisions.route_revision,
        'role_binding_id', v_scope.role_binding_public_id);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.change_exit_pool_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    TEXT, UUID, BIGINT, TEXT, BOOLEAN, BOOLEAN, INTEGER, INET[], JSONB, INTEGER, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_exit_pool_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    TEXT, UUID, BIGINT, TEXT, BOOLEAN, BOOLEAN, INTEGER, INET[], JSONB, INTEGER, UUID
) TO mesh_runtime;

-- Makes a Device an exit node of a pool or changes its priority or state
-- (route.approve), or removes it (route.withdraw). Every change advances the
-- pool's version; a put that changes nothing writes nothing. A new exit node
-- must be an active, Workspace-owned Device of the Network and no exit node
-- of another pool; p_node_limit is the plan limit, bounded by Go. An exit
-- node stays removable after its Device is gone.
CREATE FUNCTION mesh_ops.change_exit_node_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_operation TEXT,
    p_pool_public_id UUID, p_expected_version BIGINT, p_device_public_id UUID,
    p_priority INTEGER, p_state TEXT, p_node_limit INTEGER, p_node_public_id UUID,
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
    v_scope RECORD;
    v_pool mesh.network_exit_pool%ROWTYPE;
    v_device mesh.device%ROWTYPE;
    v_node mesh.network_exit_node%ROWTYPE;
    v_before JSONB;
    v_revisions RECORD;
    v_constraint TEXT;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_operation NOT IN ('put', 'delete') OR p_pool_public_id IS NULL OR p_device_public_id IS NULL
        OR p_expected_version IS NULL OR p_expected_version < 1
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR (p_operation = 'put' AND (p_priority IS NULL OR p_priority NOT BETWEEN 0 AND 999
            OR p_state IS NULL OR p_state NOT IN ('active', 'draining')
            OR p_node_limit IS NULL OR p_node_limit NOT BETWEEN 1 AND 16
            OR p_node_public_id IS NULL
            OR pg_catalog.get_byte(pg_catalog.uuid_send(p_node_public_id), 6) >> 4 <> 7)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Exit node change is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_exit_pool_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id,
        CASE WHEN p_operation = 'delete' THEN 'route.withdraw' ELSE 'route.approve' END
    );
    PERFORM mesh_ops.lock_site_scope_internal_v1(v_scope.workspace_id, v_scope.network_id);
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    SELECT * INTO v_pool FROM mesh.network_exit_pool AS exit_pool
    WHERE exit_pool.workspace_id = v_scope.workspace_id AND exit_pool.network_id = v_scope.network_id
      AND exit_pool.public_id = p_pool_public_id AND exit_pool.state = 'active'
    FOR UPDATE;
    IF v_pool.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Exit Pool is unavailable';
    END IF;
    IF v_pool.version <> p_expected_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Exit Pool version changed';
    END IF;
    v_before := mesh_ops.exit_pool_document_internal_v1(v_pool);
    -- The exit node row is found through its Device whatever that Device's
    -- state.
    SELECT exit_node.* INTO v_node FROM mesh.network_exit_node AS exit_node
    JOIN mesh.device AS device ON device.id = exit_node.device_id
    WHERE exit_node.pool_id = v_pool.id AND device.public_id = p_device_public_id
    FOR UPDATE OF exit_node;

    IF p_operation = 'delete' THEN
        IF v_node.id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Exit node is unavailable';
        END IF;
        DELETE FROM mesh.network_exit_node WHERE id = v_node.id;
    ELSIF v_node.id IS NOT NULL THEN
        IF v_node.priority = p_priority AND v_node.state = p_state THEN
            RETURN pg_catalog.jsonb_build_object(
                'pool', v_before, 'previous', v_before, 'changed', FALSE,
                'role_binding_id', v_scope.role_binding_public_id);
        END IF;
        UPDATE mesh.network_exit_node
        SET priority = p_priority, state = p_state, version = version + 1,
            updated_at = GREATEST(v_now, updated_at)
        WHERE id = v_node.id;
    ELSE
        SELECT * INTO v_device FROM mesh.device AS device
        WHERE device.workspace_id = v_scope.workspace_id AND device.network_id = v_scope.network_id
          AND device.public_id = p_device_public_id AND device.deleted_at IS NULL
        FOR SHARE;
        IF v_device.id IS NULL OR v_device.state <> 'active' OR v_device.ownership <> 'workspace' THEN
            RAISE EXCEPTION USING ERRCODE = 'MTX04',
                MESSAGE = 'Device is not an active Workspace Device of this Network';
        END IF;
        IF EXISTS (SELECT 1 FROM mesh.network_exit_node AS other WHERE other.device_id = v_device.id) THEN
            RAISE EXCEPTION USING ERRCODE = 'MTX05', MESSAGE = 'Device is an exit node of another Exit Pool';
        END IF;
        IF (SELECT pg_catalog.count(*) FROM mesh.network_exit_node AS exit_node
            WHERE exit_node.pool_id = v_pool.id) >= p_node_limit THEN
            RAISE EXCEPTION USING ERRCODE = 'MTX03', MESSAGE = 'Exit Pool already has the maximum exit nodes';
        END IF;
        BEGIN
            INSERT INTO mesh.network_exit_node (
                public_id, workspace_id, network_id, pool_id, device_id, priority, state,
                added_by_principal_id, created_at, updated_at
            ) VALUES (
                p_node_public_id, v_scope.workspace_id, v_scope.network_id, v_pool.id, v_device.id,
                p_priority, p_state, v_scope.principal_id, v_now, v_now
            );
        EXCEPTION WHEN unique_violation THEN
            GET STACKED DIAGNOSTICS v_constraint = CONSTRAINT_NAME;
            IF v_constraint = 'network_exit_node_device_key' THEN
                RAISE EXCEPTION USING ERRCODE = 'MTX05', MESSAGE = 'Device is an exit node of another Exit Pool';
            END IF;
            RAISE;
        END;
    END IF;
    UPDATE mesh.network_exit_pool SET version = version + 1, updated_at = GREATEST(v_now, updated_at)
    WHERE id = v_pool.id
    RETURNING * INTO v_pool;
    SELECT * INTO STRICT v_revisions FROM mesh_ops.advance_site_revisions_internal_v1(
        v_scope.workspace_id, v_scope.network_id);
    RETURN pg_catalog.jsonb_build_object(
        'pool', mesh_ops.exit_pool_document_internal_v1(v_pool), 'previous', v_before, 'changed', TRUE,
        'network_revision', v_revisions.network_revision, 'route_revision', v_revisions.route_revision,
        'role_binding_id', v_scope.role_binding_public_id);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.change_exit_node_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    TEXT, UUID, BIGINT, UUID, INTEGER, TEXT, INTEGER, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_exit_node_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    TEXT, UUID, BIGINT, UUID, INTEGER, TEXT, INTEGER, UUID, UUID
) TO mesh_runtime;
