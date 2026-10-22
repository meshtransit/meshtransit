-- Network DNS zones (DNS design D1a): domains whose names a Network's Devices
-- ask chosen resolvers for.
--
-- A zone is one domain of one Network (the root '.' is "every other name",
-- D1b) with 1 to 4 resolvers, in order: a Device of the Network (by its
-- public ID and a port) or an address on the Internet (port 53). It is sent
-- to every Device of the Network, or to the Devices of up to 16 Device
-- Groups. Go validates domains (special-use names, public suffixes, the mesh
-- suffix, the deployment's own names) and limits; these tables keep the
-- bounds and the identities, and the SECURITY DEFINER functions below check
-- the caller's Session and the exact Network permission (network.read to
-- read, dns.manage to change). Each change returns its document; the caller
-- appends the evidence on the Network stream with the Network and DNS
-- revisions these functions advance, so maps are rebuilt. A change that
-- changes nothing writes nothing.
--
-- A resolver Device is an active, Workspace-owned Device of the Network and
-- no exit node: an exit node redirects port 53 on its mesh addresses to its
-- exit DNS forwarder. The triggers below keep a resolver Device out of Exit
-- Pools and a Device Group a zone is sent to from being deleted, whichever
-- Core changes them.
--
-- Errors: 22023 invalid input, 42501 not authorized, P0002 unknown zone,
-- 40001 stale version, MTZ01 domain taken, MTZ02 zone limit, MTZ03 the
-- resolver Device is not eligible, MTZ04 unknown Device Group, MTZ05 search
-- domain limit, MTZ06 a resolver Device would serve more Devices than a map
-- holds, MTX07 (Exit Pools) the Device is a DNS resolver, MTD07 (Device
-- Groups) the group is used by DNS zones.

-- The resolvers of a zone: 1 to 4 objects, each {"device_id", "port"} with
-- port 53 or 1024-65535, or {"address", "port"} with an Internet address and
-- port 53, no resolver twice.
CREATE FUNCTION mesh_ops.dns_zone_resolvers_valid_internal_v1(p_resolvers JSONB)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_item JSONB;
    v_seen TEXT[] := '{}';
    v_key TEXT;
    v_port INTEGER;
BEGIN
    IF p_resolvers IS NULL OR pg_catalog.jsonb_typeof(p_resolvers) <> 'array'
        OR pg_catalog.jsonb_array_length(p_resolvers) NOT BETWEEN 1 AND 4 THEN
        RETURN FALSE;
    END IF;
    FOR v_item IN SELECT item FROM pg_catalog.jsonb_array_elements(p_resolvers) AS item LOOP
        IF pg_catalog.jsonb_typeof(v_item) <> 'object' OR pg_catalog.jsonb_typeof(v_item -> 'port') <> 'number' THEN
            RETURN FALSE;
        END IF;
        v_port := (v_item ->> 'port')::INTEGER;
        IF v_item ?& ARRAY['device_id', 'port'] AND (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(v_item)) = 2 THEN
            IF (v_item ->> 'device_id') !~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
                OR NOT (v_port = 53 OR v_port BETWEEN 1024 AND 65535) THEN
                RETURN FALSE;
            END IF;
            v_key := 'device:' || (v_item ->> 'device_id');
        ELSIF v_item ?& ARRAY['address', 'port'] AND (SELECT pg_catalog.count(*) FROM pg_catalog.jsonb_object_keys(v_item)) = 2 THEN
            IF (v_item ->> 'address') !~ '^[0-9a-f.:]{2,39}$' OR v_port <> 53
                OR NOT mesh_ops.internet_address_internal_v1((v_item ->> 'address')::INET)
                OR pg_catalog.host((v_item ->> 'address')::INET) <> (v_item ->> 'address') THEN
                RETURN FALSE;
            END IF;
            v_key := 'address:' || (v_item ->> 'address');
        ELSE
            RETURN FALSE;
        END IF;
        IF v_key = ANY (v_seen) THEN
            RETURN FALSE;
        END IF;
        v_seen := v_seen || v_key;
    END LOOP;
    RETURN TRUE;
EXCEPTION WHEN invalid_text_representation OR numeric_value_out_of_range THEN
    RETURN FALSE;
END;
$function$;

CREATE TABLE mesh.network_dns_zone (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    domain TEXT NOT NULL,
    other_names TEXT NOT NULL DEFAULT 'forward',
    failure_mode TEXT NOT NULL,
    resolvers JSONB NOT NULL,
    -- Empty: every Device of the Network.
    distribution_group_ids BIGINT[] NOT NULL DEFAULT '{}'::BIGINT[],
    search_position INTEGER,
    public_class TEXT NOT NULL,
    public_list_version TEXT NOT NULL,
    public_confirmed BOOLEAN NOT NULL,
    state TEXT NOT NULL DEFAULT 'active',
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ,
    CONSTRAINT network_dns_zone_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT network_dns_zone_domain_check CHECK (
        domain = '.' OR (
            pg_catalog.octet_length(domain) BETWEEN 1 AND 253
            AND domain ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$'
        )
    ),
    CONSTRAINT network_dns_zone_other_names_check CHECK (other_names = 'forward'),
    CONSTRAINT network_dns_zone_failure_mode_check CHECK (failure_mode IN ('open', 'closed')),
    CONSTRAINT network_dns_zone_resolvers_check CHECK (mesh_ops.dns_zone_resolvers_valid_internal_v1(resolvers)),
    CONSTRAINT network_dns_zone_distribution_check CHECK (
        pg_catalog.cardinality(distribution_group_ids) <= 16
        AND pg_catalog.array_position(distribution_group_ids, NULL) IS NULL
    ),
    CONSTRAINT network_dns_zone_search_check CHECK (
        search_position IS NULL OR (domain <> '.' AND search_position BETWEEN 1 AND 1000)
    ),
    CONSTRAINT network_dns_zone_public_check CHECK (
        public_class IN ('private', 'public')
        AND (public_class = 'private' OR public_confirmed)
        AND (domain <> '.' OR public_class = 'private')
        AND pg_catalog.char_length(public_list_version) BETWEEN 1 AND 64
    ),
    CONSTRAINT network_dns_zone_state_check CHECK (
        (state = 'active' AND deleted_at IS NULL) OR (state = 'deleted' AND deleted_at IS NOT NULL)
    ),
    CONSTRAINT network_dns_zone_timestamps_check CHECK (updated_at >= created_at),
    CONSTRAINT network_dns_zone_workspace_fk FOREIGN KEY (deployment_id, workspace_id)
        REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT network_dns_zone_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    UNIQUE (workspace_id, network_id, id)
);

CREATE UNIQUE INDEX network_dns_zone_active_domain_uidx
    ON mesh.network_dns_zone (workspace_id, network_id, domain)
    WHERE state = 'active';
-- Which zones send to a Device Group, and which use a Device as resolver.
CREATE INDEX network_dns_zone_groups_idx
    ON mesh.network_dns_zone USING GIN (distribution_group_ids)
    WHERE state = 'active';
CREATE INDEX network_dns_zone_resolvers_idx
    ON mesh.network_dns_zone USING GIN (resolvers jsonb_path_ops)
    WHERE state = 'active';

CREATE FUNCTION mesh_ops.enforce_network_dns_zone_transition_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'DNS zones are deleted by state, never removed';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'active' OR NEW.version <> 1 THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid new DNS zone';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.public_id <> OLD.public_id OR NEW.deployment_id <> OLD.deployment_id
        OR NEW.workspace_id <> OLD.workspace_id OR NEW.network_id <> OLD.network_id
        OR NEW.domain <> OLD.domain OR NEW.public_class <> OLD.public_class
        OR NEW.public_list_version <> OLD.public_list_version
        OR NEW.created_at <> OLD.created_at OR NEW.version <> OLD.version + 1
        OR OLD.state = 'deleted' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid DNS zone transition';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER network_dns_zone_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.network_dns_zone
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_network_dns_zone_transition_v1();
CREATE TRIGGER network_dns_zone_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.network_dns_zone
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('network_dns_zone', 'public_id');

ALTER TABLE mesh.network_dns_zone ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.network_dns_zone FORCE ROW LEVEL SECURITY;
CREATE POLICY network_dns_zone_migrator_policy ON mesh.network_dns_zone
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.network_dns_zone
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.dns_zone_resolvers_valid_internal_v1(JSONB)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.enforce_network_dns_zone_transition_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Whether a Device (by internal ID) is a resolver of an active zone of its
-- Network.
CREATE FUNCTION mesh_ops.device_is_dns_resolver_internal_v1(p_device_id BIGINT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT EXISTS (
        SELECT 1
        FROM mesh.device AS device
        JOIN mesh.network_dns_zone AS zone
          ON zone.workspace_id = device.workspace_id AND zone.network_id = device.network_id
        WHERE device.id = p_device_id AND zone.state = 'active'
          AND zone.resolvers @> pg_catalog.jsonb_build_array(
              pg_catalog.jsonb_build_object('device_id', device.public_id::TEXT))
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.device_is_dns_resolver_internal_v1(BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- A DNS resolver Device is never an exit node, whichever Core adds it.
CREATE FUNCTION mesh_ops.refuse_dns_resolver_exit_node_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF mesh_ops.device_is_dns_resolver_internal_v1(NEW.device_id) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTX07', MESSAGE = 'Device is a DNS resolver';
    END IF;
    RETURN NEW;
END;
$function$;
CREATE TRIGGER network_exit_node_not_dns_resolver
BEFORE INSERT OR UPDATE OF device_id ON mesh.network_exit_node
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_dns_resolver_exit_node_v1();
REVOKE ALL ON FUNCTION mesh_ops.refuse_dns_resolver_exit_node_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- A Device Group a DNS zone is sent to cannot be deleted (MTD07): the zone
-- would silently stop reaching its members. A trigger, so a Core that does
-- not know zones (a rollback) cannot delete it either.
CREATE FUNCTION mesh_ops.refuse_deleting_dns_zone_group_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF NEW.state = 'deleted' AND OLD.state <> 'deleted' AND EXISTS (
        SELECT 1 FROM mesh.network_dns_zone AS zone
        WHERE zone.state = 'active' AND zone.workspace_id = OLD.workspace_id
          AND zone.network_id = OLD.network_id AND zone.distribution_group_ids @> ARRAY[OLD.id]) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTD07', MESSAGE = 'Device Group is used by DNS zones';
    END IF;
    RETURN NEW;
END;
$function$;
CREATE TRIGGER device_group_not_used_by_dns_zone
BEFORE UPDATE OF state ON mesh.device_group
FOR EACH ROW EXECUTE FUNCTION mesh_ops.refuse_deleting_dns_zone_group_v1();
REVOKE ALL ON FUNCTION mesh_ops.refuse_deleting_dns_zone_group_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The exact Network scope bound by the caller, after one permission check.
CREATE FUNCTION mesh_ops.authorize_dns_zone_internal_v1(
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
        OR p_permission NOT IN ('network.read', 'dns.manage') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'DNS zone scope input is invalid';
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
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'DNS zone action is not authorized';
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
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'DNS zone scope is unavailable';
    END IF;
    RETURN QUERY SELECT v_deployment, v_workspace, v_network, v_principal, v_binding;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.authorize_dns_zone_internal_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TEXT
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- One zone with, for each resolver Device, the facts Go needs to show why it
-- cannot serve (state, ownership, exit node), and its Device Groups.
CREATE FUNCTION mesh_ops.dns_zone_document_internal_v1(p_zone mesh.network_dns_zone)
RETURNS JSONB
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'zone_id', p_zone.public_id,
        'domain', p_zone.domain,
        'other_names', p_zone.other_names,
        'failure_mode', p_zone.failure_mode,
        'resolvers', (
            SELECT pg_catalog.jsonb_agg(
                CASE WHEN item ? 'device_id' THEN pg_catalog.jsonb_build_object(
                    'device_id', item ->> 'device_id',
                    'port', (item ->> 'port')::INTEGER,
                    'device_name', device.hostname,
                    'device_state', CASE WHEN device.id IS NULL OR device.deleted_at IS NOT NULL
                                         THEN 'removed' ELSE device.state END,
                    'ownership', device.ownership,
                    'exit_node', EXISTS (SELECT 1 FROM mesh.network_exit_node AS exit_node
                                         WHERE exit_node.device_id = device.id))
                ELSE pg_catalog.jsonb_build_object(
                    'address', item ->> 'address', 'port', (item ->> 'port')::INTEGER) END
                ORDER BY ordinal)
            FROM pg_catalog.jsonb_array_elements(p_zone.resolvers) WITH ORDINALITY AS entry(item, ordinal)
            LEFT JOIN mesh.device AS device
              ON device.workspace_id = p_zone.workspace_id AND device.network_id = p_zone.network_id
             AND device.public_id = (item ->> 'device_id')::UUID),
        'groups', COALESCE((
            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                'group_id', device_group.public_id, 'name', device_group.name,
                'state', device_group.state) ORDER BY device_group.name_key, device_group.public_id)
            FROM mesh.device_group AS device_group
            WHERE device_group.id = ANY (p_zone.distribution_group_ids)), '[]'::JSONB),
        'search_position', p_zone.search_position,
        'public_class', p_zone.public_class,
        'public_list_version', p_zone.public_list_version,
        'public_confirmed', p_zone.public_confirmed,
        'state', p_zone.state,
        'version', p_zone.version,
        'created_at', p_zone.created_at,
        'updated_at', p_zone.updated_at
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.dns_zone_document_internal_v1(mesh.network_dns_zone)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Whether the Session may create, change and delete zones, without raising.
CREATE FUNCTION mesh_ops.dns_zone_abilities_internal_v1(
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
            p_workspace_public_id, p_network_public_id, 'dns.manage', pg_catalog.transaction_timestamp()))
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.dns_zone_abilities_internal_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- One page of the Network's active zones in domain order (the root first),
-- after the zone p_after_zone_public_id when given, with the Workspace and
-- Network display codes.
CREATE FUNCTION mesh_ops.list_dns_zones_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_after_zone_public_id UUID, p_limit INTEGER
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
    v_after_domain TEXT;
    v_page JSONB;
    v_count INTEGER;
BEGIN
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'DNS zone page is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_dns_zone_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'network.read'
    );
    IF p_after_zone_public_id IS NOT NULL THEN
        SELECT zone.domain INTO v_after_domain FROM mesh.network_dns_zone AS zone
        WHERE zone.workspace_id = v_scope.workspace_id AND zone.network_id = v_scope.network_id
          AND zone.public_id = p_after_zone_public_id;
        IF v_after_domain IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'DNS zone page cursor is unknown';
        END IF;
    END IF;
    SELECT pg_catalog.jsonb_agg(mesh_ops.dns_zone_document_internal_v1(page)
               ORDER BY page.domain COLLATE "C", page.public_id),
           pg_catalog.count(*)
    INTO v_page, v_count
    FROM (
        SELECT * FROM mesh.network_dns_zone AS zone
        WHERE zone.workspace_id = v_scope.workspace_id AND zone.network_id = v_scope.network_id
          AND zone.state = 'active'
          AND (v_after_domain IS NULL
               OR (zone.domain COLLATE "C", zone.public_id) > (v_after_domain COLLATE "C", p_after_zone_public_id))
        ORDER BY zone.domain COLLATE "C", zone.public_id
        LIMIT p_limit + 1
    ) AS page;
    RETURN pg_catalog.jsonb_build_object(
        'zones', CASE WHEN v_count > p_limit THEN v_page - p_limit ELSE COALESCE(v_page, '[]'::JSONB) END,
        'has_more', v_count > p_limit,
        -- The display codes name the Network's system zone.
        'workspace_code', (SELECT identity.display_code FROM mesh_ops.tenant_display_identity AS identity
                           WHERE identity.workspace_public_id = p_workspace_public_id),
        'network_code', (SELECT identity.display_code FROM mesh_ops.tenant_display_identity AS identity
                         WHERE identity.network_public_id = p_network_public_id)
    ) || mesh_ops.dns_zone_abilities_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.list_dns_zones_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_dns_zones_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, INTEGER
) TO mesh_runtime;

-- One active zone (network.read).
CREATE FUNCTION mesh_ops.read_dns_zone_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_zone_public_id UUID
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
    v_zone mesh.network_dns_zone%ROWTYPE;
BEGIN
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_dns_zone_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'network.read'
    );
    SELECT * INTO v_zone FROM mesh.network_dns_zone AS zone
    WHERE zone.workspace_id = v_scope.workspace_id AND zone.network_id = v_scope.network_id
      AND zone.public_id = p_zone_public_id AND zone.state = 'active';
    IF v_zone.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'DNS zone is unavailable';
    END IF;
    RETURN pg_catalog.jsonb_build_object('zone', mesh_ops.dns_zone_document_internal_v1(v_zone))
        || mesh_ops.dns_zone_abilities_internal_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_dns_zone_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_dns_zone_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) TO mesh_runtime;

-- How many Devices of the Network the active zones using a resolver Device
-- send to, the zone p_zone_id counted with p_groups instead of what it
-- stores (NULL: a new zone). The resolver Device itself does not count: a
-- zone is never sent to its own resolvers.
CREATE FUNCTION mesh_ops.dns_resolver_consumers_internal_v1(
    p_workspace_id BIGINT, p_network_id BIGINT, p_resolver_public_id TEXT, p_zone_id BIGINT,
    p_groups BIGINT[]
)
RETURNS BIGINT
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog
AS $function$
DECLARE
    v_groups BIGINT[] := p_groups;
    v_all BOOLEAN := pg_catalog.cardinality(p_groups) = 0;
    v_zone_groups BIGINT[];
BEGIN
    FOR v_zone_groups IN
        SELECT zone.distribution_group_ids
        FROM mesh.network_dns_zone AS zone
        WHERE zone.workspace_id = p_workspace_id AND zone.network_id = p_network_id
          AND zone.state = 'active' AND zone.id IS DISTINCT FROM p_zone_id
          AND zone.resolvers @> pg_catalog.jsonb_build_array(
              pg_catalog.jsonb_build_object('device_id', p_resolver_public_id))
    LOOP
        v_all := v_all OR pg_catalog.cardinality(v_zone_groups) = 0;
        v_groups := v_groups || v_zone_groups;
    END LOOP;
    -- A zone sent to every Device: count the Network's active Devices.
    IF v_all THEN
        RETURN (SELECT pg_catalog.count(*) FROM mesh.device AS device
                WHERE device.workspace_id = p_workspace_id AND device.network_id = p_network_id
                  AND device.deleted_at IS NULL AND device.state = 'active'
                  AND device.public_id <> p_resolver_public_id::UUID);
    END IF;
    RETURN (SELECT pg_catalog.count(DISTINCT member.device_id)
            FROM mesh.device_group_member AS member
            JOIN mesh.device AS device ON device.id = member.device_id
            WHERE member.device_group_id = ANY (v_groups)
              AND device.deleted_at IS NULL AND device.state = 'active'
              AND device.public_id <> p_resolver_public_id::UUID);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.dns_resolver_consumers_internal_v1(BIGINT, BIGINT, TEXT, BIGINT, BIGINT[])
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Creates, changes or deletes a zone (dns.manage). The domain and its public
-- classification never change. p_zone_limit (zones other than the root),
-- p_search_limit and p_consumer_limit are the limits Go bounds. An update
-- that changes nothing writes nothing and returns changed = false. Changes
-- serialize on the Network's revision row and advance the Network and DNS
-- revisions.
CREATE FUNCTION mesh_ops.change_dns_zone_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_operation TEXT,
    p_zone_public_id UUID, p_expected_version BIGINT, p_domain TEXT, p_failure_mode TEXT,
    p_resolvers JSONB, p_group_public_ids UUID[], p_search_position INTEGER, p_public_class TEXT,
    p_public_list_version TEXT, p_public_confirmed BOOLEAN, p_zone_limit INTEGER, p_search_limit INTEGER,
    p_consumer_limit INTEGER, p_change_public_id UUID
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
    v_zone mesh.network_dns_zone%ROWTYPE;
    v_before JSONB;
    v_groups BIGINT[] := '{}';
    v_item JSONB;
    v_device mesh.device%ROWTYPE;
    v_constraint TEXT;
    v_network_revision BIGINT;
    v_dns_revision BIGINT;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_operation NOT IN ('create', 'update', 'delete') OR p_zone_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_zone_public_id), 6) >> 4 <> 7
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR (p_operation <> 'create' AND (p_expected_version IS NULL OR p_expected_version < 1))
        OR (p_operation <> 'delete' AND (p_domain IS NULL OR p_failure_mode IS NULL OR p_resolvers IS NULL
            OR p_group_public_ids IS NULL OR pg_catalog.cardinality(p_group_public_ids) > 16
            OR p_public_class IS NULL OR p_public_list_version IS NULL OR p_public_confirmed IS NULL
            OR p_search_limit IS NULL OR p_search_limit NOT BETWEEN 0 AND 16
            OR p_consumer_limit IS NULL OR p_consumer_limit NOT BETWEEN 1 AND 100000))
        OR (p_operation = 'create' AND (p_zone_limit IS NULL OR p_zone_limit NOT BETWEEN 1 AND 1000)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'DNS zone change is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_dns_zone_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'dns.manage'
    );
    PERFORM 1 FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'DNS zone scope is unavailable';
    END IF;
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    IF p_operation <> 'create' THEN
        SELECT * INTO v_zone FROM mesh.network_dns_zone AS zone
        WHERE zone.workspace_id = v_scope.workspace_id AND zone.network_id = v_scope.network_id
          AND zone.public_id = p_zone_public_id AND zone.state = 'active'
        FOR UPDATE;
        IF v_zone.id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'DNS zone is unavailable';
        END IF;
        IF v_zone.version <> p_expected_version THEN
            RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'DNS zone version changed';
        END IF;
        v_before := mesh_ops.dns_zone_document_internal_v1(v_zone);
    END IF;

    IF p_operation = 'update' AND v_zone.domain = p_domain AND v_zone.failure_mode = p_failure_mode
        AND v_zone.resolvers = p_resolvers AND v_zone.search_position IS NOT DISTINCT FROM p_search_position
        AND v_zone.public_confirmed = p_public_confirmed AND v_zone.public_class = p_public_class
        AND v_zone.public_list_version = p_public_list_version
        AND v_zone.distribution_group_ids = COALESCE((
            SELECT pg_catalog.array_agg(device_group.id ORDER BY device_group.id)
            FROM mesh.device_group AS device_group
            WHERE device_group.workspace_id = v_scope.workspace_id AND device_group.network_id = v_scope.network_id
              AND device_group.state = 'active' AND device_group.public_id = ANY (p_group_public_ids)), '{}')
        AND pg_catalog.cardinality(v_zone.distribution_group_ids) = (
            SELECT pg_catalog.count(DISTINCT item) FROM pg_catalog.unnest(p_group_public_ids) AS item) THEN
        RETURN pg_catalog.jsonb_build_object(
            'zone', v_before, 'previous', v_before, 'changed', FALSE,
            'role_binding_id', v_scope.role_binding_public_id);
    END IF;

    IF p_operation <> 'delete' THEN
        IF p_operation = 'update' AND (p_domain <> v_zone.domain OR p_public_class <> v_zone.public_class
            OR p_public_list_version <> v_zone.public_list_version) THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'A DNS zone domain never changes';
        END IF;
        -- Device Groups of this Network, active, each named once.
        SELECT pg_catalog.array_agg(device_group.id ORDER BY device_group.id) INTO v_groups
        FROM mesh.device_group AS device_group
        WHERE device_group.workspace_id = v_scope.workspace_id AND device_group.network_id = v_scope.network_id
          AND device_group.state = 'active' AND device_group.public_id = ANY (p_group_public_ids);
        v_groups := COALESCE(v_groups, '{}');
        IF pg_catalog.cardinality(v_groups) <> (SELECT pg_catalog.count(DISTINCT item)
                                                FROM pg_catalog.unnest(p_group_public_ids) AS item) THEN
            RAISE EXCEPTION USING ERRCODE = 'MTZ04', MESSAGE = 'Device Group is not an active group of this Network';
        END IF;
        IF NOT mesh_ops.dns_zone_resolvers_valid_internal_v1(p_resolvers) THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'DNS zone resolvers are invalid';
        END IF;
        -- Resolver Devices: active, Workspace-owned Devices of this Network,
        -- no exit node, and within what a map holds.
        FOR v_item IN SELECT item FROM pg_catalog.jsonb_array_elements(p_resolvers) AS item
                      WHERE item ? 'device_id' LOOP
            SELECT * INTO v_device FROM mesh.device AS device
            WHERE device.workspace_id = v_scope.workspace_id AND device.network_id = v_scope.network_id
              AND device.public_id = (v_item ->> 'device_id')::UUID AND device.deleted_at IS NULL
            FOR SHARE;
            IF v_device.id IS NULL OR v_device.state <> 'active' OR v_device.ownership <> 'workspace'
                OR EXISTS (SELECT 1 FROM mesh.network_exit_node AS exit_node
                           WHERE exit_node.device_id = v_device.id) THEN
                RAISE EXCEPTION USING ERRCODE = 'MTZ03', MESSAGE = 'Device cannot be a DNS resolver';
            END IF;
            IF mesh_ops.dns_resolver_consumers_internal_v1(v_scope.workspace_id, v_scope.network_id,
                v_item ->> 'device_id', v_zone.id, v_groups) > p_consumer_limit THEN
                RAISE EXCEPTION USING ERRCODE = 'MTZ06',
                    MESSAGE = 'a DNS resolver Device would serve more Devices than a map holds';
            END IF;
        END LOOP;
        IF p_search_position IS NOT NULL AND (
            SELECT pg_catalog.count(*) FROM mesh.network_dns_zone AS zone
            WHERE zone.workspace_id = v_scope.workspace_id AND zone.network_id = v_scope.network_id
              AND zone.state = 'active' AND zone.search_position IS NOT NULL
              AND zone.id IS DISTINCT FROM v_zone.id) >= p_search_limit THEN
            RAISE EXCEPTION USING ERRCODE = 'MTZ05', MESSAGE = 'Network already has the maximum search domains';
        END IF;
    END IF;

    IF p_operation = 'create' THEN
        IF p_domain <> '.' AND (SELECT pg_catalog.count(*) FROM mesh.network_dns_zone AS zone
            WHERE zone.workspace_id = v_scope.workspace_id AND zone.network_id = v_scope.network_id
              AND zone.state = 'active' AND zone.domain <> '.') >= p_zone_limit THEN
            RAISE EXCEPTION USING ERRCODE = 'MTZ02', MESSAGE = 'Network already has the maximum DNS zones';
        END IF;
        BEGIN
            INSERT INTO mesh.network_dns_zone (
                public_id, deployment_id, workspace_id, network_id, domain, failure_mode, resolvers,
                distribution_group_ids, search_position, public_class, public_list_version, public_confirmed,
                created_at, updated_at
            ) VALUES (
                p_zone_public_id, v_scope.deployment_id, v_scope.workspace_id, v_scope.network_id, p_domain,
                p_failure_mode, p_resolvers, v_groups, p_search_position, p_public_class, p_public_list_version,
                p_public_confirmed, v_now, v_now
            ) RETURNING * INTO v_zone;
        EXCEPTION WHEN unique_violation THEN
            GET STACKED DIAGNOSTICS v_constraint = CONSTRAINT_NAME;
            IF v_constraint = 'network_dns_zone_active_domain_uidx' THEN
                RAISE EXCEPTION USING ERRCODE = 'MTZ01', MESSAGE = 'DNS zone domain is taken';
            END IF;
            RAISE;
        END;
    ELSIF p_operation = 'update' THEN
        UPDATE mesh.network_dns_zone
        SET failure_mode = p_failure_mode, resolvers = p_resolvers, distribution_group_ids = v_groups,
            search_position = p_search_position, public_confirmed = p_public_confirmed,
            version = version + 1, updated_at = GREATEST(v_now, updated_at)
        WHERE id = v_zone.id
        RETURNING * INTO v_zone;
    ELSE
        UPDATE mesh.network_dns_zone
        SET state = 'deleted', deleted_at = GREATEST(v_now, updated_at),
            version = version + 1, updated_at = GREATEST(v_now, updated_at)
        WHERE id = v_zone.id
        RETURNING * INTO v_zone;
    END IF;
    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1, dns_revision = revision.dns_revision + 1,
        updated_at = GREATEST(v_now, revision.updated_at)
    WHERE revision.workspace_id = v_scope.workspace_id AND revision.network_id = v_scope.network_id
    RETURNING revision.network_revision, revision.dns_revision INTO v_network_revision, v_dns_revision;
    RETURN pg_catalog.jsonb_build_object(
        'zone', mesh_ops.dns_zone_document_internal_v1(v_zone), 'previous', v_before, 'changed', TRUE,
        'network_revision', v_network_revision, 'dns_revision', v_dns_revision,
        'role_binding_id', v_scope.role_binding_public_id);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.change_dns_zone_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    TEXT, UUID, BIGINT, TEXT, TEXT, JSONB, UUID[], INTEGER, TEXT, TEXT, BOOLEAN, INTEGER, INTEGER, INTEGER, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_dns_zone_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    TEXT, UUID, BIGINT, TEXT, TEXT, JSONB, UUID[], INTEGER, TEXT, TEXT, BOOLEAN, INTEGER, INTEGER, INTEGER, UUID
) TO mesh_runtime;
