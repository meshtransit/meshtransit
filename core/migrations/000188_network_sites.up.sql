-- Network Sites and their routers (subnet routes, R1.2).
--
-- A Site is one address space behind the mesh, such as an office LAN or a
-- VPC, inside one Network (mtcp-v1 §7.6). Routers are Devices of the Network
-- that forward into it. Two Sites may use the same prefixes: a Site is a route
-- domain. Go validates names, prefixes, probes and plan limits; these tables
-- keep the bounds and the identities, and the SECURITY DEFINER functions below
-- check the caller's Session and the exact Network permission. Each change
-- returns its document; the caller appends the evidence on the Network stream
-- with the Network and route revisions these functions advance, so maps are
-- rebuilt and pending policy approvals see the change. A change that changes
-- nothing writes nothing.
--
-- A router serves only while its Device is active, owned by the Workspace
-- and offers the Site's prefixes itself (mesh.device_route_advertisement,
-- written from HostinfoReport). Documents return those facts; Go decides.
--
-- Errors: 22023 invalid input, 42501 not authorized, P0002 unknown Site or
-- router, 40001 stale version, MTS01 name taken, MTS02 Site limit, MTS03
-- router limit, MTS04 the Device is not an active, Workspace-owned Device of
-- this Network, MTS05 the Device does not offer the Site's prefixes.

-- Sites reuse the route permissions of the catalog (schema 18): route.read
-- lists them; route.approve creates and changes Sites and chooses routers;
-- route.withdraw deletes Sites and removes routers. admin and network_admin
-- hold all three, as they write the rules that decide who reaches a Site.

-- Every prefix is canonical, IPv4 /8 to /32 or IPv6 /32 to /128, and outside
-- the client overlay frame. Go also refuses special ranges, overlap within the
-- Site and the addresses clients dial.
CREATE FUNCTION mesh_ops.site_prefixes_valid_internal_v1(p_prefixes CIDR[])
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.cardinality(p_prefixes) BETWEEN 1 AND 1024
       AND NOT EXISTS (
           SELECT 1 FROM pg_catalog.unnest(p_prefixes) AS prefix
           WHERE prefix IS NULL
              OR (pg_catalog.family(prefix) = 4 AND pg_catalog.masklen(prefix) < 8)
              OR (pg_catalog.family(prefix) = 6 AND pg_catalog.masklen(prefix) < 32)
              OR prefix && '100.64.0.0/10'::CIDR OR prefix && '198.18.0.0/15'::CIDR
              OR prefix && 'fd00::/8'::CIDR)
$function$;

CREATE TABLE mesh.network_site (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    name TEXT NOT NULL,
    name_key TEXT NOT NULL,
    prefixes CIDR[] NOT NULL,
    masquerade BOOLEAN NOT NULL,
    failback BOOLEAN NOT NULL,
    probes JSONB NOT NULL DEFAULT '[]'::JSONB,
    state TEXT NOT NULL DEFAULT 'active',
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ,
    CONSTRAINT network_site_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT network_site_name_check CHECK (
        name = pg_catalog.btrim(name)
        AND pg_catalog.char_length(name) BETWEEN 1 AND 64
        AND name !~ '[[:cntrl:]]'
        AND name_key = pg_catalog.lower(name)
    ),
    CONSTRAINT network_site_prefixes_check CHECK (mesh_ops.site_prefixes_valid_internal_v1(prefixes)),
    CONSTRAINT network_site_probes_check CHECK (
        pg_catalog.jsonb_typeof(probes) = 'array' AND pg_catalog.jsonb_array_length(probes) <= 4
    ),
    CONSTRAINT network_site_state_check CHECK (
        (state = 'active' AND deleted_at IS NULL) OR (state = 'deleted' AND deleted_at IS NOT NULL)
    ),
    CONSTRAINT network_site_timestamps_check CHECK (updated_at >= created_at),
    CONSTRAINT network_site_workspace_fk FOREIGN KEY (deployment_id, workspace_id)
        REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT network_site_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    UNIQUE (workspace_id, network_id, id)
);

CREATE UNIQUE INDEX network_site_active_name_uidx
    ON mesh.network_site (workspace_id, network_id, name_key)
    WHERE state = 'active';

CREATE TABLE mesh.network_site_router (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    site_id BIGINT NOT NULL,
    device_id BIGINT NOT NULL,
    priority INTEGER NOT NULL,
    state TEXT NOT NULL,
    added_by_principal_id BIGINT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT network_site_router_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT network_site_router_priority_check CHECK (priority BETWEEN 0 AND 999),
    CONSTRAINT network_site_router_state_check CHECK (state IN ('active', 'draining')),
    CONSTRAINT network_site_router_timestamps_check CHECK (updated_at >= created_at),
    CONSTRAINT network_site_router_site_fk FOREIGN KEY (workspace_id, network_id, site_id)
        REFERENCES mesh.network_site (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT network_site_router_device_fk FOREIGN KEY (workspace_id, network_id, device_id)
        REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE RESTRICT,
    UNIQUE (site_id, device_id)
);

CREATE INDEX network_site_router_device_idx ON mesh.network_site_router (device_id);

-- What a Device offers to forward may never be a default or very wide route,
-- or the overlay: an offer of 0.0.0.0/0 would cover every Site.
CREATE FUNCTION mesh_ops.advertised_prefixes_valid_internal_v1(p_prefixes CIDR[])
RETURNS BOOLEAN
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.cardinality(p_prefixes) <= 256
       AND NOT EXISTS (
           SELECT 1 FROM pg_catalog.unnest(p_prefixes) AS prefix
           WHERE prefix IS NULL
              OR (pg_catalog.family(prefix) = 4 AND pg_catalog.masklen(prefix) < 8)
              OR (pg_catalog.family(prefix) = 6 AND pg_catalog.masklen(prefix) < 32)
              OR prefix && '100.64.0.0/10'::CIDR OR prefix && '198.18.0.0/15'::CIDR
              OR prefix && 'fd00::/8'::CIDR)
$function$;

-- What a Device's local configuration offers to forward, from its latest
-- HostinfoReport. A report, not authority: offering grants nothing.
CREATE TABLE mesh.device_route_advertisement (
    device_id BIGINT PRIMARY KEY,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    prefixes CIDR[] NOT NULL,
    reported_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT device_route_advertisement_prefixes_check CHECK (
        mesh_ops.advertised_prefixes_valid_internal_v1(prefixes)
    ),
    CONSTRAINT device_route_advertisement_device_fk FOREIGN KEY (workspace_id, network_id, device_id)
        REFERENCES mesh.device (workspace_id, network_id, id) ON DELETE CASCADE
);

CREATE FUNCTION mesh_ops.enforce_network_site_transition_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Sites are deleted by state, never removed';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.state <> 'active' OR NEW.version <> 1 THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid new Site';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.public_id <> OLD.public_id OR NEW.deployment_id <> OLD.deployment_id
        OR NEW.workspace_id <> OLD.workspace_id OR NEW.network_id <> OLD.network_id
        OR NEW.created_at <> OLD.created_at OR NEW.version <> OLD.version + 1
        OR OLD.state = 'deleted' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Site transition';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE TRIGGER network_site_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.network_site
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_network_site_transition_v1();
CREATE TRIGGER network_site_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.network_site
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('network_site', 'public_id');
CREATE TRIGGER network_site_router_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.network_site_router
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('network_site_router', 'public_id');

ALTER TABLE mesh.network_site ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.network_site FORCE ROW LEVEL SECURITY;
CREATE POLICY network_site_migrator_policy ON mesh.network_site TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
ALTER TABLE mesh.network_site_router ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.network_site_router FORCE ROW LEVEL SECURITY;
CREATE POLICY network_site_router_migrator_policy ON mesh.network_site_router
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
ALTER TABLE mesh.device_route_advertisement ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.device_route_advertisement FORCE ROW LEVEL SECURITY;
CREATE POLICY device_route_advertisement_migrator_policy ON mesh.device_route_advertisement
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.network_site, mesh.network_site_router, mesh.device_route_advertisement
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.site_prefixes_valid_internal_v1(CIDR[])
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.advertised_prefixes_valid_internal_v1(CIDR[])
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.enforce_network_site_transition_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The exact Network scope bound by the caller, after one permission check.
-- The permission resolver takes the Workspace lock first (schema 184).
CREATE FUNCTION mesh_ops.authorize_site_internal_v1(
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
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Site scope input is invalid';
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
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Site action is not authorized';
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
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Site scope is unavailable';
    END IF;
    RETURN QUERY SELECT v_deployment, v_workspace, v_network, v_principal, v_binding;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.authorize_site_internal_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TEXT
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- One Site with its routers and, for each router, the facts Go needs to
-- decide whether it can serve: Device state, ownership and whether its own
-- configuration offers every prefix of the Site.
CREATE FUNCTION mesh_ops.site_document_internal_v1(p_site mesh.network_site)
RETURNS JSONB
LANGUAGE sql
STABLE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'site_id', p_site.public_id,
        'name', p_site.name,
        'prefixes', (SELECT pg_catalog.jsonb_agg(prefix::TEXT ORDER BY ordinal)
                     FROM pg_catalog.unnest(p_site.prefixes) WITH ORDINALITY AS item(prefix, ordinal)),
        'masquerade', p_site.masquerade,
        'failback', p_site.failback,
        'probes', p_site.probes,
        'state', p_site.state,
        'version', p_site.version,
        'created_at', p_site.created_at,
        'updated_at', p_site.updated_at,
        'routers', COALESCE((
            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                'device_id', device.public_id,
                'device_name', device.hostname,
                'device_state', device.state,
                'ownership', device.ownership,
                'offers_site', NOT EXISTS (
                    SELECT 1 FROM pg_catalog.unnest(p_site.prefixes) AS wanted
                    WHERE NOT EXISTS (
                        SELECT 1 FROM mesh.device_route_advertisement AS advertisement,
                            pg_catalog.unnest(advertisement.prefixes) AS offered
                        WHERE advertisement.device_id = device.id AND wanted <<= offered)),
                'priority', router.priority,
                'state', router.state,
                'added_at', router.created_at
            ) ORDER BY router.priority, device.public_id)
            FROM mesh.network_site_router AS router
            JOIN mesh.device AS device ON device.id = router.device_id
            WHERE router.site_id = p_site.id
        ), '[]'::JSONB)
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.site_document_internal_v1(mesh.network_site)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Whether the Session may create, change and delete Sites, without raising.
CREATE FUNCTION mesh_ops.site_abilities_internal_v1(
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
REVOKE ALL ON FUNCTION mesh_ops.site_abilities_internal_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- One page of the Network's active Sites in (name, Site) order, after the
-- Site p_after_site_public_id when given.
CREATE FUNCTION mesh_ops.list_sites_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_after_site_public_id UUID, p_limit INTEGER
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
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Site page is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_site_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'route.read'
    );
    IF p_after_site_public_id IS NOT NULL THEN
        SELECT network_site.name_key INTO v_after_key FROM mesh.network_site AS network_site
        WHERE network_site.workspace_id = v_scope.workspace_id AND network_site.network_id = v_scope.network_id
          AND network_site.public_id = p_after_site_public_id;
        IF v_after_key IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Site page cursor is unknown';
        END IF;
    END IF;
    SELECT pg_catalog.jsonb_agg(mesh_ops.site_document_internal_v1(page) ORDER BY page.name_key, page.public_id),
           pg_catalog.count(*)
    INTO v_page, v_count
    FROM (
        SELECT * FROM mesh.network_site AS network_site
        WHERE network_site.workspace_id = v_scope.workspace_id AND network_site.network_id = v_scope.network_id
          AND network_site.state = 'active'
          AND (v_after_key IS NULL
               OR (network_site.name_key, network_site.public_id) > (v_after_key, p_after_site_public_id))
        ORDER BY network_site.name_key, network_site.public_id
        LIMIT p_limit + 1
    ) AS page;
    RETURN pg_catalog.jsonb_build_object(
        'sites', CASE WHEN v_count > p_limit
                      THEN v_page - p_limit
                      ELSE COALESCE(v_page, '[]'::JSONB) END,
        'has_more', v_count > p_limit
    ) || mesh_ops.site_abilities_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.list_sites_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, INTEGER
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_sites_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID, INTEGER
) TO mesh_runtime;

-- One active Site (route.read).
CREATE FUNCTION mesh_ops.read_site_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_site_public_id UUID
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
    v_site mesh.network_site%ROWTYPE;
BEGIN
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_site_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'route.read'
    );
    SELECT * INTO v_site FROM mesh.network_site AS network_site
    WHERE network_site.workspace_id = v_scope.workspace_id AND network_site.network_id = v_scope.network_id
      AND network_site.public_id = p_site_public_id AND network_site.state = 'active';
    IF v_site.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Site is unavailable';
    END IF;
    RETURN pg_catalog.jsonb_build_object('site', mesh_ops.site_document_internal_v1(v_site))
        || mesh_ops.site_abilities_internal_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, p_network_public_id);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_site_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_site_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, UUID
) TO mesh_runtime;

-- Advances the Network and route revisions of the bound scope; the caller
-- already holds the revision row.
CREATE FUNCTION mesh_ops.advance_site_revisions_internal_v1(p_workspace_id BIGINT, p_network_id BIGINT)
RETURNS TABLE (network_revision BIGINT, route_revision BIGINT)
LANGUAGE sql
VOLATILE
SET search_path = pg_catalog
AS $function$
    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1, route_revision = revision.route_revision + 1,
        updated_at = GREATEST(pg_catalog.transaction_timestamp(), revision.updated_at)
    WHERE revision.workspace_id = p_workspace_id AND revision.network_id = p_network_id
    RETURNING revision.network_revision, revision.route_revision
$function$;
REVOKE ALL ON FUNCTION mesh_ops.advance_site_revisions_internal_v1(BIGINT, BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Locks the revision row of the bound scope: Site changes serialize with
-- publication and other map inputs.
CREATE FUNCTION mesh_ops.lock_site_scope_internal_v1(p_workspace_id BIGINT, p_network_id BIGINT)
RETURNS VOID
LANGUAGE plpgsql
VOLATILE
SET search_path = pg_catalog
AS $function$
BEGIN
    PERFORM 1 FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = p_workspace_id AND revision.network_id = p_network_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Site scope is unavailable';
    END IF;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.lock_site_scope_internal_v1(BIGINT, BIGINT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Creates or changes a Site (route.approve) or deletes it (route.withdraw).
-- p_site_limit is the Workspace's plan limit, already bounded by Go. An
-- update that changes nothing writes nothing and returns changed = false.
-- Deleting a Site removes its routers.
CREATE FUNCTION mesh_ops.change_site_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_operation TEXT,
    p_site_public_id UUID, p_expected_version BIGINT, p_name TEXT, p_prefixes CIDR[],
    p_masquerade BOOLEAN, p_failback BOOLEAN, p_probes JSONB, p_site_limit INTEGER,
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
    v_site mesh.network_site%ROWTYPE;
    v_before JSONB;
    v_revisions RECORD;
    v_constraint TEXT;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_operation NOT IN ('create', 'update', 'delete') OR p_site_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_site_public_id), 6) >> 4 <> 7
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR (p_operation <> 'create' AND (p_expected_version IS NULL OR p_expected_version < 1))
        OR (p_operation <> 'delete' AND (p_name IS NULL OR p_prefixes IS NULL OR p_masquerade IS NULL
            OR p_failback IS NULL OR p_probes IS NULL))
        OR (p_operation = 'create' AND (p_site_limit IS NULL OR p_site_limit NOT BETWEEN 1 AND 1024)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Site change is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_site_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id,
        CASE WHEN p_operation = 'delete' THEN 'route.withdraw' ELSE 'route.approve' END
    );
    PERFORM mesh_ops.lock_site_scope_internal_v1(v_scope.workspace_id, v_scope.network_id);
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    IF p_operation = 'create' THEN
        IF (SELECT pg_catalog.count(*) FROM mesh.network_site AS network_site
            WHERE network_site.workspace_id = v_scope.workspace_id
              AND network_site.network_id = v_scope.network_id
              AND network_site.state = 'active') >= p_site_limit THEN
            RAISE EXCEPTION USING ERRCODE = 'MTS02', MESSAGE = 'Network already has the maximum Sites';
        END IF;
        BEGIN
            INSERT INTO mesh.network_site (
                public_id, deployment_id, workspace_id, network_id, name, name_key, prefixes,
                masquerade, failback, probes, created_at, updated_at
            ) VALUES (
                p_site_public_id, v_scope.deployment_id, v_scope.workspace_id, v_scope.network_id,
                p_name, pg_catalog.lower(p_name), p_prefixes, p_masquerade, p_failback, p_probes, v_now, v_now
            ) RETURNING * INTO v_site;
        EXCEPTION WHEN unique_violation THEN
            GET STACKED DIAGNOSTICS v_constraint = CONSTRAINT_NAME;
            IF v_constraint = 'network_site_active_name_uidx' THEN
                RAISE EXCEPTION USING ERRCODE = 'MTS01', MESSAGE = 'Site name is taken';
            END IF;
            RAISE;
        END;
    ELSE
        SELECT * INTO v_site FROM mesh.network_site AS network_site
        WHERE network_site.workspace_id = v_scope.workspace_id AND network_site.network_id = v_scope.network_id
          AND network_site.public_id = p_site_public_id AND network_site.state = 'active'
        FOR UPDATE;
        IF v_site.id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Site is unavailable';
        END IF;
        IF v_site.version <> p_expected_version THEN
            RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Site version changed';
        END IF;
        v_before := mesh_ops.site_document_internal_v1(v_site);
        IF p_operation = 'update' AND v_site.name = p_name AND v_site.prefixes = p_prefixes
            AND v_site.masquerade = p_masquerade AND v_site.failback = p_failback AND v_site.probes = p_probes THEN
            RETURN pg_catalog.jsonb_build_object(
                'site', v_before, 'previous', v_before, 'changed', FALSE,
                'role_binding_id', v_scope.role_binding_public_id);
        END IF;
        IF p_operation = 'update' THEN
            BEGIN
                UPDATE mesh.network_site
                SET name = p_name, name_key = pg_catalog.lower(p_name), prefixes = p_prefixes,
                    masquerade = p_masquerade, failback = p_failback, probes = p_probes,
                    version = version + 1, updated_at = GREATEST(v_now, updated_at)
                WHERE id = v_site.id
                RETURNING * INTO v_site;
            EXCEPTION WHEN unique_violation THEN
                GET STACKED DIAGNOSTICS v_constraint = CONSTRAINT_NAME;
                IF v_constraint = 'network_site_active_name_uidx' THEN
                    RAISE EXCEPTION USING ERRCODE = 'MTS01', MESSAGE = 'Site name is taken';
                END IF;
                RAISE;
            END;
        ELSE
            DELETE FROM mesh.network_site_router WHERE site_id = v_site.id;
            UPDATE mesh.network_site
            SET state = 'deleted', deleted_at = GREATEST(v_now, updated_at),
                version = version + 1, updated_at = GREATEST(v_now, updated_at)
            WHERE id = v_site.id
            RETURNING * INTO v_site;
        END IF;
    END IF;
    SELECT * INTO STRICT v_revisions FROM mesh_ops.advance_site_revisions_internal_v1(
        v_scope.workspace_id, v_scope.network_id);
    RETURN pg_catalog.jsonb_build_object(
        'site', mesh_ops.site_document_internal_v1(v_site), 'previous', v_before, 'changed', TRUE,
        'network_revision', v_revisions.network_revision, 'route_revision', v_revisions.route_revision,
        'role_binding_id', v_scope.role_binding_public_id);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.change_site_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    TEXT, UUID, BIGINT, TEXT, CIDR[], BOOLEAN, BOOLEAN, JSONB, INTEGER, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_site_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    TEXT, UUID, BIGINT, TEXT, CIDR[], BOOLEAN, BOOLEAN, JSONB, INTEGER, UUID
) TO mesh_runtime;

-- Makes a Device a router of a Site or changes its priority or state
-- (route.approve), or removes it (route.withdraw). Every change advances the
-- Site's version; a put that changes nothing writes nothing. A new router
-- must be an active, Workspace-owned Device of the Network that offers every
-- prefix of the Site; p_router_limit is the plan limit, bounded by Go. A
-- router stays removable after its Device is gone.
CREATE FUNCTION mesh_ops.change_site_router_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_operation TEXT,
    p_site_public_id UUID, p_expected_version BIGINT, p_device_public_id UUID,
    p_priority INTEGER, p_state TEXT, p_router_limit INTEGER, p_router_public_id UUID,
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
    v_site mesh.network_site%ROWTYPE;
    v_device mesh.device%ROWTYPE;
    v_router mesh.network_site_router%ROWTYPE;
    v_before JSONB;
    v_revisions RECORD;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_operation NOT IN ('put', 'delete') OR p_site_public_id IS NULL OR p_device_public_id IS NULL
        OR p_expected_version IS NULL OR p_expected_version < 1
        OR p_change_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR (p_operation = 'put' AND (p_priority IS NULL OR p_priority NOT BETWEEN 0 AND 999
            OR p_state IS NULL OR p_state NOT IN ('active', 'draining')
            OR p_router_limit IS NULL OR p_router_limit NOT BETWEEN 1 AND 32
            OR p_router_public_id IS NULL
            OR pg_catalog.get_byte(pg_catalog.uuid_send(p_router_public_id), 6) >> 4 <> 7)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Site router change is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_site_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id,
        CASE WHEN p_operation = 'delete' THEN 'route.withdraw' ELSE 'route.approve' END
    );
    PERFORM mesh_ops.lock_site_scope_internal_v1(v_scope.workspace_id, v_scope.network_id);
    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);

    SELECT * INTO v_site FROM mesh.network_site AS network_site
    WHERE network_site.workspace_id = v_scope.workspace_id AND network_site.network_id = v_scope.network_id
      AND network_site.public_id = p_site_public_id AND network_site.state = 'active'
    FOR UPDATE;
    IF v_site.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Site is unavailable';
    END IF;
    IF v_site.version <> p_expected_version THEN
        RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'Site version changed';
    END IF;
    v_before := mesh_ops.site_document_internal_v1(v_site);
    -- The router row is found through its Device whatever that Device's state.
    SELECT router.* INTO v_router FROM mesh.network_site_router AS router
    JOIN mesh.device AS device ON device.id = router.device_id
    WHERE router.site_id = v_site.id AND device.public_id = p_device_public_id
    FOR UPDATE OF router;

    IF p_operation = 'delete' THEN
        IF v_router.id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'Site router is unavailable';
        END IF;
        DELETE FROM mesh.network_site_router WHERE id = v_router.id;
    ELSIF v_router.id IS NOT NULL THEN
        IF v_router.priority = p_priority AND v_router.state = p_state THEN
            RETURN pg_catalog.jsonb_build_object(
                'site', v_before, 'previous', v_before, 'changed', FALSE,
                'role_binding_id', v_scope.role_binding_public_id);
        END IF;
        UPDATE mesh.network_site_router
        SET priority = p_priority, state = p_state, version = version + 1,
            updated_at = GREATEST(v_now, updated_at)
        WHERE id = v_router.id;
    ELSE
        SELECT * INTO v_device FROM mesh.device AS device
        WHERE device.workspace_id = v_scope.workspace_id AND device.network_id = v_scope.network_id
          AND device.public_id = p_device_public_id AND device.deleted_at IS NULL
        FOR SHARE;
        IF v_device.id IS NULL OR v_device.state <> 'active' OR v_device.ownership <> 'workspace' THEN
            RAISE EXCEPTION USING ERRCODE = 'MTS04',
                MESSAGE = 'Device is not an active Workspace Device of this Network';
        END IF;
        IF EXISTS (
            SELECT 1 FROM pg_catalog.unnest(v_site.prefixes) AS wanted
            WHERE NOT EXISTS (
                SELECT 1 FROM mesh.device_route_advertisement AS advertisement,
                    pg_catalog.unnest(advertisement.prefixes) AS offered
                WHERE advertisement.device_id = v_device.id AND wanted <<= offered)) THEN
            RAISE EXCEPTION USING ERRCODE = 'MTS05', MESSAGE = 'Device does not offer the Site prefixes';
        END IF;
        IF (SELECT pg_catalog.count(*) FROM mesh.network_site_router AS router
            WHERE router.site_id = v_site.id) >= p_router_limit THEN
            RAISE EXCEPTION USING ERRCODE = 'MTS03', MESSAGE = 'Site already has the maximum routers';
        END IF;
        INSERT INTO mesh.network_site_router (
            public_id, workspace_id, network_id, site_id, device_id, priority, state,
            added_by_principal_id, created_at, updated_at
        ) VALUES (
            p_router_public_id, v_scope.workspace_id, v_scope.network_id, v_site.id, v_device.id,
            p_priority, p_state, v_scope.principal_id, v_now, v_now
        );
    END IF;
    UPDATE mesh.network_site SET version = version + 1, updated_at = GREATEST(v_now, updated_at)
    WHERE id = v_site.id
    RETURNING * INTO v_site;
    SELECT * INTO STRICT v_revisions FROM mesh_ops.advance_site_revisions_internal_v1(
        v_scope.workspace_id, v_scope.network_id);
    RETURN pg_catalog.jsonb_build_object(
        'site', mesh_ops.site_document_internal_v1(v_site), 'previous', v_before, 'changed', TRUE,
        'network_revision', v_revisions.network_revision, 'route_revision', v_revisions.route_revision,
        'role_binding_id', v_scope.role_binding_public_id);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.change_site_router_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    TEXT, UUID, BIGINT, UUID, INTEGER, TEXT, INTEGER, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_site_router_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID,
    TEXT, UUID, BIGINT, UUID, INTEGER, TEXT, INTEGER, UUID, UUID
) TO mesh_runtime;
