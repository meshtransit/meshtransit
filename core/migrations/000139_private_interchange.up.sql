-- Schema 139 (P5e): Private Interchange.
--
-- A Workspace may run its own MeshTransit relays (meshrelay with
-- --private-interchange) and grant each to some of its Networks. Core adds
-- a granted relay's region, marked preferred, to those Networks' signed relay
-- maps, and tells the relay which Networks it serves in a grant sealed to the
-- relay's key (mtrp-v1 §9.2). MeshCore validates names, addresses and ports
-- and that the region code and relay key do not clash with the shared relay
-- map; this schema stores the relays, keeps every granted Network inside the
-- Workspace, keeps relay keys and region codes unique among active relays,
-- allocates region IDs, advances the revision of every Network whose relays
-- changed so their maps are rebuilt, and serves the active set to the
-- control plane.

INSERT INTO mesh.permission (permission_key, description, risk_class, allowed_scope_kinds, catalog_version)
VALUES
    ('interchange.read', 'Read the Workspace''s Private Interchange relays', 'read', ARRAY['workspace'], 1),
    ('interchange.manage', 'Add, change and remove Private Interchange relays and their Networks', 'mutation',
        ARRAY['workspace'], 1);

INSERT INTO mesh.builtin_role_permission (role_key, permission_id)
SELECT grant_row.role_key, permission.id
FROM (VALUES
    ('admin', 'interchange.read'), ('admin', 'interchange.manage'),
    ('it_admin', 'interchange.read'), ('it_admin', 'interchange.manage'),
    ('network_admin', 'interchange.read'),
    ('security_admin', 'interchange.read'),
    ('auditor', 'interchange.read')
) AS grant_row(role_key, permission_key)
JOIN mesh.permission AS permission ON permission.permission_key = grant_row.permission_key
ON CONFLICT DO NOTHING;

CREATE TABLE mesh.private_interchange (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    name TEXT NOT NULL,
    region_id INTEGER NOT NULL,
    region_code TEXT NOT NULL,
    host_name TEXT NOT NULL,
    ipv4 INET,
    ipv6 INET,
    relay_key BYTEA NOT NULL,
    udp_port INTEGER NOT NULL,
    tls_port INTEGER NOT NULL,
    stun_port INTEGER NOT NULL,
    state TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    deleted_at TIMESTAMPTZ,
    CONSTRAINT private_interchange_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT private_interchange_name_check CHECK (
        pg_catalog.char_length(name) BETWEEN 1 AND 64 AND name = pg_catalog.btrim(name)
    ),
    CONSTRAINT private_interchange_region_id_check CHECK (region_id BETWEEN 1000 AND 64999),
    CONSTRAINT private_interchange_region_code_check CHECK (region_code ~ '^[a-z][a-z0-9-]{0,15}$'),
    CONSTRAINT private_interchange_host_name_check CHECK (
        pg_catalog.char_length(host_name) BETWEEN 4 AND 253
        AND host_name ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'
    ),
    CONSTRAINT private_interchange_address_check CHECK (
        (ipv4 IS NOT NULL OR ipv6 IS NOT NULL)
        AND (ipv4 IS NULL OR (pg_catalog.family(ipv4) = 4 AND pg_catalog.masklen(ipv4) = 32))
        AND (ipv6 IS NULL OR (pg_catalog.family(ipv6) = 6 AND pg_catalog.masklen(ipv6) = 128))
    ),
    CONSTRAINT private_interchange_relay_key_check CHECK (pg_catalog.octet_length(relay_key) = 32),
    CONSTRAINT private_interchange_port_check CHECK (
        udp_port BETWEEN 1 AND 65535 AND tls_port BETWEEN 0 AND 65535 AND stun_port BETWEEN 1 AND 65535
    ),
    CONSTRAINT private_interchange_state_check CHECK (
        (state = 'active' AND deleted_at IS NULL)
        OR (state = 'deleted' AND deleted_at IS NOT NULL AND deleted_at >= created_at)
    ),
    CONSTRAINT private_interchange_timestamps_check CHECK (updated_at >= created_at),
    CONSTRAINT private_interchange_workspace_scope_fk FOREIGN KEY (deployment_id, workspace_id)
        REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT
);
CREATE INDEX private_interchange_workspace_active_idx
    ON mesh.private_interchange (workspace_id) WHERE state = 'active';
CREATE UNIQUE INDEX private_interchange_active_key_idx
    ON mesh.private_interchange (deployment_id, relay_key) WHERE state = 'active';
CREATE UNIQUE INDEX private_interchange_active_code_idx
    ON mesh.private_interchange (deployment_id, region_code) WHERE state = 'active';
CREATE UNIQUE INDEX private_interchange_active_region_idx
    ON mesh.private_interchange (deployment_id, region_id) WHERE state = 'active';

-- The Networks a relay serves; replaced as a set on every change. The
-- Network's public ID is kept here so the control plane reads the grants
-- without any access to mesh.network outside a Workspace scope.
CREATE TABLE mesh.private_interchange_network (
    interchange_id BIGINT NOT NULL REFERENCES mesh.private_interchange (id) ON DELETE RESTRICT,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    network_public_id UUID NOT NULL,
    PRIMARY KEY (interchange_id, network_id),
    CONSTRAINT private_interchange_network_scope_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT
);
CREATE INDEX private_interchange_network_network_idx ON mesh.private_interchange_network (network_id);

-- Identity, scope, region and creation never change; every change advances
-- the version; a removed relay stays as the record of what was granted.
CREATE FUNCTION mesh_ops.enforce_private_interchange_transition_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'private interchange is retained';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NEW.version <> 1 OR NEW.state <> 'active' THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid private interchange';
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.public_id <> OLD.public_id OR NEW.deployment_id <> OLD.deployment_id
        OR NEW.workspace_id <> OLD.workspace_id OR NEW.region_id <> OLD.region_id
        OR NEW.created_at <> OLD.created_at OR OLD.state = 'deleted'
        OR NEW.version <> OLD.version + 1 OR NEW.updated_at < OLD.updated_at THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid private interchange transition';
    END IF;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.enforce_private_interchange_transition_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
CREATE TRIGGER private_interchange_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.private_interchange
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_private_interchange_transition_v1();
CREATE TRIGGER private_interchange_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.private_interchange
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation('private_interchange', 'public_id');

ALTER TABLE mesh.private_interchange ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.private_interchange FORCE ROW LEVEL SECURITY;
CREATE POLICY private_interchange_migrator_policy ON mesh.private_interchange
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.private_interchange
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
ALTER TABLE mesh.private_interchange_network ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.private_interchange_network FORCE ROW LEVEL SECURITY;
CREATE POLICY private_interchange_network_migrator_policy ON mesh.private_interchange_network
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.private_interchange_network
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- One relay as the API reads it.
CREATE FUNCTION mesh_ops.private_interchange_document_internal_v1(p_interchange mesh.private_interchange)
RETURNS JSONB
LANGUAGE sql
STABLE
SET search_path = pg_catalog, mesh
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'interchange_id', p_interchange.public_id,
        'name', p_interchange.name,
        'region_id', p_interchange.region_id,
        'region_code', p_interchange.region_code,
        'host_name', p_interchange.host_name,
        'ipv4', pg_catalog.host(p_interchange.ipv4),
        'ipv6', pg_catalog.host(p_interchange.ipv6),
        'relay_key', pg_catalog.encode(p_interchange.relay_key, 'hex'),
        'udp_port', p_interchange.udp_port,
        'tls_port', p_interchange.tls_port,
        'stun_port', p_interchange.stun_port,
        'network_ids', COALESCE((
            SELECT pg_catalog.jsonb_agg(granted.network_public_id ORDER BY granted.network_public_id)
            FROM mesh.private_interchange_network AS granted
            WHERE granted.interchange_id = p_interchange.id
        ), '[]'::JSONB),
        'version', p_interchange.version,
        'created_at', p_interchange.created_at,
        'updated_at', p_interchange.updated_at
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.private_interchange_document_internal_v1(mesh.private_interchange)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- The active relays of a Workspace the Session may read (interchange.read),
-- with whether it may also manage them. NULL means not authorized.
CREATE FUNCTION mesh_ops.list_workspace_private_interchanges_v1(
    p_session_public_id UUID,
    p_deployment_public_id UUID,
    p_principal_public_id UUID,
    p_identity_subject_public_id UUID,
    p_session_version BIGINT,
    p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT,
    p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    evaluated_at TIMESTAMPTZ := pg_catalog.transaction_timestamp();
    scoped_workspace_id BIGINT;
BEGIN
    scoped_workspace_id := mesh_ops.enter_workspace_management_scope_v1(p_workspace_public_id);
    IF scoped_workspace_id IS NULL
        OR NOT mesh_ops.session_bound_to_workspace_v1(p_session_public_id, scoped_workspace_id) THEN
        RETURN NULL;
    END IF;
    PERFORM 1 FROM mesh_ops.resolve_workspace_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'interchange.read', evaluated_at
    );
    IF NOT FOUND THEN
        RETURN NULL;
    END IF;
    RETURN pg_catalog.jsonb_build_object(
        'interchanges', COALESCE((
            SELECT pg_catalog.jsonb_agg(mesh_ops.private_interchange_document_internal_v1(interchange)
                ORDER BY interchange.created_at, interchange.public_id)
            FROM mesh.private_interchange AS interchange
            WHERE interchange.workspace_id = scoped_workspace_id AND interchange.state = 'active'
        ), '[]'::JSONB),
        'can_manage', EXISTS (SELECT 1 FROM mesh_ops.resolve_workspace_permission_v1(
            p_session_public_id, p_deployment_public_id, p_principal_public_id,
            p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
            p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
            p_workspace_public_id, 'interchange.manage', evaluated_at))
    );
END;
$function$;

-- Creates, updates or removes one relay and replaces its Networks, then
-- advances the revision of every Network it served before or serves now.
-- Errors: P0002 unknown relay, 40001 stale version, MTP01 a Network is not
-- in the Workspace, MTP02 the Workspace already has 16 relays, MTP03 the
-- relay key or region code is already used by another active relay, MTP04
-- no region ID is free.
CREATE FUNCTION mesh_ops.change_workspace_private_interchange_v1(
    p_session_public_id UUID,
    p_deployment_public_id UUID,
    p_principal_public_id UUID,
    p_identity_subject_public_id UUID,
    p_session_version BIGINT,
    p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT,
    p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID,
    p_operation TEXT,
    p_interchange_public_id UUID,
    p_expected_version BIGINT,
    p_name TEXT,
    p_region_code TEXT,
    p_host_name TEXT,
    p_ipv4 INET,
    p_ipv6 INET,
    p_relay_key BYTEA,
    p_udp_port INTEGER,
    p_tls_port INTEGER,
    p_stun_port INTEGER,
    p_network_public_ids UUID[],
    p_change_public_id UUID
)
RETURNS TABLE (
    interchange JSONB,
    previous_interchange JSONB,
    advanced_networks JSONB,
    actor_binding_public_id UUID,
    actor_role_public_id UUID,
    actor_binding_generation BIGINT,
    actor_membership_generation BIGINT,
    actor_owner_generation BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    identifier UUID;
    scoped_workspace_id BIGINT;
    deployment_internal_id BIGINT;
    actor RECORD;
    existing mesh.private_interchange%ROWTYPE;
    saved mesh.private_interchange%ROWTYPE;
    evaluated_at TIMESTAMPTZ;
    previous_networks BIGINT[] := ARRAY[]::BIGINT[];
    granted_networks BIGINT[] := ARRAY[]::BIGINT[];
    affected BIGINT[];
    free_region INTEGER;
BEGIN
    FOREACH identifier IN ARRAY ARRAY[p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_workspace_public_id, p_interchange_public_id, p_change_public_id] LOOP
        IF identifier IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(identifier), 6) >> 4 <> 7 THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid private interchange change input';
        END IF;
    END LOOP;
    IF p_operation IS NULL OR p_operation NOT IN ('create', 'update', 'delete')
        OR (p_operation = 'create' AND p_expected_version IS NOT NULL)
        OR (p_operation <> 'create' AND (p_expected_version IS NULL OR p_expected_version <= 0))
        OR (p_operation <> 'delete' AND (p_name IS NULL OR p_region_code IS NULL OR p_host_name IS NULL
            OR p_relay_key IS NULL OR p_udp_port IS NULL OR p_tls_port IS NULL OR p_stun_port IS NULL
            OR p_network_public_ids IS NULL OR pg_catalog.cardinality(p_network_public_ids) > 256)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid private interchange change input';
    END IF;

    scoped_workspace_id := mesh_ops.enter_workspace_management_scope_v1(p_workspace_public_id);
    IF scoped_workspace_id IS NULL
        OR NOT mesh_ops.session_bound_to_workspace_v1(p_session_public_id, scoped_workspace_id) THEN
        RETURN;
    END IF;
    SELECT workspace.deployment_id INTO deployment_internal_id
    FROM mesh.workspace AS workspace WHERE workspace.id = scoped_workspace_id FOR UPDATE;
    evaluated_at := pg_catalog.clock_timestamp();
    SELECT * INTO actor FROM mesh_ops.resolve_workspace_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'interchange.manage', evaluated_at
    );
    IF NOT FOUND THEN
        RETURN;
    END IF;
    IF p_operation <> 'delete' THEN
        SELECT COALESCE(pg_catalog.array_agg(DISTINCT network.id), ARRAY[]::BIGINT[]) INTO granted_networks
        FROM mesh.network AS network
        WHERE network.workspace_id = scoped_workspace_id
          AND network.public_id = ANY (p_network_public_ids)
          AND network.deleted_at IS NULL;
        IF pg_catalog.cardinality(granted_networks) <> (
            SELECT pg_catalog.count(DISTINCT requested) FROM pg_catalog.unnest(p_network_public_ids) AS requested
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'MTP01', MESSAGE = 'private interchange Network is not in the Workspace';
        END IF;
        -- Serialise changes of this deployment's relay keys and region codes.
        PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('mesh.private_interchange'),
            deployment_internal_id::INTEGER);
        IF EXISTS (
            SELECT 1 FROM mesh.private_interchange AS other
            WHERE other.deployment_id = deployment_internal_id AND other.state = 'active'
              AND other.public_id <> p_interchange_public_id
              AND (other.relay_key = p_relay_key OR other.region_code = p_region_code)
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'MTP03', MESSAGE = 'relay key or region code already in use';
        END IF;
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    IF p_operation = 'create' THEN
        IF (SELECT pg_catalog.count(*) FROM mesh.private_interchange AS counted
            WHERE counted.workspace_id = scoped_workspace_id AND counted.state = 'active') >= 16 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTP02', MESSAGE = 'private interchange limit reached';
        END IF;
        SELECT candidate INTO free_region
        FROM pg_catalog.generate_series(1000, 64999) AS candidate
        WHERE NOT EXISTS (
            SELECT 1 FROM mesh.private_interchange AS used
            WHERE used.deployment_id = deployment_internal_id AND used.state = 'active'
              AND used.region_id = candidate
        )
        ORDER BY candidate
        LIMIT 1;
        IF free_region IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'MTP04', MESSAGE = 'no private interchange region is free';
        END IF;
        INSERT INTO mesh.private_interchange (
            public_id, deployment_id, workspace_id, name, region_id, region_code, host_name, ipv4, ipv6,
            relay_key, udp_port, tls_port, stun_port, state, created_at, updated_at
        ) VALUES (
            p_interchange_public_id, deployment_internal_id, scoped_workspace_id, p_name, free_region,
            p_region_code, p_host_name, p_ipv4, p_ipv6, p_relay_key, p_udp_port, p_tls_port, p_stun_port,
            'active', evaluated_at, evaluated_at
        ) RETURNING * INTO saved;
    ELSE
        SELECT * INTO existing FROM mesh.private_interchange AS current
        WHERE current.public_id = p_interchange_public_id
          AND current.workspace_id = scoped_workspace_id
          AND current.state = 'active'
        FOR UPDATE;
        IF existing.id IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'P0002', MESSAGE = 'private interchange is unavailable';
        END IF;
        IF existing.version <> p_expected_version THEN
            RAISE EXCEPTION USING ERRCODE = '40001', MESSAGE = 'private interchange changed';
        END IF;
        SELECT COALESCE(pg_catalog.array_agg(granted.network_id), ARRAY[]::BIGINT[]) INTO previous_networks
        FROM mesh.private_interchange_network AS granted WHERE granted.interchange_id = existing.id;
        previous_interchange := mesh_ops.private_interchange_document_internal_v1(existing);
        IF p_operation = 'delete' THEN
            UPDATE mesh.private_interchange AS current
            SET state = 'deleted', deleted_at = evaluated_at,
                updated_at = GREATEST(existing.updated_at, evaluated_at), version = current.version + 1
            WHERE current.id = existing.id
            RETURNING * INTO saved;
        ELSE
            UPDATE mesh.private_interchange AS current
            SET name = p_name, region_code = p_region_code, host_name = p_host_name, ipv4 = p_ipv4,
                ipv6 = p_ipv6, relay_key = p_relay_key, udp_port = p_udp_port, tls_port = p_tls_port,
                stun_port = p_stun_port,
                updated_at = GREATEST(existing.updated_at, evaluated_at), version = current.version + 1
            WHERE current.id = existing.id
            RETURNING * INTO saved;
        END IF;
        DELETE FROM mesh.private_interchange_network AS granted WHERE granted.interchange_id = existing.id;
    END IF;
    INSERT INTO mesh.private_interchange_network (interchange_id, workspace_id, network_id, network_public_id)
    SELECT saved.id, scoped_workspace_id, network.id, network.public_id
    FROM mesh.network AS network
    WHERE network.workspace_id = scoped_workspace_id AND network.id = ANY (granted_networks);

    SELECT COALESCE(pg_catalog.array_agg(DISTINCT changed ORDER BY changed), ARRAY[]::BIGINT[]) INTO affected
    FROM pg_catalog.unnest(previous_networks || granted_networks) AS changed;
    advanced_networks := '[]'::JSONB;
    IF pg_catalog.cardinality(affected) > 0 THEN
        advanced_networks := mesh_ops.advance_identity_networks_internal_v1(scoped_workspace_id, affected);
    END IF;

    interchange := mesh_ops.private_interchange_document_internal_v1(saved)
        || pg_catalog.jsonb_build_object('state', saved.state);
    actor_binding_public_id := actor.role_binding_public_id;
    actor_role_public_id := actor.role_definition_public_id;
    actor_binding_generation := actor.binding_authority_generation;
    actor_membership_generation := actor.membership_authority_generation;
    actor_owner_generation := actor.workspace_owner_authority_generation;
    RETURN NEXT;
END;
$function$;

-- Every active relay of the deployment with the Networks it serves, for the
-- control plane's relay maps and grants, and the time of the latest change
-- (any relay, including removed ones) as a monotonic revision.
CREATE FUNCTION mesh_ops.private_interchange_directory_v1()
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
    SELECT pg_catalog.jsonb_build_object(
        'revision', COALESCE((
            SELECT pg_catalog.floor(pg_catalog.date_part('epoch', pg_catalog.max(changed.updated_at)))::BIGINT
            FROM mesh.private_interchange AS changed
        ), 0),
        'interchanges', COALESCE((
            SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                'interchange_id', interchange.public_id,
                'name', interchange.name,
                'region_id', interchange.region_id,
                'region_code', interchange.region_code,
                'host_name', interchange.host_name,
                'ipv4', pg_catalog.host(interchange.ipv4),
                'ipv6', pg_catalog.host(interchange.ipv6),
                'relay_key', pg_catalog.encode(interchange.relay_key, 'hex'),
                'udp_port', interchange.udp_port,
                'tls_port', interchange.tls_port,
                'stun_port', interchange.stun_port,
                'network_ids', COALESCE((
                    SELECT pg_catalog.jsonb_agg(granted.network_public_id ORDER BY granted.network_public_id)
                    FROM mesh.private_interchange_network AS granted
                    WHERE granted.interchange_id = interchange.id
                ), '[]'::JSONB)
            ) ORDER BY interchange.region_id)
            FROM mesh.private_interchange AS interchange
            WHERE interchange.state = 'active'
        ), '[]'::JSONB)
    ) INTO v_result;
    RETURN v_result;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.list_workspace_private_interchanges_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_workspace_private_interchanges_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.change_workspace_private_interchange_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, TEXT, UUID, BIGINT,
    TEXT, TEXT, TEXT, INET, INET, BYTEA, INTEGER, INTEGER, INTEGER, UUID[], UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.change_workspace_private_interchange_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, TEXT, UUID, BIGINT,
    TEXT, TEXT, TEXT, INET, INET, BYTEA, INTEGER, INTEGER, INTEGER, UUID[], UUID
) TO mesh_runtime;
REVOKE ALL ON FUNCTION mesh_ops.private_interchange_directory_v1()
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.private_interchange_directory_v1() TO mesh_runtime;
