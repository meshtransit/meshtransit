-- Stable SQLSTATEs for provisioning outcomes, so callers never branch on
-- message text, and Network creation that assigns the IPv6 range.
--
--   MTE01  Deployment has no current entitlement
--   MTE02  entitlement is past its grace period
--   MTL01  active Workspace ceiling reached
--   MTL02  per-Account ownership quota reached
--   MTN01  Network prefix outside the Workspace overlay pools
--   23P01  Network prefix overlaps another Network (unchanged)
--
-- create_network_v2 makes the IPv6 prefix optional: when omitted, Core assigns
-- the first free /64 of the Workspace's /48 ULA pool. It also returns both
-- prefixes. create_network_v1 stays until the post-reset cleanup.

CREATE OR REPLACE FUNCTION mesh_ops.create_workspace_v1(
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
    p_display_name TEXT,
    p_membership_public_id UUID,
    p_routing_public_id UUID,
    p_realm_public_id UUID,
    p_ipv4_pool_public_id UUID,
    p_ipv6_pool_public_id UUID,
    p_ipv6_prefix CIDR,
    p_change_public_id UUID
)
RETURNS TABLE (
    workspace_public_id UUID,
    workspace_display_code TEXT,
    workspace_version BIGINT,
    workspace_created_at TIMESTAMPTZ,
    replayed BOOLEAN
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh
AS $function$
DECLARE
    actor RECORD;
    evaluated TIMESTAMPTZ;
    locked_deployment mesh.deployment%ROWTYPE;
    entitlement mesh.deployment_entitlement%ROWTYPE;
    existing mesh.workspace%ROWTYPE;
    active_count BIGINT;
    owned_count BIGINT;
    login_assurance TEXT;
    created_id BIGINT;
BEGIN
    IF p_workspace_public_id IS NULL OR p_change_public_id IS NULL OR p_display_name IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_workspace_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_change_public_id), 6) >> 4 <> 7
        OR pg_catalog.char_length(p_display_name) NOT BETWEEN 1 AND 128
        OR pg_catalog.btrim(p_display_name) <> p_display_name THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Workspace creation input';
    END IF;
    evaluated := pg_catalog.clock_timestamp();
    SELECT * INTO actor FROM mesh_ops.resolve_account_session_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, evaluated);
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Account Session is not active';
    END IF;

    SELECT * INTO locked_deployment FROM mesh.deployment WHERE id = actor.deployment_id FOR UPDATE;

    PERFORM pg_catalog.set_config('mesh.workspace_limit_guard', 'on', TRUE);
    SELECT * INTO existing FROM mesh.workspace
    WHERE deployment_id = actor.deployment_id AND public_id = p_workspace_public_id;
    IF FOUND THEN
        PERFORM pg_catalog.set_config('mesh.workspace_limit_guard', '', TRUE);
        IF existing.owner_principal_id <> actor.principal_id OR existing.display_name <> p_display_name THEN
            RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'Workspace ID was used for another request';
        END IF;
        RETURN QUERY
        SELECT existing.public_id, identity.display_code, existing.version, existing.created_at, TRUE
        FROM mesh_ops.tenant_display_identity AS identity
        WHERE identity.workspace_public_id = existing.public_id;
        RETURN;
    END IF;

    SELECT * INTO entitlement FROM mesh.deployment_entitlement AS candidate
    WHERE candidate.deployment_id = actor.deployment_id AND candidate.profile = locked_deployment.profile
    ORDER BY candidate.generation DESC LIMIT 1
    FOR SHARE;
    IF NOT FOUND OR evaluated < entitlement.not_before THEN
        PERFORM pg_catalog.set_config('mesh.workspace_limit_guard', '', TRUE);
        RAISE EXCEPTION USING ERRCODE = 'MTE01', MESSAGE = 'deployment_entitlement_missing';
    END IF;
    IF evaluated >= entitlement.expires_at + pg_catalog.make_interval(secs => entitlement.grace_seconds) THEN
        PERFORM pg_catalog.set_config('mesh.workspace_limit_guard', '', TRUE);
        RAISE EXCEPTION USING ERRCODE = 'MTE02', MESSAGE = 'deployment_entitlement_expired';
    END IF;

    SELECT pg_catalog.count(*),
        pg_catalog.count(*) FILTER (WHERE workspace.owner_principal_id = actor.principal_id)
    INTO active_count, owned_count
    FROM mesh.workspace AS workspace
    WHERE workspace.deployment_id = actor.deployment_id
      AND workspace.state = 'active' AND workspace.deleted_at IS NULL;
    PERFORM pg_catalog.set_config('mesh.workspace_limit_guard', '', TRUE);
    IF active_count >= entitlement.max_active_workspaces THEN
        RAISE EXCEPTION USING ERRCODE = 'MTL01', MESSAGE = 'deployment_workspace_limit';
    END IF;
    IF owned_count >= entitlement.max_owned_workspaces_per_account THEN
        RAISE EXCEPTION USING ERRCODE = 'MTL02', MESSAGE = 'account_workspace_limit';
    END IF;

    -- New Workspaces require the same assurance as the Workspace the
    -- creator signed in to; a Session without one requires none.
    SELECT routing.minimum_assurance INTO login_assurance
    FROM mesh.workspace_identity_provider AS routing
    WHERE routing.workspace_id = actor.login_workspace_id
      AND routing.identity_provider_id = actor.identity_provider_id
      AND routing.identity_provider_client_id = actor.identity_provider_client_id
      AND routing.state = 'active'
    LIMIT 1;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    created_id := mesh_ops.provision_workspace_v1(
        actor.deployment_id, actor.principal_id, p_workspace_public_id, p_display_name,
        p_membership_public_id, p_routing_public_id, actor.identity_provider_id,
        actor.identity_provider_client_id, login_assurance, p_realm_public_id,
        p_ipv4_pool_public_id, p_ipv6_pool_public_id, p_ipv6_prefix, evaluated);

    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', p_workspace_public_id::TEXT, TRUE);
    RETURN QUERY
    SELECT workspace.public_id, identity.display_code, workspace.version, workspace.created_at, FALSE
    FROM mesh.workspace AS workspace
    JOIN mesh_ops.tenant_display_identity AS identity ON identity.workspace_public_id = workspace.public_id
    WHERE workspace.id = created_id;
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', '', TRUE);
END;
$function$;

CREATE FUNCTION mesh_ops.create_network_v2(
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
    p_network_public_id UUID,
    p_display_name TEXT,
    p_ipv4_prefix CIDR,
    p_ipv6_prefix CIDR,
    p_ipv4_prefix_public_id UUID,
    p_ipv6_prefix_public_id UUID,
    p_membership_public_id UUID,
    p_enrollment_profile_public_id UUID,
    p_change_public_id UUID
)
RETURNS TABLE (
    network_public_id UUID,
    network_display_code TEXT,
    network_version BIGINT,
    network_created_at TIMESTAMPTZ,
    network_ipv4_prefix CIDR,
    network_ipv6_prefix CIDR,
    replayed BOOLEAN,
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
    actor RECORD;
    actor_principal_id BIGINT;
    actor_membership_id BIGINT;
    deployment_internal_id BIGINT;
    existing mesh.network%ROWTYPE;
    pool_v4 mesh.address_pool%ROWTYPE;
    pool_v6 mesh.address_pool%ROWTYPE;
    created_network_id BIGINT;
    evaluated_at TIMESTAMPTZ;
    assigned_ipv6 CIDR;
    existing_ipv6 CIDR;
    pool_hex TEXT;
BEGIN
    FOREACH identifier IN ARRAY ARRAY[p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_workspace_public_id, p_network_public_id, p_ipv4_prefix_public_id,
        p_ipv6_prefix_public_id, p_membership_public_id, p_enrollment_profile_public_id, p_change_public_id] LOOP
        IF identifier IS NULL OR pg_catalog.get_byte(pg_catalog.uuid_send(identifier), 6) >> 4 <> 7 THEN
            RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Network creation input';
        END IF;
    END LOOP;
    IF p_display_name IS NULL OR pg_catalog.char_length(p_display_name) NOT BETWEEN 1 AND 128
        OR pg_catalog.btrim(p_display_name) <> p_display_name
        OR p_ipv4_prefix IS NULL OR pg_catalog.family(p_ipv4_prefix) <> 4
        OR pg_catalog.masklen(p_ipv4_prefix) NOT BETWEEN 16 AND 28
        OR NOT (p_ipv4_prefix <<= '100.64.0.0/10'::CIDR)
        OR (p_ipv6_prefix IS NOT NULL AND (pg_catalog.family(p_ipv6_prefix) <> 6
            OR pg_catalog.masklen(p_ipv6_prefix) NOT BETWEEN 56 AND 112)) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Network creation input';
    END IF;

    scoped_workspace_id := mesh_ops.enter_workspace_management_scope_v1(p_workspace_public_id);
    IF scoped_workspace_id IS NULL
        OR NOT mesh_ops.session_bound_to_workspace_v1(p_session_public_id, scoped_workspace_id) THEN
        RETURN;
    END IF;
    -- Network creation in one Workspace is serialized by its row lock.
    SELECT workspace.deployment_id INTO deployment_internal_id
    FROM mesh.workspace AS workspace WHERE workspace.id = scoped_workspace_id FOR UPDATE;
    evaluated_at := pg_catalog.clock_timestamp();
    SELECT * INTO actor FROM mesh_ops.resolve_workspace_permission_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, 'network.create', evaluated_at
    );
    IF NOT FOUND THEN
        RETURN;
    END IF;
    SELECT principal.id, membership.id INTO STRICT actor_principal_id, actor_membership_id
    FROM mesh.principal AS principal
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = principal.deployment_id
     AND membership.workspace_id = scoped_workspace_id
     AND membership.principal_id = principal.id
     AND membership.state = 'active'
    WHERE principal.public_id = p_principal_public_id;

    SELECT * INTO existing FROM mesh.network AS network
    WHERE network.workspace_id = scoped_workspace_id AND network.public_id = p_network_public_id;
    IF FOUND THEN
        SELECT prefix.prefix INTO existing_ipv6 FROM mesh.network_prefix AS prefix
        WHERE prefix.network_id = existing.id AND prefix.family = 6 AND prefix.state = 'active';
        IF existing.display_name <> p_display_name OR NOT EXISTS (
            SELECT 1 FROM mesh.network_prefix AS prefix
            WHERE prefix.network_id = existing.id AND prefix.prefix = p_ipv4_prefix AND prefix.state = 'active'
        ) OR (p_ipv6_prefix IS NOT NULL AND existing_ipv6 IS DISTINCT FROM p_ipv6_prefix) THEN
            RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'Network ID was used for another request';
        END IF;
        PERFORM pg_catalog.set_config('mesh.network_id', existing.id::TEXT, TRUE);
        RETURN QUERY
        SELECT existing.public_id, identity.display_code, existing.version, existing.created_at,
            p_ipv4_prefix, existing_ipv6, TRUE,
            actor.role_binding_public_id, actor.role_definition_public_id, actor.binding_authority_generation,
            actor.membership_authority_generation, actor.workspace_owner_authority_generation
        FROM mesh_ops.tenant_display_identity AS identity
        WHERE identity.network_public_id = existing.public_id;
        RETURN;
    END IF;

    SELECT pool.* INTO pool_v4 FROM mesh.address_pool AS pool
    JOIN mesh.address_realm AS realm ON realm.id = pool.address_realm_id
    WHERE pool.workspace_id = scoped_workspace_id AND pool.purpose = 'node_overlay' AND pool.family = 4
      AND pool.state = 'active' AND realm.state = 'active' AND realm.kind = 'workspace_overlay'
      AND p_ipv4_prefix <<= pool.prefix;
    SELECT pool.* INTO pool_v6 FROM mesh.address_pool AS pool
    JOIN mesh.address_realm AS realm ON realm.id = pool.address_realm_id
    WHERE pool.workspace_id = scoped_workspace_id AND pool.purpose = 'node_overlay' AND pool.family = 6
      AND pool.state = 'active' AND realm.state = 'active' AND realm.kind = 'workspace_overlay'
      AND (p_ipv6_prefix IS NULL OR p_ipv6_prefix <<= pool.prefix)
    ORDER BY pool.id
    LIMIT 1;
    IF pool_v4.id IS NULL OR pool_v6.id IS NULL OR pool_v4.address_realm_id <> pool_v6.address_realm_id THEN
        RAISE EXCEPTION USING ERRCODE = 'MTN01', MESSAGE = 'Network prefix is outside the Workspace address pools';
    END IF;
    assigned_ipv6 := p_ipv6_prefix;
    IF assigned_ipv6 IS NULL THEN
        -- First free /64 of the /48 pool: the pool's 48-bit routing prefix
        -- plus a 16-bit subnet ID, skipping any overlap in the realm.
        IF pg_catalog.masklen(pool_v6.prefix) <> 48 THEN
            RAISE EXCEPTION USING ERRCODE = 'MTN01', MESSAGE = 'Workspace IPv6 pool cannot assign /64 ranges';
        END IF;
        pool_hex := pg_catalog.encode(pg_catalog.substr(
            pg_catalog.inet_send(pg_catalog.network(pool_v6.prefix)), 5, 6), 'hex');
        SELECT candidate.prefix INTO assigned_ipv6
        FROM pg_catalog.generate_series(0, 65535) AS subnet(id)
        CROSS JOIN LATERAL (
            SELECT (pg_catalog.substr(pool_hex, 1, 4) || ':' || pg_catalog.substr(pool_hex, 5, 4)
                || ':' || pg_catalog.substr(pool_hex, 9, 4) || ':'
                || pg_catalog.lpad(pg_catalog.to_hex(subnet.id), 4, '0') || '::/64')::CIDR AS prefix
        ) AS candidate
        WHERE NOT EXISTS (
            SELECT 1 FROM mesh.network_prefix AS used
            WHERE used.address_realm_id = pool_v6.address_realm_id
              AND used.state IN ('reserved', 'active', 'quarantined')
              AND used.prefix && candidate.prefix
        )
        ORDER BY subnet.id
        LIMIT 1;
        IF assigned_ipv6 IS NULL THEN
            RAISE EXCEPTION USING ERRCODE = 'MTN01', MESSAGE = 'Workspace IPv6 pool is exhausted';
        END IF;
    END IF;
    IF EXISTS (
        SELECT 1 FROM mesh.network_prefix AS prefix
        WHERE prefix.address_realm_id = pool_v4.address_realm_id
          AND prefix.state IN ('reserved', 'active', 'quarantined')
          AND (prefix.prefix && p_ipv4_prefix OR prefix.prefix && assigned_ipv6)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23P01', MESSAGE = 'network_prefix_overlap';
    END IF;

    PERFORM pg_catalog.set_config('mesh.change_public_id', p_change_public_id::TEXT, TRUE);
    SELECT pg_catalog.nextval(pg_catalog.pg_get_serial_sequence('mesh.network', 'id')) INTO created_network_id;
    PERFORM pg_catalog.set_config('mesh.network_id', created_network_id::TEXT, TRUE);
    INSERT INTO mesh.network (id, public_id, workspace_id, display_name, name_key, node_limit, state)
    OVERRIDING SYSTEM VALUE
    VALUES (created_network_id, p_network_public_id, scoped_workspace_id, p_display_name,
        pg_catalog.lower(p_display_name), 1000, 'active');
    INSERT INTO mesh_ops.network_revision (workspace_id, network_id) VALUES (scoped_workspace_id, created_network_id);
    INSERT INTO mesh.network_prefix (
        public_id, workspace_id, network_id, address_realm_id, address_pool_id, prefix, family, state
    ) VALUES
        (p_ipv4_prefix_public_id, scoped_workspace_id, created_network_id, pool_v4.address_realm_id, pool_v4.id,
            p_ipv4_prefix, 4, 'active'),
        (p_ipv6_prefix_public_id, scoped_workspace_id, created_network_id, pool_v6.address_realm_id, pool_v6.id,
            assigned_ipv6, 6, 'active');
    INSERT INTO mesh.network_membership (
        public_id, deployment_id, workspace_id, network_id, principal_id, workspace_membership_id, state, valid_from
    ) VALUES (
        p_membership_public_id, deployment_internal_id, scoped_workspace_id, created_network_id,
        actor_principal_id, actor_membership_id, 'active', evaluated_at
    );
    INSERT INTO mesh.enrollment_profile (
        public_id, workspace_id, network_id, created_by_principal_id, display_name, name_key,
        node_lifetime_seconds, ephemeral_mode, credential_use_policy, state, interactive_authorization_enabled
    ) VALUES (
        p_enrollment_profile_public_id, scoped_workspace_id, created_network_id, actor_principal_id,
        'Interactive login', 'interactive-login', 2592000, 'persistent', 'unlimited', 'active', TRUE
    );
    INSERT INTO mesh_audit.audit_stream (deployment_id, workspace_id, network_id, scope_kind)
    VALUES (deployment_internal_id, scoped_workspace_id, created_network_id, 'network');

    RETURN QUERY
    SELECT network.public_id, identity.display_code, network.version, network.created_at,
        p_ipv4_prefix, assigned_ipv6, FALSE,
        actor.role_binding_public_id, actor.role_definition_public_id, actor.binding_authority_generation,
        actor.membership_authority_generation, actor.workspace_owner_authority_generation
    FROM mesh.network AS network
    JOIN mesh_ops.tenant_display_identity AS identity ON identity.network_public_id = network.public_id
    WHERE network.id = created_network_id;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.create_network_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, TEXT, CIDR, CIDR, UUID, UUID, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.create_network_v2(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, TEXT, CIDR, CIDR, UUID, UUID, UUID, UUID, UUID
) TO mesh_runtime;
