-- ADR-050 implementation step 5b: Network creation for the owner, admins and
-- network_admins. Every Network IPv4 prefix lies inside 100.64.0.0/10 (the
-- shared CGNAT overlay range), checked explicitly and through the pools.
--
-- network_admins (permission network.create). A Network gets one IPv4 and one
-- IPv6 prefix inside its Workspace's overlay pools. Prefixes of Networks in the
-- same Workspace never overlap: every Workspace has exactly one active
-- workspace_overlay realm and network_prefix_realm_prefix_excl (migration 2)
-- excludes overlapping reserved/active/quarantined prefixes per realm. This
-- function checks first to return network_prefix_overlap; the constraint is
-- the final guard. Different Workspaces may reuse the same CIDRs.
--
-- The function leaves mesh.workspace_id and mesh.network_id set for the
-- caller, which locks the new Network audit stream and appends one
-- audit/outbox record unless the request replayed.

CREATE POLICY network_migrator_provisioning_insert ON mesh.network
    FOR INSERT TO mesh_migrator WITH CHECK (workspace_id = mesh_ops.current_workspace_id());
CREATE POLICY network_prefix_migrator_provisioning_insert ON mesh.network_prefix
    FOR INSERT TO mesh_migrator WITH CHECK (workspace_id = mesh_ops.current_workspace_id());
CREATE POLICY network_prefix_migrator_provisioning_read ON mesh.network_prefix
    FOR SELECT TO mesh_migrator USING (workspace_id = mesh_ops.current_workspace_id());
CREATE POLICY network_revision_migrator_provisioning_insert ON mesh_ops.network_revision
    FOR INSERT TO mesh_migrator WITH CHECK (workspace_id = mesh_ops.current_workspace_id());
CREATE POLICY address_pool_migrator_provisioning_read ON mesh.address_pool
    FOR SELECT TO mesh_migrator
    USING (purpose = 'node_overlay' AND workspace_id = mesh_ops.current_workspace_id());
CREATE POLICY network_migrator_provisioning_read ON mesh.network
    FOR SELECT TO mesh_migrator USING (workspace_id = mesh_ops.current_workspace_id());

-- Errors: 42501 missing network.create; 22023 invalid input or a prefix outside
-- the Workspace pools; 23P01 'network_prefix_overlap'; 23505 a reused Network
-- ID or a name already used in the Workspace.
CREATE FUNCTION mesh_ops.create_network_v1(
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
        OR p_ipv6_prefix IS NULL OR pg_catalog.family(p_ipv6_prefix) <> 6
        OR pg_catalog.masklen(p_ipv6_prefix) NOT BETWEEN 56 AND 112 THEN
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
        IF existing.display_name <> p_display_name OR NOT EXISTS (
            SELECT 1 FROM mesh.network_prefix AS prefix
            WHERE prefix.network_id = existing.id AND prefix.prefix = p_ipv4_prefix AND prefix.state = 'active'
        ) OR NOT EXISTS (
            SELECT 1 FROM mesh.network_prefix AS prefix
            WHERE prefix.network_id = existing.id AND prefix.prefix = p_ipv6_prefix AND prefix.state = 'active'
        ) THEN
            RAISE EXCEPTION USING ERRCODE = '23505', MESSAGE = 'Network ID was used for another request';
        END IF;
        PERFORM pg_catalog.set_config('mesh.network_id', existing.id::TEXT, TRUE);
        RETURN QUERY
        SELECT existing.public_id, identity.display_code, existing.version, existing.created_at, TRUE,
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
      AND p_ipv6_prefix <<= pool.prefix;
    IF pool_v4.id IS NULL OR pool_v6.id IS NULL OR pool_v4.address_realm_id <> pool_v6.address_realm_id THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Network prefix is outside the Workspace address pools';
    END IF;
    IF EXISTS (
        SELECT 1 FROM mesh.network_prefix AS prefix
        WHERE prefix.address_realm_id = pool_v4.address_realm_id
          AND prefix.state IN ('reserved', 'active', 'quarantined')
          AND (prefix.prefix && p_ipv4_prefix OR prefix.prefix && p_ipv6_prefix)
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
            p_ipv6_prefix, 6, 'active');
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
    SELECT network.public_id, identity.display_code, network.version, network.created_at, FALSE,
        actor.role_binding_public_id, actor.role_definition_public_id, actor.binding_authority_generation,
        actor.membership_authority_generation, actor.workspace_owner_authority_generation
    FROM mesh.network AS network
    JOIN mesh_ops.tenant_display_identity AS identity ON identity.network_public_id = network.public_id
    WHERE network.id = created_network_id;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.create_network_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, TEXT, CIDR, CIDR, UUID, UUID, UUID, UUID, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.create_network_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, TEXT, CIDR, CIDR, UUID, UUID, UUID, UUID, UUID
) TO mesh_runtime;
