-- ADR-050 D3: one reviewed path that builds a complete, valid Workspace. The
-- installation bootstrap and Workspace creation both call
-- provision_workspace_v1, so every Workspace gets the same rows: the
-- Workspace, the owner's membership, identity-provider routing for the
-- creating provider and client, and its own workspace_overlay address realm
-- with one IPv4 and one IPv6 node pool. Overlapping CIDRs across Workspaces
-- are allowed because each realm is separate.
--
-- The caller sets mesh.change_public_id and appends one audit/outbox record
-- for the Workspace aggregate in the same transaction.

CREATE POLICY workspace_migrator_insert_policy ON mesh.workspace
    FOR INSERT TO mesh_migrator WITH CHECK (TRUE);
CREATE POLICY address_realm_migrator_insert_policy ON mesh.address_realm
    FOR INSERT TO mesh_migrator WITH CHECK (kind = 'workspace_overlay');
CREATE POLICY address_pool_migrator_insert_policy ON mesh.address_pool
    FOR INSERT TO mesh_migrator WITH CHECK (purpose = 'node_overlay');
-- RETURNING applies SELECT policies; the new realm is visible only inside its
-- own Workspace scope.
CREATE POLICY address_realm_migrator_provisioning_read ON mesh.address_realm
    FOR SELECT TO mesh_migrator
    USING (kind = 'workspace_overlay' AND workspace_id = mesh_ops.current_workspace_id());

CREATE FUNCTION mesh_ops.provision_workspace_v1(
    p_deployment_id BIGINT,
    p_owner_principal_id BIGINT,
    p_workspace_public_id UUID,
    p_display_name TEXT,
    p_membership_public_id UUID,
    p_routing_public_id UUID,
    p_identity_provider_id BIGINT,
    p_identity_provider_client_id BIGINT,
    p_minimum_assurance TEXT,
    p_realm_public_id UUID,
    p_ipv4_pool_public_id UUID,
    p_ipv6_pool_public_id UUID,
    p_ipv6_prefix CIDR,
    p_valid_from TIMESTAMPTZ
)
RETURNS BIGINT
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh
AS $function$
DECLARE
    workspace_internal_id BIGINT;
    realm_internal_id BIGINT;
    previous_requested_workspace TEXT;
    previous_workspace TEXT;
BEGIN
    IF p_deployment_id IS NULL OR p_owner_principal_id IS NULL OR p_workspace_public_id IS NULL
        OR p_display_name IS NULL OR p_membership_public_id IS NULL OR p_routing_public_id IS NULL
        OR p_identity_provider_id IS NULL OR p_identity_provider_client_id IS NULL
        OR p_realm_public_id IS NULL OR p_ipv4_pool_public_id IS NULL OR p_ipv6_pool_public_id IS NULL
        OR p_ipv6_prefix IS NULL OR pg_catalog.family(p_ipv6_prefix) <> 6
        OR pg_catalog.masklen(p_ipv6_prefix) <> 48
        OR NOT (p_ipv6_prefix <<= 'fd00::/8'::CIDR)
        OR p_valid_from IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Workspace provisioning input';
    END IF;
    IF pg_catalog.current_setting('mesh.change_public_id', TRUE) IS NULL
        OR pg_catalog.current_setting('mesh.change_public_id', TRUE) = '' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Workspace provisioning requires an audited change';
    END IF;

    previous_requested_workspace := pg_catalog.current_setting('mesh.requested_workspace_public_id', TRUE);
    previous_workspace := pg_catalog.current_setting('mesh.workspace_id', TRUE);
    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', p_workspace_public_id::TEXT, TRUE);

    INSERT INTO mesh.workspace (public_id, deployment_id, owner_principal_id, display_name, name_key, state)
    VALUES (p_workspace_public_id, p_deployment_id, p_owner_principal_id, p_display_name,
        pg_catalog.lower(p_display_name), 'active')
    RETURNING id INTO workspace_internal_id;
    PERFORM pg_catalog.set_config('mesh.workspace_id', workspace_internal_id::TEXT, TRUE);

    INSERT INTO mesh.workspace_membership (public_id, deployment_id, workspace_id, principal_id, state, valid_from)
    VALUES (p_membership_public_id, p_deployment_id, workspace_internal_id, p_owner_principal_id, 'active', p_valid_from);

    INSERT INTO mesh.workspace_identity_provider (
        public_id, deployment_id, workspace_id, identity_provider_id, identity_provider_client_id,
        admission_mode, minimum_assurance, routing_priority, state
    ) VALUES (
        p_routing_public_id, p_deployment_id, workspace_internal_id, p_identity_provider_id,
        p_identity_provider_client_id, 'invitation_only', p_minimum_assurance, 10, 'active'
    );

    INSERT INTO mesh.address_realm (public_id, deployment_id, workspace_id, kind, ipv4_enabled, ipv6_enabled, state)
    VALUES (p_realm_public_id, p_deployment_id, workspace_internal_id, 'workspace_overlay', TRUE, TRUE, 'active')
    RETURNING id INTO realm_internal_id;

    INSERT INTO mesh.address_pool (
        public_id, deployment_id, workspace_id, address_realm_id, purpose, prefix, family, state
    ) VALUES
        (p_ipv4_pool_public_id, p_deployment_id, workspace_internal_id, realm_internal_id,
            'node_overlay', '100.64.0.0/10'::CIDR, 4, 'active'),
        (p_ipv6_pool_public_id, p_deployment_id, workspace_internal_id, realm_internal_id,
            'node_overlay', p_ipv6_prefix, 6, 'active');

    PERFORM pg_catalog.set_config('mesh.requested_workspace_public_id', COALESCE(previous_requested_workspace, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.workspace_id', COALESCE(previous_workspace, ''), TRUE);
    RETURN workspace_internal_id;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.provision_workspace_v1(
    BIGINT, BIGINT, UUID, TEXT, UUID, UUID, BIGINT, BIGINT, TEXT, UUID, UUID, UUID, CIDR, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
