-- Schema 108 (R1-60): Policy Explain answers for shared Devices and says why a
-- connection is denied.
--
-- explain_active_policy_v2 validated the question, the Network scope and the
-- policy.explain permission, but always returned no path for an imported
-- (shared) destination, so an allowed share read as denied. v3 keeps v2 as the
-- single validation and authorization gate, then:
--
-- * derives paths to an imported destination from the active release's
--   compiled imported rules, bound to the current Trust Contract and imported
--   Resource versions, while the contract is active and unexpired;
-- * withholds every path when the source or target Device is not usable now
--   (inactive, deleted or key-expired), so Explain never says "allowed" for a
--   Device that cannot connect;
-- * returns a bounded context: source and target state, and for an imported
--   destination the contract state, expiry and provider display codes plus the
--   consumer access name, which the consumer already sees on its share.
--
-- The functions run as their owner, which RLS does not restrict, so every
-- query filters explicitly to the caller's Network scope. Provider Devices,
-- addresses and Resources are never returned. Explain answers current policy
-- authority; map distribution and client enforcement evidence are separate.

CREATE FUNCTION mesh_ops.explain_active_policy_v3(
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
    p_source_device_public_id UUID,
    p_destination_device_public_id UUID,
    p_destination_resource_public_id UUID,
    p_destination_imported_resource_public_id UUID,
    p_protocol TEXT,
    p_destination_port INTEGER,
    p_evaluated_at TIMESTAMPTZ,
    p_path_limit INTEGER
)
RETURNS TABLE (
    network_revision BIGINT,
    inventory_revision BIGINT,
    group_revision BIGINT,
    policy_revision BIGINT,
    dns_revision BIGINT,
    route_revision BIGINT,
    sharing_revision BIGINT,
    isolation_generation BIGINT,
    has_active_release BOOLEAN,
    release_public_id UUID,
    compiler_format_version INTEGER,
    release_semantic_hash BYTEA,
    target_device_public_id UUID,
    paths JSONB,
    context JSONB
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    -- A share created without expiry stores this sentinel; it is reported as null.
    never_expires CONSTANT TIMESTAMPTZ := TIMESTAMPTZ '2200-01-01 00:00:00+00';
    base RECORD;
    scoped_workspace BIGINT;
    scoped_network BIGINT;
    v_source_id BIGINT;
    source_name TEXT;
    source_state TEXT := 'missing';
    target_kind TEXT;
    target_name TEXT;
    target_state TEXT := 'missing';
    v_imported_id BIGINT;
    v_imported_version BIGINT;
    v_contract_id BIGINT;
    v_contract_version BIGINT;
    v_contract_expires_at TIMESTAMPTZ;
    share_context JSONB;
    effective_paths JSONB := '[]'::JSONB;
BEGIN
    -- v2 (and v1 beneath it) validates the question, the exact Network scope and
    -- policy.explain authority, and raises on any failure.
    SELECT value.* INTO base
    FROM mesh_ops.explain_active_policy_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, p_source_device_public_id,
        p_destination_device_public_id, p_destination_resource_public_id,
        p_destination_imported_resource_public_id, p_protocol, p_destination_port,
        p_evaluated_at, p_path_limit
    ) AS value;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Access Graph explanation is unavailable';
    END IF;
    scoped_workspace := mesh_ops.current_workspace_id();
    scoped_network := mesh_ops.current_network_id();

    SELECT device.id, device.hostname,
        CASE
            WHEN device.state = 'active' AND device.deleted_at IS NULL
                AND device.expires_at > p_evaluated_at THEN 'active'
            ELSE 'inactive'
        END
    INTO v_source_id, source_name, source_state
    FROM mesh.device AS device
    WHERE device.workspace_id = scoped_workspace
      AND device.network_id = scoped_network
      AND device.public_id = p_source_device_public_id;
    source_state := COALESCE(source_state, 'missing');

    IF p_destination_device_public_id IS NOT NULL THEN
        target_kind := 'device';
        SELECT device.hostname,
            CASE
                WHEN device.state = 'active' AND device.deleted_at IS NULL
                    AND device.expires_at > p_evaluated_at THEN 'active'
                ELSE 'inactive'
            END
        INTO target_name, target_state
        FROM mesh.device AS device
        WHERE device.workspace_id = scoped_workspace
          AND device.network_id = scoped_network
          AND device.public_id = p_destination_device_public_id;
    ELSIF p_destination_resource_public_id IS NOT NULL THEN
        target_kind := 'resource';
        SELECT resource.display_name,
            CASE
                WHEN resource.state = 'active' AND resource.deleted_at IS NULL THEN 'active'
                ELSE 'inactive'
            END
        INTO target_name, target_state
        FROM mesh.resource AS resource
        WHERE resource.workspace_id = scoped_workspace
          AND resource.network_id = scoped_network
          AND resource.public_id = p_destination_resource_public_id;
    ELSE
        target_kind := 'imported_resource';
        SELECT imported.id, imported.version, imported.display_name,
            CASE WHEN imported.state = 'active' THEN 'active' ELSE 'inactive' END,
            contract.id, contract.version, contract.expires_at,
            pg_catalog.jsonb_build_object(
                'trust_contract_id', contract.public_id,
                'state', CASE
                    WHEN contract.state IN ('activating', 'active')
                        AND contract.expires_at <= p_evaluated_at THEN 'expired'
                    ELSE contract.state
                END,
                'expires_at', CASE
                    WHEN contract.expires_at >= never_expires THEN NULL
                    ELSE contract.expires_at
                END,
                'provider_workspace_code', provider_workspace_code.display_code,
                'provider_network_code', provider_network_code.display_code,
                'access_name', (
                    SELECT access_name.access_name
                    FROM mesh.imported_resource_access_name AS access_name
                    WHERE access_name.workspace_id = scoped_workspace
                      AND access_name.network_id = scoped_network
                      AND access_name.imported_resource_id = imported.id
                    ORDER BY (access_name.state = 'reserved') DESC, access_name.id DESC
                    LIMIT 1
                )
            )
        INTO v_imported_id, v_imported_version, target_name, target_state,
            v_contract_id, v_contract_version, v_contract_expires_at, share_context
        FROM mesh.imported_resource AS imported
        JOIN mesh.trust_contract AS contract
          ON contract.id = imported.trust_contract_id
         AND contract.consumer_workspace_id = scoped_workspace
         AND contract.consumer_network_id = scoped_network
        JOIN mesh.workspace AS provider_workspace
          ON provider_workspace.id = contract.provider_workspace_id
        JOIN mesh.network AS provider_network
          ON provider_network.workspace_id = contract.provider_workspace_id
         AND provider_network.id = contract.provider_network_id
        LEFT JOIN mesh_ops.tenant_display_identity AS provider_workspace_code
          ON provider_workspace_code.workspace_public_id = provider_workspace.public_id
        LEFT JOIN mesh_ops.tenant_display_identity AS provider_network_code
          ON provider_network_code.network_public_id = provider_network.public_id
        WHERE imported.workspace_id = scoped_workspace
          AND imported.network_id = scoped_network
          AND imported.public_id = p_destination_imported_resource_public_id;
    END IF;
    target_state := COALESCE(target_state, 'missing');

    IF source_state = 'active' AND target_state = 'active' THEN
        IF target_kind <> 'imported_resource' THEN
            effective_paths := base.paths;
        ELSIF share_context ->> 'state' = 'active' THEN
            SELECT COALESCE(pg_catalog.jsonb_agg(path.value ORDER BY path.rule_id, path.projection_id), '[]'::JSONB)
            INTO effective_paths
            FROM (
                SELECT
                    rule.access_rule_public_id::TEXT AS rule_id,
                    rule.public_id::TEXT AS projection_id,
                    pg_catalog.jsonb_build_object(
                        'projection_id', rule.public_id,
                        'access_rule_id', rule.access_rule_public_id,
                        'source_device_id', p_source_device_public_id,
                        'protocol', rule.protocol,
                        'destination_port_range_first', ARRAY(
                            SELECT pg_catalog.lower(port_range)::INTEGER
                            FROM pg_catalog.unnest(rule.destination_ports) AS port_range
                            ORDER BY pg_catalog.lower(port_range), pg_catalog.upper(port_range)
                        ),
                        'destination_port_range_last', ARRAY(
                            SELECT (pg_catalog.upper(port_range) - 1)::INTEGER
                            FROM pg_catalog.unnest(rule.destination_ports) AS port_range
                            ORDER BY pg_catalog.lower(port_range), pg_catalog.upper(port_range)
                        ),
                        'selector_kind', 'imported_resource',
                        'destination_imported_resource_id', p_destination_imported_resource_public_id,
                        'trust_contract_id', share_context ->> 'trust_contract_id'
                    ) AS value
                FROM mesh.policy_release AS release
                JOIN mesh.compiled_policy_imported_resource_destination AS rule
                  ON rule.workspace_id = release.workspace_id
                 AND rule.network_id = release.network_id
                 AND rule.policy_release_id = release.id
                 AND rule.policy_revision = release.policy_revision
                WHERE release.workspace_id = scoped_workspace
                  AND release.network_id = scoped_network
                  AND release.state = 'active'
                  AND release.policy_revision = base.policy_revision
                  AND rule.source_device_id = v_source_id
                  AND rule.imported_resource_id = v_imported_id
                  AND rule.imported_resource_version = v_imported_version
                  AND rule.trust_contract_id = v_contract_id
                  AND rule.trust_contract_version = v_contract_version
                  AND rule.contract_expires_at = v_contract_expires_at
                  AND rule.protocol = p_protocol
                  AND (
                    (p_protocol = 'icmp' AND pg_catalog.isempty(rule.destination_ports))
                    OR rule.destination_ports @> p_destination_port
                  )
                ORDER BY rule.access_rule_public_id, rule.public_id
                LIMIT p_path_limit
            ) AS path;
        END IF;
    END IF;

    RETURN QUERY SELECT
        base.network_revision,
        base.inventory_revision,
        base.group_revision,
        base.policy_revision,
        base.dns_revision,
        base.route_revision,
        base.sharing_revision,
        base.isolation_generation,
        base.has_active_release,
        base.release_public_id,
        base.compiler_format_version,
        base.release_semantic_hash,
        CASE WHEN target_kind = 'imported_resource' THEN NULL::UUID ELSE base.target_device_public_id END,
        effective_paths,
        pg_catalog.jsonb_build_object(
            'source', pg_catalog.jsonb_build_object('state', source_state, 'name', source_name),
            'target', pg_catalog.jsonb_build_object('kind', target_kind, 'state', target_state, 'name', target_name),
            'share', share_context
        );
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.explain_active_policy_v3(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID, UUID, TEXT, INTEGER, TIMESTAMPTZ, INTEGER
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.explain_active_policy_v3(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID, UUID, TEXT, INTEGER, TIMESTAMPTZ, INTEGER
) TO mesh_runtime;
