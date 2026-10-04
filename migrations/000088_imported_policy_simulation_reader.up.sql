-- Reconstruct immutable Imported intent under its stored bilateral scope.
-- The public baseline entry point still authorizes the Account session and
-- Consumer Network before selecting any projection for this private reader.
GRANT SELECT ON mesh.compiled_policy_imported_resource_destination TO mesh_share_writer;
CREATE POLICY compiled_policy_imported_destination_reader_policy
ON mesh.compiled_policy_imported_resource_destination
FOR SELECT TO mesh_share_writer
USING (
    workspace_id = mesh_ops.current_workspace_id()
    AND network_id = mesh_ops.current_network_id()
);

CREATE FUNCTION mesh_ops.read_compiled_imported_policy_evidence_internal_v1(
    p_projection_id BIGINT
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    provenance mesh.compiled_policy_imported_resource_destination%ROWTYPE;
    payload JSONB;
    previous_provider_workspace TEXT;
    previous_provider_network TEXT;
    previous_consumer_workspace TEXT;
    previous_consumer_network TEXT;
BEGIN
    SELECT value.* INTO provenance
    FROM mesh.compiled_policy_imported_resource_destination AS value
    WHERE value.id = p_projection_id
      AND value.workspace_id = mesh_ops.current_workspace_id()
      AND value.network_id = mesh_ops.current_network_id();
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Imported policy baseline is unavailable';
    END IF;

    previous_provider_workspace := pg_catalog.current_setting('mesh.share_provider_workspace_id', TRUE);
    previous_provider_network := pg_catalog.current_setting('mesh.share_provider_network_id', TRUE);
    previous_consumer_workspace := pg_catalog.current_setting('mesh.share_consumer_workspace_id', TRUE);
    previous_consumer_network := pg_catalog.current_setting('mesh.share_consumer_network_id', TRUE);
    BEGIN
        PERFORM mesh_ops.set_share_scope_v1(
            provenance.provider_workspace_id, provenance.provider_network_id,
            provenance.workspace_id, provenance.network_id
        );
        SELECT pg_catalog.jsonb_build_object(
            'destination_imported_resource_version', provenance.imported_resource_version,
            'destination_trust_contract_public_id', contract.public_id,
            'destination_trust_contract_version', provenance.trust_contract_version,
            'destination_share_offer_public_id', offer.public_id,
            'destination_resource_export_public_id', export.public_id,
            'destination_resource_export_version', provenance.resource_export_version,
            'destination_provider_workspace_public_id', provider_workspace.public_id,
            'destination_provider_network_public_id', provider_network.public_id,
            'destination_provider_resource_public_id', resource.public_id,
            'destination_provider_resource_version', provenance.resource_version,
            'destination_provider_target_generation', provenance.target_generation,
            'destination_provider_resource_semantic_hash', pg_catalog.encode(provenance.resource_semantic_hash, 'hex'),
            'destination_provider_inventory_revision', provenance.provider_inventory_revision,
            'destination_provider_sharing_revision', provenance.provider_sharing_revision,
            'destination_consumer_sharing_revision', provenance.consumer_sharing_revision,
            'destination_provider_authority_generation', provenance.provider_authority_generation,
            'destination_consumer_authority_generation', provenance.consumer_authority_generation,
            'destination_recovery_epoch', provenance.recovery_epoch,
            'destination_contract_expires_at', provenance.contract_expires_at,
            'destination_constraint_hash', pg_catalog.encode(provenance.constraint_hash, 'hex'),
            'destination_authority_evaluated_at', provenance.created_at,
            'destination_contract_constraints', COALESCE((
                SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
                    'protocol', constraint_row.protocol,
                    'ranges', COALESCE((
                        SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_array(
                            pg_catalog.lower(port_range), pg_catalog.upper(port_range) - 1
                        ) ORDER BY pg_catalog.lower(port_range), pg_catalog.upper(port_range))
                        FROM pg_catalog.unnest(constraint_row.destination_ports) AS port_range
                    ), '[]'::JSONB)
                ) ORDER BY constraint_row.protocol)
                FROM mesh.resource_export_constraint AS constraint_row
                WHERE constraint_row.resource_export_id = provenance.resource_export_id
                  AND constraint_row.provider_workspace_id = provenance.provider_workspace_id
                  AND constraint_row.provider_network_id = provenance.provider_network_id
                  AND constraint_row.consumer_workspace_id = provenance.workspace_id
                  AND constraint_row.consumer_network_id = provenance.network_id
            ), '[]'::JSONB)
        ) INTO payload
        FROM mesh.trust_contract AS contract
        JOIN mesh.share_offer AS offer
          ON offer.id = contract.share_offer_id
         AND offer.provider_workspace_id = provenance.provider_workspace_id
         AND offer.provider_network_id = provenance.provider_network_id
         AND offer.consumer_workspace_id = provenance.workspace_id
         AND offer.consumer_network_id = provenance.network_id
        JOIN mesh.resource_export AS export
          ON export.id = provenance.resource_export_id
         AND export.id = contract.resource_export_id
         AND export.id = offer.resource_export_id
         AND export.provider_workspace_id = provenance.provider_workspace_id
         AND export.provider_network_id = provenance.provider_network_id
         AND export.consumer_workspace_id = provenance.workspace_id
         AND export.consumer_network_id = provenance.network_id
        JOIN mesh.workspace AS provider_workspace
          ON provider_workspace.id = provenance.provider_workspace_id
        JOIN mesh.network AS provider_network
          ON provider_network.workspace_id = provenance.provider_workspace_id
         AND provider_network.id = provenance.provider_network_id
        JOIN mesh.resource AS resource
          ON resource.workspace_id = provenance.provider_workspace_id
         AND resource.network_id = provenance.provider_network_id
         AND resource.id = provenance.destination_resource_id
         AND resource.id = contract.resource_id
         AND resource.id = export.resource_id
        JOIN mesh.imported_resource AS imported
          ON imported.workspace_id = provenance.workspace_id
         AND imported.network_id = provenance.network_id
         AND imported.id = provenance.imported_resource_id
         AND imported.trust_contract_id = contract.id
        WHERE contract.id = provenance.trust_contract_id
          AND contract.provider_workspace_id = provenance.provider_workspace_id
          AND contract.provider_network_id = provenance.provider_network_id
          AND contract.consumer_workspace_id = provenance.workspace_id
          AND contract.consumer_network_id = provenance.network_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Imported policy baseline is unavailable';
        END IF;
    EXCEPTION WHEN OTHERS THEN
        PERFORM pg_catalog.set_config('mesh.share_provider_workspace_id', COALESCE(previous_provider_workspace, ''), TRUE);
        PERFORM pg_catalog.set_config('mesh.share_provider_network_id', COALESCE(previous_provider_network, ''), TRUE);
        PERFORM pg_catalog.set_config('mesh.share_consumer_workspace_id', COALESCE(previous_consumer_workspace, ''), TRUE);
        PERFORM pg_catalog.set_config('mesh.share_consumer_network_id', COALESCE(previous_consumer_network, ''), TRUE);
        RAISE;
    END;
    PERFORM pg_catalog.set_config('mesh.share_provider_workspace_id', COALESCE(previous_provider_workspace, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.share_provider_network_id', COALESCE(previous_provider_network, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_workspace_id', COALESCE(previous_consumer_workspace, ''), TRUE);
    PERFORM pg_catalog.set_config('mesh.share_consumer_network_id', COALESCE(previous_consumer_network, ''), TRUE);
    RETURN payload;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.read_compiled_imported_policy_evidence_internal_v1(BIGINT)
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_compiled_imported_policy_evidence_internal_v1(BIGINT) TO mesh_migrator;

CREATE OR REPLACE FUNCTION mesh_ops.read_policy_simulation_baseline_v2(
    p_session_public_id UUID, p_deployment_public_id UUID,
    p_principal_public_id UUID, p_identity_subject_public_id UUID,
    p_session_version BIGINT, p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT, p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT, p_workspace_public_id UUID,
    p_network_public_id UUID, p_evaluated_at TIMESTAMPTZ, p_rule_limit INTEGER
)
RETURNS TABLE (
    network_revision BIGINT, inventory_revision BIGINT, group_revision BIGINT,
    policy_revision BIGINT, dns_revision BIGINT, route_revision BIGINT,
    sharing_revision BIGINT, isolation_generation BIGINT,
    has_active_release BOOLEAN, release_public_id UUID,
    compiler_format_version INTEGER, release_semantic_hash BYTEA, rules JSONB
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    baseline RECORD;
BEGIN
    SELECT value.* INTO baseline
    FROM mesh_ops.read_policy_simulation_baseline_v1(
        p_session_public_id, p_deployment_public_id,
        p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation,
        p_deployment_recovery_epoch, p_workspace_public_id,
        p_network_public_id, p_evaluated_at, p_rule_limit
    ) AS value;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Policy simulation baseline is unavailable';
    END IF;
    RETURN QUERY
    WITH local_rule AS (
        SELECT local_entry.value AS payload,
            local_entry.value->>'access_rule_public_id' AS access_rule_public_id,
            local_entry.value->>'source_node_public_id' AS source_node_public_id,
            COALESCE(local_entry.value->>'destination_node_public_id',
                local_entry.value->>'destination_imported_resource_public_id', '') AS destination_sort,
            local_entry.value->>'projection_public_id' AS projection_public_id
        FROM pg_catalog.jsonb_array_elements(baseline.rules) AS local_entry(value)
    ), selected_imported AS MATERIALIZED (
        SELECT provenance.*, source.public_id AS source_public_id,
            imported.public_id AS imported_public_id
        FROM mesh.policy_release AS release
        JOIN mesh.compiled_policy_imported_resource_destination AS provenance
          ON provenance.workspace_id = release.workspace_id
         AND provenance.network_id = release.network_id
         AND provenance.policy_release_id = release.id
         AND provenance.policy_revision = release.policy_revision
        JOIN mesh.device AS source
          ON source.workspace_id = provenance.workspace_id
         AND source.network_id = provenance.network_id
         AND source.id = provenance.source_device_id
        JOIN mesh.imported_resource AS imported
          ON imported.workspace_id = provenance.workspace_id
         AND imported.network_id = provenance.network_id
         AND imported.id = provenance.imported_resource_id
        WHERE release.workspace_id = mesh_ops.current_workspace_id()
          AND release.network_id = mesh_ops.current_network_id()
          AND release.public_id = baseline.release_public_id
          AND release.state = 'active'
        ORDER BY provenance.access_rule_public_id, source.public_id,
            imported.public_id, provenance.public_id
        LIMIT p_rule_limit
    ), imported_rule AS MATERIALIZED (
        SELECT pg_catalog.jsonb_build_object(
            'projection_public_id', provenance.public_id,
            'access_rule_public_id', provenance.access_rule_public_id,
            'source_node_public_id', provenance.source_public_id,
            'protocol', provenance.protocol,
            'port_range_first', ARRAY(
                SELECT pg_catalog.lower(port_range)::INTEGER
                FROM pg_catalog.unnest(provenance.destination_ports) AS port_range
                ORDER BY pg_catalog.lower(port_range), pg_catalog.upper(port_range)
            ),
            'port_range_last', ARRAY(
                SELECT (pg_catalog.upper(port_range) - 1)::INTEGER
                FROM pg_catalog.unnest(provenance.destination_ports) AS port_range
                ORDER BY pg_catalog.lower(port_range), pg_catalog.upper(port_range)
            ),
            'destination_imported_resource_public_id', provenance.imported_public_id
        ) || mesh_ops.read_compiled_imported_policy_evidence_internal_v1(provenance.id) AS payload,
            provenance.access_rule_public_id::TEXT AS access_rule_public_id,
            provenance.source_public_id::TEXT AS source_node_public_id,
            provenance.imported_public_id::TEXT AS destination_sort,
            provenance.public_id::TEXT AS projection_public_id
        FROM selected_imported AS provenance
    ), bounded_rule AS (
        SELECT combined.* FROM (
            SELECT * FROM local_rule UNION ALL SELECT * FROM imported_rule
        ) AS combined
        ORDER BY combined.access_rule_public_id, combined.source_node_public_id,
            combined.destination_sort, combined.projection_public_id
        LIMIT p_rule_limit
    )
    SELECT baseline.network_revision, baseline.inventory_revision,
        baseline.group_revision, baseline.policy_revision, baseline.dns_revision,
        baseline.route_revision, baseline.sharing_revision, baseline.isolation_generation,
        baseline.has_active_release, baseline.release_public_id,
        baseline.compiler_format_version, baseline.release_semantic_hash,
        COALESCE((SELECT pg_catalog.jsonb_agg(bounded.payload
            ORDER BY bounded.access_rule_public_id, bounded.source_node_public_id,
                bounded.destination_sort, bounded.projection_public_id)
            FROM bounded_rule AS bounded), '[]'::JSONB);
END;
$function$;
