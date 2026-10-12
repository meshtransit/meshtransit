-- Schema 146: share-dependent Devices instead of share-dependent Networks
-- (TD-CORE-18). Schema 145 sent every Device of a Network taking part in a
-- share to its own map read, which costs O(N^2) rows per revision in a large
-- Network. A share changes the maps of two kinds of Device only:
--   * on the provider side, the Device a contract targets (its consumers
--     become its peers);
--   * on the consumer side, a Device the active policy release names as the
--     source of a rule to an Imported Resource (it gets the shared Device as a
--     peer, its aliases and DNS records).
-- Every other Device keeps the shared Network view (scale-out S2b).
--
-- map_network_sharing_devices_v1 lists those Devices for the scoped Network,
-- a superset of the Devices with sharing projections: contracts count from
-- acceptance to expiry, before endpoints and aliases are ready.
--
-- load_device_sharing_dependencies_v2 is v1 (schema 84) with the consumer
-- side narrowed the same way: v1 gave every consumer Device a dependency on
-- the provider Network, so every Device of a consumer Network lost the shared
-- view for good. A consumer Device that becomes a rule source is woken by its
-- own Network's policy publication, so it needs no dependency before that.

CREATE INDEX compiled_policy_imported_destination_release_source_idx
    ON mesh.compiled_policy_imported_resource_destination (
        workspace_id, network_id, policy_release_id, source_device_id
    );

CREATE FUNCTION mesh_ops.map_network_sharing_devices_v1(p_limit INTEGER)
RETURNS TABLE (device_id BIGINT)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT := mesh_ops.current_workspace_id();
    scoped_network_id BIGINT := mesh_ops.current_network_id();
BEGIN
    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'map network sharing scope is unavailable';
    END IF;
    IF p_limit IS NULL OR p_limit < 1 OR p_limit > 1000001 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid map network sharing limit';
    END IF;

    RETURN QUERY
    SELECT sharing.device_id
    FROM (
        SELECT target.device_id
        FROM mesh.trust_contract AS contract
        JOIN mesh.resource_device_target AS target
          ON target.workspace_id = contract.provider_workspace_id
         AND target.network_id = contract.provider_network_id
         AND target.resource_id = contract.resource_id
         AND target.target_generation = contract.target_generation
         AND target.state = 'active'
        WHERE contract.provider_workspace_id = scoped_workspace_id
          AND contract.provider_network_id = scoped_network_id
          AND contract.state IN ('activating', 'active')
          AND contract.expires_at > pg_catalog.transaction_timestamp()
        UNION
        SELECT rule.source_device_id
        FROM mesh_ops.network_revision AS revision
        JOIN mesh.policy_release AS release
          ON release.workspace_id = revision.workspace_id
         AND release.network_id = revision.network_id
         AND release.policy_revision = revision.policy_revision
         AND release.state = 'active'
        JOIN mesh.compiled_policy_imported_resource_destination AS rule
          ON rule.workspace_id = release.workspace_id
         AND rule.network_id = release.network_id
         AND rule.policy_release_id = release.id
        JOIN mesh.trust_contract AS contract
          ON contract.id = rule.trust_contract_id
         AND contract.state IN ('activating', 'active')
         AND contract.expires_at > pg_catalog.transaction_timestamp()
        WHERE revision.workspace_id = scoped_workspace_id
          AND revision.network_id = scoped_network_id
    ) AS sharing
    ORDER BY sharing.device_id
    LIMIT p_limit;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.map_network_sharing_devices_v1(INTEGER) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.map_network_sharing_devices_v1(INTEGER)
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.map_network_sharing_devices_v1(INTEGER) TO mesh_runtime;

-- Same body as v1 except the consumer-side condition; the operator step
-- operator/000146 hands it to the alias map reader and exposes it.
CREATE FUNCTION mesh_ops.load_device_sharing_dependencies_v2(
    p_machine_key_fingerprint BYTEA,p_node_key BYTEA,p_limit INTEGER
) RETURNS SETOF JSONB
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path=pg_catalog,mesh,mesh_ops
AS $function$
DECLARE
    self_id BIGINT; self_workspace BIGINT; self_network BIGINT;
    previous_remote TEXT; previous_alias_provider_workspace TEXT;
    previous_alias_provider_network TEXT; previous_alias_consumer_workspace TEXT;
    previous_alias_consumer_network TEXT; previous_alias_endpoint TEXT;
    contract_row mesh.trust_contract%ROWTYPE;
    contract_count INTEGER:=0;
    remote_workspace UUID; remote_network UUID;
    seen_networks UUID[]:='{}';
BEGIN
    previous_remote := pg_catalog.current_setting('mesh.direct_map_remote_network_id', TRUE);
    -- Discard caller-controlled remote scope before authenticating self.
    PERFORM pg_catalog.set_config('mesh.direct_map_remote_network_id', '', TRUE);
    previous_alias_provider_workspace := current_setting('mesh.alias_map_provider_workspace_id',TRUE);
    PERFORM set_config('mesh.alias_map_provider_workspace_id','',TRUE);
    previous_alias_provider_network := current_setting('mesh.alias_map_provider_network_id',TRUE);
    PERFORM set_config('mesh.alias_map_provider_network_id','',TRUE);
    previous_alias_consumer_workspace := current_setting('mesh.alias_map_consumer_workspace_id',TRUE);
    PERFORM set_config('mesh.alias_map_consumer_workspace_id','',TRUE);
    previous_alias_consumer_network := current_setting('mesh.alias_map_consumer_network_id',TRUE);
    PERFORM set_config('mesh.alias_map_consumer_network_id','',TRUE);
    previous_alias_endpoint := current_setting('mesh.alias_map_endpoint_id',TRUE);
    PERFORM set_config('mesh.alias_map_endpoint_id','',TRUE);
    self_workspace := mesh_ops.current_workspace_id();
    self_network := mesh_ops.current_network_id();
    IF self_workspace IS NULL OR self_network IS NULL
        OR p_machine_key_fingerprint IS NULL OR pg_catalog.octet_length(p_machine_key_fingerprint) <> 32
        OR p_node_key IS NULL OR pg_catalog.octet_length(p_node_key) <> 32
        OR p_limit IS NULL OR p_limit < 1 OR p_limit > 257 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid sharing dependency request';
    END IF;
    SELECT device.id INTO self_id
    FROM mesh.device AS device
    JOIN mesh.device_machine_key_epoch AS machine
      ON machine.workspace_id = device.workspace_id AND machine.network_id = device.network_id
     AND machine.device_id = device.id AND machine.epoch = device.current_machine_key_epoch
     AND machine.state = 'active' AND machine.valid_from <= pg_catalog.transaction_timestamp()
    JOIN mesh.device_node_key_epoch AS node_key
      ON node_key.workspace_id = device.workspace_id AND node_key.network_id = device.network_id
     AND node_key.device_id = device.id AND node_key.epoch = device.current_node_key_epoch
     AND node_key.state = 'active' AND node_key.valid_from <= pg_catalog.transaction_timestamp()
    JOIN mesh.workspace AS workspace ON workspace.id = device.workspace_id
    JOIN mesh.network AS network ON network.workspace_id = workspace.id AND network.id = device.network_id
    JOIN mesh.deployment AS deployment ON deployment.id = workspace.deployment_id
    JOIN mesh.principal AS owner ON owner.id = device.owner_principal_id AND owner.deployment_id = deployment.id
    WHERE device.workspace_id = self_workspace AND device.network_id = self_network
      AND machine.fingerprint = p_machine_key_fingerprint AND node_key.public_key = p_node_key
      AND device.state = 'active' AND device.deleted_at IS NULL
      AND device.created_at <= pg_catalog.transaction_timestamp()
      AND device.expires_at > pg_catalog.transaction_timestamp()
      AND workspace.state = 'active' AND workspace.deleted_at IS NULL
      AND network.state = 'active' AND network.deleted_at IS NULL
      AND deployment.state = 'active' AND deployment.recovery_state = 'verified' AND deployment.deleted_at IS NULL
      AND owner.state = 'active' AND owner.deleted_at IS NULL;
    IF self_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'sharing dependency authority unavailable';
    END IF;

    FOR contract_row IN
      SELECT contract.* FROM mesh.trust_contract AS contract
      WHERE contract.state IN ('activating','active') AND contract.expires_at>transaction_timestamp()
        AND ((contract.consumer_workspace_id=self_workspace AND contract.consumer_network_id=self_network)
          OR (contract.provider_workspace_id=self_workspace AND contract.provider_network_id=self_network
            AND EXISTS(SELECT 1 FROM mesh.resource_device_target AS target
              WHERE target.workspace_id=self_workspace AND target.network_id=self_network
                AND target.resource_id=contract.resource_id AND target.target_generation=contract.target_generation
                AND target.device_id=self_id AND target.state='active')))
      ORDER BY contract.id LIMIT 257
    LOOP
      contract_count:=contract_count+1;
      IF contract_count>256 THEN
        RAISE EXCEPTION USING ERRCODE='54000',MESSAGE='sharing dependency contract limit exceeded';
      END IF;
      PERFORM set_config('mesh.alias_map_provider_workspace_id',contract_row.provider_workspace_id::TEXT,TRUE);
      PERFORM set_config('mesh.alias_map_provider_network_id',contract_row.provider_network_id::TEXT,TRUE);
      PERFORM set_config('mesh.alias_map_consumer_workspace_id',contract_row.consumer_workspace_id::TEXT,TRUE);
      PERFORM set_config('mesh.alias_map_consumer_network_id',contract_row.consumer_network_id::TEXT,TRUE);
      SELECT CASE WHEN self_network=provider_network.id THEN consumer_workspace.public_id ELSE provider_workspace.public_id END,
             CASE WHEN self_network=provider_network.id THEN consumer_network.public_id ELSE provider_network.public_id END
        INTO remote_workspace,remote_network
      FROM mesh.workspace AS provider_workspace JOIN mesh.workspace AS consumer_workspace
        ON consumer_workspace.deployment_id=provider_workspace.deployment_id
      JOIN mesh.deployment AS deployment ON deployment.id=provider_workspace.deployment_id
      JOIN mesh.network AS provider_network ON provider_network.workspace_id=provider_workspace.id
      JOIN mesh.network AS consumer_network ON consumer_network.workspace_id=consumer_workspace.id
      JOIN mesh.share_offer AS offer ON offer.id=contract_row.share_offer_id AND offer.state='accepted'
        AND offer.accepted_contract_public_id=contract_row.public_id
      JOIN mesh.resource_export AS export ON export.id=contract_row.resource_export_id AND export.state='active'
        AND export.resource_id=contract_row.resource_id AND export.resource_version=contract_row.resource_version
        AND export.target_generation=contract_row.target_generation AND export.resource_semantic_hash=contract_row.resource_semantic_hash
        AND export.constraint_hash=contract_row.constraint_hash AND export.expires_at>=contract_row.expires_at
        AND (export.provider_workspace_id,export.provider_network_id,export.consumer_workspace_id,export.consumer_network_id)=
            (contract_row.provider_workspace_id,contract_row.provider_network_id,contract_row.consumer_workspace_id,contract_row.consumer_network_id)
      JOIN mesh.imported_resource AS imported ON imported.trust_contract_id=contract_row.id
        AND imported.public_id=contract_row.imported_resource_public_id AND imported.deployment_id=contract_row.deployment_id
        AND imported.workspace_id=consumer_workspace.id AND imported.network_id=consumer_network.id
        AND imported.state IN ('activating','active')
      JOIN mesh.resource AS resource ON resource.id=contract_row.resource_id AND resource.kind='device' AND resource.state='active'
        AND resource.deleted_at IS NULL AND resource.workspace_id=provider_workspace.id AND resource.network_id=provider_network.id
        AND resource.version=contract_row.resource_version AND resource.target_generation=contract_row.target_generation
        AND resource.semantic_hash=contract_row.resource_semantic_hash
      JOIN mesh.resource_device_target AS target ON target.resource_id=resource.id AND target.target_generation=resource.target_generation
        AND target.workspace_id=resource.workspace_id AND target.network_id=resource.network_id AND target.state='active'
      WHERE provider_workspace.id=contract_row.provider_workspace_id AND consumer_workspace.id=contract_row.consumer_workspace_id
        AND provider_network.id=contract_row.provider_network_id AND consumer_network.id=contract_row.consumer_network_id
        AND provider_workspace.state='active' AND provider_workspace.deleted_at IS NULL
        AND consumer_workspace.state='active' AND consumer_workspace.deleted_at IS NULL
        AND provider_network.state='active' AND provider_network.deleted_at IS NULL
        AND consumer_network.state='active' AND consumer_network.deleted_at IS NULL
        AND provider_network.authority_generation=contract_row.provider_authority_generation
        AND consumer_network.authority_generation=contract_row.consumer_authority_generation
        AND export.provider_authority_generation=provider_network.authority_generation
        AND deployment.id=contract_row.deployment_id AND deployment.state='active' AND deployment.deleted_at IS NULL
        AND deployment.recovery_state='verified' AND deployment.recovery_epoch=contract_row.recovery_epoch
        AND ((self_network=consumer_network.id AND EXISTS(
              SELECT 1 FROM mesh_ops.network_revision AS consumer_revision
              JOIN mesh.policy_release AS release ON release.workspace_id=consumer_revision.workspace_id
               AND release.network_id=consumer_revision.network_id
               AND release.policy_revision=consumer_revision.policy_revision AND release.state='active'
              JOIN mesh.compiled_policy_imported_resource_destination AS rule
                ON rule.workspace_id=release.workspace_id AND rule.network_id=release.network_id
               AND rule.policy_release_id=release.id AND rule.trust_contract_id=contract_row.id
               AND rule.source_device_id=self_id
              WHERE consumer_revision.workspace_id=consumer_network.workspace_id
                AND consumer_revision.network_id=consumer_network.id))
          OR target.device_id=self_id);
      IF FOUND AND NOT remote_network=ANY(seen_networks) THEN
        RETURN NEXT jsonb_build_object('workspace_id',remote_workspace,'network_id',remote_network);
        seen_networks:=array_append(seen_networks,remote_network);
        IF cardinality(seen_networks)>=p_limit THEN
    PERFORM set_config('mesh.alias_map_provider_workspace_id',COALESCE(previous_alias_provider_workspace,''),TRUE);
    PERFORM set_config('mesh.alias_map_provider_network_id',COALESCE(previous_alias_provider_network,''),TRUE);
    PERFORM set_config('mesh.alias_map_consumer_workspace_id',COALESCE(previous_alias_consumer_workspace,''),TRUE);
    PERFORM set_config('mesh.alias_map_consumer_network_id',COALESCE(previous_alias_consumer_network,''),TRUE);
    PERFORM set_config('mesh.alias_map_endpoint_id',COALESCE(previous_alias_endpoint,''),TRUE);
    PERFORM set_config('mesh.direct_map_remote_network_id',COALESCE(previous_remote,''),TRUE);
          RETURN;
        END IF;
      END IF;
    END LOOP;
    PERFORM set_config('mesh.alias_map_provider_workspace_id',COALESCE(previous_alias_provider_workspace,''),TRUE);
    PERFORM set_config('mesh.alias_map_provider_network_id',COALESCE(previous_alias_provider_network,''),TRUE);
    PERFORM set_config('mesh.alias_map_consumer_workspace_id',COALESCE(previous_alias_consumer_workspace,''),TRUE);
    PERFORM set_config('mesh.alias_map_consumer_network_id',COALESCE(previous_alias_consumer_network,''),TRUE);
    PERFORM set_config('mesh.alias_map_endpoint_id',COALESCE(previous_alias_endpoint,''),TRUE);
    PERFORM set_config('mesh.direct_map_remote_network_id',COALESCE(previous_remote,''),TRUE);
    RETURN;
EXCEPTION WHEN OTHERS THEN
    PERFORM set_config('mesh.alias_map_provider_workspace_id',COALESCE(previous_alias_provider_workspace,''),TRUE);
    PERFORM set_config('mesh.alias_map_provider_network_id',COALESCE(previous_alias_provider_network,''),TRUE);
    PERFORM set_config('mesh.alias_map_consumer_workspace_id',COALESCE(previous_alias_consumer_workspace,''),TRUE);
    PERFORM set_config('mesh.alias_map_consumer_network_id',COALESCE(previous_alias_consumer_network,''),TRUE);
    PERFORM set_config('mesh.alias_map_endpoint_id',COALESCE(previous_alias_endpoint,''),TRUE);
    PERFORM set_config('mesh.direct_map_remote_network_id',COALESCE(previous_remote,''),TRUE);
    RAISE;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.load_device_sharing_dependencies_v2(BYTEA,BYTEA,INTEGER)
  FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer,mesh_direct_map_reader;
