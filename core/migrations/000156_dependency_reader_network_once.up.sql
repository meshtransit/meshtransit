-- Schema 156: the dependency reader proves each remote Network once.
--
-- load_device_sharing_dependencies_v5 returns one dependency per Network on
-- the other side of the Device's live contracts, and proves every contract
-- against its full authority (offer, export, Imported Resource, Resource,
-- target, Networks, Deployment, rule) before counting it. A Device receiving
-- 3,000 shares from one Network proved 3,000 contracts to return one row:
-- 0.31 s of each of its map reads.
--
-- v6 is v5 verbatim except that, the contracts coming ordered by the other
-- side's Network, it skips the proof of a contract whose Network already
-- produced a dependency. That contract could only have produced the same
-- row, which v5 drops as a duplicate, so v6 returns exactly v5's rows, and
-- counts contracts against p_limit as v5 does. The operator step hands it to
-- mesh_device_alias_map_reader as for v5, which stays executable so the
-- previous image can roll back.

CREATE FUNCTION mesh_ops.load_device_sharing_dependencies_v6(
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
    last_network UUID;
    last_network_id BIGINT;
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
        OR p_limit IS NULL OR p_limit < 1 OR p_limit > 10000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid sharing dependency request';
    END IF;
    self_id := mesh_ops.authenticate_map_share_device_v1(
        p_machine_key_fingerprint, p_node_key, self_workspace, self_network);
    IF self_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'sharing dependency authority unavailable';
    END IF;

    FOR contract_row IN
      SELECT shared.* FROM (
        -- Receiving: count only contracts this consumer Device sources a rule
        -- to, so contracts into the Network for other Devices do not reach
        -- the contract limit for it. Found from its own rules.
        SELECT contract.* FROM (
          SELECT DISTINCT loop_rule.trust_contract_id
          FROM mesh_ops.network_revision AS loop_revision
          JOIN mesh.policy_release AS loop_release ON loop_release.workspace_id=loop_revision.workspace_id
           AND loop_release.network_id=loop_revision.network_id
           AND loop_release.policy_revision=loop_revision.policy_revision AND loop_release.state='active'
          JOIN mesh.compiled_policy_imported_resource_destination AS loop_rule
            ON loop_rule.workspace_id=loop_release.workspace_id AND loop_rule.network_id=loop_release.network_id
           AND loop_rule.policy_release_id=loop_release.id AND loop_rule.source_device_id=self_id
          WHERE loop_revision.workspace_id=self_workspace AND loop_revision.network_id=self_network
        ) AS reachable
        JOIN mesh.trust_contract AS contract ON contract.id=reachable.trust_contract_id
        WHERE contract.consumer_workspace_id=self_workspace AND contract.consumer_network_id=self_network
          AND contract.state IN ('activating','active') AND contract.expires_at>transaction_timestamp()
        UNION ALL
        -- Providing: the contracts on the Resource this Device is the active
        -- target of. A contract never has both sides in one Network, so the
        -- two parts are disjoint.
        SELECT contract.* FROM mesh.resource_device_target AS target
        JOIN mesh.trust_contract AS contract
          ON contract.provider_workspace_id=self_workspace AND contract.provider_network_id=self_network
         AND contract.resource_id=target.resource_id AND contract.target_generation=target.target_generation
        WHERE target.workspace_id=self_workspace AND target.network_id=self_network
          AND target.device_id=self_id AND target.state='active'
          AND contract.state IN ('activating','active') AND contract.expires_at>transaction_timestamp()
      ) AS shared
      -- Ordered by the other side's Network, so equal dependencies are
      -- adjacent and deduplicated in O(1); past p_limit contracts the last row
      -- is {"limited":true} instead of an error.
      ORDER BY CASE WHEN shared.provider_network_id=self_network
        THEN shared.consumer_network_id ELSE shared.provider_network_id END, shared.id
      LIMIT p_limit + 1
    LOOP
      contract_count:=contract_count+1;
      IF contract_count>p_limit THEN
        RETURN NEXT '{"limited":true}'::JSONB;
        EXIT;
      END IF;
      -- Contracts come ordered by the other side's Network: once one proved
      -- a dependency on that Network, the rest of its contracts add nothing.
      IF last_network_id = (CASE WHEN contract_row.provider_network_id=self_network
          THEN contract_row.consumer_network_id ELSE contract_row.provider_network_id END) THEN
        CONTINUE;
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
      -- At most one row per contract, and contracts are bounded above.
      IF FOUND AND remote_network IS DISTINCT FROM last_network THEN
        RETURN NEXT jsonb_build_object('workspace_id',remote_workspace,'network_id',remote_network);
        last_network:=remote_network;
        last_network_id:=CASE WHEN contract_row.provider_network_id=self_network
          THEN contract_row.consumer_network_id ELSE contract_row.provider_network_id END;
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
REVOKE ALL ON FUNCTION mesh_ops.load_device_sharing_dependencies_v6(BYTEA,BYTEA,INTEGER)
  FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_audit_writer,mesh_share_writer,mesh_direct_map_reader;
