-- The connection log receiver's reads (connection logs design §16c, s4c1b):
-- Networks that have a destination, one Network's destination, and the
-- machine keys that stopped being valid. The functions belong to
-- mesh_flowlog_reader (operator steps 268), which reads only the Networks
-- and Workspaces that have a connection log destination: a Network that
-- never set one is invisible to it (C39, review H7). Only the operator step
-- lets the runtime role execute them: before it they are not callable, so
-- the receiver gets an error, never an empty answer it would take as "not
-- logging" (review s4c1b H3).
--
-- The policies compare the guarded row's own columns with a sub-select's
-- output columns (row IN (SELECT …)): inside an EXISTS, an unqualified name
-- would bind to the sub-select's table and match every row (review s4c1b
-- H1).

GRANT USAGE ON SCHEMA mesh TO mesh_flowlog_reader;

CREATE POLICY network_connection_log_flowlog_read ON mesh.network_connection_log
    FOR SELECT TO mesh_flowlog_reader USING (TRUE);
GRANT SELECT ON mesh.network_connection_log TO mesh_flowlog_reader;
CREATE POLICY storage_credential_flowlog_read ON mesh.storage_credential
    FOR SELECT TO mesh_flowlog_reader
    USING ((workspace_id, id) IN (SELECT logged.workspace_id, logged.credential_id
                                  FROM mesh.network_connection_log AS logged));
GRANT SELECT ON mesh.storage_credential TO mesh_flowlog_reader;
CREATE POLICY workspace_feature_flowlog_read ON mesh.workspace_feature
    FOR SELECT TO mesh_flowlog_reader
    USING (workspace_id IN (SELECT logged.workspace_id FROM mesh.network_connection_log AS logged));
GRANT SELECT ON mesh.workspace_feature TO mesh_flowlog_reader;
CREATE POLICY workspace_flowlog_read ON mesh.workspace
    FOR SELECT TO mesh_flowlog_reader
    USING (id IN (SELECT logged.workspace_id FROM mesh.network_connection_log AS logged));
GRANT SELECT ON mesh.workspace TO mesh_flowlog_reader;
CREATE POLICY network_flowlog_read ON mesh.network
    FOR SELECT TO mesh_flowlog_reader
    USING ((workspace_id, id) IN (SELECT logged.workspace_id, logged.network_id
                                  FROM mesh.network_connection_log AS logged));
GRANT SELECT ON mesh.network TO mesh_flowlog_reader;
CREATE POLICY device_flowlog_read ON mesh.device
    FOR SELECT TO mesh_flowlog_reader
    USING ((workspace_id, network_id) IN (SELECT logged.workspace_id, logged.network_id
                                          FROM mesh.network_connection_log AS logged));
GRANT SELECT ON mesh.device TO mesh_flowlog_reader;
CREATE POLICY device_machine_key_epoch_flowlog_read ON mesh.device_machine_key_epoch
    FOR SELECT TO mesh_flowlog_reader
    USING ((workspace_id, network_id) IN (SELECT logged.workspace_id, logged.network_id
                                          FROM mesh.network_connection_log AS logged));
GRANT SELECT ON mesh.device_machine_key_epoch TO mesh_flowlog_reader;

-- The revocation read finds what changed in the window by index, as relay
-- revocations do (schema 135).
CREATE INDEX device_machine_key_epoch_ended_idx
    ON mesh.device_machine_key_epoch (updated_at)
    WHERE state <> 'active';
CREATE INDEX device_deleted_changed_idx
    ON mesh.device (updated_at)
    WHERE deleted_at IS NOT NULL;

-- Networks with a destination whose Workspace has the feature, by public ID
-- after p_after (C47, review v2-M5). enabled: they take batches now.
CREATE FUNCTION mesh_ops.flowlog_networks_v1(p_after UUID, p_limit INTEGER)
RETURNS TABLE (
    workspace_public_id UUID, network_public_id UUID, enabled BOOLEAN, settings_version BIGINT,
    credential_public_id UUID, sealed_version BIGINT, sealing_key_id TEXT, expected_bucket_owner TEXT
)
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    -- An empty page reads as a complete scan: a bad limit is an error.
    IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 5000 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid connection log Network page';
    END IF;
    RETURN QUERY
    SELECT workspace.public_id, settings.public_id,
        settings.enabled AND network.state = 'active' AND workspace.state = 'active',
        settings.version, credential.public_id, credential.sealed_version, credential.sealing_key_id,
        settings.expected_bucket_owner
    FROM mesh.network_connection_log AS settings
    JOIN mesh.network AS network ON network.workspace_id = settings.workspace_id AND network.id = settings.network_id
    JOIN mesh.workspace AS workspace ON workspace.id = settings.workspace_id
    JOIN mesh.storage_credential AS credential
      ON credential.workspace_id = settings.workspace_id AND credential.id = settings.credential_id
    WHERE (p_after IS NULL OR settings.public_id > p_after)
      AND network.state <> 'deleted' AND network.deleted_at IS NULL
      AND workspace.state <> 'deleted' AND workspace.deleted_at IS NULL
      AND EXISTS (SELECT 1 FROM mesh.workspace_feature AS feature
                  WHERE feature.workspace_id = settings.workspace_id AND feature.feature = 'connection_logs')
    ORDER BY settings.public_id
    LIMIT p_limit;
END;
$function$;

-- One Network's destination for the exact (Workspace, Network) pair, and
-- why it does or does not take batches (C44). No row: no such Network, or
-- no destination. A deleted Network or Workspace carries no credential.
CREATE FUNCTION mesh_ops.flowlog_destination_v1(p_workspace_public_id UUID, p_network_public_id UUID)
RETURNS TABLE (
    reason TEXT, forwarded BOOLEAN, window_s INTEGER, bucket TEXT, region TEXT, prefix TEXT,
    expected_bucket_owner TEXT, settings_version BIGINT, credential_public_id UUID, provider TEXT, account_id TEXT, sealed BYTEA,
    sealed_version BIGINT, sealing_key_id TEXT
)
LANGUAGE sql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    WITH found AS (
        SELECT settings, credential,
            CASE
                WHEN workspace.state = 'deleted' OR workspace.deleted_at IS NOT NULL THEN 'workspace_deleted'
                WHEN network.state = 'deleted' OR network.deleted_at IS NOT NULL THEN 'network_deleted'
                WHEN workspace.state = 'suspended' THEN 'workspace_suspended'
                WHEN network.state = 'suspended' THEN 'network_suspended'
                WHEN NOT settings.enabled THEN 'disabled'
                WHEN NOT EXISTS (SELECT 1 FROM mesh.workspace_feature AS feature
                                 WHERE feature.workspace_id = settings.workspace_id
                                   AND feature.feature = 'connection_logs') THEN 'feature_revoked'
                ELSE 'logging'
            END AS reason
        FROM mesh.network_connection_log AS settings
        JOIN mesh.network AS network ON network.workspace_id = settings.workspace_id AND network.id = settings.network_id
        JOIN mesh.workspace AS workspace ON workspace.id = settings.workspace_id
        JOIN mesh.storage_credential AS credential
          ON credential.workspace_id = settings.workspace_id AND credential.id = settings.credential_id
        WHERE settings.public_id = p_network_public_id AND workspace.public_id = p_workspace_public_id
    )
    SELECT found.reason, (found.settings).forwarded, (found.settings).window_s, (found.settings).bucket,
        (found.settings).region, (found.settings).prefix, (found.settings).expected_bucket_owner,
        (found.settings).version,
        CASE WHEN found.reason IN ('network_deleted', 'workspace_deleted') THEN NULL ELSE (found.credential).public_id END,
        CASE WHEN found.reason IN ('network_deleted', 'workspace_deleted') THEN NULL ELSE (found.credential).provider END,
        CASE WHEN found.reason IN ('network_deleted', 'workspace_deleted') THEN NULL ELSE (found.credential).account_id END,
        CASE WHEN found.reason IN ('network_deleted', 'workspace_deleted') THEN NULL ELSE (found.credential).sealed END,
        CASE WHEN found.reason IN ('network_deleted', 'workspace_deleted') THEN NULL ELSE (found.credential).sealed_version END,
        CASE WHEN found.reason IN ('network_deleted', 'workspace_deleted') THEN NULL ELSE (found.credential).sealing_key_id END
    FROM found
$function$;

-- Machine keys that stopped being valid since p_since (at most an hour
-- back), by Network, Device and key (C46, review v2-M3): keys of ended
-- epochs, and the current key of a Device no longer active. An exact pair
-- of a live Device and its live current key is never listed. At most
-- 100 001 rows, in order: more than 100 000 is an error for the reader, which
-- fails closed (review s4c1b H2).
CREATE FUNCTION mesh_ops.flowlog_revocations_v1(p_since TIMESTAMPTZ)
RETURNS TABLE (network_public_id UUID, device_public_id UUID, machine_key BYTEA)
LANGUAGE plpgsql
STABLE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_since IS NULL OR p_since > v_now OR p_since < v_now - INTERVAL '1 hour' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid connection log revocation window';
    END IF;
    RETURN QUERY
    WITH ended AS (
        SELECT epoch.workspace_id, epoch.network_id, epoch.device_id, epoch.public_key
        FROM mesh.device_machine_key_epoch AS epoch
        WHERE epoch.state <> 'active' AND epoch.updated_at >= p_since
        UNION
        SELECT device.workspace_id, device.network_id, device.id, current_key.public_key
        FROM mesh.device AS device
        JOIN mesh.device_machine_key_epoch AS current_key
          ON current_key.workspace_id = device.workspace_id AND current_key.network_id = device.network_id
         AND current_key.device_id = device.id AND current_key.epoch = device.current_machine_key_epoch
        WHERE device.state <> 'active' AND device.updated_at >= p_since
        UNION
        SELECT device.workspace_id, device.network_id, device.id, current_key.public_key
        FROM mesh.device AS device
        JOIN mesh.device_machine_key_epoch AS current_key
          ON current_key.workspace_id = device.workspace_id AND current_key.network_id = device.network_id
         AND current_key.device_id = device.id AND current_key.epoch = device.current_machine_key_epoch
        WHERE device.deleted_at IS NOT NULL AND device.updated_at >= p_since
    )
    SELECT settings.public_id, device.public_id, ended.public_key
    FROM ended
    JOIN mesh.network_connection_log AS settings
      ON settings.workspace_id = ended.workspace_id AND settings.network_id = ended.network_id
    JOIN mesh.device AS device
      ON device.workspace_id = ended.workspace_id AND device.network_id = ended.network_id AND device.id = ended.device_id
    WHERE NOT (
        device.state = 'active' AND device.deleted_at IS NULL AND EXISTS (
            SELECT 1 FROM mesh.device_machine_key_epoch AS live
            WHERE live.workspace_id = device.workspace_id AND live.network_id = device.network_id
              AND live.device_id = device.id AND live.epoch = device.current_machine_key_epoch
              AND live.state = 'active' AND live.public_key = ended.public_key))
    ORDER BY settings.public_id, device.public_id, ended.public_key
    LIMIT 100001;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.flowlog_networks_v1(UUID, INTEGER), mesh_ops.flowlog_destination_v1(UUID, UUID),
    mesh_ops.flowlog_revocations_v1(TIMESTAMPTZ)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
