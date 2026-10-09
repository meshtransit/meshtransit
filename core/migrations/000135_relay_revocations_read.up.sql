-- Schema 135: what Interchange relays must stop honouring (MTRP v1 §9).
--
-- Core signs a relay state every 10 seconds. Relay tickets live at most 15
-- minutes, so the state needs only what ended within that window (plus clock
-- skew); the caller passes the window start, bounded here to one hour.
--
-- Returns one row per revoked value:
--   'node'           node public key (32 bytes) of a key epoch that ended by
--                    rotation, expiry or revocation, and the current key of a
--                    Device that is suspended, revoked, expired or deleted.
--                    A key that is the current key of an active Device is
--                    never listed: a Device resumed within the window, or one
--                    that registered again with the same node key, keeps
--                    getting its fresh tickets accepted.
--   'trust_contract' Trust Contract public ID (16 bytes) that ended (revoked,
--                    invalidated, expired) or passed its expiry. Relays then
--                    close routes that relied on that contract's zone.
-- Keys and IDs are public material; relays receive only their hashes.

CREATE INDEX device_node_key_epoch_ended_idx
    ON mesh.device_node_key_epoch (updated_at)
    WHERE state <> 'active';
CREATE INDEX device_inactive_changed_idx
    ON mesh.device (updated_at)
    WHERE state <> 'active';
CREATE INDEX trust_contract_ended_idx
    ON mesh.trust_contract (ended_at)
    WHERE ended_at IS NOT NULL;
-- Open contracts past expiry use trust_contract_open_expiry_idx (schema 112).

CREATE FUNCTION mesh_ops.relay_revocations_v1(p_since TIMESTAMPTZ)
RETURNS TABLE (kind TEXT, value BYTEA)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_since IS NULL OR p_since > v_now OR p_since < v_now - INTERVAL '1 hour' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid relay revocation window';
    END IF;
    RETURN QUERY
    WITH revoked AS (
    SELECT 'node'::TEXT AS kind, ended.public_key AS value
    FROM mesh.device_node_key_epoch AS ended
    WHERE ended.state <> 'active'
      AND ended.updated_at >= p_since
    UNION
    SELECT 'node'::TEXT, current_key.public_key
    FROM mesh.device AS device
    JOIN mesh.device_node_key_epoch AS current_key
      ON current_key.workspace_id = device.workspace_id
     AND current_key.network_id = device.network_id
     AND current_key.device_id = device.id
     AND current_key.epoch = device.current_node_key_epoch
    WHERE device.state <> 'active'
      AND device.updated_at >= p_since
    UNION
    SELECT 'trust_contract'::TEXT, pg_catalog.uuid_send(contract.public_id)
    FROM mesh.trust_contract AS contract
    WHERE contract.ended_at IS NOT NULL
      AND contract.ended_at >= p_since
    UNION
    SELECT 'trust_contract'::TEXT, pg_catalog.uuid_send(contract.public_id)
    FROM mesh.trust_contract AS contract
    WHERE contract.state IN ('activating', 'active')
      AND contract.expires_at >= p_since
      AND contract.expires_at <= v_now
    )
    SELECT revoked.kind, revoked.value
    FROM revoked
    -- A key that ended in one epoch can be current again (re-registration
    -- or renewal with the same node key): never revoke a live Device's key.
    WHERE revoked.kind <> 'node' OR NOT EXISTS (
        SELECT 1
        FROM mesh.device_node_key_epoch AS live
        JOIN mesh.device AS live_device
          ON live_device.workspace_id = live.workspace_id
         AND live_device.network_id = live.network_id
         AND live_device.id = live.device_id
         AND live.epoch = live_device.current_node_key_epoch
        WHERE live.public_key = revoked.value
          AND live.state = 'active'
          AND live_device.state = 'active'
          AND live_device.deleted_at IS NULL
    );
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.relay_revocations_v1(TIMESTAMPTZ) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.relay_revocations_v1(TIMESTAMPTZ)
    FROM mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.relay_revocations_v1(TIMESTAMPTZ) TO mesh_runtime;
