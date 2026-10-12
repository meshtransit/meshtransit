-- Overlay addresses of a revoked Device go through quarantine and are then
-- reused (TD-CORE-14). Until now a revoked Device kept an active lease for
-- ever, so every revoke-and-enrol cycle used up one address of the Network.
--
-- Revocation now moves the Device's active leases to quarantined, with
-- quarantine_until one quarantine interval after the revocation. The
-- registration allocator treats a lease whose quarantine has ended as free
-- and releases it in the registering transaction, which already records
-- evidence and advances the Network revision. A Device revoked before this
-- schema still holds an active lease; the allocator reclaims it once the
-- quarantine interval has passed since the revocation (the Device's
-- updated_at), without rewriting history here.
--
-- The quarantine keeps late packets for an old address from reaching the
-- Device that receives it next. Suspended Devices keep their addresses.

CREATE FUNCTION mesh_ops.node_address_quarantine_v1()
RETURNS INTERVAL
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT INTERVAL '24 hours'
$function$;

REVOKE ALL ON FUNCTION mesh_ops.node_address_quarantine_v1() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mesh_ops.node_address_quarantine_v1() TO mesh_runtime;

-- Moves the active leases of one revoked Device to quarantined. The caller
-- holds the Device's Network revision and sets mesh.change_public_id; the
-- caller's evidence covers the lease mutations.
CREATE FUNCTION mesh_ops.quarantine_device_leases_v1(
    p_device_id BIGINT, p_now TIMESTAMPTZ
)
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_count INTEGER;
BEGIN
    IF p_device_id IS NULL OR p_device_id <= 0 OR p_now IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Device lease quarantine is invalid';
    END IF;
    PERFORM 1 FROM mesh.device AS device
    WHERE device.id = p_device_id AND device.state = 'revoked';
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MTM03', MESSAGE = 'Device leases cannot be quarantined';
    END IF;
    UPDATE mesh.node_address_lease AS lease
    SET state = 'quarantined',
        released_at = GREATEST(p_now, lease.updated_at),
        quarantine_until = GREATEST(p_now, lease.updated_at) + mesh_ops.node_address_quarantine_v1(),
        version = lease.version + 1,
        updated_at = GREATEST(p_now, lease.updated_at)
    WHERE lease.device_id = p_device_id
      AND lease.state = 'active';
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.quarantine_device_leases_v1(BIGINT, TIMESTAMPTZ)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.quarantine_device_leases_v1(BIGINT, TIMESTAMPTZ) TO mesh_runtime;

-- Revokes one Device and its current keys, and quarantines its addresses.
-- The caller holds the Device's Network revision and sets
-- mesh.change_public_id. Used by member removal and Device logout.
CREATE OR REPLACE FUNCTION mesh_ops.revoke_member_device_internal_v1(
    p_device_id BIGINT, p_reason TEXT, p_now TIMESTAMPTZ
)
RETURNS VOID LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog
AS $function$
DECLARE
    v_device mesh.device%ROWTYPE;
BEGIN
    UPDATE mesh.device AS device
    SET state = 'revoked', suspended_reason = NULL, handover_principal_id = NULL,
        session_generation = device.session_generation + 1, version = device.version + 1,
        updated_at = GREATEST(p_now, device.updated_at)
    WHERE device.id = p_device_id AND device.state IN ('active', 'suspended', 'expired')
      AND device.deleted_at IS NULL
    RETURNING * INTO v_device;
    IF v_device.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MTM03', MESSAGE = 'Device cannot be revoked';
    END IF;
    UPDATE mesh.device_machine_key_epoch AS key_epoch
    SET state = 'revoked', valid_until = GREATEST(p_now, key_epoch.valid_from), revocation_reason = p_reason,
        version = key_epoch.version + 1, updated_at = GREATEST(p_now, key_epoch.updated_at)
    WHERE key_epoch.workspace_id = v_device.workspace_id AND key_epoch.network_id = v_device.network_id
      AND key_epoch.device_id = v_device.id AND key_epoch.state = 'active';
    UPDATE mesh.device_node_key_epoch AS key_epoch
    SET state = 'revoked', valid_until = GREATEST(p_now, key_epoch.valid_from), revocation_reason = p_reason,
        version = key_epoch.version + 1, updated_at = GREATEST(p_now, key_epoch.updated_at)
    WHERE key_epoch.workspace_id = v_device.workspace_id AND key_epoch.network_id = v_device.network_id
      AND key_epoch.device_id = v_device.id AND key_epoch.state = 'active';
    PERFORM mesh_ops.quarantine_device_leases_v1(v_device.id, p_now);
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.revoke_member_device_internal_v1(BIGINT, TEXT, TIMESTAMPTZ)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
