-- Schema 286: a signed-out Device's page shows the addresses it keeps
-- (docs/device-logout-design.md §3.1, §8). read_console_device_v3 (schema
-- 209) answers addresses only for a Device that has not expired, since no
-- peer reaches an expired one; but signing out ends the expiry on purpose,
-- and what the owner keeps is exactly those addresses, which come back when
-- they sign in again. read_console_device_v6 is v5 with, for a Device its
-- owner signed out (active, expired or suspended, not deleted), its active
-- primary leases, IPv4 before IPv6, as v3 reads them. The v5 item stays for
-- Core replicas that predate this schema.

CREATE FUNCTION mesh_ops.read_console_device_v6(
    p_session_public_id UUID, p_deployment_public_id UUID,
    p_principal_public_id UUID, p_identity_subject_public_id UUID,
    p_session_version BIGINT, p_principal_authority_generation BIGINT,
    p_account_session_generation BIGINT, p_provider_generation BIGINT,
    p_deployment_recovery_epoch BIGINT, p_workspace_public_id UUID,
    p_network_public_id UUID, p_evaluated_at TIMESTAMPTZ, p_device_public_id UUID
)
RETURNS JSONB
LANGUAGE plpgsql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    v_result JSONB;
BEGIN
    -- v5 authorizes the read and finds the Device in the scope.
    v_result := mesh_ops.read_console_device_v5(
        p_session_public_id, p_deployment_public_id, p_principal_public_id, p_identity_subject_public_id,
        p_session_version, p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch, p_workspace_public_id, p_network_public_id,
        p_evaluated_at, p_device_public_id);
    IF v_result IS NULL OR NOT v_result ? 'device' OR NOT (v_result -> 'device') ? 'signed_out_at' THEN
        RETURN v_result;
    END IF;
    RETURN v_result || pg_catalog.jsonb_build_object('addresses', COALESCE((
        SELECT pg_catalog.jsonb_agg(pg_catalog.host(lease.address) ORDER BY lease.family, lease.address)
        FROM mesh.device AS device
        JOIN mesh.workspace AS workspace
          ON workspace.id = device.workspace_id AND workspace.public_id = p_workspace_public_id
        JOIN mesh.network AS network
          ON network.id = device.network_id AND network.workspace_id = device.workspace_id
         AND network.public_id = p_network_public_id
        JOIN mesh.node_address_lease AS lease
          ON lease.workspace_id = device.workspace_id AND lease.network_id = device.network_id
         AND lease.device_id = device.id
        WHERE device.public_id = p_device_public_id
          AND device.signed_out_at IS NOT NULL
          AND device.state IN ('active', 'expired', 'suspended') AND device.deleted_at IS NULL
          AND lease.state = 'active' AND lease.lease_role = 'primary'
    ), '[]'::JSONB));
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_console_device_v6(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ, UUID
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_console_device_v6(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ, UUID
) TO mesh_runtime;
