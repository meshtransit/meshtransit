-- Schema 159: how full a Network's address ranges are (H3).
--
-- Administrators see, per address range of the Network, how many addresses
-- live Devices hold, how many expired Devices still hold (they keep theirs
-- until revoked, TD-CORE-16), and how many revoked Devices' addresses are
-- held back for a day before they can be given out again. Reading it needs
-- network.read, the permission that shows the Network itself.
--
-- The counts read the Network's live and held leases once (the partial
-- index of schema 157 holds exactly those) and look up the Device of each
-- active lease by key. A Device revoked before schema 143 kept its lease
-- active; like the allocator, this counts it as held for a day after its
-- revocation and free after that.

CREATE FUNCTION mesh_ops.read_network_address_usage_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_evaluated_at TIMESTAMPTZ
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_usage JSONB;
BEGIN
    IF p_workspace_public_id IS NULL OR p_network_public_id IS NULL OR p_evaluated_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'Network address usage input is invalid';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM mesh.workspace AS workspace
        JOIN mesh.network AS network ON network.workspace_id = workspace.id
        WHERE workspace.id = v_workspace AND network.id = v_network
          AND workspace.public_id = p_workspace_public_id AND network.public_id = p_network_public_id
          AND workspace.state = 'active' AND workspace.deleted_at IS NULL
          AND network.state = 'active' AND network.deleted_at IS NULL
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Network address usage scope is unavailable';
    END IF;
    PERFORM 1 FROM mesh_ops.resolve_network_permission_v2(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version,
        p_principal_authority_generation, p_account_session_generation,
        p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'network.read', p_evaluated_at
    );
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Network address usage is not authorized';
    END IF;

    SELECT pg_catalog.jsonb_build_object('prefixes', COALESCE(pg_catalog.jsonb_agg(
        pg_catalog.jsonb_build_object(
            'family', usage.family,
            'prefix', usage.prefix::TEXT,
            -- The allocator skips the network address, and the IPv4
            -- broadcast address. An IPv6 range of /95 or wider cannot run
            -- out in practice, so it has no capacity.
            'capacity', CASE
                WHEN usage.family = 4 THEN (1::BIGINT << (32 - pg_catalog.masklen(usage.prefix))) - 2
                WHEN pg_catalog.masklen(usage.prefix) >= 96
                    THEN (1::BIGINT << (128 - pg_catalog.masklen(usage.prefix))) - 1
            END,
            'in_use', usage.in_use,
            'held_by_expired', usage.held_by_expired,
            'held_after_revocation', usage.held_after_revocation,
            'next_release', usage.next_release
        ) ORDER BY usage.family, usage.prefix), '[]'::JSONB))
    INTO v_usage
    FROM (
        SELECT held.family, held.prefix,
            pg_catalog.count(*) FILTER (WHERE held.kind = 'in_use') AS in_use,
            pg_catalog.count(*) FILTER (WHERE held.kind = 'expired') AS held_by_expired,
            pg_catalog.count(*) FILTER (WHERE held.kind = 'revoked') AS held_after_revocation,
            pg_catalog.min(held.release_at) FILTER (WHERE held.kind = 'revoked') AS next_release
        FROM (
            SELECT prefix.id, prefix.family, prefix.prefix,
                CASE
                    WHEN lease.id IS NULL THEN NULL
                    WHEN lease.state = 'quarantined' THEN
                        CASE WHEN lease.quarantine_until > p_evaluated_at THEN 'revoked' END
                    WHEN device.state = 'revoked' THEN
                        CASE WHEN device.updated_at + mesh_ops.node_address_quarantine_v1() > p_evaluated_at
                            THEN 'revoked' END
                    WHEN device.expires_at > p_evaluated_at THEN 'in_use'
                    ELSE 'expired'
                END AS kind,
                CASE
                    WHEN lease.state = 'quarantined' THEN lease.quarantine_until
                    ELSE device.updated_at + mesh_ops.node_address_quarantine_v1()
                END AS release_at
            FROM mesh.network_prefix AS prefix
            LEFT JOIN mesh.node_address_lease AS lease
              ON lease.workspace_id = prefix.workspace_id
             AND lease.network_id = prefix.network_id
             AND lease.network_prefix_id = prefix.id
             AND lease.state IN ('active', 'quarantined')
            LEFT JOIN mesh.device AS device
              ON lease.state = 'active'
             AND device.workspace_id = lease.workspace_id
             AND device.network_id = lease.network_id
             AND device.id = lease.device_id
            WHERE prefix.workspace_id = v_workspace AND prefix.network_id = v_network
              AND prefix.state = 'active' AND prefix.deleted_at IS NULL
        ) AS held
        GROUP BY held.id, held.family, held.prefix
    ) AS usage;
    RETURN v_usage;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.read_network_address_usage_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.read_network_address_usage_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TIMESTAMPTZ
) TO mesh_runtime;
