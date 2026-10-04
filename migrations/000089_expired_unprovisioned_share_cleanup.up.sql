CREATE FUNCTION mesh_ops.revoke_resource_share_v6(
    p_provider_workspace_id BIGINT,
    p_provider_network_id BIGINT,
    p_consumer_workspace_id BIGINT,
    p_consumer_network_id BIGINT,
    p_contract_public_id UUID,
    p_expected_contract_version BIGINT,
    p_expected_provider_sharing_revision BIGINT,
    p_expected_consumer_sharing_revision BIGINT,
    p_occurred_at TIMESTAMPTZ
)
RETURNS TABLE (
    provider_network_revision BIGINT,
    provider_sharing_revision BIGINT,
    consumer_network_revision BIGINT,
    consumer_sharing_revision BIGINT,
    contract_version BIGINT,
    imported_resource_version BIGINT,
    access_name_version BIGINT,
    alias_lease_version BIGINT,
    private_endpoint_version BIGINT,
    dns_publication_version BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    contract_row mesh.trust_contract%ROWTYPE;
    imported_row mesh.imported_resource%ROWTYPE;
    access_name_row mesh.imported_resource_access_name%ROWTYPE;
BEGIN
    PERFORM mesh_ops.set_share_scope_v1(
        p_provider_workspace_id,
        p_provider_network_id,
        p_consumer_workspace_id,
        p_consumer_network_id
    );
    IF p_expected_contract_version <= 0
        OR p_expected_provider_sharing_revision <= 0
        OR p_expected_consumer_sharing_revision <= 0
        OR p_occurred_at IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid Trust Contract revocation input';
    END IF;

    PERFORM revision.network_id
    FROM mesh_ops.network_revision AS revision
    WHERE (
        revision.workspace_id = p_provider_workspace_id
        AND revision.network_id = p_provider_network_id
    ) OR (
        revision.workspace_id = p_consumer_workspace_id
        AND revision.network_id = p_consumer_network_id
    )
    ORDER BY revision.workspace_id, revision.network_id
    FOR UPDATE;
    IF NOT EXISTS (
        SELECT 1
        FROM mesh_ops.network_revision AS revision
        WHERE revision.workspace_id = p_provider_workspace_id
          AND revision.network_id = p_provider_network_id
          AND revision.sharing_revision = p_expected_provider_sharing_revision
    ) OR NOT EXISTS (
        SELECT 1
        FROM mesh_ops.network_revision AS revision
        WHERE revision.workspace_id = p_consumer_workspace_id
          AND revision.network_id = p_consumer_network_id
          AND revision.sharing_revision = p_expected_consumer_sharing_revision
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'sharing revision changed';
    END IF;

    SELECT contract.*
    INTO contract_row
    FROM mesh.trust_contract AS contract
    WHERE contract.public_id = p_contract_public_id
      AND contract.provider_workspace_id = p_provider_workspace_id
      AND contract.provider_network_id = p_provider_network_id
      AND contract.consumer_workspace_id = p_consumer_workspace_id
      AND contract.consumer_network_id = p_consumer_network_id
      AND contract.version = p_expected_contract_version
      AND contract.state IN ('activating', 'active')
    FOR UPDATE;
    IF contract_row.id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT001',
            MESSAGE = 'Trust Contract changed or is unavailable';
    END IF;

    IF p_occurred_at < contract_row.expires_at THEN
        RETURN QUERY
        SELECT revoked.*
        FROM mesh_ops.revoke_resource_share_v5(
            p_provider_workspace_id,
            p_provider_network_id,
            p_consumer_workspace_id,
            p_consumer_network_id,
            p_contract_public_id,
            p_expected_contract_version,
            p_expected_provider_sharing_revision,
            p_expected_consumer_sharing_revision,
            p_occurred_at
        ) AS revoked;
        RETURN;
    END IF;

    IF EXISTS (
        SELECT 1
        FROM mesh.private_endpoint AS endpoint
        WHERE endpoint.trust_contract_id = contract_row.id
    ) OR EXISTS (
        SELECT 1
        FROM mesh.direct_device_endpoint AS endpoint
        WHERE endpoint.trust_contract_id = contract_row.id
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT001',
            MESSAGE = 'expired Trust Contract requires endpoint reconciliation';
    END IF;

    SELECT imported.*
    INTO imported_row
    FROM mesh.imported_resource AS imported
    WHERE imported.trust_contract_id = contract_row.id
      AND imported.workspace_id = p_consumer_workspace_id
      AND imported.network_id = p_consumer_network_id
      AND imported.state IN ('activating', 'active')
    FOR UPDATE;
    IF imported_row.id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Imported Resource authority is unavailable';
    END IF;

    SELECT access_name.*
    INTO access_name_row
    FROM mesh.imported_resource_access_name AS access_name
    WHERE access_name.imported_resource_id = imported_row.id
      AND access_name.workspace_id = p_consumer_workspace_id
      AND access_name.network_id = p_consumer_network_id
      AND access_name.state = 'reserved'
    FOR UPDATE;
    IF access_name_row.id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '23514',
            MESSAGE = 'Imported Resource access-name authority is unavailable';
    END IF;

    UPDATE mesh.trust_contract AS contract
    SET state = 'revoked',
        version = contract.version + 1,
        updated_at = p_occurred_at,
        ended_at = p_occurred_at
    WHERE contract.id = contract_row.id
    RETURNING contract.version INTO contract_version;
    UPDATE mesh.imported_resource AS imported
    SET state = 'revoked',
        version = imported.version + 1,
        updated_at = p_occurred_at,
        ended_at = p_occurred_at
    WHERE imported.id = imported_row.id
    RETURNING imported.version INTO imported_resource_version;
    UPDATE mesh.imported_resource_access_name AS access_name
    SET state = 'withdrawn',
        version = access_name.version + 1,
        updated_at = p_occurred_at,
        withdrawn_at = p_occurred_at
    WHERE access_name.id = access_name_row.id
    RETURNING access_name.version INTO access_name_version;

    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        sharing_revision = revision.sharing_revision + 1,
        updated_at = pg_catalog.clock_timestamp()
    WHERE (
        revision.workspace_id = p_provider_workspace_id
        AND revision.network_id = p_provider_network_id
    ) OR (
        revision.workspace_id = p_consumer_workspace_id
        AND revision.network_id = p_consumer_network_id
    );
    SELECT revision.network_revision, revision.sharing_revision
    INTO provider_network_revision, provider_sharing_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = p_provider_workspace_id
      AND revision.network_id = p_provider_network_id;
    SELECT revision.network_revision, revision.sharing_revision
    INTO consumer_network_revision, consumer_sharing_revision
    FROM mesh_ops.network_revision AS revision
    WHERE revision.workspace_id = p_consumer_workspace_id
      AND revision.network_id = p_consumer_network_id;

    alias_lease_version := 0;
    private_endpoint_version := 0;
    dns_publication_version := 0;
    RETURN NEXT;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.revoke_resource_share_v6(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer;
