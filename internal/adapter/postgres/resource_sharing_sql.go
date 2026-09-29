package postgres

const readResourceSharingNetworkStateSQL = `SELECT
    network.authority_generation,
    revision.network_revision,
    revision.sharing_revision
FROM mesh.network AS network
JOIN mesh_ops.network_revision AS revision
  ON revision.workspace_id = network.workspace_id
 AND revision.network_id = network.id
WHERE network.workspace_id = mesh_ops.current_workspace_id()
  AND network.id = mesh_ops.current_network_id()
  AND network.state = 'active'`

const readResourceSharingResourceSQL = `SELECT
    resource_version,
    target_generation,
    semantic_hash
FROM mesh_ops.read_resource_v2($1::UUID)
WHERE resource_state = 'active'`

const readResourceSharingLocatorSQL = `SELECT
    locator.provider_workspace_id,
    locator.provider_network_id,
    locator.consumer_workspace_id,
    locator.consumer_network_id,
    locator.provider_workspace_public_id::TEXT,
    locator.provider_network_public_id::TEXT,
    locator.consumer_workspace_public_id::TEXT,
    locator.consumer_network_public_id::TEXT
FROM mesh.share_offer_locator AS locator
WHERE locator.local_workspace_id = mesh_ops.current_workspace_id()
  AND locator.local_network_id = mesh_ops.current_network_id()
  AND locator.offer_public_id = $1::UUID`

const readResourceSharingContractLocatorSQL = `SELECT
    locator.provider_workspace_id,
    locator.provider_network_id,
    locator.consumer_workspace_id,
    locator.consumer_network_id,
    locator.provider_workspace_public_id::TEXT,
    locator.provider_network_public_id::TEXT,
    locator.consumer_workspace_public_id::TEXT,
    locator.consumer_network_public_id::TEXT,
    offer.public_id::TEXT
FROM mesh.trust_contract AS contract
JOIN mesh.share_offer AS offer ON offer.id = contract.share_offer_id
JOIN mesh.share_offer_locator AS locator
  ON locator.offer_id = offer.id
 AND locator.local_workspace_id = mesh_ops.current_workspace_id()
 AND locator.local_network_id = mesh_ops.current_network_id()
WHERE contract.public_id = $1::UUID`

const readImportedPolicyLocatorsSQL = `SELECT COALESCE(
    pg_catalog.jsonb_agg(
        pg_catalog.jsonb_build_object(
            'imported_resource_id', imported.public_id,
            'provider_workspace_internal_id', contract.provider_workspace_id,
            'provider_network_internal_id', contract.provider_network_id,
            'consumer_workspace_internal_id', contract.consumer_workspace_id,
            'consumer_network_internal_id', contract.consumer_network_id,
            'provider_workspace_id', locator.provider_workspace_public_id,
            'provider_network_id', locator.provider_network_public_id,
            'consumer_workspace_id', locator.consumer_workspace_public_id,
            'consumer_network_id', locator.consumer_network_public_id
        )
        ORDER BY imported.public_id
    ),
    '[]'::JSONB
)::TEXT
FROM mesh.imported_resource AS imported
JOIN mesh.trust_contract AS contract
  ON contract.id = imported.trust_contract_id
 AND contract.consumer_workspace_id = imported.workspace_id
 AND contract.consumer_network_id = imported.network_id
JOIN mesh.share_offer_locator AS locator
  ON locator.offer_id = contract.share_offer_id
 AND locator.local_workspace_id = imported.workspace_id
 AND locator.local_network_id = imported.network_id
 AND locator.direction = 'incoming'
 AND locator.state = 'accepted'
WHERE imported.workspace_id = mesh_ops.current_workspace_id()
  AND imported.network_id = mesh_ops.current_network_id()
  AND imported.public_id = ANY($1::UUID[])`

const resolveImportedPolicyDestinationsSQL = `SELECT
    mesh_ops.resolve_imported_policy_destinations_v1(
        $1::BIGINT, $2::BIGINT, $3::BIGINT, $4::BIGINT,
        $5::UUID, $6::UUID, $7::UUID, $8::UUID,
        $9::UUID[], $10::TIMESTAMPTZ
    )::TEXT`

const resourceSharingOfferProjectionSQL = `pg_catalog.jsonb_build_object(
    'offer_id', offer.public_id,
    'export_id', export.public_id,
    'provider_workspace_id', locator.provider_workspace_public_id,
    'provider_network_id', locator.provider_network_public_id,
    'consumer_workspace_id', locator.consumer_workspace_public_id,
    'consumer_network_id', locator.consumer_network_public_id,
    'resource_id', export.resource_public_id,
    'resource_version', export.resource_version,
    'target_generation', export.target_generation,
    'resource_semantic_hash', pg_catalog.encode(export.resource_semantic_hash, 'hex'),
    'provider_authority_generation', export.provider_authority_generation,
    'export_expires_at', export.expires_at,
    'export_state', export.state,
    'export_version', export.version,
    'nonce_digest', pg_catalog.encode(offer.nonce_digest, 'hex'),
    'offer_expires_at', offer.expires_at,
    'offer_state', offer.state,
    'offer_version', offer.version,
    'offer_decided_at', offer.decided_at,
    'accepted_contract_id', offer.accepted_contract_public_id,
    'created_at', offer.created_at,
    'constraints', COALESCE((
        SELECT pg_catalog.jsonb_agg(
            pg_catalog.jsonb_build_object(
                'protocol', constraint_row.protocol,
                'ranges', COALESCE((
                    SELECT pg_catalog.jsonb_agg(
                        pg_catalog.jsonb_build_array(
                            pg_catalog.lower(port_range),
                            pg_catalog.upper(port_range) - 1
                        ) ORDER BY pg_catalog.lower(port_range), pg_catalog.upper(port_range)
                    )
                    FROM pg_catalog.unnest(constraint_row.destination_ports) AS port_range
                ), '[]'::JSONB)
            ) ORDER BY constraint_row.protocol
        )
        FROM mesh.resource_export_constraint AS constraint_row
        WHERE constraint_row.resource_export_id = export.id
    ), '[]'::JSONB),
    'contract', CASE WHEN contract.id IS NULL THEN NULL ELSE pg_catalog.jsonb_build_object(
        'contract_id', contract.public_id,
        'imported_resource_id', contract.imported_resource_public_id,
        'provider_authority_generation', contract.provider_authority_generation,
        'consumer_authority_generation', contract.consumer_authority_generation,
        'recovery_epoch', contract.recovery_epoch,
        'expires_at', contract.expires_at,
        'state', contract.state,
        'version', contract.version,
        'ended_at', contract.ended_at
    ) END
)`

const readResourceSharingOfferSQL = `SELECT ` + resourceSharingOfferProjectionSQL + `::TEXT
FROM mesh.share_offer_locator AS locator
JOIN mesh.share_offer AS offer ON offer.id = locator.offer_id
JOIN mesh.resource_export AS export ON export.id = offer.resource_export_id
LEFT JOIN mesh.trust_contract AS contract ON contract.share_offer_id = offer.id
WHERE locator.local_workspace_id = mesh_ops.current_workspace_id()
  AND locator.local_network_id = mesh_ops.current_network_id()
  AND locator.offer_public_id = $1::UUID`

const listResourceSharingOffersSQL = `SELECT COALESCE(
    pg_catalog.jsonb_agg(candidate.payload ORDER BY candidate.offer_public_id),
    '[]'::JSONB
)::TEXT
FROM (
    SELECT
        offer.public_id AS offer_public_id,
        ` + resourceSharingOfferProjectionSQL + ` AS payload
    FROM mesh.share_offer_locator AS locator
    JOIN mesh.share_offer AS offer ON offer.id = locator.offer_id
    JOIN mesh.resource_export AS export ON export.id = offer.resource_export_id
    LEFT JOIN mesh.trust_contract AS contract ON contract.share_offer_id = offer.id
    WHERE locator.local_workspace_id = mesh_ops.current_workspace_id()
      AND locator.local_network_id = mesh_ops.current_network_id()
      AND locator.direction = $1::TEXT
      AND ($2::TEXT IS NULL OR offer.state = $2::TEXT)
      AND ($3::UUID IS NULL OR offer.public_id > $3::UUID)
    ORDER BY offer.public_id
    LIMIT $4::INTEGER
) AS candidate`

const createResourceShareOfferSQL = `SELECT
    provider_network_revision,
    provider_sharing_revision,
    consumer_network_revision,
    consumer_sharing_revision,
    export_version,
    offer_version
FROM mesh_ops.create_resource_share_offer_v1(
    $1::BIGINT, $2::BIGINT, $3::BIGINT, $4::BIGINT,
    $5::UUID, $6::UUID, $7::UUID, $8::UUID, $9::UUID,
    $10::BIGINT, $11::BIGINT, $12::BYTEA, $13::UUID, $14::UUID,
    $15::JSONB, $16::JSONB, $17::BYTEA, $18::BYTEA,
    $19::BIGINT, $20::BIGINT, $21::BIGINT, $22::BIGINT,
    $23::TIMESTAMPTZ, $24::TIMESTAMPTZ
)`

const decideResourceShareOfferSQL = `SELECT
    provider_network_revision,
    provider_sharing_revision,
    consumer_network_revision,
    consumer_sharing_revision,
    offer_version,
    contract_version,
    imported_resource_version,
    contract_state
FROM mesh_ops.decide_resource_share_offer_v1(
    $1::BIGINT, $2::BIGINT, $3::BIGINT, $4::BIGINT,
    $5::UUID, $6::UUID, $7::UUID, $8::UUID, $9::UUID,
    $10::BIGINT, $11::BYTEA, $12::TEXT, $13::UUID, $14::UUID,
    $15::TEXT, $16::BIGINT, $17::BIGINT, $18::BIGINT,
    $19::BIGINT, $20::BIGINT, $21::TIMESTAMPTZ
)`

const revokeResourceShareSQL = `SELECT
    provider_network_revision,
    provider_sharing_revision,
    consumer_network_revision,
    consumer_sharing_revision,
    contract_version,
    imported_resource_version
FROM mesh_ops.revoke_resource_share_v1(
    $1::BIGINT, $2::BIGINT, $3::BIGINT, $4::BIGINT,
    $5::UUID, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::TIMESTAMPTZ
)`

const activateResourceShareSQL = `SELECT
    provider_network_revision,
    provider_sharing_revision,
    consumer_network_revision,
    consumer_sharing_revision,
    contract_version,
    imported_resource_version
FROM mesh_ops.activate_resource_share_v1(
    $1::BIGINT, $2::BIGINT, $3::BIGINT, $4::BIGINT,
    $5::UUID, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::TIMESTAMPTZ
)`
