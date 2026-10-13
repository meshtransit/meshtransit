-- Schema 151: a Device is shared into a Network at most once. Each share
-- gives the Device its own alias in the receiving Network, but a map carries
-- one alias per peer, so a second live share of the same Device into the same
-- Network made the map of both Devices invalid as soon as a rule used both
-- shares. Nothing refused it: offers and acceptances only checked the offer.
--
-- device_already_shared_v1 reports, past the share writer's per-pair row
-- security, whether another live contract (activating or active, unexpired)
-- shares the Resource into the Network. Like share_limit_reached_v1 it is
-- owned by the migrator and only the share writer may run it, and it returns
-- only that answer.
--
-- decide v6 is v5 followed, for an accept, by that check (MT013): v4 inside
-- v5 has validated the offer, taken both Network revision locks and inserted
-- the contract, so concurrent accepts of two offers for one Device are
-- serialized and the second is refused. The operator hands v6 to the share
-- writer; runtime keeps v5 until it may run v6.
CREATE FUNCTION mesh_ops.device_already_shared_v1(
    p_consumer_workspace_id BIGINT, p_consumer_network_id BIGINT,
    p_provider_workspace_id BIGINT, p_provider_network_id BIGINT, p_resource_id BIGINT,
    p_except_contract_public_id UUID
)
RETURNS BOOLEAN
LANGUAGE sql VOLATILE PARALLEL UNSAFE SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
    SELECT p_resource_id IS NOT NULL AND EXISTS (
        SELECT 1 FROM mesh.trust_contract AS contract
        WHERE contract.provider_workspace_id = p_provider_workspace_id
          AND contract.provider_network_id = p_provider_network_id
          AND contract.resource_id = p_resource_id
          AND contract.consumer_workspace_id = p_consumer_workspace_id
          AND contract.consumer_network_id = p_consumer_network_id
          AND contract.public_id IS DISTINCT FROM p_except_contract_public_id
          AND contract.state IN ('activating', 'active')
          AND contract.expires_at > pg_catalog.clock_timestamp()
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.device_already_shared_v1(BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID)
    FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_share_writer,mesh_audit_writer,mesh_direct_map_reader;
GRANT EXECUTE ON FUNCTION mesh_ops.device_already_shared_v1(BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID)
    TO mesh_share_writer;

CREATE FUNCTION mesh_ops.decide_resource_share_offer_v6(
    p_provider_workspace_id BIGINT,
    p_provider_network_id BIGINT,
    p_consumer_workspace_id BIGINT,
    p_consumer_network_id BIGINT,
    p_provider_workspace_public_id UUID,
    p_provider_network_public_id UUID,
    p_consumer_workspace_public_id UUID,
    p_consumer_network_public_id UUID,
    p_offer_public_id UUID,
    p_expected_offer_version BIGINT,
    p_nonce_digest BYTEA,
    p_action TEXT,
    p_contract_public_id UUID,
    p_imported_resource_public_id UUID,
    p_imported_display_name TEXT,
    p_access_name_public_id UUID,
    p_access_name TEXT,
    p_provider_authority_generation BIGINT,
    p_consumer_authority_generation BIGINT,
    p_recovery_epoch BIGINT,
    p_expected_provider_sharing_revision BIGINT,
    p_expected_consumer_sharing_revision BIGINT,
    p_occurred_at TIMESTAMPTZ
)
RETURNS TABLE (
    provider_network_revision BIGINT,
    provider_sharing_revision BIGINT,
    consumer_network_revision BIGINT,
    consumer_sharing_revision BIGINT,
    offer_version BIGINT,
    contract_version BIGINT,
    imported_resource_version BIGINT,
    contract_state TEXT,
    access_name_version BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    offer_resource BIGINT;
BEGIN
    RETURN QUERY SELECT * FROM mesh_ops.decide_resource_share_offer_v5(
        p_provider_workspace_id, p_provider_network_id, p_consumer_workspace_id, p_consumer_network_id,
        p_provider_workspace_public_id, p_provider_network_public_id,
        p_consumer_workspace_public_id, p_consumer_network_public_id,
        p_offer_public_id, p_expected_offer_version, p_nonce_digest, p_action,
        p_contract_public_id, p_imported_resource_public_id, p_imported_display_name,
        p_access_name_public_id, p_access_name,
        p_provider_authority_generation, p_consumer_authority_generation, p_recovery_epoch,
        p_expected_provider_sharing_revision, p_expected_consumer_sharing_revision, p_occurred_at
    );
    IF p_action = 'accept' THEN
        SELECT contract.resource_id INTO offer_resource
        FROM mesh.trust_contract AS contract
        WHERE contract.provider_workspace_id = p_provider_workspace_id
          AND contract.provider_network_id = p_provider_network_id
          AND contract.consumer_workspace_id = p_consumer_workspace_id
          AND contract.consumer_network_id = p_consumer_network_id
          AND contract.public_id = p_contract_public_id;
        IF mesh_ops.device_already_shared_v1(
            p_consumer_workspace_id, p_consumer_network_id,
            p_provider_workspace_id, p_provider_network_id, offer_resource, p_contract_public_id
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'MT013', MESSAGE = 'the Device is already shared into the receiving Network';
        END IF;
    END IF;
    RETURN;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.decide_resource_share_offer_v6(
    BIGINT, BIGINT, BIGINT, BIGINT,
    UUID, UUID, UUID, UUID, UUID, BIGINT, BYTEA, TEXT,
    UUID, UUID, TEXT, UUID, TEXT,
    BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, TIMESTAMPTZ
) FROM PUBLIC,mesh_runtime,mesh_worker,mesh_observer,mesh_audit_writer,mesh_direct_map_reader;
