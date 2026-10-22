-- Service names a provider suggests on a share offer (DNS design D3): the
-- real names its web app serves, such as app.corp.com. A suggestion resolves
-- nowhere and reserves nothing in the consumer Network; a consumer that
-- approves one when it accepts the offer gets a DNS name of its own Network
-- that points at the share (schema 217), made in the same transaction.
--
-- Suggestions are written once, with the offer, by the transaction that
-- created it, and never change: at most 8, in order, none twice. Go checks
-- them as DNS (no special-use name, no public suffix, nothing overlapping the
-- mesh names or covering a name MeshTransit must reach); the table keeps
-- their shape.
--
-- The provider and the consumer of the offer read them. The consumer's
-- accept also asks which zone of its Network would hold a name: the longest
-- active one that covers it.

CREATE TABLE mesh.share_offer_service_name (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    deployment_id BIGINT NOT NULL,
    share_offer_id BIGINT NOT NULL,
    ordinal SMALLINT NOT NULL,
    fqdn TEXT COLLATE "C" NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT share_offer_service_name_ordinal_check CHECK (ordinal BETWEEN 1 AND 8),
    CONSTRAINT share_offer_service_name_fqdn_check CHECK (
        pg_catalog.octet_length(fqdn) BETWEEN 3 AND 253
        AND fqdn ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
        AND fqdn !~ '^[0-9.]+$'
    ),
    CONSTRAINT share_offer_service_name_offer_fk FOREIGN KEY (share_offer_id)
        REFERENCES mesh.share_offer (id) ON DELETE RESTRICT,
    CONSTRAINT share_offer_service_name_ordinal_uidx UNIQUE (share_offer_id, ordinal),
    CONSTRAINT share_offer_service_name_fqdn_uidx UNIQUE (share_offer_id, fqdn)
);

CREATE FUNCTION mesh_ops.enforce_share_offer_service_name_immutable_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
BEGIN
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Share offer service names never change';
END;
$function$;
CREATE TRIGGER share_offer_service_name_immutable
BEFORE UPDATE OR DELETE ON mesh.share_offer_service_name
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_share_offer_service_name_immutable_v1();

ALTER TABLE mesh.share_offer_service_name ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.share_offer_service_name FORCE ROW LEVEL SECURITY;
CREATE POLICY share_offer_service_name_migrator_policy ON mesh.share_offer_service_name
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh.share_offer_service_name
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.enforce_share_offer_service_name_immutable_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Records the service names of an offer the transaction's Network (its
-- provider) has just created: offered, at its first version, without names
-- yet. Returns how many it wrote.
CREATE FUNCTION mesh_ops.add_share_offer_service_names_v1(p_offer_public_id UUID, p_names TEXT[])
RETURNS INTEGER
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_offer mesh.share_offer%ROWTYPE;
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF p_offer_public_id IS NULL OR p_names IS NULL OR pg_catalog.cardinality(p_names) NOT BETWEEN 1 AND 8
        OR pg_catalog.array_position(p_names, NULL) IS NOT NULL
        OR (SELECT pg_catalog.count(DISTINCT name) FROM pg_catalog.unnest(p_names) AS name)
           <> pg_catalog.cardinality(p_names) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'share offer service names are invalid';
    END IF;
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'share offer scope is unavailable';
    END IF;
    SELECT * INTO v_offer FROM mesh.share_offer AS offer
    WHERE offer.public_id = p_offer_public_id
      AND offer.provider_workspace_id = v_workspace AND offer.provider_network_id = v_network
    FOR UPDATE;
    -- Only the offer this transaction created: its row is its own (xmin).
    IF v_offer.id IS NULL OR v_offer.state <> 'offered' OR v_offer.version <> 1
        OR (SELECT offer.xmin::TEXT FROM mesh.share_offer AS offer WHERE offer.id = v_offer.id)
           <> (pg_catalog.pg_current_xact_id()::TEXT::BIGINT % 4294967296)::TEXT
        OR EXISTS (SELECT 1 FROM mesh.share_offer_service_name AS name WHERE name.share_offer_id = v_offer.id) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'share offer cannot take service names';
    END IF;
    INSERT INTO mesh.share_offer_service_name (deployment_id, share_offer_id, ordinal, fqdn, created_at)
    SELECT v_offer.deployment_id, v_offer.id, entry.ordinal::SMALLINT, entry.name, v_now
    FROM pg_catalog.unnest(p_names) WITH ORDINALITY AS entry (name, ordinal);
    RETURN pg_catalog.cardinality(p_names);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.add_share_offer_service_names_v1(UUID, TEXT[])
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.add_share_offer_service_names_v1(UUID, TEXT[]) TO mesh_runtime;

-- The service names of an offer, in order, for the transaction's Network
-- when it is the offer's provider or consumer; none for another Network.
CREATE FUNCTION mesh_ops.list_share_offer_service_names_v1(p_offer_public_id UUID)
RETURNS TABLE (fqdn TEXT)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
BEGIN
    IF p_offer_public_id IS NULL OR v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'share offer scope is unavailable';
    END IF;
    RETURN QUERY
    SELECT name.fqdn::TEXT
    FROM mesh.share_offer AS offer
    JOIN mesh.share_offer_service_name AS name ON name.share_offer_id = offer.id
    WHERE offer.public_id = p_offer_public_id
      AND ((offer.provider_workspace_id = v_workspace AND offer.provider_network_id = v_network)
           OR (offer.consumer_workspace_id = v_workspace AND offer.consumer_network_id = v_network))
    ORDER BY name.ordinal;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.list_share_offer_service_names_v1(UUID)
    FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.list_share_offer_service_names_v1(UUID) TO mesh_runtime;

-- The zone of the Network that would hold a name (network.read): the longest
-- active zone, never the root, that covers it, as list_dns_zones_v2 shows
-- one; NULL when none does.
CREATE FUNCTION mesh_ops.find_dns_zone_for_name_v1(
    p_session_public_id UUID, p_deployment_public_id UUID, p_principal_public_id UUID,
    p_identity_subject_public_id UUID, p_session_version BIGINT,
    p_principal_authority_generation BIGINT, p_account_session_generation BIGINT,
    p_provider_generation BIGINT, p_deployment_recovery_epoch BIGINT,
    p_workspace_public_id UUID, p_network_public_id UUID, p_fqdn TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_scope RECORD;
    v_zone mesh.network_dns_zone%ROWTYPE;
BEGIN
    IF p_fqdn IS NULL OR pg_catalog.octet_length(p_fqdn) NOT BETWEEN 1 AND 253
        OR p_fqdn !~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'DNS name is invalid';
    END IF;
    SELECT * INTO STRICT v_scope FROM mesh_ops.authorize_dns_zone_internal_v1(
        p_session_public_id, p_deployment_public_id, p_principal_public_id,
        p_identity_subject_public_id, p_session_version, p_principal_authority_generation,
        p_account_session_generation, p_provider_generation, p_deployment_recovery_epoch,
        p_workspace_public_id, p_network_public_id, 'network.read'
    );
    SELECT * INTO v_zone FROM mesh.network_dns_zone AS zone
    WHERE zone.id = mesh_ops.dns_longest_zone_internal_v1(v_scope.workspace_id, v_scope.network_id, p_fqdn)
      AND zone.domain <> '.';
    IF v_zone.id IS NULL THEN
        RETURN NULL;
    END IF;
    RETURN mesh_ops.dns_zone_document_internal_v2(v_zone);
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.find_dns_zone_for_name_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TEXT
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.find_dns_zone_for_name_v1(
    UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, UUID, UUID, TEXT
) TO mesh_runtime;
