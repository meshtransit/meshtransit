-- Schema 303: a browser sign-in that Core refused for good ends at once (TD-CORE-150 M1, L1).
--
-- Completion refuses an approval whose machine or node key holds a Device it cannot resume or move to (another
-- account's, a Workspace's or suspended Device, a move not confirmed, a sibling profile's Device in that Network, a
-- node key from a Device's history). Asking again never changes that. Until now the approved intent and its authorized
-- registration stayed: schema 289 ended them on the next sign-in only for a machine key active in another Network, and
-- every other refusal handed the node the same approved URL until it expired (up to 15 minutes), with no event in the
-- Network's audit stream.
--
-- Control now runs a second, short transaction after the refusal: the completion authority (which proves the token and
-- the Noise-bound keys and sets the Network scope), then this function, which ends both rows; control appends
-- registration.expired evidence in the Network's stream under the same change, as for an approval that expired on time.
--
-- Expand step: only new code calls it.

CREATE FUNCTION mesh_ops.end_refused_browser_intent_v1(
    p_intent_public_id UUID,
    p_registration_public_id UUID,
    p_token_digest BYTEA,
    p_machine_key_fingerprint BYTEA,
    p_requested_node_key BYTEA
)
RETURNS TABLE (
    ended_registration_version BIGINT,
    registration_expires_at TIMESTAMPTZ
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    v_intent_id BIGINT;
    v_registration_id BIGINT;
BEGIN
    IF p_intent_public_id IS NULL OR p_registration_public_id IS NULL
        OR p_token_digest IS NULL OR pg_catalog.octet_length(p_token_digest) <> 32
        OR p_machine_key_fingerprint IS NULL
        OR pg_catalog.octet_length(p_machine_key_fingerprint) <> 32
        OR p_requested_node_key IS NULL
        OR pg_catalog.octet_length(p_requested_node_key) <> 32 THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid refused browser intent';
    END IF;
    IF COALESCE(pg_catalog.current_setting('mesh.change_public_id', TRUE), '') = '' THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'ending a refused browser intent needs a change';
    END IF;

    -- The same intent, registration and keys the completion authority locked,
    -- in the Network scope it set; never a registration that made a Device.
    SELECT intent.id, registration.id INTO v_intent_id, v_registration_id
    FROM mesh.browser_registration_intent AS intent
    JOIN mesh.deployment AS deployment ON deployment.id = intent.deployment_id
    JOIN mesh.pending_registration AS registration
      ON registration.public_id = intent.pending_registration_public_id
    WHERE intent.public_id = p_intent_public_id
      AND intent.state = 'approved'
      AND intent.token_digest_algorithm = 'sha256-domain-v1'
      AND intent.token_digest = p_token_digest
      AND intent.machine_key_fingerprint = p_machine_key_fingerprint
      AND intent.requested_node_key = p_requested_node_key
      AND intent.pending_registration_public_id = p_registration_public_id
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND deployment.recovery_epoch = intent.issued_recovery_epoch
      AND registration.authorization_kind = 'interactive'
      AND registration.browser_authorization_public_id = intent.public_id
      AND registration.state = 'authorized'
      AND registration.device_id IS NULL
      AND registration.workspace_id = mesh_ops.current_workspace_id()
      AND registration.network_id = mesh_ops.current_network_id()
      AND registration.machine_key_fingerprint = p_machine_key_fingerprint
      AND registration.requested_node_key = p_requested_node_key
    FOR UPDATE OF intent, registration;
    IF NOT FOUND THEN
        RETURN;
    END IF;

    UPDATE mesh.browser_registration_intent AS intent
    SET state = 'expired', version = intent.version + 1, updated_at = pg_catalog.clock_timestamp()
    WHERE intent.id = v_intent_id AND intent.state = 'approved';

    RETURN QUERY
    UPDATE mesh.pending_registration AS registration
    SET state = 'expired', version = registration.version + 1, updated_at = pg_catalog.clock_timestamp()
    WHERE registration.id = v_registration_id AND registration.state = 'authorized'
      AND registration.device_id IS NULL
    RETURNING registration.version, registration.expires_at;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.end_refused_browser_intent_v1(UUID, UUID, BYTEA, BYTEA, BYTEA) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION mesh_ops.end_refused_browser_intent_v1(UUID, UUID, BYTEA, BYTEA, BYTEA)
    TO mesh_control_rights;
