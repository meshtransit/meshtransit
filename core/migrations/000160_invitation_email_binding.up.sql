-- Schema 160: a Workspace invitation is accepted only by the invited address.
--
-- Schema 129 made the link the only proof: whoever completed a sign-in with it
-- joined, with the invited role. accept_workspace_invitation_v2 also requires
-- the email address the identity provider marked verified for this sign-in to
-- equal the invited address, ignoring ASCII letter case only. Invited addresses
-- are ASCII (schema 128), so a verified address with any other character is
-- refused rather than folded: lower() follows the database locale and folds
-- some non-ASCII letters (the Kelvin sign) into ASCII ones. A sign-in that proves
-- another address, or none, is refused (MTV06) and its whole transaction rolls
-- back: the invitation stays pending and no Account, identity subject,
-- membership or role is made, so the invited person can still use the link.
--
-- The address never links or identifies anyone: the identity subject digest
-- still decides who the person is. It only narrows who may consume the link.
--
-- On a match it runs accept_workspace_invitation_v1 unchanged, and an Account
-- made by this acceptance is named after the verified address as the provider
-- spells it (schema 129 named it after the invited address).
--
-- accept_workspace_invitation_v1 stays executable so the previous image can
-- roll back.
--
-- Errors: those of accept_workspace_invitation_v1, plus MTV06 the sign-in did
-- not prove the invited address.

CREATE FUNCTION mesh_ops.accept_workspace_invitation_v2(
    p_deployment_public_id UUID, p_provider_public_id UUID, p_client_public_id UUID,
    p_provider_generation BIGINT, p_recovery_epoch BIGINT,
    p_transaction_public_id UUID, p_transaction_version BIGINT, p_binding_hash BYTEA,
    p_consumed_at TIMESTAMPTZ, p_subject_algorithm TEXT, p_active_key_id TEXT, p_active_digest BYTEA,
    p_previous_key_id TEXT, p_previous_digest BYTEA, p_token_digest BYTEA,
    p_change_public_id UUID, p_verified_email TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
DECLARE
    v_invited TEXT;
    v_result JSONB;
    v_principal UUID;
BEGIN
    IF p_verified_email IS NULL OR pg_catalog.char_length(p_verified_email) NOT BETWEEN 3 AND 254
        OR pg_catalog.octet_length(p_verified_email) <> pg_catalog.char_length(p_verified_email)
        OR p_verified_email ~ '[[:space:][:cntrl:]]' THEN
        RAISE EXCEPTION USING ERRCODE = 'MTV06', MESSAGE = 'the sign-in did not prove the invited address';
    END IF;
    -- Lock the pending invitation first, in the order v1 locks it, so the
    -- address cannot change between this check and its consumption.
    SELECT invitation.email INTO v_invited
    FROM mesh.workspace_invitation AS invitation
    JOIN mesh.deployment AS deployment ON deployment.id = invitation.deployment_id
    WHERE invitation.token_digest = p_token_digest
      AND deployment.installation_public_id = p_deployment_public_id
      AND invitation.state = 'pending'
    FOR UPDATE OF invitation;
    -- An unknown, used or revoked link is v1's to refuse (P0002).
    IF v_invited IS NOT NULL AND pg_catalog.translate(p_verified_email,
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz') <> v_invited THEN
        RAISE EXCEPTION USING ERRCODE = 'MTV06', MESSAGE = 'the sign-in did not prove the invited address';
    END IF;

    v_result := mesh_ops.accept_workspace_invitation_v1(
        p_deployment_public_id, p_provider_public_id, p_client_public_id, p_provider_generation,
        p_recovery_epoch, p_transaction_public_id, p_transaction_version, p_binding_hash, p_consumed_at,
        p_subject_algorithm, p_active_key_id, p_active_digest, p_previous_key_id, p_previous_digest,
        p_token_digest, p_change_public_id
    );

    -- A display name holds at most 128 characters; a longer address keeps the
    -- name v1 gave the Account.
    IF (v_result ->> 'account_created')::BOOLEAN AND pg_catalog.char_length(p_verified_email) <= 128 THEN
        v_principal := (v_result ->> 'principal_id')::UUID;
        UPDATE mesh.account AS account
        SET display_name = p_verified_email, version = account.version + 1,
            updated_at = pg_catalog.clock_timestamp()
        FROM mesh.principal AS principal
        WHERE principal.public_id = v_principal AND account.principal_id = principal.id
          AND account.deployment_id = principal.deployment_id;
    END IF;
    RETURN v_result;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.accept_workspace_invitation_v2(
    UUID, UUID, UUID, BIGINT, BIGINT, UUID, BIGINT, BYTEA, TIMESTAMPTZ, TEXT, TEXT, BYTEA, TEXT, BYTEA, BYTEA, UUID, TEXT
) FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
GRANT EXECUTE ON FUNCTION mesh_ops.accept_workspace_invitation_v2(
    UUID, UUID, UUID, BIGINT, BIGINT, UUID, BIGINT, BYTEA, TIMESTAMPTZ, TEXT, TEXT, BYTEA, TEXT, BYTEA, BYTEA, UUID, TEXT
) TO mesh_runtime;
