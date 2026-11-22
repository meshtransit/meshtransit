-- Schema 312 (TD-API-50): an enrollment key's Devices belong to the person
-- who issued it, so that person must be a member of the key's Network, when
-- the key is issued and when it is used (owner decision QJ, 2026-11-19).
-- Before, enrollment_credential.issue alone sufficed: a Workspace
-- administrator who was not in the Network issued keys there, the Devices
-- were theirs, and offboarding the Network's members never saw them.
-- Leaving the Network already revokes the member's keys (schema 295); a
-- membership that is suspended or expires does not, so a key is also
-- refused at use while its issuer is not an active member, both by intake
-- (no pending intent is written) and by the registration transaction. Only
-- the Network's enrollment keys (profile "enrollment-keys") are concerned;
-- Kubernetes join keys have their own authority.

-- Whether the principal is an active account and an active member of the
-- Network, and of its Workspace, at p_at.
CREATE FUNCTION mesh_ops.network_member_active_internal_v1(
    p_workspace_id BIGINT, p_network_id BIGINT, p_principal_id BIGINT, p_at TIMESTAMPTZ
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT EXISTS (
        SELECT 1
        FROM mesh.network_membership AS membership
        JOIN mesh.workspace_membership AS workspace_membership
          ON workspace_membership.id = membership.workspace_membership_id
        JOIN mesh.principal AS principal ON principal.id = membership.principal_id
        WHERE principal.state = 'active' AND principal.deleted_at IS NULL AND membership.workspace_id = p_workspace_id AND membership.network_id = p_network_id
          AND membership.principal_id = p_principal_id AND membership.state = 'active'
          AND membership.valid_from <= p_at
          AND (membership.expires_at IS NULL OR membership.expires_at > p_at)
          AND workspace_membership.state = 'active' AND workspace_membership.valid_from <= p_at
          AND (workspace_membership.expires_at IS NULL OR workspace_membership.expires_at > p_at)
    )
$function$;
REVOKE ALL ON FUNCTION mesh_ops.network_member_active_internal_v1(BIGINT, BIGINT, BIGINT, TIMESTAMPTZ)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- Issuing: refuses an enrollment key whose issuer is not a member, now. A
-- trigger, so every path that stores a key keeps the rule. MTE04 lets the
-- API say "join this Network" rather than a bare "not allowed".
CREATE FUNCTION mesh_ops.enrollment_key_issuer_member_guard_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $function$
BEGIN
    IF EXISTS (
        SELECT 1 FROM mesh.enrollment_profile AS profile
        WHERE profile.id = NEW.enrollment_profile_id AND profile.name_key = 'enrollment-keys'
          AND profile.device_kind = 'standard'
    ) AND NOT mesh_ops.network_member_active_internal_v1(
        NEW.workspace_id, NEW.network_id, NEW.issuer_principal_id, pg_catalog.transaction_timestamp()
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTE04',
            MESSAGE = 'enrollment key issue is not authorized: the issuer is not a member of the Network';
    END IF;
    RETURN NEW;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.enrollment_key_issuer_member_guard_v1()
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

CREATE TRIGGER enrollment_key_issuer_member_guard
BEFORE INSERT ON mesh.enrollment_credential
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enrollment_key_issuer_member_guard_v1();

-- Using: a key that still has uses left reads as revoked while its issuer
-- is not an active member, so intake and registration refuse it exactly as
-- a revoked key. A spent key keeps its state: a completed registration
-- replays unchanged. Same signatures and bodies as schema 224 otherwise.
CREATE OR REPLACE FUNCTION mesh_ops.lock_registration_credential_v2(p_credential_public_id uuid)
 RETURNS TABLE(credential_internal_id bigint, profile_internal_id bigint, issuer_internal_id bigint, issuer_public_id text, credential_state text, use_limit_kind text, max_uses bigint, used_count bigint, issued_recovery_epoch bigint, valid_from timestamp with time zone, expires_at timestamp with time zone, credential_version bigint, device_lifetime_seconds bigint, device_never_expires boolean)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog'
AS $function$
DECLARE
    v_workspace BIGINT := mesh_ops.current_workspace_id();
    v_network BIGINT := mesh_ops.current_network_id();
    v_now TIMESTAMPTZ := pg_catalog.transaction_timestamp();
BEGIN
    IF v_workspace IS NULL OR v_network IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'transaction Network scope is unavailable';
    END IF;
    RETURN QUERY
    SELECT credential.id, credential.enrollment_profile_id, credential.issuer_principal_id,
        principal.public_id::TEXT,
        CASE
            WHEN credential.state = 'active' AND credential.used_count < credential.max_uses
                AND profile.name_key = 'enrollment-keys'
                AND NOT mesh_ops.network_member_active_internal_v1(
                    credential.workspace_id, credential.network_id, credential.issuer_principal_id, v_now)
            THEN 'revoked'
            ELSE credential.state
        END,
        credential.use_limit_kind, credential.max_uses,
        credential.used_count, credential.issued_recovery_epoch, credential.valid_from,
        credential.expires_at, credential.version, credential.device_lifetime_seconds,
        credential.device_never_expires
    FROM mesh.enrollment_credential AS credential
    JOIN mesh.principal AS principal ON principal.id = credential.issuer_principal_id
    JOIN mesh.enrollment_profile AS profile ON profile.id = credential.enrollment_profile_id
    WHERE credential.workspace_id = v_workspace AND credential.network_id = v_network
      AND credential.public_id = p_credential_public_id
      AND profile.device_kind = 'standard'
    FOR UPDATE OF credential;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = '23503', MESSAGE = 'scoped enrollment credential is unavailable';
    END IF;
END;
$function$;

-- The intake's lock (schema 224's body), with the same rule.
CREATE OR REPLACE FUNCTION mesh_ops.lock_registration_credential(p_credential_public_id uuid)
 RETURNS TABLE(credential_internal_id bigint, profile_internal_id bigint, issuer_internal_id bigint, issuer_public_id text, credential_state text, use_limit_kind text, max_uses bigint, used_count bigint, issued_recovery_epoch bigint, valid_from timestamp with time zone, expires_at timestamp with time zone, credential_version bigint)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'mesh', 'mesh_ops'
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
BEGIN
    BEGIN
        scoped_workspace_id := NULLIF(
            pg_catalog.current_setting('mesh.workspace_id', TRUE),
            ''
        )::BIGINT;
        scoped_network_id := NULLIF(
            pg_catalog.current_setting('mesh.network_id', TRUE),
            ''
        )::BIGINT;
    EXCEPTION
        WHEN invalid_text_representation OR numeric_value_out_of_range THEN
            RAISE EXCEPTION USING
                ERRCODE = '42501',
                MESSAGE = 'transaction Network scope is unavailable';
    END;

    IF scoped_workspace_id IS NULL OR scoped_network_id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'transaction Network scope is unavailable';
    END IF;

    RETURN QUERY
    SELECT
        credential.id,
        credential.enrollment_profile_id,
        credential.issuer_principal_id,
        principal.public_id::TEXT,
        CASE
            WHEN credential.state = 'active' AND credential.used_count < credential.max_uses
                AND profile.name_key = 'enrollment-keys'
                AND NOT mesh_ops.network_member_active_internal_v1(
                    credential.workspace_id, credential.network_id, credential.issuer_principal_id,
                    pg_catalog.transaction_timestamp())
            THEN 'revoked'
            ELSE credential.state
        END,
        credential.use_limit_kind,
        credential.max_uses,
        credential.used_count,
        credential.issued_recovery_epoch,
        credential.valid_from,
        credential.expires_at,
        credential.version
    FROM mesh.enrollment_credential AS credential
    JOIN mesh.principal AS principal ON principal.id = credential.issuer_principal_id
    JOIN mesh.enrollment_profile AS profile ON profile.id = credential.enrollment_profile_id
    WHERE credential.workspace_id = scoped_workspace_id
      AND credential.network_id = scoped_network_id
      AND credential.public_id = p_credential_public_id
      AND profile.device_kind = 'standard'
    FOR UPDATE OF credential;

    IF NOT FOUND THEN
        RAISE EXCEPTION USING
            ERRCODE = '23503',
            MESSAGE = 'scoped enrollment credential is unavailable';
    END IF;
END;
$function$;
