-- Schema 308 (V1-12 step 1c groundwork, docs k8s-v1-12-install-token-design.md
-- v4.1 §3.3–3.4 and §6 step 0): what the install-token approval of schema
-- 309 needs. Nothing here runs on its own.
--
-- * A gateway Device can be suspended for a contested trust, and only that:
--   suspended_reason 'trust_contested', set and lifted only inside a
--   migrator function that says so for its transaction
--   (mesh.kubernetes_trust_change = 'on', and the writer is the migrator:
--   any role can set a custom setting). A resumed gateway joins its
--   cluster's group again (schema 230 only joins on insert and releases on
--   leaving active). Every other rule of the gateway
--   guard (schema 224) stays: no admin suspension, no handover, no change of
--   identity; revocation and deletion stay final. A Device lifecycle
--   "resume" cannot lift it: the guard refuses outside such a function.
-- * kubernetes_principal_holds_permission_internal_v1: whether a principal
--   (not a session) holds a network permission now, by the same membership,
--   Workspace-owner, built-in role and custom binding rules as
--   resolve_network_permission_v2, and only while the principal could still
--   sign in to the Workspace (an active subject of an active, verified
--   provider through an active client and route). The rows that grant are
--   held FOR SHARE, the Workspace first.
--   The maker of an install token is checked with it at every approval.
-- * kubernetes_cluster_trust_digest_v1: kubejoin.ClusterTrustDigest in SQL
--   (vector checked against Go), so the approval recomputes the digest from
--   the request's stored signing material and trusts no caller's value.
-- * mesh_ops.kubernetes_join_token_use: a pod token's jti spent once by an
--   install-token approval (replay of a stolen pod token), across clusters:
--   two clusters may trust the same issuer and keys.

ALTER TABLE mesh.device DROP CONSTRAINT device_suspension_check;
ALTER TABLE mesh.device
    ADD CONSTRAINT device_suspension_check CHECK (
        (state = 'suspended') = (suspended_reason IS NOT NULL)
        AND (suspended_reason IS NULL OR suspended_reason IN ('admin', 'handover', 'member', 'trust_contested'))
        AND (handover_principal_id IS NOT NULL) = (suspended_reason IS NOT DISTINCT FROM 'handover')
        AND (suspended_reason IS DISTINCT FROM 'trust_contested' OR kind = 'kubernetes_gateway')
    ) NOT VALID;
ALTER TABLE mesh.device VALIDATE CONSTRAINT device_suspension_check;
-- Schema 224 with one change: a gateway may carry the contested-trust
-- suspension, and no other.
ALTER TABLE mesh.device DROP CONSTRAINT device_kind_check;
ALTER TABLE mesh.device
    ADD CONSTRAINT device_kind_check CHECK (
        kind IN ('standard', 'kubernetes_gateway')
        AND (kind = 'kubernetes_gateway') = (kubernetes_cluster_id IS NOT NULL)
        AND (kubernetes_cluster_id IS NULL) = (kubernetes_ordinal IS NULL)
        AND (kubernetes_ordinal IS NULL OR kubernetes_ordinal BETWEEN 0 AND 63)
        AND (kind = 'standard' OR (ownership = 'workspace' AND NOT is_ephemeral
            AND (suspended_reason IS NULL OR suspended_reason = 'trust_contested')
            AND handover_principal_id IS NULL AND hostname_locked))
    ) NOT VALID;
ALTER TABLE mesh.device VALIDATE CONSTRAINT device_kind_check;

CREATE OR REPLACE FUNCTION mesh_ops.enforce_kubernetes_gateway_device_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $function$
DECLARE
    -- Set (SET clause, restored on return) only by the trust functions of
    -- schema 309; any role can set a custom setting, so the writer must
    -- also be the migrator those functions run as.
    v_trust_change BOOLEAN := COALESCE(pg_catalog.current_setting('mesh.kubernetes_trust_change', TRUE), '') = 'on'
        AND CURRENT_USER = 'mesh_migrator';
BEGIN
    IF NEW.kind IS DISTINCT FROM OLD.kind
        OR NEW.kubernetes_cluster_id IS DISTINCT FROM OLD.kubernetes_cluster_id
        OR NEW.kubernetes_ordinal IS DISTINCT FROM OLD.kubernetes_ordinal
        OR NEW.public_id <> OLD.public_id OR NEW.workspace_id <> OLD.workspace_id
        OR NEW.network_id <> OLD.network_id OR NEW.enrollment_profile_id <> OLD.enrollment_profile_id
        OR NEW.owner_principal_id IS DISTINCT FROM OLD.owner_principal_id
        OR NEW.custodian_principal_id IS DISTINCT FROM OLD.custodian_principal_id
        OR NEW.ownership <> OLD.ownership
        OR NEW.hostname <> OLD.hostname OR NEW.hostname_locked <> OLD.hostname_locked
        -- A revoked Device's name is released for others (registration).
        OR (NEW.hostname_key <> OLD.hostname_key AND OLD.state = 'active' AND NEW.state = 'active')
        OR NEW.is_ephemeral <> OLD.is_ephemeral OR NEW.expires_at <> OLD.expires_at
        OR (NEW.suspended_reason IS NOT NULL AND NEW.suspended_reason <> 'trust_contested')
        OR NEW.handover_principal_id IS NOT NULL
        OR NEW.created_at <> OLD.created_at
        OR NOT (NEW.state = OLD.state AND NEW.suspended_reason IS NOT DISTINCT FROM OLD.suspended_reason
            OR (OLD.state = 'active' AND NEW.state IN ('revoked', 'deleted'))
            OR (OLD.state = 'revoked' AND NEW.state = 'deleted')
            -- A contested trust's Devices: suspended, then back to active or
            -- revoked once an administrator chooses; never by anyone else.
            OR (OLD.state = 'suspended' AND NEW.state IN ('revoked', 'deleted'))
            OR (v_trust_change AND OLD.state = 'active' AND NEW.state = 'suspended'
                AND NEW.suspended_reason = 'trust_contested')
            OR (v_trust_change AND OLD.state = 'suspended' AND OLD.suspended_reason = 'trust_contested'
                AND NEW.state = 'active' AND NEW.suspended_reason IS NULL)) THEN
        RAISE EXCEPTION USING ERRCODE = 'MTL01',
            MESSAGE = 'a Kubernetes gateway Device is only revoked or deleted, or suspended for a contested trust';
    END IF;
    RETURN NEW;
END;
$function$;

CREATE FUNCTION mesh_ops.kubernetes_principal_holds_permission_internal_v1(
    p_principal_id BIGINT, p_workspace_id BIGINT, p_network_id BIGINT, p_permission_key TEXT,
    p_evaluated_at TIMESTAMPTZ
)
RETURNS BOOLEAN
LANGUAGE plpgsql
VOLATILE
SET search_path = pg_catalog
AS $function$
BEGIN
    IF p_principal_id IS NULL OR p_workspace_id IS NULL OR p_network_id IS NULL
        OR p_permission_key IS NULL OR p_evaluated_at IS NULL THEN
        RETURN FALSE;
    END IF;
    -- The Workspace row first, as resolve_network_permission_v2 does: a
    -- member change holds it before it writes the membership.
    PERFORM 1 FROM mesh.workspace AS workspace WHERE workspace.id = p_workspace_id FOR SHARE;

    -- A principal who can no longer sign in to the Workspace (subject,
    -- provider, client or route gone) holds nothing here: a session of
    -- theirs would resolve nothing.
    PERFORM 1
    FROM mesh.principal AS principal
    JOIN mesh.workspace AS workspace
      ON workspace.deployment_id = principal.deployment_id AND workspace.id = p_workspace_id
    JOIN mesh.identity_subject AS subject
      ON subject.deployment_id = principal.deployment_id AND subject.principal_id = principal.id
    JOIN mesh.identity_provider AS provider
      ON provider.deployment_id = subject.deployment_id AND provider.id = subject.identity_provider_id
    JOIN mesh.identity_provider_client AS client
      ON client.deployment_id = subject.deployment_id AND client.identity_provider_id = provider.id
    JOIN mesh.workspace_identity_provider AS route
      ON route.deployment_id = subject.deployment_id
     AND route.workspace_id = workspace.id
     AND route.identity_provider_id = provider.id
     AND route.identity_provider_client_id = client.id
     AND route.state = 'active' AND route.deleted_at IS NULL
     AND route.organization_digest_algorithm IS NULL
     AND route.organization_digest_key_id IS NULL AND route.organization_digest IS NULL
    WHERE principal.id = p_principal_id
      AND subject.state = 'active'
      AND provider.state = 'active'
      AND provider.recovery_state = 'verified'
      AND client.state = 'active'
    LIMIT 1
    FOR SHARE OF subject, provider, client, route;
    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    -- A role binding of the Network that grants the permission.
    PERFORM 1
    FROM mesh.principal AS principal
    JOIN mesh.account AS account
      ON account.deployment_id = principal.deployment_id AND account.principal_id = principal.id
    JOIN mesh.workspace AS workspace
      ON workspace.deployment_id = principal.deployment_id AND workspace.id = p_workspace_id
    JOIN mesh.deployment AS deployment ON deployment.id = workspace.deployment_id
    JOIN mesh.network AS network ON network.workspace_id = workspace.id AND network.id = p_network_id
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = workspace.deployment_id
     AND membership.workspace_id = workspace.id
     AND membership.principal_id = principal.id
    JOIN mesh.role_binding AS binding
      ON binding.deployment_id = workspace.deployment_id
     AND binding.workspace_id = workspace.id
     AND binding.network_id = network.id
     AND binding.principal_id = principal.id
     AND binding.workspace_membership_id = membership.id
    JOIN mesh.role_definition AS role_definition
      ON role_definition.deployment_id = workspace.deployment_id
     AND role_definition.workspace_id = workspace.id
     AND role_definition.id = binding.role_definition_id
    JOIN mesh.role_permission AS role_permission
      ON role_permission.deployment_id = workspace.deployment_id
     AND role_permission.workspace_id = workspace.id
     AND role_permission.role_definition_id = role_definition.id
    JOIN mesh.permission AS permission
      ON permission.id = role_permission.permission_id
     AND permission.permission_key = p_permission_key
     AND 'network' = ANY(permission.allowed_scope_kinds)
    WHERE principal.id = p_principal_id
      AND principal.state = 'active'
      AND account.recovery_state = 'verified'
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND workspace.state = 'active'
      AND network.state = 'active'
      AND membership.state = 'active'
      AND membership.valid_from <= p_evaluated_at
      AND (membership.expires_at IS NULL OR membership.expires_at > p_evaluated_at)
      AND binding.state = 'active'
      AND binding.valid_from <= p_evaluated_at
      AND (binding.expires_at IS NULL OR binding.expires_at > p_evaluated_at)
      AND role_definition.state = 'active'
      AND role_permission.state = 'active'
    LIMIT 1
    FOR SHARE OF principal, account, deployment, network, membership, binding, role_definition,
        role_permission;
    IF FOUND THEN
        RETURN TRUE;
    END IF;

    -- A built-in role assigned for the Workspace (every Network) or for
    -- this Network.
    PERFORM 1
    FROM mesh.principal AS principal
    JOIN mesh.account AS account
      ON account.deployment_id = principal.deployment_id AND account.principal_id = principal.id
    JOIN mesh.workspace AS workspace
      ON workspace.deployment_id = principal.deployment_id AND workspace.id = p_workspace_id
    JOIN mesh.deployment AS deployment ON deployment.id = workspace.deployment_id
    JOIN mesh.network AS network ON network.workspace_id = workspace.id AND network.id = p_network_id
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = workspace.deployment_id
     AND membership.workspace_id = workspace.id
     AND membership.principal_id = principal.id
    JOIN mesh.permission AS permission
      ON permission.permission_key = p_permission_key
     AND 'network' = ANY(permission.allowed_scope_kinds)
    JOIN mesh.workspace_role_assignment AS assignment
      ON assignment.deployment_id = workspace.deployment_id
     AND assignment.workspace_id = workspace.id
     AND assignment.principal_id = principal.id
     AND assignment.workspace_membership_id = membership.id
     AND (assignment.network_id IS NULL OR assignment.network_id = network.id)
    JOIN mesh.builtin_role AS role ON role.role_key = assignment.role_key
    JOIN mesh.builtin_role_permission AS role_permission
      ON role_permission.role_key = role.role_key
     AND role_permission.permission_id = permission.id
    WHERE principal.id = p_principal_id
      AND principal.state = 'active'
      AND principal.kind = 'account'
      AND account.recovery_state = 'verified'
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND workspace.state = 'active'
      AND network.state = 'active'
      AND membership.state = 'active'
      AND membership.valid_from <= p_evaluated_at
      AND (membership.expires_at IS NULL OR membership.expires_at > p_evaluated_at)
      AND assignment.state = 'active'
      AND assignment.valid_from <= p_evaluated_at
      AND (assignment.expires_at IS NULL OR assignment.expires_at > p_evaluated_at)
    LIMIT 1
    FOR SHARE OF principal, account, deployment, network, membership, assignment;
    IF FOUND THEN
        RETURN TRUE;
    END IF;

    -- The Workspace owner holds every Network permission while a member.
    PERFORM 1
    FROM mesh.principal AS principal
    JOIN mesh.account AS account
      ON account.deployment_id = principal.deployment_id AND account.principal_id = principal.id
    JOIN mesh.workspace AS workspace
      ON workspace.deployment_id = principal.deployment_id AND workspace.id = p_workspace_id
    JOIN mesh.deployment AS deployment ON deployment.id = workspace.deployment_id
    JOIN mesh.network AS network ON network.workspace_id = workspace.id AND network.id = p_network_id
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = workspace.deployment_id
     AND membership.workspace_id = workspace.id
     AND membership.principal_id = principal.id
    JOIN mesh.permission AS permission
      ON permission.permission_key = p_permission_key
     AND 'network' = ANY(permission.allowed_scope_kinds)
    WHERE principal.id = p_principal_id
      AND principal.state = 'active'
      AND principal.kind = 'account'
      AND workspace.owner_principal_id = principal.id
      AND account.recovery_state = 'verified'
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND workspace.state = 'active'
      AND network.state = 'active'
      AND membership.state = 'active'
      AND membership.valid_from <= p_evaluated_at
      AND (membership.expires_at IS NULL OR membership.expires_at > p_evaluated_at)
    LIMIT 1
    FOR SHARE OF principal, account, deployment, network, membership;
    RETURN FOUND;
END;
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_principal_holds_permission_internal_v1(
    BIGINT, BIGINT, BIGINT, TEXT, TIMESTAMPTZ
) FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- kubejoin.ClusterTrustDigest: SHA-256 over the label, a NUL, then each
-- field with its length big-endian (16 bits; 32 bits for the JWKS) before
-- its bytes. The names are ASCII and at most 253 bytes, so int2send is safe
-- (a longer one raises). STRICT: a NULL input gives NULL, so callers compare
-- with IS DISTINCT FROM.
CREATE FUNCTION mesh_ops.kubernetes_cluster_trust_digest_v1(
    p_issuer TEXT, p_jwks BYTEA, p_namespace TEXT, p_service_account TEXT, p_statefulset TEXT
)
RETURNS BYTEA
LANGUAGE sql
STABLE
STRICT
PARALLEL SAFE
SET search_path = pg_catalog
AS $function$
    SELECT pg_catalog.sha256(
        pg_catalog.convert_to('meshtransit/kube-cluster-trust/v1', 'UTF8') || '\x00'::BYTEA
        || pg_catalog.int2send(pg_catalog.octet_length(p_issuer)::SMALLINT) || pg_catalog.convert_to(p_issuer, 'UTF8')
        || pg_catalog.int4send(pg_catalog.octet_length(p_jwks)) || p_jwks
        || pg_catalog.int2send(pg_catalog.octet_length(p_namespace)::SMALLINT)
        || pg_catalog.convert_to(p_namespace, 'UTF8')
        || pg_catalog.int2send(pg_catalog.octet_length(p_service_account)::SMALLINT)
        || pg_catalog.convert_to(p_service_account, 'UTF8')
        || pg_catalog.int2send(pg_catalog.octet_length(p_statefulset)::SMALLINT)
        || pg_catalog.convert_to(p_statefulset, 'UTF8'))
$function$;
REVOKE ALL ON FUNCTION mesh_ops.kubernetes_cluster_trust_digest_v1(TEXT, BYTEA, TEXT, TEXT, TEXT)
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- One install-token approval per pod token (jti), whatever the cluster.
CREATE TABLE mesh_ops.kubernetes_join_token_use (
    kubernetes_cluster_id BIGINT NOT NULL,
    jti TEXT NOT NULL CHECK (pg_catalog.octet_length(jti) BETWEEN 1 AND 128 AND jti ~ '^[!-~]+$'),
    replica_request_id BIGINT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (jti)
);
CREATE INDEX kubernetes_join_token_use_expiry_idx ON mesh_ops.kubernetes_join_token_use (expires_at);
ALTER TABLE mesh_ops.kubernetes_join_token_use ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh_ops.kubernetes_join_token_use FORCE ROW LEVEL SECURITY;
CREATE POLICY kubernetes_join_token_use_migrator_policy ON mesh_ops.kubernetes_join_token_use
    TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);
REVOKE ALL ON mesh_ops.kubernetes_join_token_use
    FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

-- A gateway resumed after a contest joins its cluster's group again (the
-- join of schema 230 runs on insert only; its release on leaving active).
CREATE TRIGGER device_kubernetes_group_rejoin
AFTER UPDATE OF state ON mesh.device
FOR EACH ROW WHEN (OLD.kind = 'kubernetes_gateway' AND OLD.state = 'suspended' AND NEW.state = 'active')
EXECUTE FUNCTION mesh_ops.join_kubernetes_cluster_group_v1();
