-- Schema 315 (TD-SEC-105): the Policy publication gate decides at the
-- transaction's own time. lock_policy_approval_for_publication_v1 checked the
-- approval evidence window and the approver session's expiry against the
-- caller's p_evaluated_at, and consume_policy_approval_for_publication_v1
-- checked the evidence window against (and stamped consumed_at with) the
-- caller's p_occurred_at: a compromised api could pass a past time and
-- publish a Network's Policy on expired approval evidence or an expired
-- approver session. Core always passes the transaction's time
-- (readTransactionTime). As schemas 181 and 314 did, the parameters stay in
-- the signatures and are only checked to be sent. The bodies are schema
-- 048's otherwise; restating a function drops the planner settings schema 107
-- gave the lock function, so they are set again.

CREATE OR REPLACE FUNCTION mesh_ops.lock_policy_approval_for_publication_v1(
    p_evidence_public_id UUID,
    p_evaluated_at TIMESTAMPTZ
)
RETURNS TABLE (
    request_public_id UUID,
    evidence_public_id UUID,
    baseline_network BIGINT,
    baseline_inventory BIGINT,
    baseline_group BIGINT,
    baseline_policy BIGINT,
    baseline_dns BIGINT,
    baseline_route BIGINT,
    baseline_sharing BIGINT,
    baseline_isolation BIGINT,
    proposed_network BIGINT,
    proposed_inventory BIGINT,
    proposed_group BIGINT,
    proposed_policy BIGINT,
    proposed_dns BIGINT,
    proposed_route BIGINT,
    proposed_sharing BIGINT,
    proposed_isolation BIGINT,
    candidate_hash BYTEA,
    compiler_format INTEGER,
    simulation_impact_hash BYTEA,
    approved_request_version BIGINT,
    approval_evidence_version BIGINT,
    evidence_approved_at TIMESTAMPTZ,
    evidence_expires_at TIMESTAMPTZ,
    approver_session_public_id UUID,
    deployment_public_id UUID,
    approver_principal_public_id UUID,
    identity_subject_public_id UUID,
    approver_session_version BIGINT,
    approver_principal_generation BIGINT,
    approver_account_generation BIGINT,
    approver_provider_generation BIGINT,
    approver_recovery_epoch BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
BEGIN
    IF p_evidence_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_evidence_public_id), 6) >> 4 <> 7
        OR p_evaluated_at IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid Policy approval publication input';
    END IF;

    RETURN QUERY
    SELECT
        request.public_id,
        evidence.public_id,
        request.baseline_network_revision,
        request.baseline_inventory_revision,
        request.baseline_group_revision,
        request.baseline_policy_revision,
        request.baseline_dns_revision,
        request.baseline_route_revision,
        request.baseline_sharing_revision,
        request.baseline_isolation_generation,
        request.proposed_network_revision,
        request.proposed_inventory_revision,
        request.proposed_group_revision,
        request.proposed_policy_revision,
        request.proposed_dns_revision,
        request.proposed_route_revision,
        request.proposed_sharing_revision,
        request.proposed_isolation_generation,
        request.candidate_semantic_hash,
        request.compiler_format_version,
        request.impact_hash,
        request.version,
        evidence.version,
        evidence.approved_at,
        evidence.expires_at,
        session.public_id,
        deployment.installation_public_id,
        approver.public_id,
        subject.public_id,
        evidence.approver_session_version,
        evidence.approver_principal_generation,
        evidence.approver_account_generation,
        evidence.approver_provider_generation,
        evidence.approver_recovery_epoch
    FROM mesh.policy_approval_evidence AS evidence
    JOIN mesh.policy_approval_request AS request
      ON request.workspace_id = evidence.workspace_id
     AND request.network_id = evidence.network_id
     AND request.id = evidence.request_id
    JOIN mesh.workspace AS workspace
      ON workspace.deployment_id = request.deployment_id
     AND workspace.id = request.workspace_id
    JOIN mesh.deployment AS deployment
      ON deployment.id = request.deployment_id
    JOIN mesh.principal AS approver
      ON approver.deployment_id = evidence.deployment_id
     AND approver.id = evidence.approver_principal_id
    JOIN mesh.account_session AS session
      ON session.deployment_id = evidence.deployment_id
     AND session.principal_id = evidence.approver_principal_id
     AND session.id = evidence.approver_account_session_id
    JOIN mesh.identity_subject AS subject
      ON subject.deployment_id = session.deployment_id
     AND subject.identity_provider_id = session.identity_provider_id
     AND subject.principal_id = session.principal_id
     AND subject.id = session.identity_subject_id
    WHERE request.workspace_id = mesh_ops.current_workspace_id()
      AND request.network_id = mesh_ops.current_network_id()
      AND evidence.public_id = p_evidence_public_id
      AND request.state = 'approved'
      AND request.version = 2
      AND request.approval_count = request.required_approvals
      AND evidence.request_version = request.version
      AND evidence.version = 1
      AND evidence.approved_at = request.approved_at
      AND evidence.expires_at = request.expires_at
      AND pg_catalog.transaction_timestamp() >= evidence.approved_at
      AND pg_catalog.transaction_timestamp() < evidence.expires_at
      AND request.proposer_principal_id <> evidence.approver_principal_id
      AND request.proposer_account_session_id <> evidence.approver_account_session_id
      AND workspace.state = 'active'
      AND deployment.state = 'active'
      AND deployment.recovery_state = 'verified'
      AND deployment.recovery_epoch = evidence.approver_recovery_epoch
      AND approver.state = 'active'
      AND approver.authority_generation = evidence.approver_principal_generation
      AND session.state = 'active'
      AND session.version = evidence.approver_session_version
      AND session.principal_authority_generation = evidence.approver_principal_generation
      AND session.account_session_generation = evidence.approver_account_generation
      AND session.provider_generation = evidence.approver_provider_generation
      AND session.deployment_recovery_epoch = evidence.approver_recovery_epoch
      AND session.authentication_time <= pg_catalog.transaction_timestamp()
      AND session.idle_expires_at > pg_catalog.transaction_timestamp()
      AND session.absolute_expires_at > pg_catalog.transaction_timestamp()
      AND subject.state = 'active'
    FOR UPDATE OF request
    FOR SHARE OF evidence, workspace, deployment, approver, session, subject;
END;
$function$;

ALTER FUNCTION mesh_ops.lock_policy_approval_for_publication_v1(uuid, timestamp with time zone)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;

CREATE OR REPLACE FUNCTION mesh_ops.consume_policy_approval_for_publication_v1(
    p_evidence_public_id UUID,
    p_release_public_id UUID,
    p_candidate_hash BYTEA,
    p_compiler_format INTEGER,
    p_impact_hash BYTEA,
    p_occurred_at TIMESTAMPTZ
)
RETURNS BIGINT
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    request_row mesh.policy_approval_request%ROWTYPE;
    evidence_row mesh.policy_approval_evidence%ROWTYPE;
    release_row mesh.policy_release%ROWTYPE;
    current_network BIGINT;
    current_inventory BIGINT;
    current_group BIGINT;
    current_policy BIGINT;
    current_dns BIGINT;
    current_route BIGINT;
    current_sharing BIGINT;
    current_isolation BIGINT;
    consumed_version BIGINT;
BEGIN
    IF p_evidence_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_evidence_public_id), 6) >> 4 <> 7
        OR p_release_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_release_public_id), 6) >> 4 <> 7
        OR p_candidate_hash IS NULL
        OR pg_catalog.octet_length(p_candidate_hash) <> 32
        OR p_candidate_hash = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_compiler_format <= 0
        OR p_compiler_format > 65535
        OR p_impact_hash IS NULL
        OR pg_catalog.octet_length(p_impact_hash) <> 32
        OR p_impact_hash = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_occurred_at IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '22023',
            MESSAGE = 'invalid Policy approval consumption input';
    END IF;

    SELECT request.*
    INTO request_row
    FROM mesh.policy_approval_request AS request
    JOIN mesh.policy_approval_evidence AS evidence
      ON evidence.workspace_id = request.workspace_id
     AND evidence.network_id = request.network_id
     AND evidence.request_id = request.id
    WHERE request.workspace_id = mesh_ops.current_workspace_id()
      AND request.network_id = mesh_ops.current_network_id()
      AND evidence.public_id = p_evidence_public_id
    FOR UPDATE OF request
    FOR SHARE OF evidence;

    IF request_row.id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'Policy approval evidence is unavailable';
    END IF;

    SELECT evidence.*
    INTO evidence_row
    FROM mesh.policy_approval_evidence AS evidence
    WHERE evidence.workspace_id = request_row.workspace_id
      AND evidence.network_id = request_row.network_id
      AND evidence.request_id = request_row.id
      AND evidence.public_id = p_evidence_public_id;

    IF evidence_row.id IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = '42501',
            MESSAGE = 'Policy approval evidence is unavailable';
    END IF;
    IF request_row.state <> 'approved'
        OR request_row.version <> 2
        OR request_row.approval_count <> request_row.required_approvals
        OR evidence_row.request_version <> request_row.version
        OR evidence_row.version <> 1 THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT003',
            MESSAGE = 'Policy approval evidence is not consumable';
    END IF;
    IF pg_catalog.transaction_timestamp() < evidence_row.approved_at
        OR pg_catalog.transaction_timestamp() >= evidence_row.expires_at
        OR evidence_row.approved_at <> request_row.approved_at
        OR evidence_row.expires_at <> request_row.expires_at THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT008',
            MESSAGE = 'Policy approval evidence expired';
    END IF;
    IF request_row.candidate_semantic_hash <> p_candidate_hash
        OR request_row.compiler_format_version <> p_compiler_format THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT009',
            MESSAGE = 'Policy approval candidate changed';
    END IF;
    IF request_row.impact_hash <> p_impact_hash THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT006',
            MESSAGE = 'Policy approval impact changed';
    END IF;

    SELECT revision.network_revision, revision.inventory_revision,
           revision.group_revision, revision.policy_revision,
           revision.dns_revision, revision.route_revision,
           revision.sharing_revision, revision.isolation_generation
    INTO current_network, current_inventory, current_group, current_policy,
         current_dns, current_route, current_sharing, current_isolation
    FROM mesh_ops.lock_network_revision() AS revision;

    IF current_network IS NULL
        OR current_network <> request_row.proposed_network_revision
        OR current_inventory <> request_row.proposed_inventory_revision
        OR current_group <> request_row.proposed_group_revision
        OR current_policy <> request_row.proposed_policy_revision
        OR current_dns <> request_row.proposed_dns_revision
        OR current_route <> request_row.proposed_route_revision
        OR current_sharing <> request_row.proposed_sharing_revision
        OR current_isolation <> request_row.proposed_isolation_generation THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT011',
            MESSAGE = 'Policy approval authority vector changed';
    END IF;

    SELECT release.*
    INTO release_row
    FROM mesh.policy_release AS release
    WHERE release.workspace_id = mesh_ops.current_workspace_id()
      AND release.network_id = mesh_ops.current_network_id()
      AND release.public_id = p_release_public_id
    FOR SHARE;

    IF release_row.id IS NULL
        OR release_row.state <> 'active'
        OR release_row.version <> 1
        OR release_row.semantic_hash <> p_candidate_hash
        OR release_row.compiler_format_version <> p_compiler_format
        OR release_row.policy_revision <> current_policy
        OR release_row.activated_network_revision <> current_network THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT011',
            MESSAGE = 'Policy release does not match approval evidence';
    END IF;

    UPDATE mesh.policy_approval_request AS request
    SET state = 'consumed',
        version = 3,
        consumed_at = pg_catalog.transaction_timestamp(),
        consumed_policy_release_id = release_row.id,
        consumed_policy_revision = release_row.policy_revision,
        updated_at = pg_catalog.transaction_timestamp()
    WHERE request.id = request_row.id
      AND request.workspace_id = mesh_ops.current_workspace_id()
      AND request.network_id = mesh_ops.current_network_id()
      AND request.state = 'approved'
      AND request.version = 2
    RETURNING request.version INTO consumed_version;

    IF consumed_version IS NULL THEN
        RAISE EXCEPTION USING
            ERRCODE = 'MT003',
            MESSAGE = 'Policy approval evidence was already consumed';
    END IF;
    RETURN consumed_version;
END;
$function$;
