-- Schema 316 (TD-SEC-105): Policy approval requests and the Resource
-- authority functions decide at the transaction's own time. Each checked the
-- actor's session or membership validity (and, for the two-person
-- workflows, the request's expiry) against the caller's p_occurred_at and
-- stamped rows and evidence with it: a compromised api could act on an
-- expired session or membership, or move the ten-minute freshness window of
-- an approval, by passing a chosen time. Core always passes the
-- transaction's time (readTransactionTime). As schemas 181, 314 and 315 did,
-- p_occurred_at stays in the signatures, checked only to be sent where it
-- was before (the two Policy approval functions never checked it, and now
-- ignore it); a request's p_expires_at must still be ten minutes after the
-- (now database) time. The bodies are their latest definitions' otherwise; restating a
-- function drops planner settings, so schema 107's are set again.

-- From schema 000047.
CREATE OR REPLACE FUNCTION mesh_ops.create_policy_approval_request_v1(
    p_request_public_id UUID,
    p_change_public_id UUID,
    p_session_public_id UUID,
    p_deployment_public_id UUID,
    p_principal_public_id UUID,
    p_session_version BIGINT,
    p_principal_generation BIGINT,
    p_account_generation BIGINT,
    p_provider_generation BIGINT,
    p_recovery_epoch BIGINT,
    p_baseline_network BIGINT,
    p_baseline_inventory BIGINT,
    p_baseline_group BIGINT,
    p_baseline_policy BIGINT,
    p_baseline_dns BIGINT,
    p_baseline_route BIGINT,
    p_baseline_sharing BIGINT,
    p_baseline_isolation BIGINT,
    p_proposed_network BIGINT,
    p_proposed_inventory BIGINT,
    p_proposed_group BIGINT,
    p_proposed_policy BIGINT,
    p_proposed_dns BIGINT,
    p_proposed_route BIGINT,
    p_proposed_sharing BIGINT,
    p_proposed_isolation BIGINT,
    p_candidate_hash BYTEA,
    p_compiler_format INTEGER,
    p_impact_hash BYTEA,
    p_request_hash BYTEA,
    p_reason TEXT,
    p_occurred_at TIMESTAMPTZ,
    p_expires_at TIMESTAMPTZ
)
RETURNS BIGINT
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
    scoped_deployment_id BIGINT;
    proposer_principal_id BIGINT;
    proposer_session_id BIGINT;
    inserted_version BIGINT;
    current_network BIGINT;
    current_inventory BIGINT;
    current_group BIGINT;
    current_policy BIGINT;
    current_dns BIGINT;
    current_route BIGINT;
    current_sharing BIGINT;
    current_isolation BIGINT;
BEGIN
    scoped_workspace_id := mesh_ops.current_workspace_id();
    scoped_network_id := mesh_ops.current_network_id();
    IF p_expires_at <> pg_catalog.transaction_timestamp() + INTERVAL '10 minutes'
        OR p_proposed_network <> p_baseline_network + 1
        OR p_proposed_policy <> p_baseline_policy + 1
        OR p_proposed_inventory <> p_baseline_inventory
        OR p_proposed_group <> p_baseline_group
        OR p_proposed_dns <> p_baseline_dns
        OR p_proposed_route <> p_baseline_route
        OR p_proposed_sharing <> p_baseline_sharing
        OR p_proposed_isolation <> p_baseline_isolation THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Policy approval request input';
    END IF;
    SELECT workspace.deployment_id, principal.id, session.id
    INTO scoped_deployment_id, proposer_principal_id, proposer_session_id
    FROM mesh.workspace AS workspace
    JOIN mesh.principal AS principal
      ON principal.deployment_id = workspace.deployment_id
     AND principal.public_id = p_principal_public_id
     AND principal.state = 'active'
    JOIN mesh.account_session AS session
      ON session.deployment_id = principal.deployment_id
     AND session.principal_id = principal.id
     AND session.public_id = p_session_public_id
     AND session.state = 'active'
    JOIN mesh.deployment AS deployment
      ON deployment.id = workspace.deployment_id
     AND deployment.installation_public_id = p_deployment_public_id
     AND deployment.recovery_epoch = p_recovery_epoch
    WHERE workspace.id = scoped_workspace_id
      AND workspace.state = 'active'
      AND session.login_workspace_id = workspace.id
      AND session.version = p_session_version
      AND session.principal_authority_generation = p_principal_generation
      AND session.account_session_generation = p_account_generation
      AND session.provider_generation = p_provider_generation
      AND session.deployment_recovery_epoch = p_recovery_epoch
      AND session.idle_expires_at > pg_catalog.transaction_timestamp()
      AND session.absolute_expires_at > pg_catalog.transaction_timestamp()
    FOR SHARE OF workspace, principal, session, deployment;
    IF scoped_deployment_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Policy approval proposer is unavailable';
    END IF;
    SELECT revision.network_revision, revision.inventory_revision,
           revision.group_revision, revision.policy_revision,
           revision.dns_revision, revision.route_revision,
           revision.sharing_revision, revision.isolation_generation
    INTO current_network, current_inventory, current_group, current_policy,
         current_dns, current_route, current_sharing, current_isolation
    FROM mesh_ops.lock_network_revision() AS revision;
    IF current_network IS NULL
        OR current_network <> p_baseline_network
        OR current_inventory <> p_baseline_inventory
        OR current_group <> p_baseline_group
        OR current_policy <> p_baseline_policy
        OR current_dns <> p_baseline_dns
        OR current_route <> p_baseline_route
        OR current_sharing <> p_baseline_sharing
        OR current_isolation <> p_baseline_isolation THEN
        RAISE EXCEPTION USING ERRCODE = 'MT006', MESSAGE = 'Policy approval baseline changed';
    END IF;
    INSERT INTO mesh.policy_approval_request (
        public_id, change_public_id, deployment_id, workspace_id, network_id,
        proposer_principal_id, proposer_account_session_id,
        proposer_session_version, proposer_principal_generation,
        proposer_account_generation, proposer_provider_generation, proposer_recovery_epoch,
        baseline_network_revision, baseline_inventory_revision, baseline_group_revision,
        baseline_policy_revision, baseline_dns_revision, baseline_route_revision,
        baseline_sharing_revision, baseline_isolation_generation,
        proposed_network_revision, proposed_inventory_revision, proposed_group_revision,
        proposed_policy_revision, proposed_dns_revision, proposed_route_revision,
        proposed_sharing_revision, proposed_isolation_generation,
        candidate_semantic_hash, compiler_format_version, impact_hash,
        proposal_request_hash, proposal_reason, required_approvals, approval_count,
        state, version, created_at, expires_at, updated_at
    ) VALUES (
        p_request_public_id, p_change_public_id, scoped_deployment_id,
        scoped_workspace_id, scoped_network_id, proposer_principal_id, proposer_session_id,
        p_session_version, p_principal_generation, p_account_generation,
        p_provider_generation, p_recovery_epoch,
        p_baseline_network, p_baseline_inventory, p_baseline_group, p_baseline_policy,
        p_baseline_dns, p_baseline_route, p_baseline_sharing, p_baseline_isolation,
        p_proposed_network, p_proposed_inventory, p_proposed_group, p_proposed_policy,
        p_proposed_dns, p_proposed_route, p_proposed_sharing, p_proposed_isolation,
        p_candidate_hash, p_compiler_format, p_impact_hash, p_request_hash, p_reason,
        1, 0, 'pending', 1, pg_catalog.transaction_timestamp(), p_expires_at, pg_catalog.transaction_timestamp()
    ) RETURNING version INTO inserted_version;
    RETURN inserted_version;
END;
$function$;

ALTER FUNCTION mesh_ops.create_policy_approval_request_v1(uuid, uuid, uuid, uuid, uuid, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint, bytea, integer, bytea, bytea, text, timestamp with time zone, timestamp with time zone)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;

-- From schema 000047.
CREATE OR REPLACE FUNCTION mesh_ops.approve_policy_approval_request_v1(
    p_evidence_public_id UUID,
    p_change_public_id UUID,
    p_request_public_id UUID,
    p_expected_request_version BIGINT,
    p_candidate_hash BYTEA,
    p_impact_hash BYTEA,
    p_session_public_id UUID,
    p_deployment_public_id UUID,
    p_principal_public_id UUID,
    p_session_version BIGINT,
    p_principal_generation BIGINT,
    p_account_generation BIGINT,
    p_provider_generation BIGINT,
    p_recovery_epoch BIGINT,
    p_decision_hash BYTEA,
    p_reason TEXT,
    p_occurred_at TIMESTAMPTZ
)
RETURNS TABLE (approved_request_version BIGINT, approval_evidence_version BIGINT)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
    scoped_deployment_id BIGINT;
    approver_principal_id BIGINT;
    approver_session_id BIGINT;
    request_row mesh.policy_approval_request%ROWTYPE;
BEGIN
    scoped_workspace_id := mesh_ops.current_workspace_id();
    scoped_network_id := mesh_ops.current_network_id();
    SELECT workspace.deployment_id, principal.id, session.id
    INTO scoped_deployment_id, approver_principal_id, approver_session_id
    FROM mesh.workspace AS workspace
    JOIN mesh.principal AS principal
      ON principal.deployment_id = workspace.deployment_id
     AND principal.public_id = p_principal_public_id
     AND principal.state = 'active'
    JOIN mesh.account_session AS session
      ON session.deployment_id = principal.deployment_id
     AND session.principal_id = principal.id
     AND session.public_id = p_session_public_id
     AND session.state = 'active'
    JOIN mesh.deployment AS deployment
      ON deployment.id = workspace.deployment_id
     AND deployment.installation_public_id = p_deployment_public_id
     AND deployment.recovery_epoch = p_recovery_epoch
    WHERE workspace.id = scoped_workspace_id
      AND workspace.state = 'active'
      AND session.login_workspace_id = workspace.id
      AND session.version = p_session_version
      AND session.principal_authority_generation = p_principal_generation
      AND session.account_session_generation = p_account_generation
      AND session.provider_generation = p_provider_generation
      AND session.deployment_recovery_epoch = p_recovery_epoch
      AND session.idle_expires_at > pg_catalog.transaction_timestamp()
      AND session.absolute_expires_at > pg_catalog.transaction_timestamp()
    FOR SHARE OF workspace, principal, session, deployment;
    IF scoped_deployment_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Policy approver is unavailable';
    END IF;
    SELECT request.* INTO request_row
    FROM mesh.policy_approval_request AS request
    WHERE request.workspace_id = scoped_workspace_id
      AND request.network_id = scoped_network_id
      AND request.public_id = p_request_public_id
    FOR UPDATE;
    IF request_row.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Policy approval request is unavailable';
    END IF;
    IF request_row.version <> p_expected_request_version THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'Policy approval request version changed';
    END IF;
    IF request_row.state <> 'pending' THEN
        RAISE EXCEPTION USING ERRCODE = 'MT003', MESSAGE = 'Policy approval request is not pending';
    END IF;
    IF pg_catalog.transaction_timestamp() >= request_row.expires_at THEN
        RAISE EXCEPTION USING ERRCODE = 'MT008', MESSAGE = 'Policy approval request expired';
    END IF;
    IF request_row.candidate_semantic_hash <> p_candidate_hash THEN
        RAISE EXCEPTION USING ERRCODE = 'MT009', MESSAGE = 'Policy approval candidate changed';
    END IF;
    IF request_row.impact_hash <> p_impact_hash THEN
        RAISE EXCEPTION USING ERRCODE = 'MT006', MESSAGE = 'Policy approval impact changed';
    END IF;
    IF request_row.proposer_principal_id = approver_principal_id
        OR request_row.proposer_account_session_id = approver_session_id THEN
        RAISE EXCEPTION USING ERRCODE = 'MT010', MESSAGE = 'independent Policy approver required';
    END IF;
    UPDATE mesh.policy_approval_request AS request
    SET approval_count = 1, state = 'approved', version = 2,
        approved_at = pg_catalog.transaction_timestamp(), updated_at = pg_catalog.transaction_timestamp()
    WHERE request.id = request_row.id
      AND request.version = p_expected_request_version
      AND request.state = 'pending'
    RETURNING request.version INTO approved_request_version;
    IF approved_request_version IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'Policy approval request changed';
    END IF;
    INSERT INTO mesh.policy_approval_evidence (
        public_id, change_public_id, deployment_id, workspace_id, network_id,
        request_id, request_version, approver_principal_id, approver_account_session_id,
        approver_session_version, approver_principal_generation,
        approver_account_generation, approver_provider_generation, approver_recovery_epoch,
        decision_hash, decision_reason, version, approved_at, expires_at, created_at
    ) VALUES (
        p_evidence_public_id, p_change_public_id, scoped_deployment_id,
        scoped_workspace_id, scoped_network_id, request_row.id, approved_request_version,
        approver_principal_id, approver_session_id, p_session_version,
        p_principal_generation, p_account_generation, p_provider_generation, p_recovery_epoch,
        p_decision_hash, p_reason, 1, pg_catalog.transaction_timestamp(), request_row.expires_at, pg_catalog.transaction_timestamp()
    ) RETURNING version INTO approval_evidence_version;
    RETURN NEXT;
END;
$function$;

ALTER FUNCTION mesh_ops.approve_policy_approval_request_v1(uuid, uuid, uuid, bigint, bytea, bytea, uuid, uuid, uuid, bigint, bigint, bigint, bigint, bigint, bytea, text, timestamp with time zone)
    SET join_collapse_limit = 1 SET from_collapse_limit = 1 SET plan_cache_mode = force_generic_plan;

-- From schema 000042.
CREATE OR REPLACE FUNCTION mesh_ops.request_resource_authority_change_v1(
    p_request_public_id UUID,
    p_step_up_evidence_public_id UUID,
    p_subject_kind TEXT,
    p_subject_public_id UUID,
    p_action TEXT,
    p_expected_subject_version BIGINT,
    p_target_principal_public_id UUID,
    p_actor_principal_public_id UUID,
    p_actor_account_session_public_id UUID,
    p_impact_hash BYTEA,
    p_occurred_at TIMESTAMPTZ,
    p_expires_at TIMESTAMPTZ
)
RETURNS TABLE (
    network_revision BIGINT,
    subsystem_revision BIGINT,
    request_version BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
    scoped_deployment_id BIGINT;
    subject_resource_id BIGINT;
    subject_group_id BIGINT;
    subject_version BIGINT;
    subject_state TEXT;
    current_owner_id BIGINT;
    current_custodian_id BIGINT;
    proposed_owner_id BIGINT;
    proposed_custodian_id BIGINT;
    target_principal_id BIGINT;
    actor_principal_id BIGINT;
    actor_session_id BIGINT;
    actor_authentication_time TIMESTAMPTZ;
    current_network_revision BIGINT;
    current_subsystem_revision BIGINT;
    advanced_network_revision BIGINT;
    advanced_subsystem_revision BIGINT;
    inserted_request_id BIGINT;
    inserted_request_version BIGINT;
BEGIN
    scoped_workspace_id := mesh_ops.current_workspace_id();
    scoped_network_id := mesh_ops.current_network_id();
    IF p_request_public_id IS NULL OR p_step_up_evidence_public_id IS NULL
        OR p_subject_public_id IS NULL OR p_target_principal_public_id IS NULL
        OR p_actor_principal_public_id IS NULL OR p_actor_account_session_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_request_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_step_up_evidence_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_subject_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_target_principal_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_actor_principal_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_actor_account_session_public_id), 6) >> 4 <> 7
        OR p_subject_kind NOT IN ('resource', 'resource_group')
        OR p_action NOT IN ('owner_transfer', 'custodian_delegation')
        OR p_expected_subject_version IS NULL OR p_expected_subject_version <= 0
        OR p_impact_hash IS NULL OR pg_catalog.octet_length(p_impact_hash) <> 32
        OR p_impact_hash = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_occurred_at IS NULL OR p_expires_at IS NULL
        OR p_expires_at <> pg_catalog.transaction_timestamp() + INTERVAL '10 minutes' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource authority change request input';
    END IF;
    SELECT workspace.deployment_id INTO scoped_deployment_id
    FROM mesh.workspace AS workspace
    WHERE workspace.id = scoped_workspace_id AND workspace.state = 'active'
    FOR SHARE;
    IF scoped_deployment_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Resource authority change scope is unavailable';
    END IF;
    SELECT step_up.account_session_id, step_up.principal_id, step_up.authentication_time
    INTO actor_session_id, actor_principal_id, actor_authentication_time
    FROM mesh_ops.require_resource_authority_step_up_v1(
        p_actor_account_session_public_id,
        p_actor_principal_public_id,
        pg_catalog.transaction_timestamp()
    ) AS step_up;
    IF actor_session_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT007', MESSAGE = 'fresh step-up evidence is required';
    END IF;
    SELECT principal.id INTO target_principal_id
    FROM mesh.principal AS principal
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = scoped_deployment_id
     AND membership.workspace_id = scoped_workspace_id
     AND membership.principal_id = principal.id
     AND membership.state = 'active'
     AND membership.valid_from <= pg_catalog.transaction_timestamp()
     AND (membership.expires_at IS NULL OR membership.expires_at > pg_catalog.transaction_timestamp())
    WHERE principal.deployment_id = scoped_deployment_id
      AND principal.public_id = p_target_principal_public_id
      AND principal.state = 'active'
    FOR SHARE OF principal, membership;
    IF target_principal_id IS NULL OR target_principal_id = actor_principal_id THEN
        RAISE EXCEPTION USING ERRCODE = 'MT005', MESSAGE = 'Resource authority target is unavailable';
    END IF;
    SELECT revision.network_revision,
           CASE WHEN p_subject_kind = 'resource'
                THEN revision.inventory_revision ELSE revision.group_revision END
    INTO current_network_revision, current_subsystem_revision
    FROM mesh_ops.lock_network_revision() AS revision;
    IF p_subject_kind = 'resource' THEN
        SELECT resource.id, resource.version, resource.state,
               resource.owner_principal_id, resource.custodian_principal_id
        INTO subject_resource_id, subject_version, subject_state,
             current_owner_id, current_custodian_id
        FROM mesh.resource AS resource
        WHERE resource.workspace_id = scoped_workspace_id
          AND resource.network_id = scoped_network_id
          AND resource.public_id = p_subject_public_id
          AND resource.kind = 'device'
        FOR UPDATE;
    ELSE
        SELECT resource_group.id, resource_group.version, resource_group.state,
               resource_group.owner_principal_id, resource_group.custodian_principal_id
        INTO subject_group_id, subject_version, subject_state,
             current_owner_id, current_custodian_id
        FROM mesh.resource_group AS resource_group
        WHERE resource_group.workspace_id = scoped_workspace_id
          AND resource_group.network_id = scoped_network_id
          AND resource_group.public_id = p_subject_public_id
        FOR UPDATE;
    END IF;
    IF subject_version IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT404', MESSAGE = 'Resource authority is unavailable';
    END IF;
    IF subject_version <> p_expected_subject_version THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'Resource authority version changed';
    END IF;
    IF subject_state = 'deleted' THEN
        RAISE EXCEPTION USING ERRCODE = 'MT004', MESSAGE = 'Resource authority cannot change';
    END IF;
    IF current_owner_id <> actor_principal_id THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'only the current owner can request authority change';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM mesh.resource_authority_change_request AS request
        WHERE request.workspace_id = scoped_workspace_id
          AND request.network_id = scoped_network_id
          AND request.state = 'pending'
          AND request.expires_at > pg_catalog.transaction_timestamp()
          AND (
              (p_subject_kind = 'resource' AND request.resource_id = subject_resource_id)
              OR
              (p_subject_kind = 'resource_group' AND request.resource_group_id = subject_group_id)
          )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MT005', MESSAGE = 'Resource authority change is already pending';
    END IF;
    proposed_owner_id := CASE WHEN p_action = 'owner_transfer'
                              THEN target_principal_id ELSE current_owner_id END;
    proposed_custodian_id := CASE WHEN p_action = 'custodian_delegation'
                                  THEN target_principal_id ELSE current_custodian_id END;
    IF proposed_owner_id = current_owner_id AND proposed_custodian_id = current_custodian_id THEN
        RAISE EXCEPTION USING ERRCODE = 'MT005', MESSAGE = 'Resource authority is unchanged';
    END IF;
    IF p_subject_kind = 'resource' THEN
        UPDATE mesh_ops.network_revision AS revision
        SET network_revision = revision.network_revision + 1,
            inventory_revision = revision.inventory_revision + 1,
            updated_at = pg_catalog.clock_timestamp()
        WHERE revision.workspace_id = scoped_workspace_id
          AND revision.network_id = scoped_network_id
          AND revision.network_revision = current_network_revision
          AND revision.inventory_revision = current_subsystem_revision
        RETURNING revision.network_revision, revision.inventory_revision
        INTO advanced_network_revision, advanced_subsystem_revision;
    ELSE
        UPDATE mesh_ops.network_revision AS revision
        SET network_revision = revision.network_revision + 1,
            group_revision = revision.group_revision + 1,
            updated_at = pg_catalog.clock_timestamp()
        WHERE revision.workspace_id = scoped_workspace_id
          AND revision.network_id = scoped_network_id
          AND revision.network_revision = current_network_revision
          AND revision.group_revision = current_subsystem_revision
        RETURNING revision.network_revision, revision.group_revision
        INTO advanced_network_revision, advanced_subsystem_revision;
    END IF;
    IF advanced_network_revision IS NULL OR advanced_subsystem_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Resource authority revision changed';
    END IF;
    INSERT INTO mesh.resource_authority_change_request (
        public_id, deployment_id, workspace_id, network_id, subject_kind,
        resource_id, resource_group_id, action, expected_subject_version,
        current_owner_principal_id, current_custodian_principal_id,
        proposed_owner_principal_id, proposed_custodian_principal_id,
        target_principal_id, requested_by_principal_id,
        requested_by_account_session_id, impact_hash,
        required_confirmations, confirmation_count, state,
        expires_at, created_at, updated_at
    ) VALUES (
        p_request_public_id, scoped_deployment_id, scoped_workspace_id, scoped_network_id,
        p_subject_kind, subject_resource_id, subject_group_id, p_action,
        p_expected_subject_version, current_owner_id, current_custodian_id,
        proposed_owner_id, proposed_custodian_id, target_principal_id,
        actor_principal_id, actor_session_id, p_impact_hash,
        1, 0, 'pending', p_expires_at, pg_catalog.transaction_timestamp(), pg_catalog.transaction_timestamp()
    ) RETURNING id, version INTO inserted_request_id, inserted_request_version;
    INSERT INTO mesh.resource_authority_step_up_evidence (
        public_id, deployment_id, workspace_id, network_id, request_id,
        account_session_id, principal_id, evidence_role,
        operation_semantic_hash, authentication_time, created_at
    ) VALUES (
        p_step_up_evidence_public_id, scoped_deployment_id, scoped_workspace_id,
        scoped_network_id, inserted_request_id, actor_session_id, actor_principal_id,
        'requester', p_impact_hash, actor_authentication_time, pg_catalog.transaction_timestamp()
    );
    network_revision := advanced_network_revision;
    subsystem_revision := advanced_subsystem_revision;
    request_version := inserted_request_version;
    RETURN NEXT;
END;
$function$;

-- From schema 000042.
CREATE OR REPLACE FUNCTION mesh_ops.confirm_resource_authority_change_v1(
    p_step_up_evidence_public_id UUID,
    p_request_public_id UUID,
    p_expected_request_version BIGINT,
    p_actor_principal_public_id UUID,
    p_actor_account_session_public_id UUID,
    p_impact_hash BYTEA,
    p_proposed_semantic_hash BYTEA,
    p_occurred_at TIMESTAMPTZ
)
RETURNS TABLE (
    network_revision BIGINT,
    subsystem_revision BIGINT,
    subject_version BIGINT,
    request_version BIGINT,
    owner_principal_public_id UUID,
    custodian_principal_public_id UUID,
    semantic_hash BYTEA
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
    request_row mesh.resource_authority_change_request%ROWTYPE;
    actor_session_id BIGINT;
    actor_principal_id BIGINT;
    actor_authentication_time TIMESTAMPTZ;
    current_subject_version BIGINT;
    current_subject_state TEXT;
    current_owner_id BIGINT;
    current_custodian_id BIGINT;
    current_semantic_hash BYTEA;
    current_network_revision BIGINT;
    current_subsystem_revision BIGINT;
    advanced_network_revision BIGINT;
    advanced_subsystem_revision BIGINT;
    advanced_subject_version BIGINT;
    advanced_request_version BIGINT;
BEGIN
    scoped_workspace_id := mesh_ops.current_workspace_id();
    scoped_network_id := mesh_ops.current_network_id();
    IF p_step_up_evidence_public_id IS NULL OR p_request_public_id IS NULL
        OR p_actor_principal_public_id IS NULL OR p_actor_account_session_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_step_up_evidence_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_request_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_actor_principal_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_actor_account_session_public_id), 6) >> 4 <> 7
        OR p_expected_request_version IS NULL OR p_expected_request_version <= 0
        OR p_impact_hash IS NULL OR pg_catalog.octet_length(p_impact_hash) <> 32
        OR p_proposed_semantic_hash IS NULL OR pg_catalog.octet_length(p_proposed_semantic_hash) <> 32
        OR p_impact_hash = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_proposed_semantic_hash = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_occurred_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource authority confirmation input';
    END IF;
    SELECT request.* INTO request_row
    FROM mesh.resource_authority_change_request AS request
    WHERE request.workspace_id = scoped_workspace_id
      AND request.network_id = scoped_network_id
      AND request.public_id = p_request_public_id
    FOR UPDATE;
    IF request_row.id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT404', MESSAGE = 'Resource authority change request is unavailable';
    END IF;
    IF request_row.version <> p_expected_request_version THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'Resource authority change request version changed';
    END IF;
    IF request_row.state <> 'pending' THEN
        RAISE EXCEPTION USING ERRCODE = 'MT004', MESSAGE = 'Resource authority change request is not pending';
    END IF;
    IF pg_catalog.transaction_timestamp() >= request_row.expires_at THEN
        RAISE EXCEPTION USING ERRCODE = 'MT008', MESSAGE = 'Resource authority change request expired';
    END IF;
    IF request_row.impact_hash <> p_impact_hash THEN
        RAISE EXCEPTION USING ERRCODE = 'MT006', MESSAGE = 'Resource authority change impact changed';
    END IF;
    SELECT step_up.account_session_id, step_up.principal_id, step_up.authentication_time
    INTO actor_session_id, actor_principal_id, actor_authentication_time
    FROM mesh_ops.require_resource_authority_step_up_v1(
        p_actor_account_session_public_id,
        p_actor_principal_public_id,
        pg_catalog.transaction_timestamp()
    ) AS step_up;
    IF actor_session_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT007', MESSAGE = 'fresh step-up evidence is required';
    END IF;
    IF actor_principal_id <> request_row.target_principal_id
        OR actor_principal_id = request_row.requested_by_principal_id
        OR actor_session_id = request_row.requested_by_account_session_id THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'independent confirmation is required';
    END IF;
    SELECT revision.network_revision,
           CASE WHEN request_row.subject_kind = 'resource'
                THEN revision.inventory_revision ELSE revision.group_revision END
    INTO current_network_revision, current_subsystem_revision
    FROM mesh_ops.lock_network_revision() AS revision;
    IF request_row.subject_kind = 'resource' THEN
        SELECT resource.version, resource.state, resource.owner_principal_id,
               resource.custodian_principal_id, resource.semantic_hash
        INTO current_subject_version, current_subject_state, current_owner_id,
             current_custodian_id, current_semantic_hash
        FROM mesh.resource AS resource
        WHERE resource.workspace_id = scoped_workspace_id
          AND resource.network_id = scoped_network_id
          AND resource.id = request_row.resource_id
        FOR UPDATE;
    ELSE
        SELECT resource_group.version, resource_group.state,
               resource_group.owner_principal_id, resource_group.custodian_principal_id,
               resource_group.semantic_hash
        INTO current_subject_version, current_subject_state, current_owner_id,
             current_custodian_id, current_semantic_hash
        FROM mesh.resource_group AS resource_group
        WHERE resource_group.workspace_id = scoped_workspace_id
          AND resource_group.network_id = scoped_network_id
          AND resource_group.id = request_row.resource_group_id
        FOR UPDATE;
    END IF;
    IF current_subject_version IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT404', MESSAGE = 'Resource authority is unavailable';
    END IF;
    IF current_subject_version <> request_row.expected_subject_version
        OR current_owner_id <> request_row.current_owner_principal_id
        OR current_custodian_id <> request_row.current_custodian_principal_id THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'Resource authority changed';
    END IF;
    IF current_subject_state = 'deleted' OR current_semantic_hash = p_proposed_semantic_hash THEN
        RAISE EXCEPTION USING ERRCODE = 'MT004', MESSAGE = 'Resource authority cannot change';
    END IF;
    IF request_row.subject_kind = 'resource' THEN
        UPDATE mesh_ops.network_revision AS revision
        SET network_revision = revision.network_revision + 1,
            inventory_revision = revision.inventory_revision + 1,
            updated_at = pg_catalog.clock_timestamp()
        WHERE revision.workspace_id = scoped_workspace_id
          AND revision.network_id = scoped_network_id
          AND revision.network_revision = current_network_revision
          AND revision.inventory_revision = current_subsystem_revision
        RETURNING revision.network_revision, revision.inventory_revision
        INTO advanced_network_revision, advanced_subsystem_revision;
        UPDATE mesh.resource AS resource
        SET owner_principal_id = request_row.proposed_owner_principal_id,
            custodian_principal_id = request_row.proposed_custodian_principal_id,
            semantic_hash = p_proposed_semantic_hash,
            activated_network_revision = advanced_network_revision,
            inventory_revision = advanced_subsystem_revision,
            version = resource.version + 1,
            updated_at = pg_catalog.transaction_timestamp()
        WHERE resource.id = request_row.resource_id
          AND resource.version = request_row.expected_subject_version
        RETURNING resource.version INTO advanced_subject_version;
    ELSE
        UPDATE mesh_ops.network_revision AS revision
        SET network_revision = revision.network_revision + 1,
            group_revision = revision.group_revision + 1,
            updated_at = pg_catalog.clock_timestamp()
        WHERE revision.workspace_id = scoped_workspace_id
          AND revision.network_id = scoped_network_id
          AND revision.network_revision = current_network_revision
          AND revision.group_revision = current_subsystem_revision
        RETURNING revision.network_revision, revision.group_revision
        INTO advanced_network_revision, advanced_subsystem_revision;
        UPDATE mesh.resource_group AS resource_group
        SET owner_principal_id = request_row.proposed_owner_principal_id,
            custodian_principal_id = request_row.proposed_custodian_principal_id,
            semantic_hash = p_proposed_semantic_hash,
            activated_network_revision = advanced_network_revision,
            group_revision = advanced_subsystem_revision,
            version = resource_group.version + 1,
            updated_at = pg_catalog.transaction_timestamp()
        WHERE resource_group.id = request_row.resource_group_id
          AND resource_group.version = request_row.expected_subject_version
        RETURNING resource_group.version INTO advanced_subject_version;
    END IF;
    IF advanced_network_revision IS NULL OR advanced_subsystem_revision IS NULL
        OR advanced_subject_version IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Resource authority revision changed';
    END IF;
    INSERT INTO mesh.resource_authority_step_up_evidence (
        public_id, deployment_id, workspace_id, network_id, request_id,
        account_session_id, principal_id, evidence_role,
        operation_semantic_hash, authentication_time, created_at
    ) VALUES (
        p_step_up_evidence_public_id, request_row.deployment_id, scoped_workspace_id,
        scoped_network_id, request_row.id, actor_session_id, actor_principal_id,
        'confirmer', p_impact_hash, actor_authentication_time, pg_catalog.transaction_timestamp()
    );
    UPDATE mesh.resource_authority_change_request AS request
    SET confirmation_count = 1,
        state = 'applied',
        applied_at = pg_catalog.transaction_timestamp(),
        version = request.version + 1,
        updated_at = pg_catalog.transaction_timestamp()
    WHERE request.id = request_row.id
      AND request.version = p_expected_request_version
      AND request.state = 'pending'
    RETURNING request.version INTO advanced_request_version;
    IF advanced_request_version IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'Resource authority request changed';
    END IF;
    network_revision := advanced_network_revision;
    subsystem_revision := advanced_subsystem_revision;
    subject_version := advanced_subject_version;
    request_version := advanced_request_version;
    SELECT owner.public_id, custodian.public_id
    INTO owner_principal_public_id, custodian_principal_public_id
    FROM mesh.principal AS owner
    JOIN mesh.principal AS custodian
      ON custodian.id = request_row.proposed_custodian_principal_id
    WHERE owner.id = request_row.proposed_owner_principal_id;
    semantic_hash := p_proposed_semantic_hash;
    RETURN NEXT;
END;
$function$;

-- From schema 000037.
CREATE OR REPLACE FUNCTION mesh_ops.create_device_resource_v1(
    p_resource_public_id UUID,
    p_target_public_id UUID,
    p_expected_inventory_revision BIGINT,
    p_device_public_id UUID,
    p_actor_principal_public_id UUID,
    p_display_name TEXT,
    p_semantic_hash BYTEA,
    p_occurred_at TIMESTAMPTZ
)
RETURNS TABLE (
    network_revision BIGINT,
    inventory_revision BIGINT,
    resource_version BIGINT,
    target_generation BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
    scoped_deployment_id BIGINT;
    actor_principal_id BIGINT;
    target_device_id BIGINT;
    new_resource_id BIGINT;
    current_network_revision BIGINT;
    current_inventory_revision BIGINT;
    advanced_network_revision BIGINT;
    advanced_inventory_revision BIGINT;
    new_resource_version BIGINT;
BEGIN
    scoped_workspace_id := mesh_ops.current_workspace_id();
    scoped_network_id := mesh_ops.current_network_id();
    IF p_resource_public_id IS NULL OR p_target_public_id IS NULL
        OR p_device_public_id IS NULL OR p_actor_principal_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_resource_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_target_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_device_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_actor_principal_public_id), 6) >> 4 <> 7
        OR p_expected_inventory_revision IS NULL OR p_expected_inventory_revision <= 0
        OR p_display_name IS NULL OR pg_catalog.char_length(p_display_name) NOT BETWEEN 1 AND 128
        OR p_display_name <> pg_catalog.btrim(p_display_name)
        OR p_semantic_hash IS NULL OR pg_catalog.octet_length(p_semantic_hash) <> 32
        OR p_semantic_hash = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_occurred_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Device Resource input';
    END IF;

    SELECT revision.network_revision, revision.inventory_revision
    INTO current_network_revision, current_inventory_revision
    FROM mesh_ops.lock_network_revision() AS revision;
    IF current_inventory_revision <> p_expected_inventory_revision THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Resource inventory revision changed';
    END IF;

    SELECT workspace.deployment_id, principal.id
    INTO scoped_deployment_id, actor_principal_id
    FROM mesh.workspace AS workspace
    JOIN mesh.principal AS principal
      ON principal.deployment_id = workspace.deployment_id
     AND principal.public_id = p_actor_principal_public_id
     AND principal.state = 'active'
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = workspace.deployment_id
     AND membership.workspace_id = workspace.id
     AND membership.principal_id = principal.id
     AND membership.state = 'active'
     AND membership.valid_from <= pg_catalog.transaction_timestamp()
     AND (membership.expires_at IS NULL OR membership.expires_at > pg_catalog.transaction_timestamp())
    WHERE workspace.id = scoped_workspace_id
      AND workspace.state = 'active'
    FOR SHARE OF workspace, principal, membership;
    IF scoped_deployment_id IS NULL OR actor_principal_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Resource creator authority is unavailable';
    END IF;

    SELECT device.id INTO target_device_id
    FROM mesh.device AS device
    WHERE device.workspace_id = scoped_workspace_id
      AND device.network_id = scoped_network_id
      AND device.public_id = p_device_public_id
      AND device.state = 'active'
      AND device.deleted_at IS NULL
    FOR SHARE;
    IF target_device_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Device target changed or is unavailable';
    END IF;

    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        inventory_revision = revision.inventory_revision + 1,
        updated_at = pg_catalog.clock_timestamp()
    WHERE revision.workspace_id = scoped_workspace_id
      AND revision.network_id = scoped_network_id
      AND revision.network_revision = current_network_revision
      AND revision.inventory_revision = current_inventory_revision
    RETURNING revision.network_revision, revision.inventory_revision
    INTO advanced_network_revision, advanced_inventory_revision;
    IF advanced_network_revision IS NULL OR advanced_inventory_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Resource inventory revision changed';
    END IF;

    INSERT INTO mesh.resource (
        public_id, deployment_id, workspace_id, network_id, kind,
        display_name, name_key, owner_principal_id, custodian_principal_id,
        state, target_generation, provenance_kind, provenance_principal_id,
        provenance_at, semantic_hash, activated_network_revision, inventory_revision,
        created_at, updated_at
    ) VALUES (
        p_resource_public_id, scoped_deployment_id, scoped_workspace_id, scoped_network_id, 'device',
        p_display_name, pg_catalog.lower(p_display_name), actor_principal_id, actor_principal_id,
        'active', 1, 'manual', actor_principal_id,
        pg_catalog.transaction_timestamp(), p_semantic_hash, advanced_network_revision, advanced_inventory_revision,
        pg_catalog.transaction_timestamp(), pg_catalog.transaction_timestamp()
    ) RETURNING id, version INTO new_resource_id, new_resource_version;

    INSERT INTO mesh.resource_device_target (
        public_id, workspace_id, network_id, resource_id, device_id,
        target_generation, state, bound_by_principal_id, bound_at, created_at, updated_at
    ) VALUES (
        p_target_public_id, scoped_workspace_id, scoped_network_id, new_resource_id, target_device_id,
        1, 'active', actor_principal_id, pg_catalog.transaction_timestamp(), pg_catalog.transaction_timestamp(), pg_catalog.transaction_timestamp()
    );

    network_revision := advanced_network_revision;
    inventory_revision := advanced_inventory_revision;
    resource_version := new_resource_version;
    target_generation := 1;
    RETURN NEXT;
END;
$function$;

-- From schema 000037.
CREATE OR REPLACE FUNCTION mesh_ops.create_resource_group_v1(
    p_group_public_id UUID,
    p_group_version_public_id UUID,
    p_expected_group_revision BIGINT,
    p_actor_principal_public_id UUID,
    p_display_name TEXT,
    p_semantic_hash BYTEA,
    p_occurred_at TIMESTAMPTZ,
    p_members JSONB
)
RETURNS TABLE (
    network_revision BIGINT,
    group_revision BIGINT,
    group_version BIGINT,
    definition_version BIGINT
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
    scoped_deployment_id BIGINT;
    actor_principal_id BIGINT;
    new_group_id BIGINT;
    new_group_version_id BIGINT;
    current_network_revision BIGINT;
    current_group_revision BIGINT;
    advanced_network_revision BIGINT;
    advanced_group_revision BIGINT;
    new_group_version BIGINT;
    expected_member_count INTEGER;
    resolved_member_count INTEGER;
BEGIN
    scoped_workspace_id := mesh_ops.current_workspace_id();
    scoped_network_id := mesh_ops.current_network_id();
    IF p_group_public_id IS NULL OR p_group_version_public_id IS NULL
        OR p_actor_principal_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_group_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_group_version_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_actor_principal_public_id), 6) >> 4 <> 7
        OR p_expected_group_revision IS NULL OR p_expected_group_revision <= 0
        OR p_display_name IS NULL OR pg_catalog.char_length(p_display_name) NOT BETWEEN 1 AND 128
        OR p_display_name <> pg_catalog.btrim(p_display_name)
        OR p_semantic_hash IS NULL OR pg_catalog.octet_length(p_semantic_hash) <> 32
        OR p_semantic_hash = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_occurred_at IS NULL OR p_members IS NULL
        OR pg_catalog.jsonb_typeof(p_members) <> 'array'
        OR pg_catalog.jsonb_array_length(p_members) NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource Group input';
    END IF;
    expected_member_count := pg_catalog.jsonb_array_length(p_members);
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.jsonb_to_recordset(p_members) AS member(
            member_public_id UUID,
            ordinal INTEGER,
            resource_public_id UUID,
            resource_version BIGINT,
            target_generation BIGINT
        )
        WHERE member.member_public_id IS NULL
           OR member.resource_public_id IS NULL
           OR pg_catalog.get_byte(pg_catalog.uuid_send(member.member_public_id), 6) >> 4 <> 7
           OR pg_catalog.get_byte(pg_catalog.uuid_send(member.resource_public_id), 6) >> 4 <> 7
           OR member.ordinal NOT BETWEEN 1 AND expected_member_count
           OR member.resource_version <= 0
           OR member.target_generation <= 0
    ) OR (
        SELECT pg_catalog.count(DISTINCT member.ordinal) <> expected_member_count
            OR pg_catalog.count(DISTINCT member.member_public_id) <> expected_member_count
            OR pg_catalog.count(DISTINCT member.resource_public_id) <> expected_member_count
        FROM pg_catalog.jsonb_to_recordset(p_members) AS member(
            member_public_id UUID,
            ordinal INTEGER,
            resource_public_id UUID,
            resource_version BIGINT,
            target_generation BIGINT
        )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource Group membership';
    END IF;

    SELECT revision.network_revision, revision.group_revision
    INTO current_network_revision, current_group_revision
    FROM mesh_ops.lock_network_revision() AS revision;
    IF current_group_revision <> p_expected_group_revision THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Resource Group revision changed';
    END IF;

    SELECT workspace.deployment_id, principal.id
    INTO scoped_deployment_id, actor_principal_id
    FROM mesh.workspace AS workspace
    JOIN mesh.principal AS principal
      ON principal.deployment_id = workspace.deployment_id
     AND principal.public_id = p_actor_principal_public_id
     AND principal.state = 'active'
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = workspace.deployment_id
     AND membership.workspace_id = workspace.id
     AND membership.principal_id = principal.id
     AND membership.state = 'active'
     AND membership.valid_from <= pg_catalog.transaction_timestamp()
     AND (membership.expires_at IS NULL OR membership.expires_at > pg_catalog.transaction_timestamp())
    WHERE workspace.id = scoped_workspace_id
      AND workspace.state = 'active'
    FOR SHARE OF workspace, principal, membership;
    IF scoped_deployment_id IS NULL OR actor_principal_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Resource Group creator authority is unavailable';
    END IF;

    PERFORM resource.id
    FROM pg_catalog.jsonb_to_recordset(p_members) AS member(
        member_public_id UUID,
        ordinal INTEGER,
        resource_public_id UUID,
        resource_version BIGINT,
        target_generation BIGINT
    )
    JOIN mesh.resource AS resource
      ON resource.workspace_id = scoped_workspace_id
     AND resource.network_id = scoped_network_id
     AND resource.public_id = member.resource_public_id
    ORDER BY resource.id
    FOR SHARE OF resource;

    SELECT pg_catalog.count(*) INTO resolved_member_count
    FROM pg_catalog.jsonb_to_recordset(p_members) AS member(
        member_public_id UUID,
        ordinal INTEGER,
        resource_public_id UUID,
        resource_version BIGINT,
        target_generation BIGINT
    )
    JOIN mesh.resource AS resource
      ON resource.workspace_id = scoped_workspace_id
     AND resource.network_id = scoped_network_id
     AND resource.public_id = member.resource_public_id
     AND resource.version = member.resource_version
     AND resource.target_generation = member.target_generation
     AND resource.state = 'active'
    JOIN mesh.resource_device_target AS target
      ON target.workspace_id = resource.workspace_id
     AND target.network_id = resource.network_id
     AND target.resource_id = resource.id
     AND target.target_generation = member.target_generation
     AND target.state = 'active';
    IF resolved_member_count <> expected_member_count THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Resource Group member changed or is unavailable';
    END IF;

    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        group_revision = revision.group_revision + 1,
        updated_at = pg_catalog.clock_timestamp()
    WHERE revision.workspace_id = scoped_workspace_id
      AND revision.network_id = scoped_network_id
      AND revision.network_revision = current_network_revision
      AND revision.group_revision = current_group_revision
    RETURNING revision.network_revision, revision.group_revision
    INTO advanced_network_revision, advanced_group_revision;
    IF advanced_network_revision IS NULL OR advanced_group_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Resource Group revision changed';
    END IF;

    INSERT INTO mesh.resource_group (
        public_id, deployment_id, workspace_id, network_id,
        display_name, name_key, owner_principal_id, custodian_principal_id,
        state, active_definition_version, semantic_hash,
        activated_network_revision, group_revision, created_at, updated_at
    ) VALUES (
        p_group_public_id, scoped_deployment_id, scoped_workspace_id, scoped_network_id,
        p_display_name, pg_catalog.lower(p_display_name), actor_principal_id, actor_principal_id,
        'active', 1, p_semantic_hash,
        advanced_network_revision, advanced_group_revision, pg_catalog.transaction_timestamp(), pg_catalog.transaction_timestamp()
    ) RETURNING id, version INTO new_group_id, new_group_version;

    INSERT INTO mesh.resource_group_version (
        public_id, workspace_id, network_id, resource_group_id,
        definition_version, semantic_hash, member_count,
        created_by_principal_id, created_at
    ) VALUES (
        p_group_version_public_id, scoped_workspace_id, scoped_network_id, new_group_id,
        1, p_semantic_hash, expected_member_count,
        actor_principal_id, pg_catalog.transaction_timestamp()
    ) RETURNING id INTO new_group_version_id;

    INSERT INTO mesh.resource_group_version_member (
        public_id, workspace_id, network_id, resource_group_id,
        resource_group_version_id, ordinal, resource_id,
        resource_version, target_generation, created_at
    )
    SELECT
        member.member_public_id,
        scoped_workspace_id,
        scoped_network_id,
        new_group_id,
        new_group_version_id,
        member.ordinal,
        resource.id,
        member.resource_version,
        member.target_generation,
        pg_catalog.transaction_timestamp()
    FROM pg_catalog.jsonb_to_recordset(p_members) AS member(
        member_public_id UUID,
        ordinal INTEGER,
        resource_public_id UUID,
        resource_version BIGINT,
        target_generation BIGINT
    )
    JOIN mesh.resource AS resource
      ON resource.workspace_id = scoped_workspace_id
     AND resource.network_id = scoped_network_id
     AND resource.public_id = member.resource_public_id
    ORDER BY member.ordinal;

    network_revision := advanced_network_revision;
    group_revision := advanced_group_revision;
    group_version := new_group_version;
    definition_version := 1;
    RETURN NEXT;
END;
$function$;

-- From schema 000186.
CREATE OR REPLACE FUNCTION mesh_ops.transition_resource_lifecycle_v1(p_resource_public_id uuid, p_expected_resource_version bigint, p_target_state text, p_actor_principal_public_id uuid, p_occurred_at timestamp with time zone)
 RETURNS TABLE(network_revision bigint, inventory_revision bigint, resource_version bigint, resource_state text, semantic_hash bytea)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'mesh', 'mesh_ops'
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
    actor_principal_id BIGINT;
    current_network_revision BIGINT;
    current_inventory_revision BIGINT;
    current_resource_id BIGINT;
    current_resource_version BIGINT;
    current_resource_state TEXT;
    current_semantic_hash BYTEA;
    advanced_network_revision BIGINT;
    advanced_inventory_revision BIGINT;
    advanced_resource_version BIGINT;
BEGIN
    scoped_workspace_id := mesh_ops.current_workspace_id();
    scoped_network_id := mesh_ops.current_network_id();
    IF p_resource_public_id IS NULL OR p_actor_principal_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_resource_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_actor_principal_public_id), 6) >> 4 <> 7
        OR p_expected_resource_version IS NULL OR p_expected_resource_version <= 0
        OR p_target_state IS NULL OR p_target_state NOT IN ('active', 'suspended', 'deleted')
        OR p_occurred_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource lifecycle input';
    END IF;

    SELECT revision.network_revision, revision.inventory_revision
    INTO current_network_revision, current_inventory_revision
    FROM mesh_ops.lock_network_revision() AS revision;

    SELECT principal.id INTO actor_principal_id
    FROM mesh.workspace AS workspace
    JOIN mesh.principal AS principal
      ON principal.deployment_id = workspace.deployment_id
     AND principal.public_id = p_actor_principal_public_id
     AND principal.state = 'active'
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = workspace.deployment_id
     AND membership.workspace_id = workspace.id
     AND membership.principal_id = principal.id
     AND membership.state = 'active'
     AND membership.valid_from <= pg_catalog.transaction_timestamp()
     AND (membership.expires_at IS NULL OR membership.expires_at > pg_catalog.transaction_timestamp())
    WHERE workspace.id = scoped_workspace_id
      AND workspace.state = 'active'
    FOR SHARE OF workspace, principal, membership;
    IF actor_principal_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Resource lifecycle authority is unavailable';
    END IF;

    SELECT resource.id, resource.version, resource.state, resource.semantic_hash
    INTO current_resource_id, current_resource_version, current_resource_state, current_semantic_hash
    FROM mesh.resource AS resource
    WHERE resource.workspace_id = scoped_workspace_id
      AND resource.network_id = scoped_network_id
      AND resource.public_id = p_resource_public_id
    FOR UPDATE;
    IF current_resource_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT404', MESSAGE = 'Resource is unavailable';
    END IF;
    IF current_resource_version <> p_expected_resource_version THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'Resource version changed';
    END IF;
    IF current_resource_state = 'deleted'
        OR (p_target_state = 'active' AND current_resource_state <> 'suspended')
        OR (p_target_state = 'suspended' AND current_resource_state <> 'active')
        OR p_target_state = current_resource_state THEN
        RAISE EXCEPTION USING ERRCODE = 'MT003', MESSAGE = 'invalid Resource lifecycle transition';
    END IF;

    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        inventory_revision = revision.inventory_revision + 1,
        updated_at = pg_catalog.clock_timestamp()
    WHERE revision.workspace_id = scoped_workspace_id
      AND revision.network_id = scoped_network_id
      AND revision.network_revision = current_network_revision
      AND revision.inventory_revision = current_inventory_revision
    RETURNING revision.network_revision, revision.inventory_revision
    INTO advanced_network_revision, advanced_inventory_revision;
    IF advanced_network_revision IS NULL OR advanced_inventory_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Resource inventory revision changed';
    END IF;

    UPDATE mesh.resource AS resource
    SET state = p_target_state,
        activated_network_revision = advanced_network_revision,
        inventory_revision = advanced_inventory_revision,
        version = resource.version + 1,
        updated_at = pg_catalog.transaction_timestamp(),
        deleted_at = CASE WHEN p_target_state = 'deleted' THEN pg_catalog.transaction_timestamp() ELSE NULL END
    WHERE resource.id = current_resource_id
      AND resource.version = current_resource_version
    RETURNING resource.version INTO advanced_resource_version;
    IF advanced_resource_version IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'Resource version changed';
    END IF;

    -- A deleted Resource frees its Device for a new Resource.
    IF p_target_state = 'deleted' THEN
        UPDATE mesh.resource_device_target AS target
        SET state = 'superseded', version = target.version + 1,
            updated_at = GREATEST(pg_catalog.transaction_timestamp(), target.updated_at)
        WHERE target.workspace_id = scoped_workspace_id
          AND target.network_id = scoped_network_id
          AND target.resource_id = current_resource_id
          AND target.state = 'active';
    END IF;

    network_revision := advanced_network_revision;
    inventory_revision := advanced_inventory_revision;
    resource_version := advanced_resource_version;
    resource_state := p_target_state;
    semantic_hash := current_semantic_hash;
    RETURN NEXT;
END;
$function$;

-- From schema 000039.
CREATE OR REPLACE FUNCTION mesh_ops.transition_resource_group_lifecycle_v1(
    p_group_public_id UUID,
    p_expected_group_version BIGINT,
    p_target_state TEXT,
    p_actor_principal_public_id UUID,
    p_occurred_at TIMESTAMPTZ
)
RETURNS TABLE (
    network_revision BIGINT,
    group_revision BIGINT,
    group_version BIGINT,
    group_state TEXT,
    semantic_hash BYTEA
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
    actor_principal_id BIGINT;
    current_network_revision BIGINT;
    current_group_revision BIGINT;
    current_group_id BIGINT;
    current_group_version BIGINT;
    current_group_state TEXT;
    current_semantic_hash BYTEA;
    advanced_network_revision BIGINT;
    advanced_group_revision BIGINT;
    advanced_group_version BIGINT;
BEGIN
    scoped_workspace_id := mesh_ops.current_workspace_id();
    scoped_network_id := mesh_ops.current_network_id();
    IF p_group_public_id IS NULL OR p_actor_principal_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_group_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_actor_principal_public_id), 6) >> 4 <> 7
        OR p_expected_group_version IS NULL OR p_expected_group_version <= 0
        OR p_target_state IS NULL OR p_target_state NOT IN ('active', 'suspended', 'deleted')
        OR p_occurred_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource Group lifecycle input';
    END IF;

    SELECT revision.network_revision, revision.group_revision
    INTO current_network_revision, current_group_revision
    FROM mesh_ops.lock_network_revision() AS revision;

    SELECT principal.id INTO actor_principal_id
    FROM mesh.workspace AS workspace
    JOIN mesh.principal AS principal
      ON principal.deployment_id = workspace.deployment_id
     AND principal.public_id = p_actor_principal_public_id
     AND principal.state = 'active'
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = workspace.deployment_id
     AND membership.workspace_id = workspace.id
     AND membership.principal_id = principal.id
     AND membership.state = 'active'
     AND membership.valid_from <= pg_catalog.transaction_timestamp()
     AND (membership.expires_at IS NULL OR membership.expires_at > pg_catalog.transaction_timestamp())
    WHERE workspace.id = scoped_workspace_id
      AND workspace.state = 'active'
    FOR SHARE OF workspace, principal, membership;
    IF actor_principal_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Resource Group lifecycle authority is unavailable';
    END IF;

    SELECT resource_group.id, resource_group.version,
           resource_group.state, resource_group.semantic_hash
    INTO current_group_id, current_group_version, current_group_state, current_semantic_hash
    FROM mesh.resource_group AS resource_group
    WHERE resource_group.workspace_id = scoped_workspace_id
      AND resource_group.network_id = scoped_network_id
      AND resource_group.public_id = p_group_public_id
    FOR UPDATE;
    IF current_group_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT404', MESSAGE = 'Resource Group is unavailable';
    END IF;
    IF current_group_version <> p_expected_group_version THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'Resource Group version changed';
    END IF;
    IF current_group_state = 'deleted'
        OR (p_target_state = 'active' AND current_group_state <> 'suspended')
        OR (p_target_state = 'suspended' AND current_group_state <> 'active')
        OR p_target_state = current_group_state THEN
        RAISE EXCEPTION USING ERRCODE = 'MT003', MESSAGE = 'invalid Resource Group lifecycle transition';
    END IF;

    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        group_revision = revision.group_revision + 1,
        updated_at = pg_catalog.clock_timestamp()
    WHERE revision.workspace_id = scoped_workspace_id
      AND revision.network_id = scoped_network_id
      AND revision.network_revision = current_network_revision
      AND revision.group_revision = current_group_revision
    RETURNING revision.network_revision, revision.group_revision
    INTO advanced_network_revision, advanced_group_revision;
    IF advanced_network_revision IS NULL OR advanced_group_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Resource Group revision changed';
    END IF;

    UPDATE mesh.resource_group AS resource_group
    SET state = p_target_state,
        activated_network_revision = advanced_network_revision,
        group_revision = advanced_group_revision,
        version = resource_group.version + 1,
        updated_at = pg_catalog.transaction_timestamp(),
        deleted_at = CASE WHEN p_target_state = 'deleted' THEN pg_catalog.transaction_timestamp() ELSE NULL END
    WHERE resource_group.id = current_group_id
      AND resource_group.version = current_group_version
    RETURNING resource_group.version INTO advanced_group_version;
    IF advanced_group_version IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'Resource Group version changed';
    END IF;

    network_revision := advanced_network_revision;
    group_revision := advanced_group_revision;
    group_version := advanced_group_version;
    group_state := p_target_state;
    semantic_hash := current_semantic_hash;
    RETURN NEXT;
END;
$function$;

-- From schema 000040.
CREATE OR REPLACE FUNCTION mesh_ops.rebind_device_resource_v1(
    p_resource_public_id UUID,
    p_expected_resource_version BIGINT,
    p_target_public_id UUID,
    p_device_public_id UUID,
    p_actor_principal_public_id UUID,
    p_semantic_hash BYTEA,
    p_occurred_at TIMESTAMPTZ
)
RETURNS TABLE (
    network_revision BIGINT,
    inventory_revision BIGINT,
    resource_version BIGINT,
    target_generation BIGINT,
    semantic_hash BYTEA
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
    actor_principal_id BIGINT;
    replacement_device_id BIGINT;
    current_network_revision BIGINT;
    current_inventory_revision BIGINT;
    current_resource_id BIGINT;
    current_resource_version BIGINT;
    current_resource_state TEXT;
    current_target_generation BIGINT;
    current_target_id BIGINT;
    current_device_id BIGINT;
    advanced_network_revision BIGINT;
    advanced_inventory_revision BIGINT;
    advanced_resource_version BIGINT;
    advanced_target_generation BIGINT;
BEGIN
    scoped_workspace_id := mesh_ops.current_workspace_id();
    scoped_network_id := mesh_ops.current_network_id();
    IF p_resource_public_id IS NULL OR p_target_public_id IS NULL
        OR p_device_public_id IS NULL OR p_actor_principal_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_resource_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_target_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_device_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_actor_principal_public_id), 6) >> 4 <> 7
        OR p_expected_resource_version IS NULL OR p_expected_resource_version <= 0
        OR p_semantic_hash IS NULL OR pg_catalog.octet_length(p_semantic_hash) <> 32
        OR p_semantic_hash = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_occurred_at IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource rebind input';
    END IF;

    SELECT revision.network_revision, revision.inventory_revision
    INTO current_network_revision, current_inventory_revision
    FROM mesh_ops.lock_network_revision() AS revision;

    SELECT principal.id INTO actor_principal_id
    FROM mesh.workspace AS workspace
    JOIN mesh.principal AS principal
      ON principal.deployment_id = workspace.deployment_id
     AND principal.public_id = p_actor_principal_public_id
     AND principal.state = 'active'
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = workspace.deployment_id
     AND membership.workspace_id = workspace.id
     AND membership.principal_id = principal.id
     AND membership.state = 'active'
     AND membership.valid_from <= pg_catalog.transaction_timestamp()
     AND (membership.expires_at IS NULL OR membership.expires_at > pg_catalog.transaction_timestamp())
    WHERE workspace.id = scoped_workspace_id
      AND workspace.state = 'active'
    FOR SHARE OF workspace, principal, membership;
    IF actor_principal_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Resource rebind authority is unavailable';
    END IF;

    SELECT resource.id, resource.version, resource.state, resource.target_generation
    INTO current_resource_id, current_resource_version, current_resource_state, current_target_generation
    FROM mesh.resource AS resource
    WHERE resource.workspace_id = scoped_workspace_id
      AND resource.network_id = scoped_network_id
      AND resource.public_id = p_resource_public_id
      AND resource.kind = 'device'
    FOR UPDATE;
    IF current_resource_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT404', MESSAGE = 'Resource is unavailable';
    END IF;
    IF current_resource_version <> p_expected_resource_version THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'Resource version changed';
    END IF;
    IF current_resource_state = 'deleted' OR current_target_generation = 9223372036854775807 THEN
        RAISE EXCEPTION USING ERRCODE = 'MT004', MESSAGE = 'Resource cannot be rebound';
    END IF;

    SELECT target.id, target.device_id
    INTO current_target_id, current_device_id
    FROM mesh.resource_device_target AS target
    WHERE target.workspace_id = scoped_workspace_id
      AND target.network_id = scoped_network_id
      AND target.resource_id = current_resource_id
      AND target.target_generation = current_target_generation
      AND target.state = 'active'
    FOR UPDATE;
    IF current_target_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'active Resource target is unavailable';
    END IF;

    SELECT device.id INTO replacement_device_id
    FROM mesh.device AS device
    WHERE device.workspace_id = scoped_workspace_id
      AND device.network_id = scoped_network_id
      AND device.public_id = p_device_public_id
      AND device.state = 'active'
    FOR SHARE;
    IF replacement_device_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT404', MESSAGE = 'Device is unavailable';
    END IF;
    IF replacement_device_id = current_device_id OR EXISTS (
        SELECT 1
        FROM mesh.resource_device_target AS target
        WHERE target.workspace_id = scoped_workspace_id
          AND target.network_id = scoped_network_id
          AND target.device_id = replacement_device_id
          AND target.state = 'active'
    ) THEN
        RAISE EXCEPTION USING ERRCODE = 'MT005', MESSAGE = 'Device target is already bound';
    END IF;

    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        inventory_revision = revision.inventory_revision + 1,
        updated_at = pg_catalog.clock_timestamp()
    WHERE revision.workspace_id = scoped_workspace_id
      AND revision.network_id = scoped_network_id
      AND revision.network_revision = current_network_revision
      AND revision.inventory_revision = current_inventory_revision
    RETURNING revision.network_revision, revision.inventory_revision
    INTO advanced_network_revision, advanced_inventory_revision;
    IF advanced_network_revision IS NULL OR advanced_inventory_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Resource inventory revision changed';
    END IF;

    UPDATE mesh.resource_device_target AS target
    SET state = 'superseded',
        version = target.version + 1,
        updated_at = pg_catalog.transaction_timestamp()
    WHERE target.id = current_target_id
      AND target.state = 'active';
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'MT005', MESSAGE = 'Device target changed';
    END IF;

    advanced_target_generation := current_target_generation + 1;
    INSERT INTO mesh.resource_device_target (
        public_id, workspace_id, network_id, resource_id, device_id,
        target_generation, state, bound_by_principal_id, bound_at,
        version, created_at, updated_at
    ) VALUES (
        p_target_public_id, scoped_workspace_id, scoped_network_id, current_resource_id,
        replacement_device_id, advanced_target_generation, 'active', actor_principal_id,
        pg_catalog.transaction_timestamp(), 1, pg_catalog.transaction_timestamp(), pg_catalog.transaction_timestamp()
    );

    UPDATE mesh.resource AS resource
    SET target_generation = advanced_target_generation,
        semantic_hash = p_semantic_hash,
        activated_network_revision = advanced_network_revision,
        inventory_revision = advanced_inventory_revision,
        version = resource.version + 1,
        updated_at = pg_catalog.transaction_timestamp()
    WHERE resource.id = current_resource_id
      AND resource.version = current_resource_version
    RETURNING resource.version INTO advanced_resource_version;
    IF advanced_resource_version IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'Resource version changed';
    END IF;

    network_revision := advanced_network_revision;
    inventory_revision := advanced_inventory_revision;
    resource_version := advanced_resource_version;
    target_generation := advanced_target_generation;
    semantic_hash := p_semantic_hash;
    RETURN NEXT;
END;
$function$;

-- From schema 000041.
CREATE OR REPLACE FUNCTION mesh_ops.replace_resource_group_definition_v1(
    p_group_public_id UUID,
    p_expected_group_version BIGINT,
    p_group_version_public_id UUID,
    p_actor_principal_public_id UUID,
    p_semantic_hash BYTEA,
    p_occurred_at TIMESTAMPTZ,
    p_members JSONB
)
RETURNS TABLE (
    network_revision BIGINT,
    group_revision BIGINT,
    group_version BIGINT,
    definition_version BIGINT,
    semantic_hash BYTEA
)
LANGUAGE plpgsql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    scoped_workspace_id BIGINT;
    scoped_network_id BIGINT;
    actor_principal_id BIGINT;
    current_network_revision BIGINT;
    current_group_revision BIGINT;
    current_group_id BIGINT;
    current_group_version BIGINT;
    current_group_state TEXT;
    current_definition_version BIGINT;
    new_group_version_id BIGINT;
    proposed_member_count INTEGER;
    resolved_member_count INTEGER;
    advanced_network_revision BIGINT;
    advanced_group_revision BIGINT;
    advanced_group_version BIGINT;
    advanced_definition_version BIGINT;
BEGIN
    scoped_workspace_id := mesh_ops.current_workspace_id();
    scoped_network_id := mesh_ops.current_network_id();
    IF p_group_public_id IS NULL OR p_group_version_public_id IS NULL
        OR p_actor_principal_public_id IS NULL
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_group_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_group_version_public_id), 6) >> 4 <> 7
        OR pg_catalog.get_byte(pg_catalog.uuid_send(p_actor_principal_public_id), 6) >> 4 <> 7
        OR p_expected_group_version IS NULL OR p_expected_group_version <= 0
        OR p_semantic_hash IS NULL OR pg_catalog.octet_length(p_semantic_hash) <> 32
        OR p_semantic_hash = pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        OR p_occurred_at IS NULL OR p_members IS NULL
        OR pg_catalog.jsonb_typeof(p_members) <> 'array'
        OR pg_catalog.jsonb_array_length(p_members) NOT BETWEEN 1 AND 256 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Resource Group replacement input';
    END IF;
    proposed_member_count := pg_catalog.jsonb_array_length(p_members);
    IF EXISTS (
        SELECT 1
        FROM pg_catalog.jsonb_array_elements(p_members) AS entry(value)
        WHERE pg_catalog.jsonb_typeof(entry.value) <> 'object'
           OR NOT entry.value ? 'member_public_id'
           OR NOT entry.value ? 'ordinal'
           OR NOT entry.value ? 'resource_public_id'
           OR NOT entry.value ? 'resource_version'
           OR NOT entry.value ? 'target_generation'
           OR EXISTS (
               SELECT 1
               FROM pg_catalog.jsonb_object_keys(entry.value) AS field(key)
               WHERE field.key NOT IN (
                   'member_public_id', 'ordinal', 'resource_public_id',
                   'resource_version', 'target_generation'
               )
           )
    ) OR EXISTS (
        SELECT 1
        FROM pg_catalog.jsonb_to_recordset(p_members) AS member(
            member_public_id UUID,
            ordinal INTEGER,
            resource_public_id UUID,
            resource_version BIGINT,
            target_generation BIGINT
        )
        WHERE member.member_public_id IS NULL OR member.resource_public_id IS NULL
           OR pg_catalog.get_byte(pg_catalog.uuid_send(member.member_public_id), 6) >> 4 <> 7
           OR pg_catalog.get_byte(pg_catalog.uuid_send(member.resource_public_id), 6) >> 4 <> 7
           OR member.ordinal NOT BETWEEN 1 AND proposed_member_count
           OR member.resource_version <= 0 OR member.target_generation <= 0
    ) OR (
        SELECT pg_catalog.count(DISTINCT member.ordinal) <> proposed_member_count
            OR pg_catalog.count(DISTINCT member.member_public_id) <> proposed_member_count
            OR pg_catalog.count(DISTINCT member.resource_public_id) <> proposed_member_count
        FROM pg_catalog.jsonb_to_recordset(p_members) AS member(
            member_public_id UUID,
            ordinal INTEGER,
            resource_public_id UUID,
            resource_version BIGINT,
            target_generation BIGINT
        )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid replacement Resource Group membership';
    END IF;

    SELECT revision.network_revision, revision.group_revision
    INTO current_network_revision, current_group_revision
    FROM mesh_ops.lock_network_revision() AS revision;

    SELECT principal.id INTO actor_principal_id
    FROM mesh.workspace AS workspace
    JOIN mesh.principal AS principal
      ON principal.deployment_id = workspace.deployment_id
     AND principal.public_id = p_actor_principal_public_id
     AND principal.state = 'active'
    JOIN mesh.workspace_membership AS membership
      ON membership.deployment_id = workspace.deployment_id
     AND membership.workspace_id = workspace.id
     AND membership.principal_id = principal.id
     AND membership.state = 'active'
     AND membership.valid_from <= pg_catalog.transaction_timestamp()
     AND (membership.expires_at IS NULL OR membership.expires_at > pg_catalog.transaction_timestamp())
    WHERE workspace.id = scoped_workspace_id
      AND workspace.state = 'active'
    FOR SHARE OF workspace, principal, membership;
    IF actor_principal_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = '42501', MESSAGE = 'Resource Group replacement authority is unavailable';
    END IF;

    SELECT resource_group.id, resource_group.version, resource_group.state,
           resource_group.active_definition_version
    INTO current_group_id, current_group_version, current_group_state,
         current_definition_version
    FROM mesh.resource_group AS resource_group
    WHERE resource_group.workspace_id = scoped_workspace_id
      AND resource_group.network_id = scoped_network_id
      AND resource_group.public_id = p_group_public_id
    FOR UPDATE;
    IF current_group_id IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT404', MESSAGE = 'Resource Group is unavailable';
    END IF;
    IF current_group_version <> p_expected_group_version THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'Resource Group version changed';
    END IF;
    IF current_group_state = 'deleted' OR current_definition_version = 9223372036854775807 THEN
        RAISE EXCEPTION USING ERRCODE = 'MT004', MESSAGE = 'Resource Group cannot be replaced';
    END IF;

    PERFORM resource.id
    FROM pg_catalog.jsonb_to_recordset(p_members) AS member(
        member_public_id UUID,
        ordinal INTEGER,
        resource_public_id UUID,
        resource_version BIGINT,
        target_generation BIGINT
    )
    JOIN mesh.resource AS resource
      ON resource.workspace_id = scoped_workspace_id
     AND resource.network_id = scoped_network_id
     AND resource.public_id = member.resource_public_id
    ORDER BY resource.id
    FOR SHARE OF resource;

    SELECT pg_catalog.count(*) INTO resolved_member_count
    FROM pg_catalog.jsonb_to_recordset(p_members) AS member(
        member_public_id UUID,
        ordinal INTEGER,
        resource_public_id UUID,
        resource_version BIGINT,
        target_generation BIGINT
    )
    JOIN mesh.resource AS resource
      ON resource.workspace_id = scoped_workspace_id
     AND resource.network_id = scoped_network_id
     AND resource.public_id = member.resource_public_id
     AND resource.version = member.resource_version
     AND resource.target_generation = member.target_generation
     AND resource.state = 'active'
    JOIN mesh.resource_device_target AS target
      ON target.workspace_id = resource.workspace_id
     AND target.network_id = resource.network_id
     AND target.resource_id = resource.id
     AND target.target_generation = member.target_generation
     AND target.state = 'active';
    IF resolved_member_count <> proposed_member_count THEN
        RAISE EXCEPTION USING ERRCODE = 'MT006', MESSAGE = 'Resource Group member changed or is unavailable';
    END IF;

    UPDATE mesh_ops.network_revision AS revision
    SET network_revision = revision.network_revision + 1,
        group_revision = revision.group_revision + 1,
        updated_at = pg_catalog.clock_timestamp()
    WHERE revision.workspace_id = scoped_workspace_id
      AND revision.network_id = scoped_network_id
      AND revision.network_revision = current_network_revision
      AND revision.group_revision = current_group_revision
    RETURNING revision.network_revision, revision.group_revision
    INTO advanced_network_revision, advanced_group_revision;
    IF advanced_network_revision IS NULL OR advanced_group_revision IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT001', MESSAGE = 'Resource Group revision changed';
    END IF;

    advanced_definition_version := current_definition_version + 1;
    INSERT INTO mesh.resource_group_version (
        public_id, workspace_id, network_id, resource_group_id,
        definition_version, semantic_hash, member_count,
        created_by_principal_id, created_at
    ) VALUES (
        p_group_version_public_id, scoped_workspace_id, scoped_network_id, current_group_id,
        advanced_definition_version, p_semantic_hash, proposed_member_count,
        actor_principal_id, pg_catalog.transaction_timestamp()
    ) RETURNING id INTO new_group_version_id;

    INSERT INTO mesh.resource_group_version_member (
        public_id, workspace_id, network_id, resource_group_id,
        resource_group_version_id, ordinal, resource_id,
        resource_version, target_generation, created_at
    )
    SELECT member.member_public_id, scoped_workspace_id, scoped_network_id,
           current_group_id, new_group_version_id, member.ordinal, resource.id,
           member.resource_version, member.target_generation, pg_catalog.transaction_timestamp()
    FROM pg_catalog.jsonb_to_recordset(p_members) AS member(
        member_public_id UUID,
        ordinal INTEGER,
        resource_public_id UUID,
        resource_version BIGINT,
        target_generation BIGINT
    )
    JOIN mesh.resource AS resource
      ON resource.workspace_id = scoped_workspace_id
     AND resource.network_id = scoped_network_id
     AND resource.public_id = member.resource_public_id
    ORDER BY member.ordinal;

    UPDATE mesh.resource_group AS resource_group
    SET active_definition_version = advanced_definition_version,
        semantic_hash = p_semantic_hash,
        activated_network_revision = advanced_network_revision,
        group_revision = advanced_group_revision,
        version = resource_group.version + 1,
        updated_at = pg_catalog.transaction_timestamp()
    WHERE resource_group.id = current_group_id
      AND resource_group.version = current_group_version
    RETURNING resource_group.version INTO advanced_group_version;
    IF advanced_group_version IS NULL THEN
        RAISE EXCEPTION USING ERRCODE = 'MT002', MESSAGE = 'Resource Group version changed';
    END IF;

    network_revision := advanced_network_revision;
    group_revision := advanced_group_revision;
    group_version := advanced_group_version;
    definition_version := advanced_definition_version;
    semantic_hash := p_semantic_hash;
    RETURN NEXT;
END;
$function$;
