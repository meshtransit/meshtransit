CREATE TABLE mesh.policy_approval_request (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    change_public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    proposer_principal_id BIGINT NOT NULL,
    proposer_account_session_id BIGINT NOT NULL,
    proposer_session_version BIGINT NOT NULL CHECK (proposer_session_version > 0),
    proposer_principal_generation BIGINT NOT NULL CHECK (proposer_principal_generation > 0),
    proposer_account_generation BIGINT NOT NULL CHECK (proposer_account_generation > 0),
    proposer_provider_generation BIGINT NOT NULL CHECK (proposer_provider_generation > 0),
    proposer_recovery_epoch BIGINT NOT NULL CHECK (proposer_recovery_epoch > 0),
    baseline_network_revision BIGINT NOT NULL CHECK (baseline_network_revision > 0),
    baseline_inventory_revision BIGINT NOT NULL CHECK (baseline_inventory_revision > 0),
    baseline_group_revision BIGINT NOT NULL CHECK (baseline_group_revision > 0),
    baseline_policy_revision BIGINT NOT NULL CHECK (baseline_policy_revision > 0),
    baseline_dns_revision BIGINT NOT NULL CHECK (baseline_dns_revision > 0),
    baseline_route_revision BIGINT NOT NULL CHECK (baseline_route_revision > 0),
    baseline_sharing_revision BIGINT NOT NULL CHECK (baseline_sharing_revision > 0),
    baseline_isolation_generation BIGINT NOT NULL CHECK (baseline_isolation_generation > 0),
    proposed_network_revision BIGINT NOT NULL CHECK (proposed_network_revision > 0),
    proposed_inventory_revision BIGINT NOT NULL CHECK (proposed_inventory_revision > 0),
    proposed_group_revision BIGINT NOT NULL CHECK (proposed_group_revision > 0),
    proposed_policy_revision BIGINT NOT NULL CHECK (proposed_policy_revision > 0),
    proposed_dns_revision BIGINT NOT NULL CHECK (proposed_dns_revision > 0),
    proposed_route_revision BIGINT NOT NULL CHECK (proposed_route_revision > 0),
    proposed_sharing_revision BIGINT NOT NULL CHECK (proposed_sharing_revision > 0),
    proposed_isolation_generation BIGINT NOT NULL CHECK (proposed_isolation_generation > 0),
    candidate_semantic_hash BYTEA NOT NULL,
    compiler_format_version INTEGER NOT NULL CHECK (compiler_format_version BETWEEN 1 AND 3),
    impact_hash BYTEA NOT NULL,
    proposal_request_hash BYTEA NOT NULL,
    proposal_reason TEXT NOT NULL,
    required_approvals SMALLINT NOT NULL DEFAULT 1,
    approval_count SMALLINT NOT NULL DEFAULT 0,
    state TEXT NOT NULL DEFAULT 'pending',
    version BIGINT NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    approved_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    consumed_policy_release_id BIGINT,
    consumed_policy_revision BIGINT,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT policy_approval_request_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT policy_approval_request_change_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(change_public_id), 6) >> 4 = 7
    ),
    CONSTRAINT policy_approval_request_vector_check CHECK (
        proposed_network_revision = baseline_network_revision + 1
        AND proposed_policy_revision = baseline_policy_revision + 1
        AND proposed_inventory_revision = baseline_inventory_revision
        AND proposed_group_revision = baseline_group_revision
        AND proposed_dns_revision = baseline_dns_revision
        AND proposed_route_revision = baseline_route_revision
        AND proposed_sharing_revision = baseline_sharing_revision
        AND proposed_isolation_generation = baseline_isolation_generation
    ),
    CONSTRAINT policy_approval_request_hash_check CHECK (
        pg_catalog.octet_length(candidate_semantic_hash) = 32
        AND pg_catalog.octet_length(impact_hash) = 32
        AND pg_catalog.octet_length(proposal_request_hash) = 32
        AND candidate_semantic_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        AND impact_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
        AND proposal_request_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
    ),
    CONSTRAINT policy_approval_request_reason_check CHECK (
        pg_catalog.octet_length(proposal_reason) BETWEEN 1 AND 512
        AND proposal_reason = pg_catalog.btrim(proposal_reason)
    ),
    CONSTRAINT policy_approval_request_quorum_check CHECK (
        required_approvals = 1
        AND approval_count BETWEEN 0 AND required_approvals
    ),
    CONSTRAINT policy_approval_request_state_check CHECK (
        (
            state = 'pending' AND version = 1 AND approval_count = 0
            AND approved_at IS NULL AND consumed_at IS NULL
            AND consumed_policy_release_id IS NULL AND consumed_policy_revision IS NULL
        )
        OR (
            state = 'approved' AND version = 2 AND approval_count = 1
            AND approved_at IS NOT NULL AND consumed_at IS NULL
            AND consumed_policy_release_id IS NULL AND consumed_policy_revision IS NULL
        )
        OR (
            state = 'consumed' AND version = 3 AND approval_count = 1
            AND approved_at IS NOT NULL AND consumed_at IS NOT NULL
            AND consumed_policy_release_id IS NOT NULL AND consumed_policy_revision > 0
        )
    ),
    CONSTRAINT policy_approval_request_timestamps_check CHECK (
        expires_at = created_at + INTERVAL '10 minutes'
        AND updated_at >= created_at
        AND (approved_at IS NULL OR (approved_at >= created_at AND approved_at < expires_at))
        AND (consumed_at IS NULL OR (consumed_at >= approved_at AND consumed_at < expires_at))
    ),
    CONSTRAINT policy_approval_request_workspace_fk FOREIGN KEY (deployment_id, workspace_id)
        REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT policy_approval_request_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT policy_approval_request_proposer_fk FOREIGN KEY (deployment_id, proposer_principal_id)
        REFERENCES mesh.principal (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT policy_approval_request_session_fk FOREIGN KEY (
        deployment_id, proposer_principal_id, proposer_account_session_id
    ) REFERENCES mesh.account_session (deployment_id, principal_id, id) ON DELETE RESTRICT,
    CONSTRAINT policy_approval_request_release_fk FOREIGN KEY (
        workspace_id, network_id, consumed_policy_release_id, consumed_policy_revision
    ) REFERENCES mesh.policy_release (
        workspace_id, network_id, id, policy_revision
    ) ON DELETE RESTRICT,
    UNIQUE (workspace_id, network_id, id)
);

CREATE INDEX policy_approval_request_scope_state_idx
ON mesh.policy_approval_request (workspace_id, network_id, state, expires_at, id);

CREATE INDEX policy_approval_request_proposer_session_idx
ON mesh.policy_approval_request (
    deployment_id, proposer_principal_id, proposer_account_session_id
);

CREATE TABLE mesh.policy_approval_evidence (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    public_id UUID NOT NULL UNIQUE,
    change_public_id UUID NOT NULL UNIQUE,
    deployment_id BIGINT NOT NULL,
    workspace_id BIGINT NOT NULL,
    network_id BIGINT NOT NULL,
    request_id BIGINT NOT NULL UNIQUE,
    request_version BIGINT NOT NULL CHECK (request_version = 2),
    approver_principal_id BIGINT NOT NULL,
    approver_account_session_id BIGINT NOT NULL,
    approver_session_version BIGINT NOT NULL CHECK (approver_session_version > 0),
    approver_principal_generation BIGINT NOT NULL CHECK (approver_principal_generation > 0),
    approver_account_generation BIGINT NOT NULL CHECK (approver_account_generation > 0),
    approver_provider_generation BIGINT NOT NULL CHECK (approver_provider_generation > 0),
    approver_recovery_epoch BIGINT NOT NULL CHECK (approver_recovery_epoch > 0),
    decision_hash BYTEA NOT NULL,
    decision_reason TEXT NOT NULL,
    version BIGINT NOT NULL DEFAULT 1 CHECK (version = 1),
    approved_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT policy_approval_evidence_public_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(public_id), 6) >> 4 = 7
    ),
    CONSTRAINT policy_approval_evidence_change_id_v7_check CHECK (
        pg_catalog.get_byte(pg_catalog.uuid_send(change_public_id), 6) >> 4 = 7
    ),
    CONSTRAINT policy_approval_evidence_hash_check CHECK (
        pg_catalog.octet_length(decision_hash) = 32
        AND decision_hash <> pg_catalog.decode(pg_catalog.repeat('00', 32), 'hex')
    ),
    CONSTRAINT policy_approval_evidence_reason_check CHECK (
        pg_catalog.octet_length(decision_reason) BETWEEN 1 AND 512
        AND decision_reason = pg_catalog.btrim(decision_reason)
    ),
    CONSTRAINT policy_approval_evidence_timestamps_check CHECK (
        created_at = approved_at AND approved_at < expires_at
    ),
    CONSTRAINT policy_approval_evidence_workspace_fk FOREIGN KEY (deployment_id, workspace_id)
        REFERENCES mesh.workspace (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT policy_approval_evidence_network_fk FOREIGN KEY (workspace_id, network_id)
        REFERENCES mesh.network (workspace_id, id) ON DELETE RESTRICT,
    CONSTRAINT policy_approval_evidence_request_fk FOREIGN KEY (workspace_id, network_id, request_id)
        REFERENCES mesh.policy_approval_request (workspace_id, network_id, id) ON DELETE RESTRICT,
    CONSTRAINT policy_approval_evidence_approver_fk FOREIGN KEY (deployment_id, approver_principal_id)
        REFERENCES mesh.principal (deployment_id, id) ON DELETE RESTRICT,
    CONSTRAINT policy_approval_evidence_session_fk FOREIGN KEY (
        deployment_id, approver_principal_id, approver_account_session_id
    ) REFERENCES mesh.account_session (deployment_id, principal_id, id) ON DELETE RESTRICT
);

CREATE INDEX policy_approval_evidence_scope_request_idx
ON mesh.policy_approval_evidence (workspace_id, network_id, request_id);

CREATE INDEX policy_approval_evidence_approver_session_idx
ON mesh.policy_approval_evidence (
    deployment_id, approver_principal_id, approver_account_session_id
);

CREATE FUNCTION mesh_ops.enforce_policy_approval_workflow_v1()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, mesh
AS $function$
BEGIN
    IF TG_TABLE_NAME = 'policy_approval_evidence' THEN
        IF TG_OP <> 'INSERT' THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Policy approval evidence is immutable';
        END IF;
        RETURN NEW;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Policy approval request evidence is retained';
    END IF;
    IF TG_OP = 'INSERT' THEN
        RETURN NEW;
    END IF;
    IF OLD.public_id <> NEW.public_id
        OR OLD.change_public_id <> NEW.change_public_id
        OR OLD.deployment_id <> NEW.deployment_id
        OR OLD.workspace_id <> NEW.workspace_id
        OR OLD.network_id <> NEW.network_id
        OR OLD.proposer_principal_id <> NEW.proposer_principal_id
        OR OLD.proposer_account_session_id <> NEW.proposer_account_session_id
        OR OLD.proposer_session_version <> NEW.proposer_session_version
        OR OLD.proposer_principal_generation <> NEW.proposer_principal_generation
        OR OLD.proposer_account_generation <> NEW.proposer_account_generation
        OR OLD.proposer_provider_generation <> NEW.proposer_provider_generation
        OR OLD.proposer_recovery_epoch <> NEW.proposer_recovery_epoch
        OR OLD.baseline_network_revision <> NEW.baseline_network_revision
        OR OLD.baseline_inventory_revision <> NEW.baseline_inventory_revision
        OR OLD.baseline_group_revision <> NEW.baseline_group_revision
        OR OLD.baseline_policy_revision <> NEW.baseline_policy_revision
        OR OLD.baseline_dns_revision <> NEW.baseline_dns_revision
        OR OLD.baseline_route_revision <> NEW.baseline_route_revision
        OR OLD.baseline_sharing_revision <> NEW.baseline_sharing_revision
        OR OLD.baseline_isolation_generation <> NEW.baseline_isolation_generation
        OR OLD.proposed_network_revision <> NEW.proposed_network_revision
        OR OLD.proposed_inventory_revision <> NEW.proposed_inventory_revision
        OR OLD.proposed_group_revision <> NEW.proposed_group_revision
        OR OLD.proposed_policy_revision <> NEW.proposed_policy_revision
        OR OLD.proposed_dns_revision <> NEW.proposed_dns_revision
        OR OLD.proposed_route_revision <> NEW.proposed_route_revision
        OR OLD.proposed_sharing_revision <> NEW.proposed_sharing_revision
        OR OLD.proposed_isolation_generation <> NEW.proposed_isolation_generation
        OR OLD.candidate_semantic_hash <> NEW.candidate_semantic_hash
        OR OLD.compiler_format_version <> NEW.compiler_format_version
        OR OLD.impact_hash <> NEW.impact_hash
        OR OLD.proposal_request_hash <> NEW.proposal_request_hash
        OR OLD.proposal_reason <> NEW.proposal_reason
        OR OLD.required_approvals <> NEW.required_approvals
        OR OLD.expires_at <> NEW.expires_at
        OR OLD.created_at <> NEW.created_at THEN
        RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'Policy approval binding is immutable';
    END IF;
    IF OLD.state = 'pending' AND NEW.state = 'approved' THEN
        IF OLD.version <> 1 OR NEW.version <> 2
            OR OLD.approval_count <> 0 OR NEW.approval_count <> 1
            OR OLD.approved_at IS NOT NULL OR NEW.approved_at IS NULL
            OR NEW.consumed_at IS NOT NULL OR NEW.consumed_policy_release_id IS NOT NULL
            OR NEW.consumed_policy_revision IS NOT NULL OR NEW.updated_at <> NEW.approved_at THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Policy approval transition';
        END IF;
        RETURN NEW;
    END IF;
    IF OLD.state = 'approved' AND NEW.state = 'consumed' THEN
        IF OLD.version <> 2 OR NEW.version <> 3
            OR OLD.approval_count <> 1 OR NEW.approval_count <> 1
            OR OLD.approved_at <> NEW.approved_at
            OR OLD.consumed_at IS NOT NULL OR NEW.consumed_at IS NULL
            OR NEW.consumed_policy_release_id IS NULL OR NEW.consumed_policy_revision IS NULL
            OR NEW.updated_at <> NEW.consumed_at THEN
            RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Policy approval consumption';
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION USING ERRCODE = '23514', MESSAGE = 'invalid Policy approval request transition';
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.enforce_policy_approval_workflow_v1() FROM PUBLIC;

CREATE TRIGGER policy_approval_request_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.policy_approval_request
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_policy_approval_workflow_v1();

CREATE TRIGGER policy_approval_evidence_transition
BEFORE INSERT OR UPDATE OR DELETE ON mesh.policy_approval_evidence
FOR EACH ROW EXECUTE FUNCTION mesh_ops.enforce_policy_approval_workflow_v1();

CREATE TRIGGER policy_approval_request_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.policy_approval_request
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation(
    'policy_approval_request', 'public_id'
);

CREATE TRIGGER policy_approval_evidence_authority_mutation
AFTER INSERT OR UPDATE OR DELETE ON mesh.policy_approval_evidence
FOR EACH ROW EXECUTE FUNCTION mesh_audit.capture_authority_mutation(
    'policy_approval_evidence', 'public_id'
);

ALTER TABLE mesh.policy_approval_request ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.policy_approval_request FORCE ROW LEVEL SECURITY;
CREATE POLICY policy_approval_request_migrator_policy ON mesh.policy_approval_request
TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);

ALTER TABLE mesh.policy_approval_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE mesh.policy_approval_evidence FORCE ROW LEVEL SECURITY;
CREATE POLICY policy_approval_evidence_migrator_policy ON mesh.policy_approval_evidence
TO mesh_migrator USING (TRUE) WITH CHECK (TRUE);

CREATE FUNCTION mesh_ops.create_policy_approval_request_v1(
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
    IF p_expires_at <> p_occurred_at + INTERVAL '10 minutes'
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
      AND session.idle_expires_at > p_occurred_at
      AND session.absolute_expires_at > p_occurred_at
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
        1, 0, 'pending', 1, p_occurred_at, p_expires_at, p_occurred_at
    ) RETURNING version INTO inserted_version;
    RETURN inserted_version;
END;
$function$;

CREATE FUNCTION mesh_ops.lock_policy_approval_request_v1(p_request_public_id UUID)
RETURNS TABLE (
    request_version BIGINT, request_state TEXT,
    proposer_principal_public_id UUID, proposer_session_public_id UUID,
    baseline_network BIGINT, baseline_inventory BIGINT, baseline_group BIGINT,
    baseline_policy BIGINT, baseline_dns BIGINT, baseline_route BIGINT,
    baseline_sharing BIGINT, baseline_isolation BIGINT,
    proposed_network BIGINT, proposed_inventory BIGINT, proposed_group BIGINT,
    proposed_policy BIGINT, proposed_dns BIGINT, proposed_route BIGINT,
    proposed_sharing BIGINT, proposed_isolation BIGINT,
    candidate_hash BYTEA, compiler_format INTEGER, simulation_impact_hash BYTEA,
    request_created_at TIMESTAMPTZ, request_expires_at TIMESTAMPTZ
)
LANGUAGE sql
VOLATILE
PARALLEL UNSAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
    SELECT request.version, request.state, proposer.public_id, session.public_id,
           request.baseline_network_revision, request.baseline_inventory_revision,
           request.baseline_group_revision, request.baseline_policy_revision,
           request.baseline_dns_revision, request.baseline_route_revision,
           request.baseline_sharing_revision, request.baseline_isolation_generation,
           request.proposed_network_revision, request.proposed_inventory_revision,
           request.proposed_group_revision, request.proposed_policy_revision,
           request.proposed_dns_revision, request.proposed_route_revision,
           request.proposed_sharing_revision, request.proposed_isolation_generation,
           request.candidate_semantic_hash, request.compiler_format_version,
           request.impact_hash, request.created_at, request.expires_at
    FROM mesh.policy_approval_request AS request
    JOIN mesh.principal AS proposer ON proposer.id = request.proposer_principal_id
    JOIN mesh.account_session AS session ON session.id = request.proposer_account_session_id
    WHERE request.workspace_id = mesh_ops.current_workspace_id()
      AND request.network_id = mesh_ops.current_network_id()
      AND request.public_id = p_request_public_id
    FOR UPDATE OF request
$function$;

CREATE FUNCTION mesh_ops.load_policy_approval_request_v1(p_request_public_id UUID)
RETURNS TABLE (
    proposer_principal_public_id UUID, proposer_session_public_id UUID,
    baseline_network BIGINT, baseline_inventory BIGINT, baseline_group BIGINT,
    baseline_policy BIGINT, baseline_dns BIGINT, baseline_route BIGINT,
    baseline_sharing BIGINT, baseline_isolation BIGINT,
    proposed_network BIGINT, proposed_inventory BIGINT, proposed_group BIGINT,
    proposed_policy BIGINT, proposed_dns BIGINT, proposed_route BIGINT,
    proposed_sharing BIGINT, proposed_isolation BIGINT,
    candidate_hash BYTEA, compiler_format INTEGER, simulation_impact_hash BYTEA,
    request_created_at TIMESTAMPTZ, request_expires_at TIMESTAMPTZ
)
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
    SELECT proposer.public_id, session.public_id,
           request.baseline_network_revision, request.baseline_inventory_revision,
           request.baseline_group_revision, request.baseline_policy_revision,
           request.baseline_dns_revision, request.baseline_route_revision,
           request.baseline_sharing_revision, request.baseline_isolation_generation,
           request.proposed_network_revision, request.proposed_inventory_revision,
           request.proposed_group_revision, request.proposed_policy_revision,
           request.proposed_dns_revision, request.proposed_route_revision,
           request.proposed_sharing_revision, request.proposed_isolation_generation,
           request.candidate_semantic_hash, request.compiler_format_version,
           request.impact_hash, request.created_at, request.expires_at
    FROM mesh.policy_approval_request AS request
    JOIN mesh.principal AS proposer ON proposer.id = request.proposer_principal_id
    JOIN mesh.account_session AS session ON session.id = request.proposer_account_session_id
    WHERE request.workspace_id = mesh_ops.current_workspace_id()
      AND request.network_id = mesh_ops.current_network_id()
      AND request.public_id = p_request_public_id
$function$;

CREATE FUNCTION mesh_ops.approve_policy_approval_request_v1(
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
      AND session.idle_expires_at > p_occurred_at
      AND session.absolute_expires_at > p_occurred_at
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
    IF p_occurred_at >= request_row.expires_at THEN
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
        approved_at = p_occurred_at, updated_at = p_occurred_at
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
        p_decision_hash, p_reason, 1, p_occurred_at, request_row.expires_at, p_occurred_at
    ) RETURNING version INTO approval_evidence_version;
    RETURN NEXT;
END;
$function$;

CREATE FUNCTION mesh_ops.load_policy_approval_evidence_v1(p_evidence_public_id UUID)
RETURNS TABLE (
    request_public_id UUID,
    proposer_principal_public_id UUID, proposer_session_public_id UUID,
    approver_principal_public_id UUID, approver_session_public_id UUID,
    baseline_network BIGINT, baseline_inventory BIGINT, baseline_group BIGINT,
    baseline_policy BIGINT, baseline_dns BIGINT, baseline_route BIGINT,
    baseline_sharing BIGINT, baseline_isolation BIGINT,
    proposed_network BIGINT, proposed_inventory BIGINT, proposed_group BIGINT,
    proposed_policy BIGINT, proposed_dns BIGINT, proposed_route BIGINT,
    proposed_sharing BIGINT, proposed_isolation BIGINT,
    candidate_hash BYTEA, compiler_format INTEGER, simulation_impact_hash BYTEA,
    approved_request_version BIGINT, approval_evidence_version BIGINT,
    evidence_approved_at TIMESTAMPTZ, evidence_expires_at TIMESTAMPTZ
)
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
    SELECT request.public_id, proposer.public_id, proposer_session.public_id,
           approver.public_id, approver_session.public_id,
           request.baseline_network_revision, request.baseline_inventory_revision,
           request.baseline_group_revision, request.baseline_policy_revision,
           request.baseline_dns_revision, request.baseline_route_revision,
           request.baseline_sharing_revision, request.baseline_isolation_generation,
           request.proposed_network_revision, request.proposed_inventory_revision,
           request.proposed_group_revision, request.proposed_policy_revision,
           request.proposed_dns_revision, request.proposed_route_revision,
           request.proposed_sharing_revision, request.proposed_isolation_generation,
           request.candidate_semantic_hash, request.compiler_format_version,
           request.impact_hash, evidence.request_version, evidence.version,
           evidence.approved_at, evidence.expires_at
    FROM mesh.policy_approval_evidence AS evidence
    JOIN mesh.policy_approval_request AS request ON request.id = evidence.request_id
    JOIN mesh.principal AS proposer ON proposer.id = request.proposer_principal_id
    JOIN mesh.account_session AS proposer_session
      ON proposer_session.id = request.proposer_account_session_id
    JOIN mesh.principal AS approver ON approver.id = evidence.approver_principal_id
    JOIN mesh.account_session AS approver_session
      ON approver_session.id = evidence.approver_account_session_id
    WHERE evidence.workspace_id = mesh_ops.current_workspace_id()
      AND evidence.network_id = mesh_ops.current_network_id()
      AND evidence.public_id = p_evidence_public_id
$function$;

REVOKE ALL ON mesh.policy_approval_request, mesh.policy_approval_evidence
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

REVOKE ALL ON SEQUENCE mesh.policy_approval_request_id_seq,
                       mesh.policy_approval_evidence_id_seq
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

REVOKE ALL ON FUNCTION mesh_ops.create_policy_approval_request_v1(
    UUID, UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    BYTEA, INTEGER, BYTEA, BYTEA, TEXT, TIMESTAMPTZ, TIMESTAMPTZ
) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.lock_policy_approval_request_v1(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.load_policy_approval_request_v1(UUID) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.approve_policy_approval_request_v1(
    UUID, UUID, UUID, BIGINT, BYTEA, BYTEA, UUID, UUID, UUID,
    BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BYTEA, TEXT, TIMESTAMPTZ
) FROM PUBLIC;
REVOKE ALL ON FUNCTION mesh_ops.load_policy_approval_evidence_v1(UUID) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION mesh_ops.create_policy_approval_request_v1(
    UUID, UUID, UUID, UUID, UUID, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BIGINT,
    BYTEA, INTEGER, BYTEA, BYTEA, TEXT, TIMESTAMPTZ, TIMESTAMPTZ
) TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.lock_policy_approval_request_v1(UUID) TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.load_policy_approval_request_v1(UUID) TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.approve_policy_approval_request_v1(
    UUID, UUID, UUID, BIGINT, BYTEA, BYTEA, UUID, UUID, UUID,
    BIGINT, BIGINT, BIGINT, BIGINT, BIGINT, BYTEA, TEXT, TIMESTAMPTZ
) TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.load_policy_approval_evidence_v1(UUID) TO mesh_runtime;

ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA mesh_ops REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
