CREATE INDEX policy_approval_request_management_cursor_idx
ON mesh.policy_approval_request (workspace_id, network_id, public_id);

CREATE INDEX policy_approval_request_management_state_cursor_idx
ON mesh.policy_approval_request (workspace_id, network_id, state, public_id);

CREATE FUNCTION mesh_ops.policy_approval_request_payload_v1(p_request_id BIGINT)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
    SELECT pg_catalog.jsonb_build_object(
        'request_id', request.public_id,
        'proposer_principal_id', proposer.public_id,
        'proposal_reason', request.proposal_reason,
        'state', request.state,
        'request_version', request.version,
        'baseline', pg_catalog.jsonb_build_array(
            request.baseline_network_revision, request.baseline_inventory_revision,
            request.baseline_group_revision, request.baseline_policy_revision,
            request.baseline_dns_revision, request.baseline_route_revision,
            request.baseline_sharing_revision, request.baseline_isolation_generation
        ),
        'proposed', pg_catalog.jsonb_build_array(
            request.proposed_network_revision, request.proposed_inventory_revision,
            request.proposed_group_revision, request.proposed_policy_revision,
            request.proposed_dns_revision, request.proposed_route_revision,
            request.proposed_sharing_revision, request.proposed_isolation_generation
        ),
        'candidate_semantic_hash', pg_catalog.encode(request.candidate_semantic_hash, 'hex'),
        'compiler_format_version', request.compiler_format_version,
        'impact_hash', pg_catalog.encode(request.impact_hash, 'hex'),
        'created_at', request.created_at,
        'expires_at', request.expires_at,
        'updated_at', request.updated_at,
        'evidence_id', evidence.public_id,
        'approver_principal_id', approver.public_id,
        'decision_reason', evidence.decision_reason,
        'evidence_version', evidence.version,
        'approved_at', evidence.approved_at,
        'release_id', release.public_id,
        'consumed_policy_revision', request.consumed_policy_revision,
        'consumed_at', request.consumed_at
    )
    FROM mesh.policy_approval_request AS request
    JOIN mesh.principal AS proposer
      ON proposer.deployment_id = request.deployment_id
     AND proposer.id = request.proposer_principal_id
    LEFT JOIN mesh.policy_approval_evidence AS evidence
      ON evidence.workspace_id = request.workspace_id
     AND evidence.network_id = request.network_id
     AND evidence.request_id = request.id
    LEFT JOIN mesh.principal AS approver
      ON approver.deployment_id = evidence.deployment_id
     AND approver.id = evidence.approver_principal_id
    LEFT JOIN mesh.policy_release AS release
      ON release.workspace_id = request.workspace_id
     AND release.network_id = request.network_id
     AND release.id = request.consumed_policy_release_id
    WHERE request.id = p_request_id
      AND request.workspace_id = mesh_ops.current_workspace_id()
      AND request.network_id = mesh_ops.current_network_id()
$function$;

CREATE FUNCTION mesh_ops.read_policy_approval_request_management_v1(p_request_public_id UUID)
RETURNS JSONB
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
    SELECT mesh_ops.policy_approval_request_payload_v1(request.id)
    FROM mesh.policy_approval_request AS request
    WHERE request.workspace_id = mesh_ops.current_workspace_id()
      AND request.network_id = mesh_ops.current_network_id()
      AND request.public_id = p_request_public_id
$function$;

CREATE FUNCTION mesh_ops.list_policy_approval_requests_management_v1(
    p_after_public_id UUID,
    p_state TEXT,
    p_limit INTEGER
)
RETURNS JSONB
LANGUAGE plpgsql
STABLE
PARALLEL SAFE
SECURITY DEFINER
SET search_path = pg_catalog, mesh, mesh_ops
AS $function$
DECLARE
    result JSONB;
BEGIN
    IF p_limit < 1 OR p_limit > 101 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Policy approval page limit';
    END IF;
    IF p_state IS NOT NULL AND p_state NOT IN ('pending', 'approved', 'consumed') THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'invalid Policy approval state filter';
    END IF;

    SELECT COALESCE(
        pg_catalog.jsonb_agg(candidate.payload ORDER BY candidate.public_id),
        '[]'::JSONB
    ) INTO result
    FROM (
        SELECT
            request.public_id,
            mesh_ops.policy_approval_request_payload_v1(request.id) AS payload
        FROM mesh.policy_approval_request AS request
        WHERE request.workspace_id = mesh_ops.current_workspace_id()
          AND request.network_id = mesh_ops.current_network_id()
          AND (p_after_public_id IS NULL OR request.public_id > p_after_public_id)
          AND (p_state IS NULL OR request.state = p_state)
        ORDER BY request.public_id
        LIMIT p_limit
    ) AS candidate;
    RETURN result;
END;
$function$;

REVOKE ALL ON FUNCTION mesh_ops.policy_approval_request_payload_v1(BIGINT)
FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.read_policy_approval_request_management_v1(UUID)
FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;
REVOKE ALL ON FUNCTION mesh_ops.list_policy_approval_requests_management_v1(UUID, TEXT, INTEGER)
FROM PUBLIC, mesh_worker, mesh_observer, mesh_audit_writer, mesh_share_writer;

GRANT EXECUTE ON FUNCTION mesh_ops.read_policy_approval_request_management_v1(UUID)
TO mesh_runtime;
GRANT EXECUTE ON FUNCTION mesh_ops.list_policy_approval_requests_management_v1(UUID, TEXT, INTEGER)
TO mesh_runtime;
