package postgres

const configurePolicyPublicationTransactionSQL = `SELECT
    pg_catalog.set_config('statement_timeout', $1, TRUE),
    pg_catalog.set_config('lock_timeout', $2, TRUE),
    pg_catalog.set_config('idle_in_transaction_session_timeout', $3, TRUE)`

const setPolicyPublicationScopeSQL = `SELECT workspace_internal_id, network_internal_id
FROM mesh_ops.set_network_scope($1::UUID, $2::UUID)`

const authorizePolicyPublicationSQL = `SELECT
    COALESCE(role_binding_public_id::TEXT, ''),
    COALESCE(role_definition_public_id::TEXT, ''),
    scope_authority_generation,
    membership_authority_generation,
    binding_authority_generation,
    role_authority_generation,
    binding_expires_at IS NOT NULL,
    COALESCE(binding_expires_at, $13::TIMESTAMPTZ),
    workspace_owner_authority_generation
FROM mesh_ops.resolve_network_permission_v2(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID,
    $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::UUID, $12::TEXT, $13::TIMESTAMPTZ
)
LIMIT 1`

const lockPolicyPublicationRevisionSQL = `SELECT *
FROM mesh_ops.lock_network_revision()`

const lockActivePolicyReleaseSQL = `SELECT *
FROM mesh_ops.lock_active_policy_release()`

const lockPolicyPublicationAuditStreamSQL = `SELECT stream_internal_id, next_sequence, latest_event_hash
FROM mesh_audit.lock_network_stream_head()`

const lockPolicyPublicationApprovalSQL = `SELECT
    request_public_id::TEXT, evidence_public_id::TEXT,
    baseline_network, baseline_inventory, baseline_group, baseline_policy,
    baseline_dns, baseline_route, baseline_sharing, baseline_isolation,
    proposed_network, proposed_inventory, proposed_group, proposed_policy,
    proposed_dns, proposed_route, proposed_sharing, proposed_isolation,
    candidate_hash, compiler_format, simulation_impact_hash,
    approved_request_version, approval_evidence_version,
    evidence_approved_at, evidence_expires_at,
    approver_session_public_id::TEXT, deployment_public_id::TEXT,
    approver_principal_public_id::TEXT, identity_subject_public_id::TEXT,
    approver_session_version, approver_principal_generation,
    approver_account_generation, approver_provider_generation,
    approver_recovery_epoch
FROM mesh_ops.lock_policy_approval_for_publication_v1(
    $1::UUID, $2::TIMESTAMPTZ
)`

const setPolicyPublicationChangeSQL = `SELECT pg_catalog.set_config(
    'mesh.change_public_id',
    $1::TEXT,
    TRUE
)`

const publishCompiledPolicySQL = `SELECT network_revision, policy_revision, release_version
FROM mesh_ops.publish_compiled_policy(
    $1::UUID,
    $2::BIGINT,
    $3::BYTEA,
    $4::INTEGER,
    $5::TIMESTAMPTZ,
    $6::JSONB
)`

// publishScaledCompiledPolicySQL publishes a policy naming up to 10000
// Imported Resources instead of 256 (schema 148); used once runtime may run
// it.
const publishScaledCompiledPolicySQL = `SELECT network_revision, policy_revision, release_version
FROM mesh_ops.publish_compiled_policy_v2(
    $1::UUID,
    $2::BIGINT,
    $3::BYTEA,
    $4::INTEGER,
    $5::TIMESTAMPTZ,
    $6::JSONB
)`

const scaledPolicyPublicationGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.publish_compiled_policy_v2(uuid,bigint,bytea,integer,timestamp with time zone,jsonb)'),
    'EXECUTE'), FALSE)`

const attachPolicyResourceDestinationsSQL = `SELECT attached_count
FROM mesh_ops.attach_policy_resource_destinations(
    $1::UUID,
    $2::TIMESTAMPTZ,
    $3::JSONB
)`

const attachPolicyResourceGroupDestinationsSQL = `SELECT attached_count
FROM mesh_ops.attach_policy_resource_group_destinations(
    $1::UUID,
    $2::TIMESTAMPTZ,
    $3::JSONB
)`

const attachPolicyGroupRulesSQL = `SELECT mesh_ops.attach_policy_group_rules_v2(
    $1::UUID,
    $2::TIMESTAMPTZ,
    $3::JSONB
)`

// attachKubernetesPolicyGroupRulesSQL attaches group rules with the
// Kubernetes groups of rules to clusters, marking them hashed (schema 236).
const attachKubernetesPolicyGroupRulesSQL = `SELECT mesh_ops.attach_policy_group_rules_v3(
    $1::UUID,
    $2::TIMESTAMPTZ,
    $3::JSONB
)`

const kubernetesGroupRulesGrantedSQL = `SELECT COALESCE(pg_catalog.has_function_privilege(
    pg_catalog.to_regprocedure('mesh_ops.attach_policy_group_rules_v3(uuid,timestamp with time zone,jsonb)'),
    'EXECUTE'), FALSE)`

const consumePolicyPublicationApprovalSQL = `SELECT
    mesh_ops.consume_policy_approval_for_publication_v1(
        $1::UUID, $2::UUID, $3::BYTEA, $4::INTEGER,
        $5::BYTEA, $6::TIMESTAMPTZ
    )`

const appendPolicyPublicationEvidenceSQL = `SELECT mesh_audit.append_authority_evidence(
    $1::BIGINT, $2::UUID, $3::UUID, $4::BIGINT, $5::BYTEA, $6::BYTEA,
    'policy_release', $7::UUID, $8::BIGINT, $9::BIGINT, $10::UUID,
    $11::TEXT, 'policy.publish', $12::UUID, $13::BYTEA, $14::BYTEA,
    $15::JSONB, 'network.revision.advanced', $16::JSONB
)`

const loadCommittedPolicyReleaseSQL = `SELECT
    release.activated_network_revision,
    release.policy_revision,
    release.semantic_hash,
    evidence.public_id::TEXT
FROM mesh.policy_release AS release
LEFT JOIN mesh.policy_approval_request AS approval_request
  ON approval_request.workspace_id = release.workspace_id
 AND approval_request.network_id = release.network_id
 AND approval_request.consumed_policy_release_id = release.id
 AND approval_request.consumed_policy_revision = release.policy_revision
LEFT JOIN mesh.policy_approval_evidence AS evidence
  ON evidence.workspace_id = approval_request.workspace_id
 AND evidence.network_id = approval_request.network_id
 AND evidence.request_id = approval_request.id
WHERE release.workspace_id = $1::BIGINT
  AND release.network_id = $2::BIGINT
  AND release.public_id = $3::UUID`

// readPolicyReleaseRuleFingerprintsSQL returns the stored rule fingerprints
// of the release being replaced, or NULL when it has none (schema 174).
const readPolicyReleaseRuleFingerprintsSQL = `SELECT mesh_ops.read_policy_release_rule_fingerprints_v1($1::UUID)`

// recordPolicyReleaseRuleFingerprintsSQL stores the new release's rule
// fingerprints and returns their rule count (schema 174).
const recordPolicyReleaseRuleFingerprintsSQL = `SELECT mesh_ops.record_policy_release_rule_fingerprints_v1(
    $1::UUID, $2::BYTEA
)`
