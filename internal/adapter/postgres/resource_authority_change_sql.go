package postgres

const previewResourceAuthorityChangeSQL = `SELECT
    display_name, owner_principal_public_id::TEXT,
    custodian_principal_public_id::TEXT, resource_state,
    resource_version, semantic_hash, device_public_id::TEXT,
    target_generation, target_principal_public_id::TEXT
FROM mesh_ops.preview_resource_authority_change_v1($1::UUID, $2, $3::UUID)`

const lockResourceAuthorityChangeSQL = `SELECT
    display_name, owner_principal_public_id::TEXT,
    custodian_principal_public_id::TEXT, resource_state,
    resource_version, semantic_hash, device_public_id::TEXT,
    target_generation, target_principal_public_id::TEXT
FROM mesh_ops.lock_resource_authority_change_v1($1::UUID, $2, $3::UUID)`

const previewResourceGroupAuthorityChangeSQL = `SELECT
    display_name, owner_principal_public_id::TEXT,
    custodian_principal_public_id::TEXT, group_state,
    group_version, definition_version, semantic_hash, members,
    target_principal_public_id::TEXT
FROM mesh_ops.preview_resource_group_authority_change_v1($1::UUID, $2, $3::UUID)`

const lockResourceGroupAuthorityChangeSQL = `SELECT
    display_name, owner_principal_public_id::TEXT,
    custodian_principal_public_id::TEXT, group_state,
    group_version, definition_version, semantic_hash, members,
    target_principal_public_id::TEXT
FROM mesh_ops.lock_resource_group_authority_change_v1($1::UUID, $2, $3::UUID)`

const requestResourceAuthorityChangeSQL = `SELECT
    network_revision, subsystem_revision, request_version
FROM mesh_ops.request_resource_authority_change_v1(
    $1::UUID, $2::UUID, $3, $4::UUID, $5, $6,
    $7::UUID, $8::UUID, $9::UUID, $10, $11, $12
)`

const lockResourceAuthorityChangeRequestSQL = `SELECT
    subject_kind, subject_public_id::TEXT, action,
    target_principal_public_id::TEXT, expected_subject_version,
    impact_hash, request_version, request_state, expires_at,
    requester_session_public_id::TEXT, requester_deployment_public_id::TEXT,
    requester_principal_public_id::TEXT, requester_identity_subject_public_id::TEXT,
    requester_login_workspace_public_id::TEXT, requester_authentication_time,
    requester_acr, requester_amr, requester_session_version,
    requester_principal_generation, requester_account_generation,
    requester_provider_generation, requester_recovery_epoch,
    requester_idle_expires_at, requester_absolute_expires_at
FROM mesh_ops.lock_resource_authority_change_request_v1($1::UUID)`

const confirmResourceAuthorityChangeSQL = `SELECT
    network_revision, subsystem_revision, subject_version, request_version,
    owner_principal_public_id::TEXT, custodian_principal_public_id::TEXT,
    semantic_hash
FROM mesh_ops.confirm_resource_authority_change_v1(
    $1::UUID, $2::UUID, $3, $4::UUID, $5::UUID, $6, $7, $8
)`
