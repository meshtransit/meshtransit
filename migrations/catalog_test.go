package migrations

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestCatalogContainsOrderedFoundations(t *testing.T) {
	t.Parallel()

	catalog := Catalog()
	if len(catalog) != 43 {
		t.Fatalf("len(Catalog()) = %d, want 43", len(catalog))
	}

	persistence := catalog[26]
	if persistence.Description != "OIDC authentication transaction persistence" {
		t.Fatalf("migration 27 description = %q, want OIDC transaction persistence", persistence.Description)
	}
	for _, required := range []string{
		"ADD COLUMN authorization_endpoint TEXT",
		"ADD COLUMN token_endpoint TEXT",
		"ADD COLUMN binding_semantic_hash BYTEA",
		"auth_transaction_open_expiry_idx",
		"workspace_oidc_auth_transaction_scope_policy",
		"workspace_oidc_auth_transaction_lock_policy",
		"mesh.requested_workspace_public_id",
		"CREATE FUNCTION mesh_audit.lock_deployment_stream_head",
		"CREATE FUNCTION mesh_ops.create_oidc_auth_transaction_v1",
		"CREATE FUNCTION mesh_ops.load_oidc_auth_transaction_creation_v1",
		"provider.authorization_endpoint = p_authorization_endpoint",
		"provider.token_endpoint = p_token_endpoint",
		"provider.current_generation = p_provider_generation",
		"generation.valid_from <= pg_catalog.transaction_timestamp()",
		"deployment.recovery_epoch = p_recovery_epoch",
		"workspace_provider.organization_digest IS NULL",
		"FOR SHARE OF",
		"GRANT EXECUTE ON FUNCTION mesh_ops.create_oidc_auth_transaction_v1",
	} {
		if !strings.Contains(persistence.SQL, required) {
			t.Errorf("OIDC transaction persistence SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"DROP ",
	} {
		if strings.Contains(persistence.SQL, forbidden) {
			t.Errorf("OIDC transaction persistence SQL contains excessive capability %q", forbidden)
		}
	}

	rotation := catalog[25]
	if rotation.Description != "authenticated Node-key rotation authority" {
		t.Fatalf("migration 26 description = %q, want Node-key rotation authority", rotation.Description)
	}
	for _, required := range []string{
		"device_node_key_epoch_key_history_uidx",
		"workspace_node_key_rotation_scope_policy",
		"network_node_key_rotation_scope_policy",
		"CREATE FUNCTION mesh_ops.resolve_node_key_rotation_scope",
		"p_old_node_key = p_new_node_key THEN",
		"node_key.public_key IN (p_old_node_key, p_new_node_key)",
		"mesh.node_key_rotation_workspace_id",
		"COALESCE(previous_workspace_id, '')",
		"SECURITY DEFINER",
		"GRANT EXECUTE ON FUNCTION mesh_ops.resolve_node_key_rotation_scope",
	} {
		if !strings.Contains(rotation.SQL, required) {
			t.Errorf("Node-key rotation migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"BYPASSRLS",
		"DROP ",
	} {
		if strings.Contains(rotation.SQL, forbidden) {
			t.Errorf("Node-key rotation migration SQL contains excessive capability %q", forbidden)
		}
	}
	for index, migration := range catalog {
		if migration.Version != int64(index+1) {
			t.Fatalf("migration %d version = %d, want %d", index, migration.Version, index+1)
		}
		digest := sha256.Sum256([]byte(migration.SQL))
		if migration.Checksum != hex.EncodeToString(digest[:]) {
			t.Fatalf("migration %d checksum = %q, want SHA-256 of SQL", migration.Version, migration.Checksum)
		}
	}

	platform := catalog[0]
	if platform.Description != "platform migration foundation" {
		t.Fatalf("migration 1 description = %q, want platform foundation", platform.Description)
	}
	for _, required := range []string{
		"REVOKE ALL ON DATABASE",
		"GRANT CONNECT ON DATABASE",
		"CREATE SCHEMA mesh;",
		"CREATE SCHEMA mesh_ops;",
		"CREATE SCHEMA mesh_audit;",
		"CREATE TABLE mesh_ops.schema_migration",
		"CREATE TABLE mesh_ops.schema_compatibility",
		"CREATE TABLE mesh_ops.data_backfill",
	} {
		if !strings.Contains(platform.SQL, required) {
			t.Errorf("migration SQL missing %q", required)
		}
	}
	if strings.Contains(platform.SQL, "CREATE TABLE mesh.") {
		t.Fatal("platform migration created a business table")
	}

	authority := catalog[1]
	if authority.Description != "tenancy and address authority foundation" {
		t.Fatalf("migration 2 description = %q, want tenancy and address authority foundation", authority.Description)
	}
	for _, required := range []string{
		"REVOKE ALL ON DATABASE",
		"GRANT CONNECT ON DATABASE",
		"CREATE TABLE mesh.deployment",
		"CREATE TABLE mesh.principal",
		"CREATE TABLE mesh.workspace",
		"CREATE TABLE mesh.network",
		"CREATE TABLE mesh.address_realm",
		"CREATE TABLE mesh.address_pool",
		"CREATE TABLE mesh.network_prefix",
		"CREATE TABLE mesh_ops.network_revision",
		"EXCLUDE USING gist",
		"prefix inet_ops WITH &&",
		"ENABLE ROW LEVEL SECURITY",
		"FORCE ROW LEVEL SECURITY",
		"CREATE POLICY",
		"GRANT SELECT",
	} {
		if !strings.Contains(authority.SQL, required) {
			t.Errorf("authority migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"CREATE TABLE mesh.device",
		"CREATE TABLE mesh.access_rule",
		"CREATE TABLE mesh.enrollment",
	} {
		if strings.Contains(authority.SQL, forbidden) {
			t.Errorf("authority migration SQL contains deferred capability %q", forbidden)
		}
	}

	integrity := catalog[2]
	if integrity.Description != "audit and outbox integrity foundation" {
		t.Fatalf("migration 3 description = %q, want audit and outbox integrity foundation", integrity.Description)
	}
	for _, required := range []string{
		"CREATE TABLE mesh_ops.outbox_event",
		"CREATE TABLE mesh_audit.audit_stream",
		"CREATE TABLE mesh_audit.audit_event_identity",
		"CREATE TABLE mesh_audit.authority_mutation",
		"CREATE TABLE mesh_audit.audit_event",
		"PARTITION BY RANGE (occurred_at)",
		"CREATE TABLE mesh_audit.audit_event_default",
		"CREATE CONSTRAINT TRIGGER authority_mutation_evidence_check",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh_audit, mesh_ops, mesh",
		"REVOKE ALL ON FUNCTION mesh_audit.append_authority_evidence",
		"ENABLE ROW LEVEL SECURITY",
		"FORCE ROW LEVEL SECURITY",
		"CREATE TRIGGER deployment_authority_mutation",
		"CREATE TRIGGER principal_authority_mutation",
		"CREATE TRIGGER workspace_authority_mutation",
		"CREATE TRIGGER network_authority_mutation",
		"CREATE TRIGGER address_realm_authority_mutation",
		"CREATE TRIGGER address_pool_authority_mutation",
		"CREATE TRIGGER network_prefix_authority_mutation",
		"outbox_event_pending_idx",
	} {
		if !strings.Contains(integrity.SQL, required) {
			t.Errorf("integrity migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT INSERT ON mesh_ops.outbox_event TO mesh_runtime",
		"GRANT UPDATE ON mesh_ops.outbox_event TO mesh_worker",
		"GRANT EXECUTE ON FUNCTION mesh_audit.append_authority_evidence TO mesh_runtime",
	} {
		if strings.Contains(integrity.SQL, forbidden) {
			t.Errorf("integrity migration SQL exposes deferred serving capability %q", forbidden)
		}
	}

	delivery := catalog[3]
	if delivery.Description != "outbox worker delivery capability" {
		t.Fatalf("migration 4 description = %q, want outbox worker delivery capability", delivery.Description)
	}
	for _, required := range []string{
		"CREATE POLICY outbox_event_worker_policy",
		"TO mesh_worker",
		"GRANT SELECT (",
		"GRANT UPDATE (",
		"GRANT INSERT (",
		"GRANT USAGE, SELECT ON SEQUENCE mesh_ops.outbox_attempt_id_seq TO mesh_worker",
	} {
		if !strings.Contains(delivery.SQL, required) {
			t.Errorf("outbox delivery migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"TO mesh_runtime",
		"GRANT DELETE",
		"GRANT TRUNCATE",
		"GRANT ALL",
		"BYPASSRLS",
	} {
		if strings.Contains(delivery.SQL, forbidden) {
			t.Errorf("outbox delivery migration SQL contains excessive capability %q", forbidden)
		}
	}

	registration := catalog[4]
	if registration.Description != "node enrollment and registration authority" {
		t.Fatalf("migration 5 description = %q, want node enrollment authority", registration.Description)
	}
	for _, required := range []string{
		"CREATE TABLE mesh.enrollment_profile",
		"CREATE TABLE mesh.enrollment_credential",
		"CREATE TABLE mesh.device",
		"CREATE TABLE mesh.device_machine_key_epoch",
		"CREATE TABLE mesh.device_node_key_epoch",
		"CREATE TABLE mesh.pending_registration",
		"CREATE TABLE mesh.enrollment_credential_use",
		"CREATE TABLE mesh.node_address_lease",
		"ENABLE ROW LEVEL SECURITY",
		"FORCE ROW LEVEL SECURITY",
		"CREATE TRIGGER enrollment_credential_authority_mutation",
		"CREATE TRIGGER device_authority_mutation",
		"CREATE TRIGGER node_address_lease_authority_mutation",
		"GRANT EXECUTE ON FUNCTION mesh_audit.append_authority_evidence",
	} {
		if !strings.Contains(registration.SQL, required) {
			t.Errorf("registration migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"plaintext",
		"GRANT DELETE",
		"GRANT TRUNCATE",
		"GRANT ALL",
		"BYPASSRLS",
	} {
		if strings.Contains(registration.SQL, forbidden) {
			t.Errorf("registration migration SQL contains forbidden capability %q", forbidden)
		}
	}
	intentHash := catalog[5]
	if intentHash.Description != "registration intent semantic hash" {
		t.Fatalf("migration 6 description = %q, want registration intent semantic hash", intentHash.Description)
	}
	for _, required := range []string{
		"ADD COLUMN request_hash BYTEA",
		"uuid_send(public_id) || pg_catalog.uuid_send(public_id)",
		"ALTER COLUMN request_hash SET NOT NULL",
		"pending_registration_request_hash_check",
	} {
		if !strings.Contains(intentHash.SQL, required) {
			t.Errorf("registration intent hash migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT UPDATE",
		"DROP COLUMN",
		"DISABLE ROW LEVEL SECURITY",
	} {
		if strings.Contains(intentHash.SQL, forbidden) {
			t.Errorf("registration intent hash migration SQL contains unsafe change %q", forbidden)
		}
	}
	scopeResolver := catalog[6]
	if scopeResolver.Description != "transaction-local public network scope" {
		t.Fatalf("migration 7 description = %q, want public network scope", scopeResolver.Description)
	}
	for _, required := range []string{
		"CREATE POLICY workspace_scope_resolution_policy",
		"CREATE POLICY network_scope_resolution_policy",
		"'mesh.requested_workspace_public_id'",
		"'mesh.requested_network_public_id'",
		"CREATE FUNCTION mesh_ops.set_network_scope",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh, mesh_ops",
		"pg_catalog.set_config(",
		"'mesh.workspace_id'",
		"'mesh.network_id'",
		"REVOKE ALL ON FUNCTION mesh_ops.set_network_scope",
		"GRANT EXECUTE ON FUNCTION mesh_ops.set_network_scope",
	} {
		if !strings.Contains(scopeResolver.SQL, required) {
			t.Errorf("network scope migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"USING (TRUE)",
		"WITH CHECK (TRUE)",
		"GRANT EXECUTE ON FUNCTION mesh_ops.set_network_scope(UUID, UUID) TO mesh_worker",
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"BYPASSRLS",
	} {
		if strings.Contains(scopeResolver.SQL, forbidden) {
			t.Errorf("network scope migration SQL contains excessive capability %q", forbidden)
		}
	}
	auditStreamHead := catalog[7]
	if auditStreamHead.Description != "transaction-local network audit stream head" {
		t.Fatalf(
			"migration 8 description = %q, want Network audit stream head",
			auditStreamHead.Description,
		)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_audit.lock_network_stream_head",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh_audit, mesh_ops",
		"pg_catalog.current_setting('mesh.workspace_id', TRUE)",
		"pg_catalog.current_setting('mesh.network_id', TRUE)",
		"stream.scope_kind = 'network'",
		"FOR UPDATE",
		"REVOKE ALL ON FUNCTION mesh_audit.lock_network_stream_head",
		"GRANT USAGE ON SCHEMA mesh_audit TO mesh_runtime",
		"GRANT EXECUTE ON FUNCTION mesh_audit.lock_network_stream_head() TO mesh_runtime",
	} {
		if !strings.Contains(auditStreamHead.SQL, required) {
			t.Errorf("Network audit stream head migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"BYPASSRLS",
		"TO mesh_worker",
	} {
		if strings.Contains(auditStreamHead.SQL, forbidden) {
			t.Errorf("Network audit stream head migration SQL contains excessive capability %q", forbidden)
		}
	}
	inventoryAdvance := catalog[8]
	if inventoryAdvance.Description != "transaction-local network inventory revision advance" {
		t.Fatalf(
			"migration 9 description = %q, want Network inventory revision advance",
			inventoryAdvance.Description,
		)
	}
	for _, required := range []string{
		"CREATE POLICY network_revision_scoped_read_policy",
		"FOR SELECT",
		"CREATE POLICY network_revision_scoped_mutation_policy",
		"FOR UPDATE",
		"TO mesh_migrator",
		"CREATE FUNCTION mesh_ops.advance_network_inventory_revision",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh_ops",
		"pg_catalog.current_setting('mesh.workspace_id', TRUE)",
		"pg_catalog.current_setting('mesh.network_id', TRUE)",
		"UPDATE mesh_ops.network_revision AS revision",
		"network_revision = revision.network_revision + 1",
		"inventory_revision = revision.inventory_revision + 1",
		"REVOKE ALL ON FUNCTION mesh_ops.advance_network_inventory_revision",
		"GRANT EXECUTE ON FUNCTION mesh_ops.advance_network_inventory_revision() TO mesh_runtime",
	} {
		if !strings.Contains(inventoryAdvance.SQL, required) {
			t.Errorf("Network inventory revision migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"USING (TRUE)",
		"WITH CHECK (TRUE)",
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"BYPASSRLS",
		"TO mesh_worker",
	} {
		if strings.Contains(inventoryAdvance.SQL, forbidden) {
			t.Errorf("Network inventory revision migration SQL contains excessive capability %q", forbidden)
		}
	}
	replayEvidence := catalog[9]
	if replayEvidence.Description != "registration idempotency replay evidence" {
		t.Fatalf(
			"migration 10 description = %q, want registration replay evidence",
			replayEvidence.Description,
		)
	}
	for _, required := range []string{
		"ADD COLUMN intent_format_version SMALLINT NOT NULL DEFAULT 1",
		"ALTER COLUMN intent_format_version SET DEFAULT 2",
		"ADD COLUMN requested_node_key BYTEA",
		"ADD COLUMN completed_hostname TEXT",
		"ADD COLUMN completed_disposition TEXT",
		"ADD COLUMN completed_network_revision BIGINT",
		"pending_registration_requested_node_key_check",
		"pg_catalog.octet_length(requested_node_key) = 32",
		"pending_registration_completion_replay_check",
		"completed_disposition IN ('created', 'resumed')",
		"completed_network_revision > 0",
		"GRANT UPDATE (",
		"completed_hostname",
		"completed_disposition",
		"completed_network_revision",
		") ON mesh.pending_registration TO mesh_runtime",
	} {
		if !strings.Contains(replayEvidence.SQL, required) {
			t.Errorf("registration replay evidence migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"plaintext",
		"GRANT DELETE",
		"GRANT TRUNCATE",
		"GRANT ALL",
		"BYPASSRLS",
		"DISABLE ROW LEVEL SECURITY",
	} {
		if strings.Contains(replayEvidence.SQL, forbidden) {
			t.Errorf("registration replay evidence migration SQL contains unsafe capability %q", forbidden)
		}
	}
	networkRevisionLock := catalog[10]
	if networkRevisionLock.Description != "transaction-local network revision lock" {
		t.Fatalf(
			"migration 11 description = %q, want Network revision lock",
			networkRevisionLock.Description,
		)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.lock_network_revision",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh_ops",
		"pg_catalog.current_setting('mesh.workspace_id', TRUE)",
		"pg_catalog.current_setting('mesh.network_id', TRUE)",
		"FROM mesh_ops.network_revision AS revision",
		"FOR UPDATE",
		"REVOKE ALL ON FUNCTION mesh_ops.lock_network_revision",
		"GRANT EXECUTE ON FUNCTION mesh_ops.lock_network_revision() TO mesh_runtime",
	} {
		if !strings.Contains(networkRevisionLock.SQL, required) {
			t.Errorf("Network revision lock migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"USING (TRUE)",
		"WITH CHECK (TRUE)",
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"BYPASSRLS",
		"TO mesh_worker",
	} {
		if strings.Contains(networkRevisionLock.SQL, forbidden) {
			t.Errorf("Network revision lock migration SQL contains excessive capability %q", forbidden)
		}
	}
	registrationTransactionLocks := catalog[11]
	if registrationTransactionLocks.Description != "registration transaction scoped lock helpers" {
		t.Fatalf(
			"migration 12 description = %q, want registration transaction lock helpers",
			registrationTransactionLocks.Description,
		)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.lock_registration_credential",
		"CREATE FUNCTION mesh_ops.lock_registration_prefixes",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh, mesh_ops",
		"pg_catalog.current_setting('mesh.workspace_id', TRUE)",
		"pg_catalog.current_setting('mesh.network_id', TRUE)",
		"FOR UPDATE OF credential",
		"pg_catalog.pg_advisory_xact_lock(",
		"meshtransit:registration_allocator:",
		"REVOKE ALL ON FUNCTION mesh_ops.lock_registration_credential(UUID) FROM PUBLIC",
		"REVOKE ALL ON FUNCTION mesh_ops.lock_registration_prefixes(BIGINT) FROM PUBLIC",
		"GRANT EXECUTE ON FUNCTION mesh_ops.lock_registration_credential(UUID) TO mesh_runtime",
		"GRANT EXECUTE ON FUNCTION mesh_ops.lock_registration_prefixes(BIGINT) TO mesh_runtime",
	} {
		if !strings.Contains(registrationTransactionLocks.SQL, required) {
			t.Errorf("registration transaction lock migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"FOR UPDATE OF realm, pool, prefix",
		"TO mesh_worker",
	} {
		if strings.Contains(registrationTransactionLocks.SQL, forbidden) {
			t.Errorf("registration transaction lock migration SQL contains excessive capability %q", forbidden)
		}
	}
	intakeScope := catalog[12]
	if intakeScope.Description != "registration intake scope resolution" {
		t.Fatalf(
			"migration 13 description = %q, want registration intake scope resolution",
			intakeScope.Description,
		)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.resolve_registration_intake_scope",
		"RETURNS TABLE (",
		"deployment_public_id UUID",
		"workspace_public_id UUID",
		"network_public_id UUID",
		"recovery_epoch BIGINT",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh, mesh_ops",
		"credential.public_id = p_credential_public_id",
		"deployment.state = 'active'",
		"deployment.recovery_state = 'verified'",
		"workspace.state = 'active'",
		"network.state = 'active'",
		"REVOKE ALL ON FUNCTION mesh_ops.resolve_registration_intake_scope(UUID) FROM PUBLIC",
		"GRANT EXECUTE ON FUNCTION mesh_ops.resolve_registration_intake_scope(UUID) TO mesh_runtime",
	} {
		if !strings.Contains(intakeScope.SQL, required) {
			t.Errorf("registration intake scope migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"TO mesh_worker",
	} {
		if strings.Contains(intakeScope.SQL, forbidden) {
			t.Errorf("registration intake scope migration SQL contains excessive capability %q", forbidden)
		}
	}
	intakeScopeQuery := catalog[13]
	if intakeScopeQuery.Description != "registration intake scope query correction" {
		t.Fatalf(
			"migration 14 description = %q, want registration intake scope query correction",
			intakeScopeQuery.Description,
		)
	}
	for _, required := range []string{
		"CREATE POLICY workspace_registration_intake_scope_policy",
		"CREATE POLICY network_registration_intake_scope_policy",
		"TO mesh_migrator",
		"credential.workspace_id = workspace.id",
		"credential.network_id = network.id",
		"CREATE OR REPLACE FUNCTION mesh_ops.resolve_registration_intake_scope",
		"LANGUAGE plpgsql",
		"SECURITY DEFINER",
		"mesh.registration_intake_credential_public_id",
		"credential.public_id = p_credential_public_id",
		"REVOKE ALL ON FUNCTION mesh_ops.resolve_registration_intake_scope(UUID) FROM PUBLIC",
		"GRANT EXECUTE ON FUNCTION mesh_ops.resolve_registration_intake_scope(UUID) TO mesh_runtime",
	} {
		if !strings.Contains(intakeScopeQuery.SQL, required) {
			t.Errorf("registration intake scope-query migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"TO mesh_worker",
	} {
		if strings.Contains(intakeScopeQuery.SQL, forbidden) {
			t.Errorf("registration intake scope-query migration SQL contains excessive capability %q", forbidden)
		}
	}
	mapSessionScope := catalog[14]
	if mapSessionScope.Description != "map session scope resolution" {
		t.Fatalf(
			"migration 15 description = %q, want map session scope resolution",
			mapSessionScope.Description,
		)
	}
	for _, required := range []string{
		"CREATE POLICY workspace_map_session_scope_policy",
		"CREATE POLICY network_map_session_scope_policy",
		"TO mesh_migrator",
		"mesh.map_session_workspace_id",
		"mesh.map_session_network_id",
		"CREATE FUNCTION mesh_ops.resolve_map_session_scope",
		"p_machine_key_fingerprint BYTEA",
		"p_node_key BYTEA",
		"RETURNS TABLE (",
		"workspace_public_id UUID",
		"network_public_id UUID",
		"recovery_epoch BIGINT",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh, mesh_ops",
		"machine.fingerprint = p_machine_key_fingerprint",
		"node_key.public_key = p_node_key",
		"machine.epoch = device.current_machine_key_epoch",
		"node_key.epoch = device.current_node_key_epoch",
		"deployment.recovery_state = 'verified'",
		"device.expires_at > pg_catalog.transaction_timestamp()",
		"REVOKE ALL ON FUNCTION mesh_ops.resolve_map_session_scope(BYTEA, BYTEA) FROM PUBLIC",
		"GRANT EXECUTE ON FUNCTION mesh_ops.resolve_map_session_scope(BYTEA, BYTEA) TO mesh_runtime",
	} {
		if !strings.Contains(mapSessionScope.SQL, required) {
			t.Errorf("map session scope migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"TO mesh_worker",
	} {
		if strings.Contains(mapSessionScope.SQL, forbidden) {
			t.Errorf("map session scope migration SQL contains excessive capability %q", forbidden)
		}
	}
	peerCandidates := catalog[15]
	if peerCandidates.Description != "bounded map session peer candidate projection" {
		t.Fatalf(
			"migration 16 description = %q, want map peer candidates",
			peerCandidates.Description,
		)
	}
	for _, required := range []string{
		"CREATE POLICY workspace_map_peer_candidate_scope_policy",
		"CREATE POLICY network_map_peer_candidate_scope_policy",
		"TO mesh_migrator",
		"CREATE FUNCTION mesh_ops.load_map_peer_candidates",
		"p_machine_key_fingerprint BYTEA",
		"p_node_key BYTEA",
		"p_limit INTEGER",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh, mesh_ops",
		"candidate.workspace_id = scoped_workspace_id",
		"candidate.network_id = scoped_network_id",
		"candidate.id <> authenticated_device_id",
		"candidate.state = 'active'",
		"candidate.expires_at > pg_catalog.transaction_timestamp()",
		"machine.state = 'active'",
		"current_node_key.state = 'active'",
		"owner.state = 'active'",
		"lease.state = 'active'",
		"ORDER BY candidate.created_at DESC, candidate.id DESC",
		"LIMIT p_limit",
		"REVOKE ALL ON FUNCTION mesh_ops.load_map_peer_candidates",
		"GRANT EXECUTE ON FUNCTION mesh_ops.load_map_peer_candidates(BYTEA, BYTEA, INTEGER)",
	} {
		if !strings.Contains(peerCandidates.SQL, required) {
			t.Errorf("map peer candidate migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"USING (TRUE)",
		"WITH CHECK (TRUE)",
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"TO mesh_worker",
	} {
		if strings.Contains(peerCandidates.SQL, forbidden) {
			t.Errorf("map peer candidate migration SQL contains excessive capability %q", forbidden)
		}
	}
	identityProviderAuthority := catalog[16]
	if identityProviderAuthority.Description != "identity provider authority foundation" {
		t.Fatalf(
			"migration 17 description = %q, want identity provider authority foundation",
			identityProviderAuthority.Description,
		)
	}
	for _, required := range []string{
		"CREATE TABLE mesh.identity_provider",
		"CREATE TABLE mesh.identity_provider_generation",
		"CREATE TABLE mesh.identity_provider_client",
		"CREATE TABLE mesh.workspace_identity_provider",
		"identity_provider_current_generation_fk",
		"CREATE CONSTRAINT TRIGGER identity_provider_current_generation_state_check",
		"CREATE CONSTRAINT TRIGGER identity_provider_generation_current_check",
		"workspace_identity_provider_workspace_fk",
		"workspace_identity_provider_client_fk",
		"ENABLE ROW LEVEL SECURITY",
		"FORCE ROW LEVEL SECURITY",
		"CREATE POLICY workspace_identity_provider_exact_scope_policy",
		"CREATE TRIGGER identity_provider_authority_mutation",
		"CREATE TRIGGER identity_provider_generation_authority_mutation",
		"CREATE TRIGGER identity_provider_client_authority_mutation",
		"CREATE TRIGGER workspace_identity_provider_authority_mutation",
		"REVOKE ALL ON",
	} {
		if !strings.Contains(identityProviderAuthority.SQL, required) {
			t.Errorf("identity provider migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"client_secret TEXT",
		"provider_token",
		"refresh_token",
		"raw_subject",
		"GRANT SELECT ON",
		"GRANT INSERT ON",
		"GRANT UPDATE ON",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"TO mesh_worker",
	} {
		if strings.Contains(identityProviderAuthority.SQL, forbidden) {
			t.Errorf("identity provider migration SQL contains unsafe capability %q", forbidden)
		}
	}
	accountIdentityPermission := catalog[17]
	if accountIdentityPermission.Description != "account identity and permission catalog foundation" {
		t.Fatalf(
			"migration 18 description = %q, want account identity and permission catalog foundation",
			accountIdentityPermission.Description,
		)
	}
	for _, required := range []string{
		"ADD CONSTRAINT principal_deployment_id_kind_unique",
		"CREATE TABLE mesh.account",
		"account_principal_scope_fk",
		"CREATE TABLE mesh.identity_subject",
		"identity_subject_provider_scope_fk",
		"identity_subject_account_scope_fk",
		"subject_digest_algorithm = 'hmac-sha256-v1'",
		"CREATE TABLE mesh.permission",
		"permission_immutable",
		"catalog_version",
		"CREATE TRIGGER account_authority_mutation",
		"CREATE TRIGGER identity_subject_authority_mutation",
		"REVOKE ALL ON",
	} {
		if !strings.Contains(accountIdentityPermission.SQL, required) {
			t.Errorf("account identity migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"raw_subject",
		"subject TEXT",
		"email TEXT",
		"provider_token",
		"refresh_token",
		"GRANT SELECT ON",
		"GRANT INSERT ON",
		"GRANT UPDATE ON",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"TO mesh_worker",
	} {
		if strings.Contains(accountIdentityPermission.SQL, forbidden) {
			t.Errorf("account identity migration SQL contains unsafe capability %q", forbidden)
		}
	}
	humanAuthenticationSession := catalog[18]
	if humanAuthenticationSession.Description != "human authentication and account session authority" {
		t.Fatalf(
			"migration 19 description = %q, want human authentication and account session authority",
			humanAuthenticationSession.Description,
		)
	}
	for _, required := range []string{
		"CREATE TABLE mesh.auth_transaction",
		"CREATE TABLE mesh.account_session",
		"CREATE TABLE mesh.identity_link_request",
		"CREATE TABLE mesh.oidc_logout_replay",
		"identity_subject_provider_principal_id_unique",
		"auth_transaction_provider_generation_fk",
		"account_session_subject_scope_fk",
		"identity_link_request_current_proof_fk",
		"oidc_logout_replay_provider_client_fk",
		"CREATE FUNCTION mesh_ops.enforce_human_auth_state_transition",
		"CREATE FUNCTION mesh_ops.resolve_account_session",
		"CREATE FUNCTION mesh_ops.revoke_account_session",
		"pg_catalog.set_config(",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh, mesh_ops",
		"CREATE TRIGGER auth_transaction_authority_mutation",
		"CREATE TRIGGER account_session_authority_mutation",
		"CREATE TRIGGER identity_link_request_authority_mutation",
		"CREATE TRIGGER oidc_logout_replay_authority_mutation",
		"GRANT EXECUTE ON FUNCTION mesh_ops.resolve_account_session",
		"GRANT EXECUTE ON FUNCTION mesh_ops.revoke_account_session",
	} {
		if !strings.Contains(humanAuthenticationSession.SQL, required) {
			t.Errorf("human authentication migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"state_token",
		"nonce TEXT",
		"pkce_verifier TEXT",
		"session_token TEXT",
		"provider_token",
		"refresh_token",
		"raw_subject",
		"email TEXT",
		"USING (TRUE)",
		"WITH CHECK (TRUE)",
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"TO mesh_worker",
	} {
		if strings.Contains(humanAuthenticationSession.SQL, forbidden) {
			t.Errorf("human authentication migration SQL contains unsafe capability %q", forbidden)
		}
	}
	compiledPacketPolicy := catalog[19]
	if compiledPacketPolicy.Description != "compiled packet policy authority" {
		t.Fatalf(
			"migration 20 description = %q, want compiled packet policy authority",
			compiledPacketPolicy.Description,
		)
	}
	for _, required := range []string{
		"CREATE TABLE mesh.policy_release",
		"CREATE TABLE mesh.compiled_policy_rule",
		"INT4MULTIRANGE",
		"policy_release_active_uidx",
		"compiled_policy_rule_release_scope_fk",
		"compiled_policy_rule_source_device_scope_fk",
		"compiled_policy_rule_destination_device_scope_fk",
		"compiled_policy_rule_edge_unique",
		"CREATE FUNCTION mesh_ops.advance_network_policy_revision",
		"network_revision = revision.network_revision + 1",
		"policy_revision = revision.policy_revision + 1",
		"ENABLE ROW LEVEL SECURITY",
		"FORCE ROW LEVEL SECURITY",
		"CREATE POLICY policy_release_exact_scope_policy",
		"CREATE POLICY compiled_policy_rule_exact_scope_policy",
		"CREATE TRIGGER policy_release_authority_mutation",
		"CREATE TRIGGER compiled_policy_rule_authority_mutation",
		"CREATE TRIGGER compiled_policy_rule_immutable",
		"GRANT SELECT ON",
		"TO mesh_runtime",
	} {
		if !strings.Contains(compiledPacketPolicy.SQL, required) {
			t.Errorf("compiled packet policy migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT INSERT ON",
		"GRANT UPDATE ON",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"TO mesh_worker",
		"TO mesh_observer",
	} {
		if strings.Contains(compiledPacketPolicy.SQL, forbidden) {
			t.Errorf("compiled packet policy migration SQL contains unsafe capability %q", forbidden)
		}
	}
	policyPublication := catalog[20]
	if policyPublication.Description != "atomic packet policy publication" {
		t.Fatalf(
			"migration 21 description = %q, want atomic packet policy publication",
			policyPublication.Description,
		)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.lock_active_policy_release",
		"CREATE FUNCTION mesh_ops.publish_compiled_policy",
		"p_expected_policy_revision",
		"FOR UPDATE",
		"MT001",
		"jsonb_to_recordset",
		"advance_network_policy_revision",
		"activated_network_revision",
		"compiled policy rule count mismatch",
		"GRANT EXECUTE ON FUNCTION mesh_ops.publish_compiled_policy",
		"GRANT EXECUTE ON FUNCTION mesh_ops.lock_active_policy_release",
		"TO mesh_runtime",
	} {
		if !strings.Contains(policyPublication.SQL, required) {
			t.Errorf("policy publication migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT INSERT ON",
		"GRANT UPDATE ON",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"TO mesh_worker",
		"TO mesh_observer",
	} {
		if strings.Contains(policyPublication.SQL, forbidden) {
			t.Errorf("policy publication migration SQL contains unsafe capability %q", forbidden)
		}
	}
	mapPeerProtocolIdentity := catalog[21]
	if mapPeerProtocolIdentity.Description != "map peer protocol identity projection" {
		t.Fatalf(
			"migration 22 description = %q, want map peer protocol identity projection",
			mapPeerProtocolIdentity.Description,
		)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.load_map_peer_candidates_v2",
		"numeric_node_id BIGINT",
		"numeric_owner_id BIGINT",
		"mesh_ops.load_map_peer_candidates(",
		"candidate.public_id = projected.node_public_id",
		"owner.public_id = projected.owner_public_id",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh, mesh_ops",
		"REVOKE ALL ON FUNCTION mesh_ops.load_map_peer_candidates_v2",
		"GRANT EXECUTE ON FUNCTION mesh_ops.load_map_peer_candidates_v2",
		"TO mesh_runtime",
	} {
		if !strings.Contains(mapPeerProtocolIdentity.SQL, required) {
			t.Errorf("map peer protocol identity migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"TO mesh_worker",
	} {
		if strings.Contains(mapPeerProtocolIdentity.SQL, forbidden) {
			t.Errorf("map peer protocol identity migration SQL contains unsafe capability %q", forbidden)
		}
	}
	networkIdempotency := catalog[22]
	if networkIdempotency.Description != "network idempotency record foundation" {
		t.Fatalf(
			"migration 23 description = %q, want Network idempotency record foundation",
			networkIdempotency.Description,
		)
	}
	for _, required := range []string{
		"CREATE TABLE mesh_ops.idempotency_record",
		"hmac-sha256-v1",
		"UNIQUE NULLS NOT DISTINCT",
		"idempotency_record_outbox_unique UNIQUE",
		"CREATE FUNCTION mesh_ops.enforce_idempotency_record_transition",
		"CREATE FUNCTION mesh_ops.enforce_idempotency_record_completion",
		"CREATE FUNCTION mesh_ops.claim_network_idempotency",
		"CREATE FUNCTION mesh_ops.load_network_idempotency",
		"CREATE FUNCTION mesh_ops.complete_network_idempotency",
		"CREATE CONSTRAINT TRIGGER idempotency_record_completion",
		"ENABLE ROW LEVEL SECURITY",
		"FORCE ROW LEVEL SECURITY",
		"CREATE POLICY idempotency_record_exact_scope_policy",
		"GRANT EXECUTE ON FUNCTION mesh_ops.claim_network_idempotency",
		"GRANT EXECUTE ON FUNCTION mesh_ops.load_network_idempotency",
		"GRANT EXECUTE ON FUNCTION mesh_ops.complete_network_idempotency",
	} {
		if !strings.Contains(networkIdempotency.SQL, required) {
			t.Errorf("Network idempotency migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"plaintext",
		"GRANT SELECT ON mesh_ops.idempotency_record TO mesh_runtime",
		"GRANT INSERT (",
		"GRANT UPDATE (",
		"GRANT DELETE",
		"GRANT TRUNCATE",
		"GRANT ALL",
		"BYPASSRLS",
		"TO mesh_worker",
		"TO mesh_observer",
	} {
		if strings.Contains(networkIdempotency.SQL, forbidden) {
			t.Errorf("Network idempotency migration SQL contains unsafe capability %q", forbidden)
		}
	}
	accountSessionResolution := catalog[23]
	if accountSessionResolution.Description != "deployment-bound account session resolution" {
		t.Fatalf(
			"migration 24 description = %q, want deployment-bound account session resolution",
			accountSessionResolution.Description,
		)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.resolve_account_session_v2",
		"p_expected_deployment_public_id UUID",
		"p_expected_recovery_epoch BIGINT",
		"deployment.installation_public_id = p_expected_deployment_public_id",
		"deployment.recovery_epoch = p_expected_recovery_epoch",
		"session.deployment_recovery_epoch = p_expected_recovery_epoch",
		"session.principal_authority_generation",
		"session.account_session_generation",
		"session.provider_generation",
		"GRANT EXECUTE ON FUNCTION mesh_ops.resolve_account_session_v2",
	} {
		if !strings.Contains(accountSessionResolution.SQL, required) {
			t.Errorf("Account Session resolution migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"TO mesh_worker",
		"TO mesh_observer",
	} {
		if strings.Contains(accountSessionResolution.SQL, forbidden) {
			t.Errorf("Account Session resolution migration SQL contains unsafe capability %q", forbidden)
		}
	}
	networkManagementRBAC := catalog[24]
	if networkManagementRBAC.Description != "network management RBAC authority" {
		t.Fatalf(
			"migration 25 description = %q, want Network management RBAC authority",
			networkManagementRBAC.Description,
		)
	}
	for _, required := range []string{
		"CREATE TABLE mesh.workspace_membership",
		"CREATE TABLE mesh.role_definition",
		"CREATE TABLE mesh.role_permission",
		"CREATE TABLE mesh.role_binding",
		"CREATE FUNCTION mesh_ops.resolve_network_permission_v1",
		"p_session_public_id UUID",
		"session.principal_authority_generation = p_principal_authority_generation",
		"membership.state = 'active'",
		"binding.state = 'active'",
		"permission.permission_key = p_permission_key",
		"FOR SHARE OF session",
		"FORCE ROW LEVEL SECURITY",
		"GRANT EXECUTE ON FUNCTION mesh_ops.resolve_network_permission_v1",
	} {
		if !strings.Contains(networkManagementRBAC.SQL, required) {
			t.Errorf("Network management RBAC migration SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT ON mesh.workspace_membership TO mesh_runtime",
		"GRANT SELECT ON mesh.role_binding TO mesh_runtime",
		"GRANT INSERT",
		"GRANT UPDATE",
		"GRANT DELETE",
		"GRANT ALL",
		"BYPASSRLS",
		"TO mesh_worker",
		"TO mesh_observer",
	} {
		if strings.Contains(networkManagementRBAC.SQL, forbidden) {
			t.Errorf("Network management RBAC migration SQL contains unsafe capability %q", forbidden)
		}
	}
	if LatestVersion() != 43 {
		t.Fatalf("LatestVersion() = %d, want 43", LatestVersion())
	}
}

func TestSubjectResolutionMigrationIsAdditiveNoGrant(t *testing.T) {
	t.Parallel()
	migration := Catalog()[31]
	for _, required := range []string{"CREATE FUNCTION mesh_ops.resolve_oidc_login_subject_v1", "SECURITY DEFINER", "SET search_path = pg_catalog, mesh, mesh_ops", "matched_subject AS MATERIALIZED", "LIMIT 2", "pg_catalog.count(*) FROM matched_subject", "pg_catalog.clock_timestamp()", "auth.state = 'consuming'", "auth.binding_semantic_hash = p_binding_hash", "auth.consumed_at = p_consumed_at", "provider.current_generation = p_provider_generation", "deployment.recovery_epoch = p_recovery_epoch", "membership.state = 'active'", "membership.expires_at > decision.at", "account.recovery_state = 'verified'", "principal.kind = 'account'", "EXCEPTION WHEN OTHERS THEN", "FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer", "TO mesh_runtime"} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("subject resolution SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{"CREATE TABLE", "CREATE INDEX", "ALTER TABLE", "INSERT INTO", "UPDATE mesh.", "DELETE FROM", "FOR SHARE", "FOR UPDATE", "GRANT SELECT", "GRANT ALL", "DROP ", "BYPASSRLS"} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("subject read has excess capability %q", forbidden)
		}
	}
	if migration.MinimumReaderGeneration != 1 || migration.MaximumReaderGeneration != 1 || migration.MinimumWriterGeneration != 1 || migration.MaximumWriterGeneration != 1 {
		t.Fatal("read capability changed application generations")
	}
}

func TestOIDCLoginRouteAdmissionIsNarrowReadOnlyCapability(t *testing.T) {
	t.Parallel()
	admission := Catalog()[27]
	if admission.Description != "durable OIDC login route admission" {
		t.Fatalf("migration 28 description = %q", admission.Description)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.admit_oidc_login_route_v1",
		"RETURNS BOOLEAN", "SECURITY DEFINER", "SET search_path = pg_catalog, mesh, mesh_ops",
		"SELECT EXISTS", "INTO STRICT admitted", "EXCEPTION WHEN OTHERS",
		"mesh.requested_workspace_public_id", "p_workspace_public_id::TEXT",
		"deployment.recovery_epoch = p_recovery_epoch",
		"provider.current_generation = p_provider_generation",
		"provider.authorization_endpoint = p_authorization_endpoint",
		"provider.token_endpoint = p_token_endpoint",
		"client.allowed_scopes = p_scopes", "client.allowed_algorithms = p_allowed_algorithms",
		"p_redirect_uri = ANY (client.redirect_uris)", "workspace_provider.organization_digest IS NULL",
		"FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer", "TO mesh_runtime;",
	} {
		if !strings.Contains(admission.SQL, required) {
			t.Errorf("route admission SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE", "GRANT ALL",
		"INSERT INTO", "UPDATE mesh.", "DELETE FROM", "FOR SHARE", "FOR UPDATE",
		"BYPASSRLS", "ALTER TABLE", "DROP ",
	} {
		if strings.Contains(admission.SQL, forbidden) {
			t.Errorf("route admission SQL contains excessive capability %q", forbidden)
		}
	}
}

func TestOIDCPendingBrowserEvidenceIsReadOnlyAndNotAClaim(t *testing.T) {
	t.Parallel()
	migration := Catalog()[28]
	if migration.Description != "read-only OIDC pending browser evidence" {
		t.Fatal("incorrect migration 29 description")
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.load_oidc_pending_browser_v1", "SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh, mesh_ops", "mesh_ops.admit_oidc_login_route_v1",
		"p_workspace_public_id::TEXT", "EXCEPTION WHEN OTHERS", "pg_catalog.clock_timestamp()",
		"auth.state = 'pending' AND auth.version = 1", "auth.binding_semantic_hash IS NOT NULL",
		"auth.state_digest = p_state_digest", "auth.return_route_id = p_return_route_id",
		"auth.expires_at > observed_at", "provider.current_generation = p_provider_generation",
		"client.allowed_scopes = p_scopes", "client.allowed_algorithms = p_allowed_algorithms",
		"FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer", "TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("pending browser SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT UPDATE", "GRANT INSERT", "GRANT DELETE", "GRANT ALL", "BYPASSRLS",
		"INSERT INTO", "UPDATE mesh.", "DELETE FROM", "ALTER TABLE", "FOR SHARE", "FOR UPDATE", "DROP ",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("pending browser SQL excessive capability %q", forbidden)
		}
	}
}

func TestBrowserClaimMigrationPreservesBindingAndExplicitLockOrder(t *testing.T) {
	t.Parallel()
	migration := Catalog()[29]
	if migration.Description != "single-use OIDC browser transaction claim" {
		t.Fatal("incorrect claim description")
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.claim_oidc_browser_v1", "SECURITY DEFINER", "SET search_path = pg_catalog, mesh, mesh_ops",
		"mesh_ops.admit_oidc_login_route_v1", "EXCEPTION WHEN OTHERS", "p_workspace_public_id::TEXT",
		"auth.state = 'pending' AND auth.version = p_expected_version AND auth.binding_semantic_hash = p_binding_hash",
		"auth.pkce_verifier_encryption_algorithm = 'aead-aes-256-gcm-v1'", "auth.expires_at > observed_at",
		"SET state = 'consuming', version = auth.version + 1, consumed_at = observed_at",
		"FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer", "TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("claim SQL missing %q", required)
		}
	}
	previous := -1
	for _, lock := range []string{
		"FROM mesh.workspace WHERE", "FROM mesh.deployment WHERE", "FROM mesh.identity_provider AS provider",
		"FROM mesh.identity_provider_generation AS generation", "FROM mesh.identity_provider_client AS client",
		"FROM mesh.workspace_identity_provider AS workspace_provider", "FOR UPDATE OF auth", "observed_at := pg_catalog.clock_timestamp()",
	} {
		position := strings.Index(migration.SQL, lock)
		if position <= previous {
			t.Errorf("claim lock/clock order lost at %q", lock)
		}
		previous = position
	}
	for _, forbidden := range []string{"GRANT SELECT", "GRANT UPDATE", "GRANT ALL", "BYPASSRLS", "binding_semantic_hash = observed", "pkce_verifier_ciphertext =", "INSERT INTO", "DELETE FROM", "DROP ", "transaction_timestamp()"} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("claim SQL excessive or stale capability %q", forbidden)
		}
	}
}

func TestBrowserFailureMigrationNarrowErasureAndLiveClock(t *testing.T) {
	t.Parallel()
	sql := Catalog()[30].SQL
	for _, required := range []string{"CREATE FUNCTION mesh_ops.fail_oidc_browser_v1", "SECURITY DEFINER", "SET search_path = pg_catalog, mesh, mesh_ops", "auth.version = p_expected_version", "auth.binding_semantic_hash = p_binding_hash", "auth.consumed_at = p_consumed_at", "EXCEPTION WHEN OTHERS", "pkce_verifier_encryption_algorithm = NULL", "pkce_verifier_encryption_key_id = NULL", "pkce_verifier_ciphertext = NULL", "TO mesh_runtime;", "FROM PUBLIC, mesh_worker, mesh_observer"} {
		if !strings.Contains(sql, required) {
			t.Errorf("terminal SQL missing %q", required)
		}
	}
	previous := -1
	for _, required := range []string{"FOR UPDATE OF auth", "FROM mesh_audit.lock_deployment_stream_head", "finished_at := pg_catalog.clock_timestamp()", "UPDATE mesh.auth_transaction AS auth"} {
		position := strings.Index(sql, required)
		if position <= previous {
			t.Errorf("terminal lock/clock order %q", required)
		}
		previous = position
	}
	for _, forbidden := range []string{"admit_oidc_login_route", "FOR SHARE", "transaction_timestamp()", "INSERT INTO", "GRANT SELECT", "GRANT UPDATE", "GRANT ALL", "UPDATE mesh.account", "state = 'succeeded'", "provider.state =", "workspace.state ="} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("terminal excessive capability %q", forbidden)
		}
	}
}

func TestCatalogReturnsDefensiveCopy(t *testing.T) {
	t.Parallel()

	first := Catalog()
	first[0].Description = "changed"
	first[0].SQL = "changed"

	second := Catalog()
	if second[0].Description == "changed" || second[0].SQL == "changed" {
		t.Fatal("Catalog() returned mutable shared state")
	}
}

func TestAccountSessionLogoutIsDeploymentBoundAndLeastPrivilege(t *testing.T) {
	t.Parallel()
	migration := Catalog()[34]
	if migration.Description != "deployment-bound local account session logout" {
		t.Fatalf("migration 35 description = %q", migration.Description)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.logout_account_session_v1",
		"p_expected_deployment_public_id UUID",
		"p_expected_recovery_epoch BIGINT",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh, mesh_ops",
		"deployment.installation_public_id = p_expected_deployment_public_id",
		"deployment.recovery_epoch = p_expected_recovery_epoch",
		"session.deployment_recovery_epoch = p_expected_recovery_epoch",
		"session.state = 'active'",
		"end_reason = 'local_logout'",
		"version = session.version + 1",
		"pg_catalog.clock_timestamp()",
		"FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer",
		"TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("Account Session logout SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE", "GRANT ALL",
		"BYPASSRLS", "TO mesh_worker;", "TO mesh_observer;", "DROP ", "p_end_reason",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("Account Session logout SQL contains excessive capability %q", forbidden)
		}
	}
}

func TestAccountSessionLogoutEvidenceIsPrincipalBoundAndLeastPrivilege(t *testing.T) {
	t.Parallel()
	migration := Catalog()[35]
	if migration.Description != "audited account session logout evidence" {
		t.Fatalf("migration 36 description = %q", migration.Description)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.logout_account_session_v2",
		"mesh_ops.logout_account_session_v1(",
		"principal_public_id UUID",
		"ended_at TIMESTAMPTZ",
		"SECURITY DEFINER",
		"SET search_path = pg_catalog, mesh, mesh_ops",
		"principal.deployment_id = session.deployment_id",
		"principal.id = session.principal_id",
		"session.state = 'revoked'",
		"session.end_reason = 'local_logout'",
		"account session logout evidence is unavailable",
		"FROM PUBLIC, mesh_runtime, mesh_worker, mesh_observer",
		"TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("Account Session logout evidence SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE", "GRANT ALL",
		"BYPASSRLS", "TO mesh_worker;", "TO mesh_observer;", "DROP ",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("Account Session logout evidence SQL contains excessive capability %q", forbidden)
		}
	}
}

func TestResourceGroupAuthorityIsScopedVersionedAndLeastPrivilege(t *testing.T) {
	t.Parallel()
	migration := Catalog()[36]
	if migration.Description != "Resource and Resource Group authority foundation" {
		t.Fatalf("migration 37 description = %q", migration.Description)
	}
	for _, required := range []string{
		"CREATE TABLE mesh.resource (",
		"CREATE TABLE mesh.resource_device_target (",
		"CREATE TABLE mesh.resource_group (",
		"CREATE TABLE mesh.resource_group_version (",
		"CREATE TABLE mesh.resource_group_version_member (",
		"target_generation BIGINT NOT NULL",
		"active_definition_version BIGINT NOT NULL",
		"resource_active_target_generation_fk",
		"resource_group_active_version_fk",
		"DEFERRABLE INITIALLY DEFERRED",
		"capture_authority_mutation('resource'",
		"capture_authority_mutation('resource_group'",
		"CREATE FUNCTION mesh_ops.create_device_resource_v1",
		"CREATE FUNCTION mesh_ops.create_resource_group_v1",
		"CREATE FUNCTION mesh_ops.resolve_resource_v1",
		"CREATE FUNCTION mesh_ops.resolve_resource_group_v1",
		"p_expected_inventory_revision BIGINT",
		"p_expected_group_revision BIGINT",
		"FROM mesh_ops.lock_network_revision()",
		"resource.version = member.resource_version",
		"resource.target_generation = member.target_generation",
		"SECURITY DEFINER",
		"TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("Resource authority SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE", "GRANT ALL",
		"BYPASSRLS", "TO mesh_worker;", "TO mesh_observer;", "DROP ",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("Resource authority SQL contains excessive capability %q", forbidden)
		}
	}
}

func TestResourceManagementReadsAreScopedBoundedAndLeastPrivilege(t *testing.T) {
	t.Parallel()
	migration := Catalog()[37]
	if migration.Description != "Resource management read API" {
		t.Fatalf("migration 38 description = %q", migration.Description)
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.read_network_revision_v1",
		"CREATE FUNCTION mesh_ops.read_resource_v2",
		"CREATE FUNCTION mesh_ops.list_resources_v1",
		"CREATE FUNCTION mesh_ops.read_resource_group_v2",
		"CREATE FUNCTION mesh_ops.list_resource_groups_v1",
		"mesh_ops.current_workspace_id()",
		"mesh_ops.current_network_id()",
		"p_limit > 101",
		"ORDER BY resource.public_id",
		"ORDER BY resource_group.public_id",
		"FROM mesh_ops.network_revision AS revision",
		"SECURITY DEFINER",
		"TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("Resource management read SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE", "GRANT ALL",
		"BYPASSRLS", "TO mesh_worker;", "TO mesh_observer;", "FOR UPDATE", "DROP ",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("Resource management read SQL contains excessive capability %q", forbidden)
		}
	}
}

func TestResourceLifecycleIsRetainedVersionedAndLeastPrivilege(t *testing.T) {
	t.Parallel()
	migration := Catalog()[38]
	if migration.Description != "Resource lifecycle authority" {
		t.Fatalf("migration 39 description = %q", migration.Description)
	}
	for _, required := range []string{
		"CREATE OR REPLACE FUNCTION mesh_ops.enforce_resource_authority_transition",
		"CREATE FUNCTION mesh_ops.transition_resource_lifecycle_v1",
		"CREATE FUNCTION mesh_ops.transition_resource_group_lifecycle_v1",
		"p_expected_resource_version BIGINT",
		"p_expected_group_version BIGINT",
		"FROM mesh_ops.lock_network_revision()",
		"FOR SHARE OF workspace, principal, membership",
		"FOR UPDATE;",
		"OLD.state = 'deleted'",
		"state = p_target_state",
		"version = resource.version + 1",
		"version = resource_group.version + 1",
		"GRANT EXECUTE ON FUNCTION mesh_ops.transition_resource_lifecycle_v1",
		"GRANT EXECUTE ON FUNCTION mesh_ops.transition_resource_group_lifecycle_v1",
		"TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("Resource lifecycle SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE", "GRANT ALL",
		"BYPASSRLS", "TO mesh_worker;", "TO mesh_observer;", "DROP ", "DELETE FROM",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("Resource lifecycle SQL contains excessive capability %q", forbidden)
		}
	}
}

func TestResourceTargetRebindingIsVersionedAndLeastPrivilege(t *testing.T) {
	t.Parallel()
	migration := Catalog()[39]
	if migration.Description != "Resource target rebinding authority" {
		t.Fatalf("migration 40 description = %q", migration.Description)
	}
	for _, required := range []string{
		"CREATE OR REPLACE FUNCTION mesh_ops.enforce_resource_authority_transition",
		"CREATE FUNCTION mesh_ops.preview_device_resource_rebind_v1",
		"CREATE FUNCTION mesh_ops.lock_device_resource_rebind_v1",
		"CREATE FUNCTION mesh_ops.rebind_device_resource_v1",
		"p_expected_resource_version BIGINT",
		"FROM mesh_ops.lock_network_revision()",
		"FOR SHARE OF workspace, principal, membership",
		"SET state = 'superseded'",
		"target_generation = advanced_target_generation",
		"version = resource.version + 1",
		"GRANT EXECUTE ON FUNCTION mesh_ops.rebind_device_resource_v1",
		"GRANT EXECUTE ON FUNCTION mesh_ops.preview_device_resource_rebind_v1",
		"GRANT EXECUTE ON FUNCTION mesh_ops.lock_device_resource_rebind_v1",
		"TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("Resource target rebinding SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE", "GRANT ALL",
		"BYPASSRLS", "TO mesh_worker;", "TO mesh_observer;", "DROP ", "DELETE FROM",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("Resource target rebinding SQL contains excessive capability %q", forbidden)
		}
	}
}

func TestResourceGroupReplacementIsImmutableAndLeastPrivilege(t *testing.T) {
	t.Parallel()
	migration := Catalog()[40]
	if migration.Description != "Resource Group definition replacement authority" {
		t.Fatalf("migration 41 description = %q", migration.Description)
	}
	for _, required := range []string{
		"CREATE OR REPLACE FUNCTION mesh_ops.enforce_resource_authority_transition",
		"CREATE FUNCTION mesh_ops.preview_resource_group_replace_v1",
		"CREATE FUNCTION mesh_ops.lock_resource_group_replace_v1",
		"CREATE FUNCTION mesh_ops.replace_resource_group_definition_v1",
		"p_expected_group_version BIGINT",
		"FROM mesh_ops.lock_network_revision()",
		"FOR SHARE OF workspace, principal, membership",
		"INSERT INTO mesh.resource_group_version",
		"INSERT INTO mesh.resource_group_version_member",
		"active_definition_version = advanced_definition_version",
		"version = resource_group.version + 1",
		"GRANT EXECUTE ON FUNCTION mesh_ops.replace_resource_group_definition_v1",
		"GRANT EXECUTE ON FUNCTION mesh_ops.preview_resource_group_replace_v1",
		"GRANT EXECUTE ON FUNCTION mesh_ops.lock_resource_group_replace_v1",
		"TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("Resource Group replacement SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE", "GRANT ALL",
		"BYPASSRLS", "TO mesh_worker;", "TO mesh_observer;", "DROP ", "DELETE FROM",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("Resource Group replacement SQL contains excessive capability %q", forbidden)
		}
	}
}

func TestResourceAuthorityChangeRequiresStepUpAndSecondActor(t *testing.T) {
	t.Parallel()
	migration := Catalog()[41]
	if migration.Description != "protected Resource ownership and custody authority" {
		t.Fatalf("migration 42 description = %q", migration.Description)
	}
	for _, required := range []string{
		"('resource.transfer'",
		"('resource_group.transfer'",
		"CREATE TABLE mesh.resource_authority_change_request",
		"CREATE TABLE mesh.resource_authority_step_up_evidence",
		"CREATE TRIGGER resource_authority_change_request_authority_mutation",
		"CREATE TRIGGER resource_authority_step_up_authority_mutation",
		"EXECUTE FUNCTION mesh_audit.capture_authority_mutation",
		"FORCE ROW LEVEL SECURITY",
		"UNIQUE (account_session_id)",
		"authentication_time > created_at - INTERVAL '5 minutes'",
		"required_confirmations = 1",
		"target_principal_id <> requested_by_principal_id",
		"CREATE FUNCTION mesh_ops.require_resource_authority_step_up_v1",
		"routing.minimum_assurance IS NOT NULL",
		"session.acr = routing.minimum_assurance",
		"CREATE FUNCTION mesh_ops.request_resource_authority_change_v1",
		"CREATE FUNCTION mesh_ops.confirm_resource_authority_change_v1",
		"CREATE FUNCTION mesh_ops.lock_resource_authority_change_request_v1",
		"FOR UPDATE OF session",
		"FOR UPDATE OF request",
		"GRANT EXECUTE ON FUNCTION mesh_ops.confirm_resource_authority_change_v1",
		"REVOKE ALL ON mesh.resource_authority_change_request",
		"TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("Resource authority change SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE", "GRANT ALL",
		"BYPASSRLS", "TO mesh_worker;", "TO mesh_observer;", "DROP ", "DELETE FROM",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("Resource authority change SQL contains excessive capability %q", forbidden)
		}
	}
}

func TestPolicyResourceDestinationPinsAuthorityAndExactScope(t *testing.T) {
	t.Parallel()
	migration := Catalog()[42]
	if migration.Description != "policy Resource destination provenance" {
		t.Fatalf("migration 43 description = %q", migration.Description)
	}
	for _, required := range []string{
		"CREATE TABLE mesh.compiled_policy_resource_destination",
		"compiled_policy_resource_destination_rule_scope_fk",
		"compiled_policy_resource_destination_resource_scope_fk",
		"resource_version BIGINT NOT NULL",
		"target_generation BIGINT NOT NULL",
		"inventory_revision BIGINT NOT NULL",
		"resource_semantic_hash BYTEA NOT NULL",
		"FORCE ROW LEVEL SECURITY",
		"CREATE TRIGGER compiled_policy_resource_destination_authority_mutation",
		"CREATE TRIGGER compiled_policy_resource_destination_immutable",
		"CREATE FUNCTION mesh_ops.attach_policy_resource_destinations",
		"FROM mesh.policy_release AS release",
		"FROM mesh.resource AS resource",
		"FOR KEY SHARE OF resource",
		"target.state = 'active'",
		"ERRCODE = 'MT001'",
		"GRANT EXECUTE ON FUNCTION mesh_ops.attach_policy_resource_destinations",
		"TO mesh_runtime;",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("policy Resource destination SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"BYPASSRLS", "DROP ", "DELETE FROM", "TO mesh_worker;", "TO mesh_observer;",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("policy Resource destination SQL contains excessive capability %q", forbidden)
		}
	}
}
