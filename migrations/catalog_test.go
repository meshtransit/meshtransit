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
	if len(catalog) != 24 {
		t.Fatalf("len(Catalog()) = %d, want 24", len(catalog))
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
	if LatestVersion() != 24 {
		t.Fatalf("LatestVersion() = %d, want 24", LatestVersion())
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
