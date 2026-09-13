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
	if len(catalog) != 5 {
		t.Fatalf("len(Catalog()) = %d, want 5", len(catalog))
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
	if LatestVersion() != 5 {
		t.Fatalf("LatestVersion() = %d, want 5", LatestVersion())
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
