package migrations

import (
	"strings"
	"testing"
)

func TestBrowserExpiryMigrationIsPurposeOwnedNoGrant(t *testing.T) {
	t.Parallel()
	migration := Catalog()[33]
	if migration.Description != "bounded abandoned OIDC browser expiry" {
		t.Fatal("expiry catalog entry missing")
	}
	for _, required := range []string{
		"CREATE FUNCTION mesh_ops.list_due_oidc_browser_v1", "p_limit > 128", "ORDER BY auth.expires_at, auth.id LIMIT p_limit",
		"auth.binding_semantic_hash IS NOT NULL", "CREATE FUNCTION mesh_ops.expire_oidc_browser_v1", "FOR UPDATE OF auth",
		"FOR UPDATE OF stream", "decision_at := pg_catalog.clock_timestamp()", "failure_class = 'deadline_expired'",
		"consumed_at = COALESCE(auth.consumed_at, decision_at)", "pkce_verifier_ciphertext = NULL",
		"mutation.transaction_id = transaction_value", "browser expiry requires fresh owned unit",
		"CREATE INDEX authority_mutation_transaction_idx", "CREATE FUNCTION mesh_ops.append_oidc_expiry_evidence_v1",
		"p_sequence IS NULL", "p_previous_hash IS NULL", "p_event_hash IS NULL", "mutation.after_version = auth.version",
		"'auth_transaction.expired', 'system.lifecycle'", "'identity.auth_transaction.expired'", "TO mesh_worker",
		"OWNER TO mesh_migrator", "SECURITY DEFINER", "EXCEPTION WHEN OTHERS THEN",
	} {
		if !strings.Contains(migration.SQL, required) {
			t.Errorf("expiry SQL missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"GRANT SELECT", "GRANT INSERT", "GRANT UPDATE", "GRANT DELETE", "GRANT ALL", "BYPASSRLS", "DROP ",
		"CREATE POLICY", "JOIN mesh.workspace", "JOIN mesh.identity_provider", "lock_deployment_stream_head(",
		"UPDATE mesh.account_session", "UPDATE mesh.deployment", "CREATE TABLE", "ALTER TABLE",
	} {
		if strings.Contains(migration.SQL, forbidden) {
			t.Errorf("expiry SQL contains unsafe/unreviewed capability %q", forbidden)
		}
	}
}
