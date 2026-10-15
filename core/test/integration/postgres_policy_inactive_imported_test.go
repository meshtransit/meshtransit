//go:build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"meshtransit.net/core/internal/domain/sharing"
)

// assertImportedPolicyInactiveSource qualifies schema 165 for Imported
// Resource rules through both publication chains: rules whose source Device
// is suspended or expired publish, rules whose source Device is later
// revoked keep publishing, and a new rule for the revoked Device is refused
// with MTP05 instead of MT001. Every change rolls back.
func assertImportedPolicyInactiveSource(ctx context.Context, t *testing.T, admin *pgx.Conn,
	destination sharing.PolicyDestination) {
	t.Helper()
	for _, function := range []string{"publish_compiled_policy", "publish_compiled_policy_v2"} {
		assertImportedPolicyInactiveSourceWith(ctx, t, admin, destination, function)
	}
}

func assertImportedPolicyInactiveSourceWith(ctx context.Context, t *testing.T, admin *pgx.Conn,
	destination sharing.PolicyDestination, function string) {
	t.Helper()
	transaction, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = transaction.Rollback(ctx) }()
	setIntegrationScope(ctx, t, transaction, 103, 204)
	setIntegrationChange(ctx, t, transaction, newCorrelationID(t).String())
	var source string
	if err := transaction.QueryRow(ctx, `SELECT public_id::TEXT FROM mesh.device
WHERE workspace_id = 103 AND network_id = 204 AND state = 'active'
  AND pg_catalog.transaction_timestamp() < expires_at
ORDER BY id LIMIT 1`).Scan(&source); err != nil {
		t.Fatalf("query active consumer Device: %v", err)
	}
	step := 0
	publish := func(ruleIDs ...string) error {
		t.Helper()
		step++
		rules := make([]map[string]any, len(ruleIDs))
		for index, ruleID := range ruleIDs {
			rules[index] = importedPublicationRule(destination, newCorrelationID(t).String(), ruleID, source)
		}
		payload, err := json.Marshal(rules)
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(payload)
		var base int64
		if err := transaction.QueryRow(ctx, `SELECT policy_revision FROM mesh_ops.network_revision
WHERE workspace_id = 103 AND network_id = 204`).Scan(&base); err != nil {
			t.Fatal(err)
		}
		savepoint, err := transaction.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := savepoint.Exec(ctx, `SELECT * FROM mesh_ops.`+function+`(
    $1::UUID, $2::BIGINT, $3::BYTEA, 4, $4::TIMESTAMPTZ, $5::JSONB)`,
			newCorrelationID(t).String(), base, hash[:],
			destination.EvaluatedAt().Add(time.Duration(step)*time.Millisecond), payload); err != nil {
			_ = savepoint.Rollback(ctx)
			return err
		}
		return savepoint.Commit(ctx)
	}
	published := func(stage string, ruleIDs ...string) {
		t.Helper()
		if err := publish(ruleIDs...); err != nil {
			t.Fatalf("%s %s: %v", function, stage, err)
		}
	}
	setSource := func(assignment string) {
		t.Helper()
		if _, err := transaction.Exec(ctx, `UPDATE mesh.device SET `+assignment+`, version = version + 1
WHERE workspace_id = 103 AND network_id = 204 AND public_id = $1::UUID`, source); err != nil {
			t.Fatalf("change consumer Device: %v", err)
		}
	}

	kept, suspended, expired := newCorrelationID(t).String(), newCorrelationID(t).String(),
		newCorrelationID(t).String()
	published("with an active source Device", kept)
	setSource("state = 'suspended', suspended_reason = 'admin'")
	published("with a suspended source Device", kept, suspended)
	setSource("state = 'active', suspended_reason = NULL, expires_at = created_at + interval '1 microsecond'")
	published("with an expired source Device", kept, suspended, expired)
	setSource("state = 'revoked'")
	published("with a revoked source Device", kept, suspended, expired)
	err = publish(kept, suspended, expired, newCorrelationID(t).String())
	if postgresError, ok := errors.AsType[*pgconn.PgError](err); !ok || postgresError.Code != "MTP05" {
		t.Fatalf("%s new rule for a revoked source Device: %v, want MTP05", function, err)
	}
}

// importedPublicationRule is one compiled Imported Resource rule allowing
// TCP 443 from source to destination.
func importedPublicationRule(destination sharing.PolicyDestination, projectionID, ruleID,
	source string) map[string]any {
	contract := destination.Contract()
	binding := contract.Resource()
	resourceHash := binding.SemanticHash().Bytes()
	constraintHash := contract.MaximumTraffic().Hash()
	return map[string]any{
		"projection_public_id":                        projectionID,
		"access_rule_public_id":                       ruleID,
		"source_node_public_id":                       source,
		"protocol":                                    "tcp",
		"port_range_first":                            []int{443},
		"port_range_last":                             []int{443},
		"destination_imported_resource_public_id":     destination.ImportedResourceID().String(),
		"destination_imported_resource_version":       destination.ImportedResourceVersion(),
		"destination_trust_contract_public_id":        contract.ID().String(),
		"destination_trust_contract_version":          contract.Version(),
		"destination_resource_export_public_id":       contract.ExportID().String(),
		"destination_resource_export_version":         destination.ExportVersion(),
		"destination_provider_workspace_public_id":    destination.ProviderScope().WorkspaceID().String(),
		"destination_provider_network_public_id":      destination.ProviderScope().NetworkID().String(),
		"destination_provider_resource_public_id":     binding.ResourceID().String(),
		"destination_provider_resource_version":       binding.ResourceVersion(),
		"destination_provider_target_generation":      binding.TargetGeneration(),
		"destination_provider_resource_semantic_hash": hex.EncodeToString(resourceHash[:]),
		"destination_provider_inventory_revision":     destination.ProviderInventoryRevision(),
		"destination_provider_sharing_revision":       destination.ProviderSharingRevision(),
		"destination_consumer_sharing_revision":       destination.ConsumerSharingRevision(),
		"destination_provider_authority_generation":   contract.ProviderAuthorityGeneration(),
		"destination_consumer_authority_generation":   contract.ConsumerAuthorityGeneration(),
		"destination_recovery_epoch":                  contract.RecoveryEpoch(),
		"destination_contract_expires_at":             contract.ExpiresAt().UTC().Format(time.RFC3339Nano),
		"destination_constraint_hash":                 hex.EncodeToString(constraintHash[:]),
	}
}
