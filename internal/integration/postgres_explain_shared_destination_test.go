//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/meshtransit/meshtransit/internal/accessgraph"
	postgresadapter "github.com/meshtransit/meshtransit/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/sharing"
)

type sharedExplanationPath struct {
	AccessRuleID                  string `json:"access_rule_id"`
	SourceDeviceID                string `json:"source_device_id"`
	DestinationDeviceID           string `json:"destination_device_id"`
	SelectorKind                  string `json:"selector_kind"`
	DestinationImportedResourceID string `json:"destination_imported_resource_id"`
	TrustContractID               string `json:"trust_contract_id"`
}

type sharedExplanationContext struct {
	Source struct {
		State string `json:"state"`
	} `json:"source"`
	Target struct {
		Kind  string `json:"kind"`
		State string `json:"state"`
	} `json:"target"`
	Share *struct {
		TrustContractID       string  `json:"trust_contract_id"`
		State                 string  `json:"state"`
		ExpiresAt             *string `json:"expires_at"`
		ProviderWorkspaceCode *string `json:"provider_workspace_code"`
		ProviderNetworkCode   *string `json:"provider_network_code"`
	} `json:"share"`
}

type sharedExplanation struct {
	hasActiveRelease bool
	paths            []sharedExplanationPath
	context          sharedExplanationContext
}

// assertSharedDestinationExplanation runs inside the transaction that just
// published a compiled imported rule, so v3 sees the release before rollback.
// It proves a shared Device reads as allowed only on the published traffic and
// only while the Trust Contract is in force, and that the provider topology
// never appears in the answer.
func assertSharedDestinationExplanation(
	ctx context.Context,
	t *testing.T,
	transaction pgx.Tx,
	session accountsession.Session,
	destination sharing.PolicyDestination,
	sourceNodeID string,
	ruleID string,
) {
	t.Helper()
	contract := destination.Contract()
	importedID := destination.ImportedResourceID().String()
	now := time.Now().UTC()

	allowed := explainSharedDestination(ctx, t, transaction, session, destination, sourceNodeID, 443, now)
	if !allowed.hasActiveRelease || len(allowed.paths) != 1 {
		t.Fatalf("shared allow explanation = %+v", allowed)
	}
	path := allowed.paths[0]
	if path.SelectorKind != "imported_resource" || path.AccessRuleID != ruleID ||
		path.SourceDeviceID != sourceNodeID || path.DestinationDeviceID != "" ||
		path.DestinationImportedResourceID != importedID || path.TrustContractID != contract.ID().String() {
		t.Fatalf("shared allow path = %+v", path)
	}
	share := allowed.context.Share
	if allowed.context.Source.State != "active" || allowed.context.Target.Kind != "imported_resource" ||
		allowed.context.Target.State != "active" || share == nil ||
		share.TrustContractID != contract.ID().String() || share.State != "active" ||
		share.ExpiresAt == nil || share.ProviderWorkspaceCode == nil || share.ProviderNetworkCode == nil {
		t.Fatalf("shared allow context = %+v share=%+v", allowed.context, share)
	}

	otherPort := explainSharedDestination(ctx, t, transaction, session, destination, sourceNodeID, 80, now)
	if len(otherPort.paths) != 0 || otherPort.context.Share == nil || otherPort.context.Share.State != "active" {
		t.Fatalf("shared explanation on unpublished port = %+v", otherPort)
	}

	assertSharedDestinationHiddenFromProvider(ctx, t, transaction, session, destination, sourceNodeID, now)

}

func explainSharedDestination(
	ctx context.Context,
	t *testing.T,
	transaction pgx.Tx,
	session accountsession.Session,
	destination sharing.PolicyDestination,
	sourceNodeID string,
	port int,
	evaluatedAt time.Time,
) sharedExplanation {
	t.Helper()
	explanation, err := explainSharedDestinationIn(
		ctx, t, transaction, session, destination.ConsumerScope(), destination, sourceNodeID, port, evaluatedAt,
	)
	if err != nil {
		t.Fatalf("explain shared destination on port %d at %s: %v", port, evaluatedAt.Format(time.RFC3339), err)
	}
	return explanation
}

// assertRevokedShareExplained explains a connection to a revoked share
// through the real service on committed data: the answer is a denial that
// names the ended contract, so a person sees why the shared Device stopped
// working.
func assertRevokedShareExplained(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	runtimePool *postgresadapter.Pool,
	session accountsession.Session,
	scope network.Scope,
	contract sharing.Contract,
) {
	t.Helper()
	var sourceNodeID string
	if err := admin.QueryRow(ctx, `SELECT device.public_id::TEXT
FROM mesh.device AS device
WHERE device.workspace_id = 103
  AND device.network_id = 204
  AND device.state = 'active'
  AND pg_catalog.transaction_timestamp() < device.expires_at
ORDER BY device.id
LIMIT 1`).Scan(&sourceNodeID); err != nil {
		t.Fatalf("query active consumer Device: %v", err)
	}
	source, err := node.ParseID(sourceNodeID)
	if err != nil {
		t.Fatalf("parse consumer Device: %v", err)
	}
	query, err := accessgraph.NewQuery(accessgraph.QueryParams{
		Scope: scope, SourceNodeID: source, DestinationImportedResourceID: contract.ImportedResourceID(),
		Protocol: policy.ProtocolTCP, DestinationPort: 443,
	})
	if err != nil {
		t.Fatalf("construct revoked share explanation query: %v", err)
	}
	result, err := newIntegrationPolicyExplainer(t, runtimePool).Explain(ctx, session, query)
	if err != nil {
		t.Fatalf("explain revoked share: %v", err)
	}
	share, hasShare := result.Snapshot().Share()
	reason, denied := result.DenyReason()
	_, _, _, hasRelease := result.Snapshot().ActiveRelease()
	wantReason := accessgraph.DenyReasonShareEnded
	if !hasRelease {
		wantReason = accessgraph.DenyReasonNoActiveRelease
	}
	if !result.IsValid() || result.Decision() != accessgraph.DecisionDeny || !denied || reason != wantReason ||
		!hasShare || share.ContractID() != contract.ID() || share.State() != sharing.ContractStateRevoked ||
		len(result.Paths()) != 0 {
		t.Fatalf("revoked share explanation = %+v share=%+v", result, share)
	}
}

// assertSharedDestinationHiddenFromProvider asks about the consumer's imported
// Resource from the provider Network. The definer function bypasses row-level
// security, so it must fail closed by scope: either the session holds no
// policy.explain there, or the answer names no target, share or path.
func assertSharedDestinationHiddenFromProvider(
	ctx context.Context,
	t *testing.T,
	transaction pgx.Tx,
	session accountsession.Session,
	destination sharing.PolicyDestination,
	sourceNodeID string,
	evaluatedAt time.Time,
) {
	t.Helper()
	savepoint, err := transaction.Begin(ctx)
	if err != nil {
		t.Fatalf("begin provider-scope explanation savepoint: %v", err)
	}
	setIntegrationScope(ctx, t, savepoint, 103, 203)
	foreign, err := explainSharedDestinationIn(
		ctx, t, savepoint, session, destination.ProviderScope(), destination, sourceNodeID, 443, evaluatedAt,
	)
	if rollbackErr := savepoint.Rollback(ctx); rollbackErr != nil {
		t.Fatalf("rollback provider-scope explanation savepoint: %v", rollbackErr)
	}
	if err != nil {
		if postgresError, ok := errors.AsType[*pgconn.PgError](err); ok && postgresError.Code == "42501" {
			return
		}
		t.Fatalf("provider-scope shared explanation error = %v", err)
	}
	if len(foreign.paths) != 0 || foreign.context.Share != nil || foreign.context.Target.State != "missing" {
		t.Fatalf("provider-scope shared explanation = %+v", foreign)
	}
}

func explainSharedDestinationIn(
	ctx context.Context,
	t *testing.T,
	transaction pgx.Tx,
	session accountsession.Session,
	scope network.Scope,
	destination sharing.PolicyDestination,
	sourceNodeID string,
	port int,
	evaluatedAt time.Time,
) (sharedExplanation, error) {
	t.Helper()
	var explanation sharedExplanation
	var paths, explanationContext string
	if err := transaction.QueryRow(ctx, `SELECT has_active_release, paths::TEXT, context::TEXT
FROM mesh_ops.explain_active_policy_v3(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID,
    $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::UUID, $12::UUID, NULL::UUID, NULL::UUID, $13::UUID,
    'tcp', $14::INTEGER, $15::TIMESTAMPTZ, 17
)`,
		session.ID().String(), session.DeploymentID().String(), session.PrincipalID().String(),
		session.IdentitySubjectID().String(), session.Version(), session.PrincipalAuthorityGeneration(),
		session.AccountSessionGeneration(), session.ProviderGeneration(), session.DeploymentRecoveryEpoch(),
		scope.WorkspaceID().String(), scope.NetworkID().String(), sourceNodeID,
		destination.ImportedResourceID().String(), port, evaluatedAt,
	).Scan(&explanation.hasActiveRelease, &paths, &explanationContext); err != nil {
		return sharedExplanation{}, err
	}
	if err := json.Unmarshal([]byte(paths), &explanation.paths); err != nil {
		t.Fatalf("decode shared explanation paths: %v", err)
	}
	if err := json.Unmarshal([]byte(explanationContext), &explanation.context); err != nil {
		t.Fatalf("decode shared explanation context: %v", err)
	}
	for _, leaked := range []string{"provider_device_id", "provider_resource_id", "address"} {
		if containsJSONKey(explanationContext, leaked) {
			t.Fatalf("shared explanation context exposes %s: %s", leaked, explanationContext)
		}
	}
	return explanation, nil
}

func containsJSONKey(document, key string) bool {
	var decoded map[string]any
	if err := json.Unmarshal([]byte(document), &decoded); err != nil {
		return false
	}
	var walk func(any) bool
	walk = func(value any) bool {
		switch typed := value.(type) {
		case map[string]any:
			for name, nested := range typed {
				if name == key || walk(nested) {
					return true
				}
			}
		case []any:
			for _, nested := range typed {
				if walk(nested) {
					return true
				}
			}
		}
		return false
	}
	return walk(decoded)
}
