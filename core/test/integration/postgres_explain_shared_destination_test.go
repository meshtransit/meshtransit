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

	postgresadapter "github.com/meshtransit/meshtransit/core/internal/adapter/postgres"
	"github.com/meshtransit/meshtransit/core/internal/domain/accessgraph"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
	"github.com/meshtransit/meshtransit/core/internal/domain/policy"
	"github.com/meshtransit/meshtransit/core/internal/domain/sharing"
)

type sharedExplanationPath struct {
	ProjectionID                  string `json:"projection_id"`
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

// assertCrossWorkspaceShareExplained explains a share imported from another
// Workspace. Provider tenant rows stay hidden from the consumer, so the answer
// must still name the active share and the provider's display codes.
func assertCrossWorkspaceShareExplained(
	ctx context.Context,
	t *testing.T,
	admin *pgx.Conn,
	runtimePool *postgresadapter.Pool,
	session accountsession.Session,
	scope network.Scope,
	importedID sharing.ImportedResourceID,
) {
	t.Helper()
	var sourceNodeID string
	if err := admin.QueryRow(ctx, `SELECT device.public_id::TEXT
FROM mesh.device AS device
JOIN mesh.network AS network ON network.id = device.network_id
WHERE network.public_id = $1::UUID
  AND device.state = 'active'
  AND pg_catalog.transaction_timestamp() < device.expires_at
ORDER BY device.id
LIMIT 1`, scope.NetworkID().String()).Scan(&sourceNodeID); err != nil {
		t.Fatalf("query active cross-Workspace consumer Device: %v", err)
	}
	source, err := node.ParseID(sourceNodeID)
	if err != nil {
		t.Fatalf("parse cross-Workspace consumer Device: %v", err)
	}
	query, err := accessgraph.NewQuery(accessgraph.QueryParams{
		Scope: scope, SourceNodeID: source, DestinationImportedResourceID: importedID,
		Protocol: policy.ProtocolTCP, DestinationPort: 443,
	})
	if err != nil {
		t.Fatalf("construct cross-Workspace explanation query: %v", err)
	}
	result, err := newIntegrationPolicyExplainer(t, runtimePool).Explain(ctx, session, query)
	if err != nil {
		t.Fatalf("explain cross-Workspace share: %v", err)
	}
	share, hasShare := result.Snapshot().Share()
	if !result.IsValid() || !hasShare || share.State() != sharing.ContractStateActive ||
		!share.ProviderWorkspaceCode().IsValid() || !share.ProviderNetworkCode().IsValid() ||
		result.Snapshot().Target().State() != accessgraph.ParticipantStateActive {
		t.Fatalf("cross-Workspace share explanation = %+v share=%+v", result.Snapshot(), share)
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

type sharedGraphListing struct {
	matching int
	hasMore  bool
	paths    []sharedExplanationPath
	nodes    []struct {
		Kind  string `json:"kind"`
		ID    string `json:"id"`
		State string `json:"state"`
		Share *struct {
			TrustContractID       string `json:"trust_contract_id"`
			State                 string `json:"state"`
			ProviderWorkspaceCode string `json:"provider_workspace_code"`
		} `json:"share"`
	}
}

// assertSharedDestinationGraph lists the graph inside the transaction that
// published a compiled imported rule: the shared Device appears as a node
// with its contract, and filters and pages hold.
func assertSharedDestinationGraph(
	ctx context.Context,
	t *testing.T,
	transaction pgx.Tx,
	session accountsession.Session,
	destination sharing.PolicyDestination,
	sourceNodeID string,
	ruleID string,
) {
	t.Helper()
	assertGraphListingRequiresReadAuthority(ctx, t, transaction, session, destination)
	// The shared fixture role lacks policy.read and device.read; grant them
	// only inside this rolled-back transaction.
	for _, grant := range []struct {
		id         int
		permission string
	}{{871, "policy.read"}, {872, "device.read"}} {
		if _, err := transaction.Exec(ctx, `INSERT INTO mesh.role_permission (
    id, public_id, deployment_id, workspace_id, role_definition_id, permission_id
) OVERRIDING SYSTEM VALUE
SELECT $1::BIGINT, ('01890f00-0000-7000-8000-' || lpad($1::TEXT, 12, '0'))::UUID, 1, 103, 842, permission.id
FROM mesh.permission AS permission WHERE permission.permission_key = $2::TEXT`, grant.id, grant.permission); err != nil {
			t.Fatalf("grant %s for the graph listing: %v", grant.permission, err)
		}
	}
	all := listSharedGraph(ctx, t, transaction, session, destination, nil, nil, nil, 500)
	if all.matching != 1 || all.hasMore || len(all.paths) != 1 || len(all.nodes) != 2 {
		t.Fatalf("shared graph listing = %+v", all)
	}
	path := all.paths[0]
	if path.SelectorKind != "imported_resource" || path.AccessRuleID != ruleID || path.SourceDeviceID != sourceNodeID ||
		path.DestinationImportedResourceID != destination.ImportedResourceID().String() ||
		path.TrustContractID != destination.Contract().ID().String() {
		t.Fatalf("shared graph path = %+v", path)
	}
	device, imported := all.nodes[0], all.nodes[1]
	if device.Kind != "device" || device.ID != sourceNodeID || device.State != "active" || device.Share != nil ||
		imported.Kind != "imported_resource" || imported.ID != destination.ImportedResourceID().String() ||
		imported.Share == nil || imported.Share.State != "active" || imported.Share.ProviderWorkspaceCode == "" {
		t.Fatalf("shared graph nodes = %+v", all.nodes)
	}

	udp := "udp"
	if filtered := listSharedGraph(ctx, t, transaction, session, destination, nil, &udp, nil, 500); filtered.matching != 0 ||
		len(filtered.paths) != 0 || len(filtered.nodes) != 0 {
		t.Fatalf("protocol-filtered graph = %+v", filtered)
	}
	if bySource := listSharedGraph(ctx, t, transaction, session, destination, &sourceNodeID, nil, nil, 500); bySource.matching != 1 ||
		len(bySource.paths) != 1 {
		t.Fatalf("Device-filtered graph = %+v", bySource)
	}
	projection := path.ProjectionID
	if after := listSharedGraph(ctx, t, transaction, session, destination, nil, nil, &projection, 1); after.matching != 1 ||
		after.hasMore || len(after.paths) != 0 || len(after.nodes) != 0 {
		t.Fatalf("graph page after the last edge = %+v", after)
	}
}

func listSharedGraph(
	ctx context.Context,
	t *testing.T,
	transaction pgx.Tx,
	session accountsession.Session,
	destination sharing.PolicyDestination,
	deviceID *string,
	protocol *string,
	afterProjection *string,
	pageSize int,
) sharedGraphListing {
	t.Helper()
	scope := destination.ConsumerScope()
	var listing sharedGraphListing
	var paths, nodes string
	if err := transaction.QueryRow(ctx, `SELECT matching_paths, has_more, paths::TEXT, nodes::TEXT
FROM mesh_ops.read_access_graph_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID,
    $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::UUID, $12::UUID, $13::TEXT, $14::UUID, $15::INTEGER, $16::TIMESTAMPTZ
)`,
		session.ID().String(), session.DeploymentID().String(), session.PrincipalID().String(),
		session.IdentitySubjectID().String(), session.Version(), session.PrincipalAuthorityGeneration(),
		session.AccountSessionGeneration(), session.ProviderGeneration(), session.DeploymentRecoveryEpoch(),
		scope.WorkspaceID().String(), scope.NetworkID().String(), deviceID, protocol, afterProjection,
		pageSize, time.Now().UTC(),
	).Scan(&listing.matching, &listing.hasMore, &paths, &nodes); err != nil {
		t.Fatalf("list shared graph: %v", err)
	}
	if err := json.Unmarshal([]byte(paths), &listing.paths); err != nil {
		t.Fatalf("decode graph paths: %v", err)
	}
	if err := json.Unmarshal([]byte(nodes), &listing.nodes); err != nil {
		t.Fatalf("decode graph nodes: %v", err)
	}
	return listing
}

// assertGraphListingRequiresReadAuthority proves the listing fails closed
// while the session lacks policy.read and device.read.
func assertGraphListingRequiresReadAuthority(
	ctx context.Context,
	t *testing.T,
	transaction pgx.Tx,
	session accountsession.Session,
	destination sharing.PolicyDestination,
) {
	t.Helper()
	savepoint, err := transaction.Begin(ctx)
	if err != nil {
		t.Fatalf("begin graph authority savepoint: %v", err)
	}
	scope := destination.ConsumerScope()
	_, err = savepoint.Exec(ctx, `SELECT * FROM mesh_ops.read_access_graph_v1(
    $1::UUID, $2::UUID, $3::UUID, $4::UUID,
    $5::BIGINT, $6::BIGINT, $7::BIGINT, $8::BIGINT, $9::BIGINT,
    $10::UUID, $11::UUID, NULL, NULL, NULL, 100, $12::TIMESTAMPTZ
)`,
		session.ID().String(), session.DeploymentID().String(), session.PrincipalID().String(),
		session.IdentitySubjectID().String(), session.Version(), session.PrincipalAuthorityGeneration(),
		session.AccountSessionGeneration(), session.ProviderGeneration(), session.DeploymentRecoveryEpoch(),
		scope.WorkspaceID().String(), scope.NetworkID().String(), time.Now().UTC(),
	)
	if rollbackErr := savepoint.Rollback(ctx); rollbackErr != nil {
		t.Fatalf("rollback graph authority savepoint: %v", rollbackErr)
	}
	postgresError, ok := errors.AsType[*pgconn.PgError](err)
	if !ok || postgresError.Code != "42501" {
		t.Fatalf("graph listing without read authority error = %v, want 42501", err)
	}
}
