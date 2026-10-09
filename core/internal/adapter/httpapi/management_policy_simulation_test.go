package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/core/internal/domain/accessgraph"
	"github.com/meshtransit/meshtransit/core/internal/domain/accessgraph/simulation"
	"github.com/meshtransit/meshtransit/core/internal/domain/identity/accountsession"
	"github.com/meshtransit/meshtransit/core/internal/domain/network"
	"github.com/meshtransit/meshtransit/core/internal/domain/node"
	"github.com/meshtransit/meshtransit/core/internal/domain/policy"
	"github.com/meshtransit/meshtransit/core/internal/domain/policy/compilation"
	policypublication "github.com/meshtransit/meshtransit/core/internal/domain/policy/publication"
	"github.com/meshtransit/meshtransit/core/internal/domain/sharing"
	"github.com/meshtransit/meshtransit/core/internal/domain/workspace"
)

func TestManagementHandlerSimulatesPolicyWithoutPublishing(t *testing.T) {
	t.Parallel()

	scope := managementPolicySimulationScope(t)
	baseline := managementPolicySimulationBaseline(t, scope)
	reader := &managementPolicySimulationReader{values: []simulation.Baseline{baseline, baseline}}
	compiler := managementPolicyCompilerFunc(func(
		_ context.Context,
		_ accountsession.Session,
		request compilation.Request,
	) (policypublication.Candidate, error) {
		return compileDirectManagementPolicy(request)
	})
	service, err := simulation.NewService(simulation.Dependencies{
		Baselines: reader, Compiler: compiler, Clock: simulation.SystemClock{},
	})
	if err != nil {
		t.Fatal(err)
	}
	options := validManagementHandlerOptions(t)
	options.PolicySimulations = service
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	request := newManagementRequest(
		t,
		http.MethodPost,
		managementPolicySimulationPath(),
		`{"rules":[{"id":"01890f00-0000-7000-8000-000000000501",`+
			`"source_device_id":"01890f00-0000-7000-8000-000000000301",`+
			`"destination_device_id":"01890f00-0000-7000-8000-000000000302",`+
			`"destination_resource_id":"","destination_resource_group_id":"",`+
			`"protocol":"icmp","destination_port_ranges":[]}]}`,
	)
	request.Header.Del("Idempotency-Key")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || response.Header().Get("ETag") != `"1"` ||
		response.Header().Get("Cache-Control") != "no-store" || reader.calls != 2 {
		t.Fatalf("status/headers/reads = %d/%+v/%d; body = %s", response.Code, response.Header(), reader.calls, response.Body.String())
	}
	var body simulatePolicyResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Data.Baseline.RevisionVector.PolicyRevision != 1 ||
		body.Data.Proposed.RevisionVector.PolicyRevision != 2 ||
		body.Data.Proposed.RuleCount != 1 || body.Data.Impact.AddedRelationshipCount != 1 ||
		len(body.Data.Impact.AddedRelationships) != 1 ||
		len(body.Data.Impact.ImpactHash) != 64 || body.Data.Impact.StaleInputs ||
		body.Data.Impact.Uncertain || body.Data.Impact.ImportedIntentChanges != nil ||
		body.CorrelationID != managementCorrelationID() {
		t.Fatalf("response = %+v", body)
	}
}

func TestPolicySimulationEncodesImportedIntentAndCountsWithoutPacketEdges(t *testing.T) {
	t.Parallel()
	fixture, contract, _ := managementSharingContractFixture(t, sharing.ContractStateActive, 2)
	baseline := managementPolicySimulationBaseline(t, fixture.consumer)
	resolution, err := sharing.NewPolicyDestination(sharing.PolicyDestinationParams{
		ImportedResourceID: contract.ImportedResourceID(), ImportedResourceVersion: 2,
		Contract: contract, ExportVersion: 1, ProviderInventoryRevision: 9,
		ProviderSharingRevision: 50, ConsumerSharingRevision: 2, EvaluatedAt: fixture.snapshot.CreatedAt(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ruleID, _ := policy.ParseRuleID("01890f00-0000-7000-8000-000000000501")
	sourceID, _ := node.ParseID("01890f00-0000-7000-8000-000000000301")
	traffic := contract.MaximumTraffic().Constraints()[0]
	intent, err := compilation.NewRuleIntent(compilation.RuleIntentParams{
		ID: ruleID, Scope: fixture.consumer, SourceNodeID: sourceID,
		DestinationImportedResourceID: contract.ImportedResourceID(), Protocol: traffic.Protocol(),
		DestinationPortRanges: traffic.DestinationPortRanges(),
	})
	if err != nil {
		t.Fatal(err)
	}
	request, err := compilation.NewRequest(compilation.RequestParams{Scope: fixture.consumer, Revision: 2, Rules: []compilation.RuleIntent{intent}})
	if err != nil {
		t.Fatal(err)
	}
	destination, err := policypublication.NewImportedResourceDestination(policypublication.ImportedResourceDestinationParams{
		RuleID: ruleID, SourceNodeID: sourceID, Resolution: resolution,
		Protocol: traffic.Protocol(), DestinationPortRanges: traffic.DestinationPortRanges(),
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := policy.NewSnapshot(policy.SnapshotParams{Scope: fixture.consumer, Revision: 2, Rules: []policy.Rule{}})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := policypublication.NewCandidateWithImportedResourceDestinations(snapshot, nil, nil, []policypublication.ImportedResourceDestination{destination})
	if err != nil {
		t.Fatal(err)
	}
	reader := &managementPolicySimulationReader{values: []simulation.Baseline{baseline, baseline}}
	compiler := managementPolicyCompilerFunc(func(context.Context, accountsession.Session, compilation.Request) (policypublication.Candidate, error) {
		return candidate, nil
	})
	service, err := simulation.NewService(simulation.Dependencies{Baselines: reader, Compiler: compiler, Clock: simulation.SystemClock{}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.Simulate(t.Context(), managementSessionFixture(t), request)
	if err != nil {
		t.Fatal(err)
	}
	encoded := encodePolicySimulationResult(result)
	changes := encoded.Impact.ImportedIntentChanges
	if changes == nil || changes.PacketAuthorityEvaluated || changes.AddedCount != 1 ||
		len(changes.Added) != 1 || changes.RemovedCount != 0 || changes.Removed == nil ||
		encoded.Proposed.RuleCount != 1 || encoded.Proposed.CompilerFormatVersion != 4 ||
		encoded.Impact.AddedRelationshipCount != 0 || encoded.Impact.AddedExplanationCount != 0 ||
		encoded.Impact.AffectedDeviceCount != 1 {
		t.Fatalf("incomplete or synthetic imported impact: %+v", encoded)
	}
	item := changes.Added[0]
	if item.ImportedResourceID != contract.ImportedResourceID().String() || item.ContractVersion != 2 ||
		item.TrustContractID != contract.ID().String() || item.SourceDeviceID != sourceID.String() ||
		item.ProviderWorkspaceID != fixture.provider.WorkspaceID().String() ||
		item.ConsumerNetworkID != fixture.consumer.NetworkID().String() || item.ProviderSharingRevision != 50 ||
		item.Resource.TargetGeneration != fixture.binding.TargetGeneration() || item.Resource.InventoryRevision != 9 ||
		item.ExpiresAt != contract.ExpiresAt().UTC().Format(time.RFC3339Nano) ||
		item.Protocol != traffic.Protocol().String() || len(item.MaximumTraffic) != len(contract.MaximumTraffic().Constraints()) {
		t.Fatalf("lost pinned contract evidence: %+v", item)
	}
	body, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"destination_device_id", "address", "alias", "endpoint", "offer_token"} {
		if _, found := fields[forbidden]; found {
			t.Fatalf("preview disclosed %s", forbidden)
		}
	}
}

func TestManagementHandlerPolicySimulationFailsClosed(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{name: "forbidden", err: simulation.ErrForbidden, status: http.StatusForbidden, code: "forbidden"},
		{name: "stale", err: simulation.ErrStaleInputs, status: http.StatusPreconditionFailed, code: "precondition_failed"},
		{name: "invalid baseline", err: simulation.ErrInvalidBaseline, status: http.StatusInternalServerError, code: "internal_failure"},
		{name: "unavailable", err: simulation.ErrUnavailable, status: http.StatusServiceUnavailable, code: "operation_unavailable"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := validManagementHandlerOptions(t)
			options.PolicySimulations = managementPolicySimulatorFunc(func(
				context.Context,
				accountsession.Session,
				compilation.Request,
			) (simulation.Result, error) {
				return simulation.Result{}, test.err
			})
			handler, err := NewManagementHandler(options)
			if err != nil {
				t.Fatal(err)
			}
			request := newManagementRequest(
				t,
				http.MethodPost,
				managementPolicySimulationPath(),
				`{"rules":[]}`,
			)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d; body = %s", response.Code, test.status, response.Body.String())
			}
			var body managementErrorResponse
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.Error.Code != test.code {
				t.Fatalf("error = (%+v, %v), want %s", body, err, test.code)
			}
		})
	}
}

func TestDecodePolicySimulationRejectsPublicationReason(t *testing.T) {
	t.Parallel()

	options := validManagementHandlerOptions(t)
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	request := newManagementRequest(
		t,
		http.MethodPost,
		managementPolicySimulationPath(),
		`{"reason":"not a mutation","rules":[]}`,
	)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", response.Code, response.Body.String())
	}
}

type managementPolicySimulationReader struct {
	values []simulation.Baseline
	calls  int
}

func (reader *managementPolicySimulationReader) ReadSimulationBaseline(
	_ context.Context,
	_ accountsession.Session,
	_ network.Scope,
	_ time.Time,
) (simulation.Baseline, error) {
	if reader.calls >= len(reader.values) {
		return simulation.Baseline{}, simulation.ErrUnavailable
	}
	value := reader.values[reader.calls]
	reader.calls++
	return value, nil
}

func managementPolicySimulationBaseline(
	t *testing.T,
	scope network.Scope,
) simulation.Baseline {
	t.Helper()
	snapshot, err := policy.NewSnapshot(policy.SnapshotParams{
		Scope: scope, Revision: 1, Rules: []policy.Rule{},
	})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := policypublication.NewCandidate(snapshot, 1)
	if err != nil {
		t.Fatal(err)
	}
	vector, err := accessgraph.NewRevisionVector(accessgraph.RevisionVectorParams{
		NetworkRevision: 5, InventoryRevision: 2, GroupRevision: 2, PolicyRevision: 1,
		DNSRevision: 2, RouteRevision: 2, SharingRevision: 2, IsolationGeneration: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := simulation.NewBaseline(simulation.BaselineParams{
		Scope: scope, RevisionVector: vector, Candidate: candidate,
	})
	if err != nil {
		t.Fatal(err)
	}
	return baseline
}

func managementPolicySimulationScope(t *testing.T) network.Scope {
	t.Helper()
	workspaceID, err := workspace.ParseID(managementWorkspaceID())
	if err != nil {
		t.Fatal(err)
	}
	networkID, err := network.ParseID(managementNetworkID())
	if err != nil {
		t.Fatal(err)
	}
	scope, err := network.NewScope(workspaceID, networkID)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func managementPolicySimulationPath() string {
	return "/api/v1/workspaces/" + managementWorkspaceID() + "/networks/" + managementNetworkID() +
		"/policy/actions/simulate"
}
