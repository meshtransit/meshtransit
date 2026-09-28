package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/accessgraph"
	"github.com/meshtransit/meshtransit/internal/accessgraph/simulation"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/network"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/policy/compilation"
	policypublication "github.com/meshtransit/meshtransit/internal/policy/publication"
	"github.com/meshtransit/meshtransit/internal/workspace"
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
		body.Data.Impact.Uncertain || body.CorrelationID != managementCorrelationID() {
		t.Fatalf("response = %+v", body)
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
