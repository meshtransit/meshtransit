package httpapi

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/accessgraph"
	"github.com/meshtransit/meshtransit/internal/identity/accountsession"
	"github.com/meshtransit/meshtransit/internal/node"
	"github.com/meshtransit/meshtransit/internal/policy"
	"github.com/meshtransit/meshtransit/internal/policy/publication"
	"github.com/meshtransit/meshtransit/internal/resource"
)

func TestManagementHandlerExplainsActiveResourceGroupPolicy(t *testing.T) {
	t.Parallel()

	reader := managementAccessGraphReaderFunc(func(
		_ context.Context,
		_ accountsession.Session,
		query accessgraph.Query,
		_ time.Time,
	) (accessgraph.Snapshot, error) {
		return managementAccessGraphSnapshot(t, query), nil
	})
	service, err := accessgraph.NewService(accessgraph.Dependencies{
		Reader: reader, Clock: accessgraph.SystemClock{},
	})
	if err != nil {
		t.Fatal(err)
	}
	options := validManagementHandlerOptions(t)
	options.PolicyExplanations = service
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	request := newManagementRequest(
		t,
		http.MethodPost,
		validAccessGraphExplainPath(),
		`{"source_device_id":"01890f00-0000-7000-8000-000000000301",`+
			`"destination_resource_id":"01890f00-0000-7000-8000-000000000601",`+
			`"protocol":"tcp","destination_port":443}`,
	)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", response.Code, http.StatusOK, response.Body.String())
	}
	var body explainPolicyResponse
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Data.Decision != "allow" || body.Data.Reason != "matching_active_rule" ||
		body.Data.Action.Name != "network.connect" || body.Data.Action.Protocol != "tcp" ||
		body.Data.Action.DestinationPort == nil || *body.Data.Action.DestinationPort != 443 ||
		body.Data.Target.ResourceID != managementResourceID() ||
		body.Data.Evidence.PolicyRevision != 6 || !body.Data.Evidence.HasActiveRelease ||
		len(body.Data.Paths) != 1 || body.Data.Paths[0].SelectorKind != "resource_group" ||
		body.Data.Paths[0].DestinationResourceID != managementResourceID() ||
		body.Data.Paths[0].DestinationGroupID != managementResourceGroupID() ||
		response.Header().Get("ETag") != `"6"` || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response = %+v; headers = %+v", body, response.Header())
	}
}

func TestManagementHandlerAccessGraphFailsClosed(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		body      string
		readerErr error
		status    int
		code      string
		wantCall  bool
		retryable bool
	}{
		{
			name: "ambiguous target",
			body: `{"source_device_id":"01890f00-0000-7000-8000-000000000301",` +
				`"destination_device_id":"01890f00-0000-7000-8000-000000000302",` +
				`"destination_resource_id":"01890f00-0000-7000-8000-000000000601",` +
				`"protocol":"tcp","destination_port":443}`,
			status: http.StatusBadRequest, code: "invalid_request",
		},
		{
			name: "icmp port",
			body: `{"source_device_id":"01890f00-0000-7000-8000-000000000301",` +
				`"destination_device_id":"01890f00-0000-7000-8000-000000000302",` +
				`"protocol":"icmp","destination_port":1}`,
			status: http.StatusBadRequest, code: "invalid_request",
		},
		{
			name: "forbidden",
			body: `{"source_device_id":"01890f00-0000-7000-8000-000000000301",` +
				`"destination_device_id":"01890f00-0000-7000-8000-000000000302",` +
				`"protocol":"icmp"}`,
			readerErr: accessgraph.ErrForbidden, status: http.StatusForbidden,
			code: "forbidden", wantCall: true,
		},
		{
			name: "invalid authority evidence",
			body: `{"source_device_id":"01890f00-0000-7000-8000-000000000301",` +
				`"destination_device_id":"01890f00-0000-7000-8000-000000000302",` +
				`"protocol":"icmp"}`,
			status: http.StatusInternalServerError, code: "internal_failure", wantCall: true,
		},
		{
			name: "dependency unavailable",
			body: `{"source_device_id":"01890f00-0000-7000-8000-000000000301",` +
				`"destination_device_id":"01890f00-0000-7000-8000-000000000302",` +
				`"protocol":"icmp"}`,
			readerErr: accessgraph.ErrUnavailable, status: http.StatusServiceUnavailable,
			code: "operation_unavailable", wantCall: true, retryable: true,
		},
		{
			name: "deadline expired",
			body: `{"source_device_id":"01890f00-0000-7000-8000-000000000301",` +
				`"destination_device_id":"01890f00-0000-7000-8000-000000000302",` +
				`"protocol":"icmp"}`,
			readerErr: context.DeadlineExceeded, status: http.StatusGatewayTimeout,
			code: "request_timeout", wantCall: true, retryable: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			called := false
			reader := managementAccessGraphReaderFunc(func(
				_ context.Context,
				_ accountsession.Session,
				_ accessgraph.Query,
				_ time.Time,
			) (accessgraph.Snapshot, error) {
				called = true
				return accessgraph.Snapshot{}, test.readerErr
			})
			service, err := accessgraph.NewService(accessgraph.Dependencies{
				Reader: reader, Clock: accessgraph.SystemClock{},
			})
			if err != nil {
				t.Fatal(err)
			}
			options := validManagementHandlerOptions(t)
			options.PolicyExplanations = service
			handler, err := NewManagementHandler(options)
			if err != nil {
				t.Fatal(err)
			}
			request := newManagementRequest(t, http.MethodPost, validAccessGraphExplainPath(), test.body)
			response := httptest.NewRecorder()

			handler.ServeHTTP(response, request)

			if response.Code != test.status || called != test.wantCall {
				t.Fatalf("status/called = %d/%t, want %d/%t; body = %s",
					response.Code, called, test.status, test.wantCall, response.Body.String())
			}
			var apiError managementErrorResponse
			if err := json.Unmarshal(response.Body.Bytes(), &apiError); err != nil {
				t.Fatal(err)
			}
			if apiError.Error.Code != test.code || apiError.Error.Retryable != test.retryable {
				t.Fatalf("error code/retryable = %q/%t, want %q/%t",
					apiError.Error.Code, apiError.Error.Retryable, test.code, test.retryable)
			}
		})
	}
}

func TestManagementHandlerRejectsAccessGraphWrongMethod(t *testing.T) {
	t.Parallel()

	options := validManagementHandlerOptions(t)
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	request := newManagementRequest(t, http.MethodGet, validAccessGraphExplainPath(), "")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("status/Allow = %d/%q", response.Code, response.Header().Get("Allow"))
	}
}

type managementAccessGraphReaderFunc func(
	context.Context,
	accountsession.Session,
	accessgraph.Query,
	time.Time,
) (accessgraph.Snapshot, error)

func (function managementAccessGraphReaderFunc) ReadActive(
	ctx context.Context,
	session accountsession.Session,
	query accessgraph.Query,
	evaluatedAt time.Time,
) (accessgraph.Snapshot, error) {
	return function(ctx, session, query, evaluatedAt)
}

func managementAccessGraphSnapshot(
	t *testing.T,
	query accessgraph.Query,
) accessgraph.Snapshot {
	t.Helper()
	targetNodeID, err := node.ParseID("01890f00-0000-7000-8000-000000000302")
	if err != nil {
		t.Fatal(err)
	}
	projectionID, err := publication.ParseProjectionID("01890f00-0000-7000-8000-000000000701")
	if err != nil {
		t.Fatal(err)
	}
	ruleID, err := policy.ParseRuleID("01890f00-0000-7000-8000-000000000501")
	if err != nil {
		t.Fatal(err)
	}
	portRange, err := policy.NewPortRange(443, 443)
	if err != nil {
		t.Fatal(err)
	}
	groupID, err := resource.ParseGroupID(managementResourceGroupID())
	if err != nil {
		t.Fatal(err)
	}
	path, err := accessgraph.NewPath(accessgraph.PathParams{
		ProjectionID: projectionID, RuleID: ruleID, SourceNodeID: query.SourceNodeID(),
		DestinationNodeID: targetNodeID, Protocol: policy.ProtocolTCP,
		DestinationPortRanges: []policy.PortRange{portRange},
		SelectorKind:          accessgraph.SelectorKindResourceGroup,
		DestinationResourceID: query.DestinationResourceID(), DestinationGroupID: groupID,
	})
	if err != nil {
		t.Fatal(err)
	}
	releaseID, err := publication.ParseReleaseID("01890f00-0000-7000-8000-000000000901")
	if err != nil {
		t.Fatal(err)
	}
	semanticHash, err := publication.NewSemanticHash(sha256.Sum256([]byte("access graph fixture")))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := accessgraph.NewSnapshot(accessgraph.SnapshotParams{
		Scope: query.Scope(), NetworkRevision: 12, InventoryRevision: 8,
		GroupRevision: 9, PolicyRevision: 6, DNSRevision: 2, RouteRevision: 2,
		SharingRevision: 2, IsolationGeneration: 1, HasActiveRelease: true,
		ReleaseID: releaseID, CompilerFormatVersion: 3, SemanticHash: semanticHash,
		TargetNodeID: targetNodeID, Paths: []accessgraph.Path{path},
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func validAccessGraphExplainPath() string {
	return "/api/v1/workspaces/" + managementWorkspaceID() + "/networks/" +
		managementNetworkID() + "/access-graph/actions/explain"
}

func validAccessGraphExplainBody() string {
	return `{"source_device_id":"01890f00-0000-7000-8000-000000000301",` +
		`"destination_resource_id":"01890f00-0000-7000-8000-000000000601",` +
		`"protocol":"tcp","destination_port":443}`
}
