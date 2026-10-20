package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/exitpool"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
)

func TestParseExitPoolPath(t *testing.T) {
	t.Parallel()
	base := "/api/v1/workspaces/01890f00-0000-7000-8000-000000000101/networks/01890f00-0000-7000-8000-000000000201/exit-pools"
	poolID := "01890f00-0000-7000-8000-000000000301"
	deviceID := "01890f00-0000-7000-8000-000000000401"
	for _, test := range []struct {
		method, path, operation string
		matched                 bool
	}{
		{http.MethodGet, base, exitPoolListOperation, true},
		{http.MethodPost, base, exitPoolCreateOperation, true},
		{http.MethodDelete, base, "", true},
		{http.MethodGet, base + "/" + poolID, exitPoolReadOperation, true},
		{http.MethodPatch, base + "/" + poolID, exitPoolUpdateOperation, true},
		{http.MethodDelete, base + "/" + poolID, exitPoolDeleteOperation, true},
		{http.MethodPost, base + "/" + poolID, "", true},
		{http.MethodPut, base + "/" + poolID + "/nodes/" + deviceID, exitPoolNodePutOperation, true},
		{http.MethodDelete, base + "/" + poolID + "/nodes/" + deviceID, exitPoolNodeDeleteOperation, true},
		{http.MethodGet, base + "/" + poolID + "/nodes/" + deviceID, "", true},
		{http.MethodGet, base + "?limit=1", exitPoolListOperation, true},
		{http.MethodGet, base + "?after=" + poolID + "&limit=10", exitPoolListOperation, true},
		{http.MethodGet, base + "?limit=101", "", false},
		{http.MethodGet, base + "?limit=1&limit=2", "", false},
		{http.MethodGet, base + "?cursor=x", "", false},
		{http.MethodGet, base + "/" + poolID + "?limit=1", "", false},
		{http.MethodGet, base + "/not-an-id", "", false},
		{http.MethodPut, base + "/" + poolID + "/nodes", "", false},
		{http.MethodPut, base + "/" + poolID + "/routers/" + deviceID, "", false},
		{http.MethodGet, strings.TrimSuffix(base, "exit-pools") + "sites", "", false},
	} {
		request := httptest.NewRequestWithContext(t.Context(), test.method, test.path, nil)
		path, matched := parseExitPoolPath(request)
		if matched != test.matched || (matched && path.operation != test.operation) {
			t.Errorf("%s %s = %q, %v; want %q, %v", test.method, test.path, path.operation, matched,
				test.operation, test.matched)
		}
	}
}

func TestClassifyExitPoolError(t *testing.T) {
	t.Parallel()
	for err, code := range map[error]string{
		exitpool.ErrForbidden:       "permission_denied",
		exitpool.ErrNotFound:        "exit_pool_not_found",
		exitpool.ErrVersionConflict: "version_conflict",
		exitpool.ErrNameTaken:       "exit_pool_name_taken",
		exitpool.ErrPoolLimit:       "exit_pool_limit",
		exitpool.ErrNodeLimit:       "exit_node_limit",
		exitpool.ErrNodeNotEligible: "exit_node_not_eligible",
		exitpool.ErrNodeInOtherPool: "exit_node_in_other_pool",
		exitpool.ErrInUse:           "exit_pool_in_use",
		exitpool.ErrNotInternet:     "exit_pool_address_not_internet",
		exitpool.ErrInvalid:         "invalid_request",
		errors.New("database"):      "temporarily_unavailable",
	} {
		if got := classifyExitPoolError(err).Code; got != code {
			t.Errorf("classifyExitPoolError(%v) = %q, want %q", err, got, code)
		}
	}
}

type fakeExitPoolManager struct {
	created    exitpool.Definition
	expected   int64
	assignment exitpool.NodeAssignment
	removed    node.ID
	pool       exitpool.Pool
}

func (manager *fakeExitPoolManager) List(context.Context, accountsession.Session, network.Scope, exitpool.ID,
	int) (exitpool.Listing, error) {
	return exitpool.Listing{Pools: []exitpool.Pool{manager.pool}, Abilities: exitpool.Abilities{CanManage: true}}, nil
}

func (manager *fakeExitPoolManager) Read(context.Context, accountsession.Session, network.Scope,
	exitpool.ID) (exitpool.Reading, error) {
	return exitpool.Reading{Pool: manager.pool}, nil
}

func (manager *fakeExitPoolManager) Create(_ context.Context, _ accountsession.Session, _ network.Scope,
	definition exitpool.Definition, _ publicid.ID) (exitpool.Result, error) {
	manager.created = definition
	return exitpool.Result{Pool: manager.pool, Changed: true}, nil
}

func (manager *fakeExitPoolManager) Update(_ context.Context, _ accountsession.Session, _ network.Scope,
	_ exitpool.ID, expected int64, definition exitpool.Definition, _ publicid.ID) (exitpool.Result, error) {
	manager.created, manager.expected = definition, expected
	return exitpool.Result{Pool: manager.pool, Changed: true}, nil
}

func (manager *fakeExitPoolManager) Delete(_ context.Context, _ accountsession.Session, _ network.Scope,
	_ exitpool.ID, expected int64, _ publicid.ID) (exitpool.Result, error) {
	manager.expected = expected
	return exitpool.Result{Pool: manager.pool, Deleted: true, Changed: true}, nil
}

func (manager *fakeExitPoolManager) PutNode(_ context.Context, _ accountsession.Session, _ network.Scope,
	_ exitpool.ID, expected int64, assignment exitpool.NodeAssignment, _ publicid.ID) (exitpool.Result, error) {
	manager.expected, manager.assignment = expected, assignment
	return exitpool.Result{Pool: manager.pool, Changed: true}, nil
}

func (manager *fakeExitPoolManager) RemoveNode(_ context.Context, _ accountsession.Session, _ network.Scope,
	_ exitpool.ID, expected int64, device node.ID, _ publicid.ID) (exitpool.Result, error) {
	manager.expected, manager.removed = expected, device
	return exitpool.Result{Pool: manager.pool, Changed: true}, nil
}

func TestHandleExitPools(t *testing.T) {
	t.Parallel()
	poolID, _ := exitpool.ParseID("01890f00-0000-7000-8000-000000000301")
	device, _ := node.ParseID("01890f00-0000-7000-8000-000000000401")
	stored := exitpool.Pool{ID: poolID, Version: 4, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		Definition: exitpool.Definition{Name: "SG", ConntrackPerConsumer: exitpool.DefaultConntrackPerConsumer,
			DNSUpstreams: []netip.Addr{netip.MustParseAddr("1.1.1.1")}},
		Nodes: []exitpool.Node{{NodeAssignment: exitpool.NodeAssignment{DeviceID: device, Priority: 1,
			State: exitpool.NodeActive}, Offered: true, Eligible: true, DeviceName: "exit-1", AddedAt: time.Now()}}}
	manager := &fakeExitPoolManager{pool: stored}
	handler := &ManagementHandler{exitPools: manager, logger: slog.New(slog.DiscardHandler)}
	base := "/api/v1/workspaces/01890f00-0000-7000-8000-000000000101/networks/01890f00-0000-7000-8000-000000000201/exit-pools"
	correlationID, _ := publicid.New()
	serve := func(method, target, body string, header map[string]string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequestWithContext(t.Context(), method, target, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		for key, value := range header {
			request.Header.Set(key, value)
		}
		path, ok := parseExitPoolPath(request)
		if !ok {
			t.Fatalf("%s %s did not match", method, target)
		}
		response := httptest.NewRecorder()
		handler.handleExitPools(t.Context(), response, request, correlationID, path, accountsession.Session{})
		return response
	}

	created := serve(http.MethodPost, base, `{"name":"SG","failback":false,"smtp_allowed":false,
"conntrack_per_consumer":16384,"dns_upstreams":["1.1.1.1"],"probes":[{"address":"8.8.8.8","port":443}]}`, nil)
	if created.Code != http.StatusCreated || created.Header().Get("ETag") != `"4"` ||
		manager.created.Probes[0].Port != 443 {
		t.Fatalf("create = %d %s", created.Code, created.Body)
	}
	var output struct {
		Data struct {
			Pool struct {
				PoolID string `json:"exit_pool_id"`
				Nodes  []struct {
					Offered  bool `json:"offered"`
					Eligible bool `json:"eligible"`
				} `json:"nodes"`
			} `json:"exit_pool"`
		} `json:"data"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &output); err != nil || output.Data.Pool.PoolID != poolID.String() ||
		!output.Data.Pool.Nodes[0].Eligible {
		t.Fatalf("create body = %s, error = %v", created.Body, err)
	}
	// Non-canonical addresses and missing fields are refused before the
	// service.
	for _, body := range []string{
		`{"name":"SG","failback":false,"smtp_allowed":false,"conntrack_per_consumer":16384,"dns_upstreams":["001.1.1.1"],"probes":[]}`,
		`{"name":"SG","failback":false,"smtp_allowed":false,"dns_upstreams":[],"probes":[]}`,
		`{"name":"SG","failback":false,"smtp_allowed":false,"conntrack_per_consumer":16384,"dns_upstreams":[],"probes":[],"masquerade":true}`,
	} {
		if response := serve(http.MethodPost, base, body, nil); response.Code != http.StatusBadRequest {
			t.Errorf("create %s = %d", body, response.Code)
		}
	}
	if response := serve(http.MethodPatch, base+"/"+poolID.String(), `{}`, nil); response.Code ==
		http.StatusOK {
		t.Fatal("an update without If-Match was accepted")
	}
	put := serve(http.MethodPut, base+"/"+poolID.String()+"/nodes/"+device.String(),
		`{"priority":7,"state":"draining"}`, map[string]string{"If-Match": `"4"`})
	if put.Code != http.StatusOK || manager.expected != 4 || manager.assignment.Priority != 7 ||
		manager.assignment.State != exitpool.NodeDraining || manager.assignment.DeviceID != device {
		t.Fatalf("put node = %d %s, %+v", put.Code, put.Body, manager.assignment)
	}
	if bad := serve(http.MethodPut, base+"/"+poolID.String()+"/nodes/"+device.String(),
		`{"priority":7,"state":"primary"}`, map[string]string{"If-Match": `"4"`}); bad.Code != http.StatusBadRequest {
		t.Fatalf("put node with an unknown state = %d", bad.Code)
	}
	removed := serve(http.MethodDelete, base+"/"+poolID.String()+"/nodes/"+device.String(), "",
		map[string]string{"If-Match": `"5"`})
	if removed.Code != http.StatusOK || manager.removed != device || manager.expected != 5 {
		t.Fatalf("remove node = %d %s", removed.Code, removed.Body)
	}
	listed := serve(http.MethodGet, base+"?limit=5", "", nil)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"exit_pools":[`) {
		t.Fatalf("list = %d %s", listed.Code, listed.Body)
	}
}

// TestExitPoolsThroughServeHTTP drives every method through the whole
// handler: operation, allowed method and Allow header must know the paths.
func TestExitPoolsThroughServeHTTP(t *testing.T) {
	t.Parallel()
	poolID, _ := exitpool.ParseID("01890f00-0000-7000-8000-000000000a01")
	device, _ := node.ParseID("01890f00-0000-7000-8000-000000000a02")
	manager := &fakeExitPoolManager{pool: exitpool.Pool{ID: poolID, Version: 2, CreatedAt: time.Now(),
		UpdatedAt: time.Now(), Definition: exitpool.Definition{Name: "SG",
			ConntrackPerConsumer: exitpool.DefaultConntrackPerConsumer}}}
	options := validManagementHandlerOptions(t)
	options.ExitPools = manager
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	base := "/api/v1/workspaces/" + managementWorkspaceID() + "/networks/" + managementNetworkID() + "/exit-pools"
	pool := base + "/" + poolID.String()
	exitNode := pool + "/nodes/" + device.String()
	definition := `{"name":"SG","failback":false,"smtp_allowed":false,"conntrack_per_consumer":16384,` +
		`"dns_upstreams":[],"probes":[]}`
	for _, test := range []struct {
		method, path, body string
		status             int
		allow              string
	}{
		{http.MethodGet, base, "", http.StatusOK, ""},
		{http.MethodGet, pool, "", http.StatusOK, ""},
		{http.MethodPatch, pool, definition, http.StatusOK, ""},
		{http.MethodDelete, pool, "", http.StatusOK, ""},
		{http.MethodPut, exitNode, `{"priority":1,"state":"active"}`, http.StatusOK, ""},
		{http.MethodDelete, exitNode, "", http.StatusOK, ""},
		{http.MethodPut, pool, definition, http.StatusMethodNotAllowed, "GET, PATCH, DELETE"},
		{http.MethodGet, exitNode, "", http.StatusMethodNotAllowed, "PUT, DELETE"},
	} {
		request := newManagementRequest(t, test.method, test.path, test.body)
		request.Header.Del("Idempotency-Key")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.status || (test.allow != "" && response.Header().Get("Allow") != test.allow) {
			t.Errorf("%s %s = %d (Allow %q); %s", test.method, test.path, response.Code,
				response.Header().Get("Allow"), response.Body)
		}
	}
}
