package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/accessgraph/simulation"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/policy/catalog"
)

type activePolicyReaderFunc func(context.Context, accountsession.Session, network.Scope, time.Time) (catalog.Snapshot, error)

func (reader activePolicyReaderFunc) ReadActivePolicy(ctx context.Context, session accountsession.Session, scope network.Scope, now time.Time) (catalog.Snapshot, error) {
	return reader(ctx, session, scope, now)
}

func TestManagementActivePolicyReadBindsScopeRevisionAndPermissionFailure(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name   string
		denied bool
		status int
	}{
		{name: "authorized empty policy", status: http.StatusOK},
		{name: "missing policy.read", denied: true, status: http.StatusForbidden},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := validManagementHandlerOptions(t)
			scope := managementPolicySimulationScope(t)
			options.ActivePolicies = activePolicyReaderFunc(func(_ context.Context, session accountsession.Session, actual network.Scope, now time.Time) (catalog.Snapshot, error) {
				if !session.IsValid() || actual != scope || now.IsZero() {
					t.Fatal("unbound read")
				}
				if test.denied {
					return catalog.Snapshot{}, simulation.ErrForbidden
				}
				baseline := managementPolicySimulationBaseline(t, scope)
				return catalog.NewSnapshot(catalog.SnapshotParams{Scope: scope, Revision: 1, SemanticHash: baseline.Candidate().SemanticHash(), DeviceRulesOnly: true, Rows: []catalog.Row{}})
			})
			handler, err := NewManagementHandler(options)
			if err != nil {
				t.Fatal(err)
			}
			request := newManagementRequest(t, http.MethodGet, "/api/v1/workspaces/01890f00-0000-7000-8000-000000000101/networks/01890f00-0000-7000-8000-000000000201/policy", "")
			request.Header.Del("If-Match")
			request.Header.Del("Idempotency-Key")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
			}
			if test.denied {
				return
			}
			var body activePolicyResponse
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if response.Header().Get("ETag") != `"1"` || body.Data.PolicyRevision != 1 || body.Data.WorkspaceID != scope.WorkspaceID().String() || !body.Data.Complete || !body.Data.DeviceRulesOnly || body.Data.Rules == nil {
				t.Fatalf("unbound response: %+v", body)
			}
		})
	}
}
