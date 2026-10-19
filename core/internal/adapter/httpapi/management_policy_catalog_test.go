package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"meshtransit.net/core/internal/domain/accessgraph/simulation"
	"meshtransit.net/core/internal/domain/devicegroup"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/catalog"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/site"
)

type activePolicyReaderFunc func(context.Context, accountsession.Session, network.Scope) (catalog.Snapshot, error)

func (reader activePolicyReaderFunc) ReadActivePolicy(ctx context.Context, session accountsession.Session, scope network.Scope) (catalog.Snapshot, error) {
	return reader(ctx, session, scope)
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
			options.ActivePolicies = activePolicyReaderFunc(func(_ context.Context, session accountsession.Session, actual network.Scope) (catalog.Snapshot, error) {
				if !session.IsValid() || actual != scope {
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

// TestManagementActivePolicyReadAddsPrefixesOnlyToSiteRules keeps rows other
// than Site rules exactly as clients that know no Sites parse them.
func TestManagementActivePolicyReadAddsPrefixesOnlyToSiteRules(t *testing.T) {
	t.Parallel()
	options := validManagementHandlerOptions(t)
	scope := managementPolicySimulationScope(t)
	intent := func(id string, params compilation.RuleIntentParams) catalog.Row {
		ruleID, err := policy.ParseRuleID(id)
		if err != nil {
			t.Fatal(err)
		}
		params.ID, params.Scope, params.Protocol = ruleID, scope, policy.ProtocolICMP
		params.DestinationPortRanges = []policy.PortRange{}
		built, err := compilation.NewRuleIntent(params)
		if err != nil {
			t.Fatal(err)
		}
		return catalog.Row{Intent: built}
	}
	source, _ := devicegroup.ParseID("01890f00-0000-7000-8000-000000000501")
	destination, _ := devicegroup.ParseID("01890f00-0000-7000-8000-000000000502")
	siteID, _ := site.ParseID("01890f00-0000-7000-8000-000000000503")
	rows := []catalog.Row{
		intent("01890f00-0000-7000-8000-000000000511", compilation.RuleIntentParams{
			SourceGroupID: source, DestinationDeviceGroupID: destination,
		}),
		intent("01890f00-0000-7000-8000-000000000512", compilation.RuleIntentParams{
			SourceGroupID: source, DestinationSiteID: siteID,
			DestinationPrefixes: []netip.Prefix{netip.MustParsePrefix("10.20.5.0/24")},
		}),
	}
	options.ActivePolicies = activePolicyReaderFunc(func(context.Context, accountsession.Session, network.Scope) (catalog.Snapshot, error) {
		baseline := managementPolicySimulationBaseline(t, scope)
		return catalog.NewSnapshot(catalog.SnapshotParams{Scope: scope, Revision: 1,
			SemanticHash: baseline.Candidate().SemanticHash(), RuleCount: len(rows), Rows: rows})
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
	var body struct {
		Data struct {
			Rules []map[string]json.RawMessage `json:"rules"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || response.Code != http.StatusOK || len(body.Data.Rules) != 2 {
		t.Fatalf("status = %d, error = %v, body = %s", response.Code, err, response.Body.String())
	}
	for _, row := range body.Data.Rules {
		prefixes, present := row["destination_prefixes"]
		switch string(row["selector_kind"]) {
		case `"site"`:
			if string(prefixes) != `["10.20.5.0/24"]` {
				t.Fatalf("Site rule prefixes = %s", prefixes)
			}
		default:
			if present {
				t.Fatalf("a rule to %s carries destination_prefixes", row["selector_kind"])
			}
		}
	}
}
