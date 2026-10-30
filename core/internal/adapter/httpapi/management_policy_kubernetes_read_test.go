package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/policy"
	"meshtransit.net/core/internal/domain/policy/compilation"
	"meshtransit.net/core/internal/domain/policy/publication"
	"meshtransit.net/shared/kubeprofile"
)

type kubernetesAccessReaderFunc func(context.Context, accountsession.Session, network.Scope,
	int64) (compilation.ReleasedKubernetesAccess, error)

func (reader kubernetesAccessReaderFunc) ReadPolicyKubernetesAccess(ctx context.Context,
	session accountsession.Session, scope network.Scope, revision int64,
) (compilation.ReleasedKubernetesAccess, error) {
	return reader(ctx, session, scope, revision)
}

const policyKubernetesAccessURL = "/api/v1/workspaces/01890f00-0000-7000-8000-000000000101/networks/" +
	"01890f00-0000-7000-8000-000000000201/policy/kubernetes-access"

func releasedKubernetesAccess(t *testing.T) compilation.ReleasedKubernetesAccess {
	t.Helper()
	profileID, err := publication.ParseKubernetesProfileID("01890f00-0000-7000-8000-000000000c01")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := publication.NewKubernetesProfile(publication.KubernetesProfileParams{
		ID: profileID, Description: "work on apps",
		Profile: kubeprofile.Profile{Name: "developer", Namespaced: []kubeprofile.Rule{{
			APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	until := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	access, err := publication.NewKubernetesAccess(publication.KubernetesAccessParams{
		ProfileID: profileID, ProfileHash: profile.ContentHash(), Namespaces: []string{"team-b", "team-a"},
		Report: true, ReportUntil: until,
	})
	if err != nil {
		t.Fatal(err)
	}
	cluster, _ := kubecluster.ParseID("01890f00-0000-7000-8000-000000000a01")
	full, _ := policy.ParseRuleID("01890f00-0000-7000-8000-000000000d01")
	legacy, _ := policy.ParseRuleID("01890f00-0000-7000-8000-000000000d03")
	profiled, _ := policy.ParseRuleID("01890f00-0000-7000-8000-000000000d02")
	return compilation.ReleasedKubernetesAccess{
		Profiles: []publication.KubernetesProfile{profile},
		Rules: map[policy.RuleID]compilation.ReleasedClusterRule{
			full:     {Cluster: cluster, Groups: []string{"view"}},
			profiled: {Cluster: cluster, Groups: []string{"edit"}, Access: access},
			legacy:   {Cluster: cluster},
		},
	}
}

func TestManagementPolicyKubernetesAccessRead(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, query string
		err         error
		status      int
	}{
		{name: "read", query: "?policy_revision=7", status: http.StatusOK},
		{name: "no revision", query: "", status: http.StatusBadRequest},
		{name: "zero", query: "?policy_revision=0", status: http.StatusBadRequest},
		{name: "padded", query: "?policy_revision=07", status: http.StatusBadRequest},
		{name: "extra key", query: "?policy_revision=7&x=1", status: http.StatusBadRequest},
		{name: "twice", query: "?policy_revision=7&policy_revision=7", status: http.StatusBadRequest},
		{name: "forbidden", query: "?policy_revision=7", err: compilation.ErrForbidden,
			status: http.StatusForbidden},
		{name: "trailing ampersand", query: "?policy_revision=7&", status: http.StatusBadRequest},
		{name: "escaped", query: "?policy_revision=%37", status: http.StatusBadRequest},
		{name: "unavailable", query: "?policy_revision=7", err: errors.New("down"),
			status: http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := validManagementHandlerOptions(t)
			scope := managementPolicySimulationScope(t)
			options.PolicyKubernetesAccess = kubernetesAccessReaderFunc(func(_ context.Context,
				session accountsession.Session, actual network.Scope, revision int64,
			) (compilation.ReleasedKubernetesAccess, error) {
				if !session.IsValid() || actual != scope || revision != 7 {
					t.Fatal("unbound read")
				}
				if test.err != nil {
					return compilation.ReleasedKubernetesAccess{}, test.err
				}
				return releasedKubernetesAccess(t), nil
			})
			handler, err := NewManagementHandler(options)
			if err != nil {
				t.Fatal(err)
			}
			request := newManagementRequest(t, http.MethodGet, policyKubernetesAccessURL+test.query, "")
			request.Header.Del("If-Match")
			request.Header.Del("Idempotency-Key")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d; body = %s", response.Code, response.Body.String())
			}
			if test.status != http.StatusOK {
				return
			}
			var body policyKubernetesAccessResponse
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			data := body.Data
			if response.Header().Get("ETag") != `"7"` || data.PolicyRevision != 7 || len(data.Profiles) != 1 ||
				data.Profiles[0].Name != "developer" || len(data.Profiles[0].ContentHash) != 64 ||
				data.Profiles[0].Cluster == nil || len(data.Rules) != 3 {
				t.Fatalf("response %+v", data)
			}
			if data.Rules[2].Groups != nil || data.Rules[2].Access != nil ||
				!strings.Contains(response.Body.String(), `"rule_id":"01890f00-0000-7000-8000-000000000d03","cluster_id":"01890f00-0000-7000-8000-000000000a01","groups":null}`) {
				t.Fatalf("a rule before groups %+v", data.Rules[2])
			}
			if !data.Rules[0].Access.Full || data.Rules[0].Groups[0] != "view" {
				t.Fatalf("full rule %+v", data.Rules[0])
			}
			profiled := data.Rules[1].Access
			if profiled.Full || profiled.ProfileID != "01890f00-0000-7000-8000-000000000c01" ||
				strings.Join(profiled.Namespaces, ",") != "team-a,team-b" || profiled.Mode != "report" ||
				profiled.ReportUntil == nil || !strings.Contains(response.Body.String(), `"report_until":"2026-11-02T10:00:00Z"`) {
				t.Fatalf("profiled rule %+v", profiled)
			}
		})
	}
}

func TestPolicyKubernetesAccessBrowserAdmission(t *testing.T) {
	t.Parallel()
	for target, want := range map[string]bool{
		policyKubernetesAccessURL + "?policy_revision=3":   true,
		policyKubernetesAccessURL + "?policy_revision=abc": false,
		policyKubernetesAccessURL:                          false,
	} {
		request := httptest.NewRequest(http.MethodGet, target, nil)
		if got := isPolicyKubernetesAccessRead(request); got != want {
			t.Errorf("%s: %v", target, got)
		}
	}
	if isPolicyKubernetesAccessRead(httptest.NewRequest(http.MethodPost, policyKubernetesAccessURL+"?policy_revision=3",
		nil)) {
		t.Error("a POST admitted")
	}
}

func TestManagementPolicyKubernetesAccessMethodAndDependency(t *testing.T) {
	t.Parallel()
	options := validManagementHandlerOptions(t)
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	request := newManagementRequest(t, http.MethodGet, policyKubernetesAccessURL+"?policy_revision=7", "")
	request.Header.Del("If-Match")
	request.Header.Del("Idempotency-Key")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("without a reader: %d", response.Code)
	}
	post := newManagementRequest(t, http.MethodPost, policyKubernetesAccessURL+"?policy_revision=7", "{}")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, post)
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("POST: %d %q", response.Code, response.Header().Get("Allow"))
	}
}
