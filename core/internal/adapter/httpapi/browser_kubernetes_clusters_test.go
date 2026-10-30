package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
	"meshtransit.net/core/internal/domain/publicid"
	"meshtransit.net/core/internal/domain/workspace"
)

// The Console reaches the cluster list, a cluster's read, its keys and its
// replica decisions through the account-session cookie; only the key and
// request lists take a query, a page (K1d d1a).
func TestBrowserManagementAdmitsKubernetesClusterRoutes(t *testing.T) {
	t.Parallel()
	browser, _ := newBrowserManagementFixture(t)
	const cluster, child = "/01890f00-0000-7000-8000-000000000a01", "/01890f00-0000-7000-8000-000000000a02"
	for _, path := range []string{
		kubernetesClustersTestPath(cluster + "/join-keys?page_size=10"),
		kubernetesClustersTestPath(cluster + "/replica-requests?page_size=100"),
		kubernetesClustersTestPath(cluster + "/replicas?page_size=10"),
		kubernetesClustersTestPath(cluster + "/operations?class=write&from=2026-10-29T00:00:00Z"),
		kubernetesClustersTestPath(cluster + "/operations" + child),
		kubernetesClustersTestPath(cluster + "/operation-denial-counts?to=2026-10-30T00:00:00Z"),
		kubernetesClustersTestPath(cluster + "/operation-exports?from=2026-10-29T00:00:00Z&to=2026-10-30T00:00:00Z"),
		kubernetesClustersTestPath(cluster + "/certificate-authorities?page_size=10"),
		kubernetesClustersTestPath(cluster + "/approver-additions"),
		kubernetesClustersTestPath(cluster + "/replicas" + child),
		kubernetesClustersTestPath(cluster + "/certificate-authorities" + child),
		kubernetesClustersTestPath(cluster + "/join-keys?page_size=10&page_token=" + kubernetesBrowserPageToken(t)),
	} {
		if !browser.validRequest(browserManagementReadRequest(t, path)) {
			t.Errorf("the browser cannot read a page %s", path)
		}
	}
	for _, path := range []string{
		kubernetesClustersTestPath(cluster + "?page_size=10"),
		kubernetesClustersTestPath(cluster + "/join-keys" + child + "?page_size=10"),
		kubernetesClustersTestPath(cluster + "/signing?page_size=10"),
		kubernetesClustersTestPath(cluster + "/join-keys?page_size=101"),
		kubernetesClustersTestPath(cluster + "/replica-requests?page_token=x"),
		kubernetesClustersTestPath(cluster + "/operation-exports?class=write"),
	} {
		if browser.validRequest(browserManagementReadRequest(t, path)) {
			t.Errorf("the browser admitted GET %s", path)
		}
	}
	for _, path := range []string{
		kubernetesClustersTestPath(""),
		kubernetesClustersTestPath(cluster),
		kubernetesClustersTestPath(cluster + "/join-keys"),
		kubernetesClustersTestPath(cluster + "/replica-requests"),
		kubernetesClustersTestPath(cluster + "/join-keys" + child),
		kubernetesClustersTestPath(cluster + "/replica-requests" + child),
		kubernetesClustersTestPath(cluster + "/signing"),
		kubernetesClustersTestPath(cluster + "/signing-trust"),
	} {
		if !browser.validRequest(browserManagementReadRequest(t, path)) {
			t.Errorf("the browser cannot read %s", path)
		}
	}
	for _, path := range []string{
		kubernetesClustersTestPath(""),
		kubernetesClustersTestPath(cluster + "/join-keys"),
		kubernetesClustersTestPath(cluster + "/join-keys" + child + "/actions/revoke"),
		kubernetesClustersTestPath(cluster + "/replica-requests" + child + "/actions/approve"),
		kubernetesClustersTestPath(cluster + "/replica-requests" + child + "/actions/reject"),
	} {
		request := browserManagementRequest(t, path, `{}`)
		if !browser.validRequest(request) || !isBrowserManagementOperation(request) {
			t.Errorf("the browser cannot POST %s", path)
		}
	}
	// An administrator pastes the cluster's signing keys (K1.1b): a PUT, the only one here.
	paste := browserManagementRequest(t, kubernetesClustersTestPath(cluster+"/signing-trust"), `{}`)
	paste.Method = http.MethodPut
	paste.Header.Set("If-Match", `"1"`)
	if !browser.validRequest(paste) || !isBrowserManagementOperation(paste) {
		t.Error("the browser cannot PUT a cluster's signing trust")
	}
	deletion := browserManagementRequest(t, kubernetesClustersTestPath(cluster), "")
	deletion.Method, deletion.Body, deletion.ContentLength = http.MethodDelete, http.NoBody, 0
	deletion.Header.Del("Content-Type")
	deletion.Header.Del("Idempotency-Key")
	if !browser.validRequest(deletion) || !isBrowserManagementOperation(deletion) {
		t.Error("the browser cannot DELETE a cluster")
	}
	if browser.validRequest(browserManagementRequest(t, kubernetesClustersTestPath(cluster+"/join-keys?x=1"), `{}`)) {
		t.Error("the browser admitted a query on a mutation")
	}
	for _, path := range []string{
		kubernetesClustersTestPath("?limit=10"),
		kubernetesClustersTestPath(cluster + "?view=full"),
		kubernetesClustersTestPath(cluster + "/replica-requests" + child + "/actions/approve"),
	} {
		if browser.validRequest(browserManagementReadRequest(t, path)) {
			t.Errorf("the browser admitted GET %s", path)
		}
	}
	for _, method := range []string{http.MethodPut, http.MethodPatch} {
		served, fixture := newBrowserManagementFixture(t)
		request := browserManagementRequest(t, kubernetesClustersTestPath(cluster), `{}`)
		request.Method = method
		request.Header.Set("X-MeshTransit-CSRF", preparedBrowserProof(t, served))
		response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
		if err := served.Handle(response, request); err == nil || len(fixture.kubernetesClusters.calls) != 0 {
			t.Errorf("%s on a cluster = %v, calls %v", method, err, fixture.kubernetesClusters.calls)
		}
	}
}

// The cookie path serves the list and an approval, with the code the
// administrator typed, through the Network's cluster manager.
func TestBrowserManagementServesKubernetesClusters(t *testing.T) {
	t.Parallel()
	browser, fixture := newBrowserManagementFixture(t)
	list := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(list, browserManagementReadRequest(t, kubernetesClustersTestPath(""))); err != nil {
		t.Fatal(err)
	}
	if list.Code != http.StatusOK || list.Header().Get("Cache-Control") != "no-store" ||
		!slices.Contains(fixture.kubernetesClusters.calls, "list") {
		t.Fatalf("list = %d after %v; %s", list.Code, fixture.kubernetesClusters.calls, list.Body)
	}
	request := browserManagementRequest(t, kubernetesClustersTestPath("/"+kubernetesTestCluster+
		"/replica-requests/"+kubernetesTestRequest+"/actions/approve"), `{"code":"ABCDE-FG234"}`)
	request.Header.Del("If-Match")
	request.Header.Del("Idempotency-Key")
	request.Header.Set("X-MeshTransit-CSRF", preparedBrowserProof(t, browser))
	approved := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(approved, request); err != nil {
		t.Fatal(err)
	}
	if approved.Code != http.StatusOK || !slices.Equal(fixture.kubernetesClusters.codes, []string{"ABCDE-FG234"}) ||
		approved.Header().Get("Set-Cookie") != "" {
		t.Fatalf("approve = %d, codes %v; %s", approved.Code, fixture.kubernetesClusters.codes, approved.Body)
	}
	// The signing keys an administrator pasted reach the manager under their version.
	paste := browserManagementRequest(t, kubernetesClustersTestPath("/"+kubernetesTestCluster+"/signing-trust"),
		pastedTrustBody(kindSigningJWKS))
	paste.Method = http.MethodPut
	paste.Header.Set("If-Match", `"1"`)
	paste.Header.Del("Idempotency-Key")
	paste.Header.Set("X-MeshTransit-CSRF", preparedBrowserProof(t, browser))
	pasted := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(pasted, paste); err != nil {
		t.Fatal(err)
	}
	if pasted.Code != http.StatusOK || len(fixture.kubernetesClusters.replacements) != 1 ||
		fixture.kubernetesClusters.replacements[0].ExpectedVersion != 1 {
		t.Fatalf("paste = %d, replacements %+v; %s", pasted.Code, fixture.kubernetesClusters.replacements, pasted.Body)
	}
}

// A new join key's secret travels only in an uncached response, and a
// decision without the CSRF proof reaches nothing.
func TestBrowserManagementIssuesJoinKeysUncached(t *testing.T) {
	t.Parallel()
	browser, fixture := newBrowserManagementFixture(t)
	keys := kubernetesClustersTestPath("/" + kubernetesTestCluster + "/join-keys")
	request := browserManagementRequest(t, keys, `{"uses":2}`)
	request.Header.Del("If-Match")
	request.Header.Del("Idempotency-Key")
	request.Header.Set("X-MeshTransit-CSRF", preparedBrowserProof(t, browser))
	issued := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(issued, request); err != nil {
		t.Fatal(err)
	}
	if issued.Code != http.StatusCreated || issued.Header().Get("Cache-Control") != "no-store" ||
		len(fixture.kubernetesClusters.keys) != 1 || issued.Header().Get("Set-Cookie") != "" {
		t.Fatalf("issue = %d, %q; %s", issued.Code, issued.Header().Get("Cache-Control"), issued.Body)
	}

	approve := browserManagementRequest(t, kubernetesClustersTestPath("/"+kubernetesTestCluster+
		"/replica-requests/"+kubernetesTestRequest+"/actions/approve"), `{"code":"ABCDE-FG234"}`)
	approve.Header.Del("If-Match")
	approve.Header.Del("Idempotency-Key")
	approve.Header.Del("X-MeshTransit-CSRF")
	refused := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	err := browser.Handle(refused, approve)
	if err == nil && refused.Code < http.StatusBadRequest || len(fixture.kubernetesClusters.codes) != 0 {
		t.Fatalf("approve without proof = %v, %d, codes %v", err, refused.Code, fixture.kubernetesClusters.codes)
	}
}

// kubernetesBrowserPageToken is the next-page token of the fixture
// cluster's key list.
func kubernetesBrowserPageToken(t *testing.T) string {
	t.Helper()
	scope, err := network.NewScope(workspace.ID(mustBrowserPublicID(t, managementWorkspaceID())),
		network.ID(mustBrowserPublicID(t, networkMemberTestNetwork)))
	if err != nil {
		t.Fatal(err)
	}
	cluster, _ := kubecluster.ParseID("01890f00-0000-7000-8000-000000000a01")
	token := encodeKubernetesPageToken(scope, cluster, kubernetesJoinKeyListOperation, kubecluster.PageCursor{
		At: time.Date(2026, time.October, 30, 1, 0, 0, 0, time.UTC), ID: mustBrowserPublicID(t,
			"01890f00-0000-7000-8000-000000000a02")})
	if token == "" {
		t.Fatal("no token")
	}
	return token
}

func mustBrowserPublicID(t *testing.T, value string) publicid.ID {
	t.Helper()
	id, err := publicid.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// The Console sets a cluster's audit settings with PUT (K1d d1d).
func TestBrowserManagementAdmitsKubernetesAuditSettingsPut(t *testing.T) {
	t.Parallel()
	browser, _ := newBrowserManagementFixture(t)
	request := browserManagementRequest(t, kubernetesClustersTestPath("/01890f00-0000-7000-8000-000000000a01/audit-settings"),
		`{"privileged_groups":[],"secret_resources":[]}`)
	request.Method = http.MethodPut
	if !browser.validRequest(request) {
		t.Fatal("the browser cannot PUT audit settings")
	}
	request = browserManagementRequest(t, kubernetesClustersTestPath("/01890f00-0000-7000-8000-000000000a01/access-settings"),
		`{"access_contact":""}`)
	request.Method = http.MethodPut
	if !browser.validRequest(request) {
		t.Fatal("the browser cannot PUT access settings")
	}
	request = browserManagementRequest(t, kubernetesClustersTestPath("/01890f00-0000-7000-8000-000000000a01/replicas"),
		`{}`)
	request.Method = http.MethodPut
	if browser.validRequest(request) {
		t.Fatal("the browser admitted a PUT on replicas")
	}
}

// A browser asking about a cluster is admitted again before Core reads the
// cluster's replicas: a session revoked meanwhile reads nothing (K1d d4c).
func TestBrowserExplainKubernetesClusterRevalidatesBeforeReading(t *testing.T) {
	t.Parallel()
	browser, fixture := newBrowserManagementFixture(t)
	proof := preparedBrowserProof(t, browser)
	fixture.kubernetesClusters.explainReplica, _ = node.ParseID("01890f00-0000-7000-8000-000000000c03")
	original := browser.management.sessions
	browser.management.sessions = managementSessionAuthenticatorFunc(func(ctx context.Context,
		token accountsession.Token) (accountsession.Session, error) {
		// The front door admits the session; the handler's check finds it revoked.
		fixture.sessionRevoked = fixture.auth >= 1
		return original.Authenticate(ctx, token)
	})
	request := browserManagementRequest(t, validAccessGraphExplainPath(), explainKubernetesBody)
	request.Header.Set("X-MeshTransit-CSRF", proof)
	response := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(response, request); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusUnauthorized || fixture.auth != 2 || len(fixture.kubernetesClusters.calls) != 0 ||
		fixture.explain != 0 {
		t.Fatalf("status %d, auth %d, cluster calls %v, explained %d", response.Code, fixture.auth,
			fixture.kubernetesClusters.calls, fixture.explain)
	}
}

// The Console's export streams past the 256 KiB a buffered browser answer
// holds; a refusal stays buffered (K1d d1d-b, the 502 at record 1044).
func TestBrowserManagementStreamsKubernetesOperationExport(t *testing.T) {
	t.Parallel()
	browser, fixture := newBrowserManagementFixture(t)
	fixture.kubernetesClusters.exportNamespace = "mt-kube-k1"
	fixture.kubernetesClusters.exportRecords = kubecluster.ExportPageSize
	fixture.kubernetesClusters.exportPages = 4
	path := kubernetesClustersTestPath("/" + kubernetesTestCluster +
		"/operation-exports?from=2026-10-29T00:00:00Z&to=2026-10-30T00:00:00Z")
	streamed := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := browser.Handle(streamed, browserManagementReadRequest(t, path)); err != nil {
		t.Fatal(err)
	}
	var file struct {
		Records  []map[string]any `json:"records"`
		Complete bool             `json:"complete"`
	}
	body := streamed.Body.Bytes()
	if streamed.Code != http.StatusOK || len(body) <= maximumBrowserManagementResponseBytes ||
		json.Unmarshal(body, &file) != nil || len(file.Records) != 4*kubecluster.ExportPageSize || !file.Complete {
		t.Fatalf("export = %d, %d bytes, %d records", streamed.Code, len(body), len(file.Records))
	}
	if streamed.Header().Get("Content-Length") != "" || streamed.Header().Get("Set-Cookie") != "" ||
		!strings.HasPrefix(streamed.Header().Get("Content-Disposition"), "attachment;") ||
		streamed.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("export header %v", streamed.Header())
	}

	refusing, refusingFixture := newBrowserManagementFixture(t)
	refusingFixture.kubernetesClusters.exportCount = 1
	refused := &continuationStatusRecorder{loginHTTPRecorder: newLoginHTTPRecorder()}
	if err := refusing.Handle(refused, browserManagementReadRequest(t, path)); err != nil {
		t.Fatal(err)
	}
	if refused.Code != http.StatusConflict || refused.Header().Get("Content-Length") == "" ||
		!strings.Contains(refused.Body.String(), "gateway_namespace_unknown") {
		t.Fatalf("refusal = %d, %v; %s", refused.Code, refused.Header(), refused.Body)
	}
}

// A 200 the session no longer admits sends nothing: the export's next
// write fails and it aborts.
func TestBrowserStreamingResponseRefusesWithoutAdmission(t *testing.T) {
	t.Parallel()
	target := newLoginHTTPRecorder()
	response := &browserStreamingResponse{browserManagementResponse: &browserManagementResponse{header: http.Header{}},
		target: target, admit: func(http.Header) error { return ErrBrowserManagementUnavailable }}
	response.WriteHeader(http.StatusOK)
	if written, err := response.Write([]byte("{")); err == nil || written != 0 || target.Body.Len() != 0 ||
		response.started {
		t.Fatalf("write without admission = %d, %v; target %q", written, err, target.Body)
	}
}

// Over a real connection the stream outlives the browser's request
// timeout. Handle's read deadline cancelling it (review H1) is a race the
// context's own timer usually wins, so this guards the stream, not the race.
func TestBrowserManagementExportOutlivesRequestTimeout(t *testing.T) {
	t.Parallel()
	browser, fixture := newBrowserManagementFixture(t)
	browser.management.timeout = 100 * time.Millisecond
	fixture.kubernetesClusters.exportNamespace = "mt-kube-k1"
	fixture.kubernetesClusters.exportRecords = kubecluster.ExportPageSize
	fixture.kubernetesClusters.exportPages = 3
	fixture.kubernetesClusters.exportPageDelay = 150 * time.Millisecond
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if err := browser.Handle(response, request); err != nil {
			http.Error(response, err.Error(), http.StatusBadGateway)
		}
	}))
	server.StartTLS()
	t.Cleanup(server.Close)
	model := browserManagementReadRequest(t, kubernetesClustersTestPath("/"+kubernetesTestCluster+
		"/operation-exports?from=2026-10-29T00:00:00Z&to=2026-10-30T00:00:00Z"))
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+model.URL.RequestURI(), nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header, request.Host = model.Header.Clone(), model.Host
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	var file struct {
		Records  []json.RawMessage `json:"records"`
		Complete bool              `json:"complete"`
	}
	if err != nil || response.StatusCode != http.StatusOK || json.Unmarshal(body, &file) != nil ||
		len(file.Records) != 3*kubecluster.ExportPageSize || !file.Complete {
		t.Fatalf("export = %d, %v, %d records; tail %q", response.StatusCode, err, len(file.Records),
			body[max(0, len(body)-80):])
	}
}

// A streamed 200 with a header a browser answer never carries, or without
// a session, sends nothing (review M2, L2).
func TestBrowserManagementAdmitStreamRefuses(t *testing.T) {
	t.Parallel()
	browser, _ := newBrowserManagementFixture(t)
	for name, test := range map[string]struct {
		header    http.Header
		admission *browserManagementAdmission
	}{
		"a cookie":   {http.Header{"Set-Cookie": {"x=1"}}, &browserManagementAdmission{browser: browser, hasSession: true}},
		"a length":   {http.Header{"Content-Length": {"1"}}, &browserManagementAdmission{browser: browser, hasSession: true}},
		"no session": {http.Header{"Content-Type": {"application/json"}}, &browserManagementAdmission{browser: browser}},
	} {
		target := newLoginHTTPRecorder()
		if err := browser.admitStream(t.Context(), target, test.header, test.admission); err == nil ||
			len(target.Header()) != 0 || target.Body.Len() != 0 {
			t.Errorf("%s: admitted %v, header %v", name, err, target.Header())
		}
	}
}
