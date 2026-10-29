package httpapi

import (
	"net/http"
	"slices"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
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
