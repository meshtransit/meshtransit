package httpapi

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/identity"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/node"
)

const (
	kubernetesTestCluster = "01890f00-0000-7000-8000-000000000b01"
	kubernetesTestKey     = "01890f00-0000-7000-8000-000000000b02"
	kubernetesTestRequest = "01890f00-0000-7000-8000-000000000b03"
)

func kubernetesClustersTestPath(rest string) string {
	return "/api/v1/workspaces/" + managementWorkspaceID() + "/networks/" + networkMemberTestNetwork +
		"/kubernetes-clusters" + rest
}

type kubernetesClusterStub struct {
	readOnly  bool
	calls     []string
	creations []kubecluster.Creation
	deletions []kubecluster.Deletion
	keys      []kubecluster.KeyRequest
	decisions []kubecluster.Decision
	codes     []string
	failure   error
}

func kubernetesTestClusterValue(t testing.TB) kubecluster.Cluster {
	id, _ := kubecluster.ParseID(kubernetesTestCluster)
	creator, _ := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000011")
	created := time.Date(2026, time.October, 25, 8, 0, 0, 0, time.UTC)
	cluster, err := kubecluster.NewCluster(kubecluster.ClusterParams{
		ID: id, Name: "prod", Description: "EKS Singapore", State: kubecluster.StateActive, Version: 3,
		Replicas: 1, CreatedBy: creator, CreatedAt: created, UpdatedAt: created,
	})
	if err != nil {
		t.Fatalf("NewCluster() error = %v", err)
	}
	return cluster
}

func kubernetesTestKeyValue(t testing.TB, state kubecluster.KeyState) kubecluster.JoinKey {
	id, _ := enrollment.ParseCredentialID(kubernetesTestKey)
	issuer, _ := identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000011")
	created := time.Date(2026, time.October, 25, 8, 0, 0, 0, time.UTC)
	params := kubecluster.JoinKeyParams{ID: id, IssuedBy: issuer, CreatedAt: created,
		ExpiresAt: created.Add(time.Hour), Uses: 2, State: state, Version: 1}
	if state == kubecluster.KeyRevoked {
		params.RevokedAt = created.Add(time.Minute)
	}
	key, err := kubecluster.NewJoinKey(params)
	if err != nil {
		t.Fatalf("NewJoinKey() error = %v", err)
	}
	return key
}

func kubernetesTestRequestValue(t testing.TB, state kubecluster.RequestState) kubecluster.ReplicaRequestView {
	id, _ := kubecluster.ParseRequestID(kubernetesTestRequest)
	cluster, _ := kubecluster.ParseID(kubernetesTestCluster)
	key, _ := enrollment.ParseCredentialID(kubernetesTestKey)
	created := time.Date(2026, time.October, 25, 8, 0, 0, 0, time.UTC)
	lifecycle, err := kubecluster.NewRequest(kubecluster.RequestParams{
		State: state, FailedAttempts: 1, CreatedAt: created, ExpiresAt: created.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	params := kubecluster.ReplicaRequestParams{
		ID: id, ClusterID: cluster, KeyID: key, MachineFingerprint: strings.Repeat("a", 64),
		NodeFingerprint: strings.Repeat("b", 64), Hostname: "meshgw-0",
		Reported: []byte(`{"pod":"meshgw-0"}`), Lifecycle: lifecycle, Version: 2, UpdatedAt: created,
	}
	if state == kubecluster.RequestApproved {
		params.ApprovedBy, _ = identity.ParsePrincipalID("01890f00-0000-7000-8000-000000000011")
		params.ApprovedAt, params.CompletionDeadline = created, created.Add(15*time.Minute)
		params.ReservedOrdinal, params.ReservedHostname = 0, "prod-0"
	}
	view, err := kubecluster.NewReplicaRequestView(params)
	if err != nil {
		t.Fatalf("NewReplicaRequestView() error = %v", err)
	}
	return view
}

func (stub *kubernetesClusterStub) Create(_ context.Context, creation kubecluster.Creation) (kubecluster.Cluster,
	error) {
	stub.calls, stub.creations = append(stub.calls, "create"), append(stub.creations, creation)
	if stub.failure != nil {
		return kubecluster.Cluster{}, stub.failure
	}
	return kubernetesTestClusterValue(&testing.T{}), nil
}

func (stub *kubernetesClusterStub) Delete(_ context.Context, deletion kubecluster.Deletion) (kubecluster.Cluster,
	error) {
	stub.calls, stub.deletions = append(stub.calls, "delete"), append(stub.deletions, deletion)
	if stub.failure != nil {
		return kubecluster.Cluster{}, stub.failure
	}
	return kubernetesTestClusterValue(&testing.T{}), nil
}

func (stub *kubernetesClusterStub) List(context.Context, accountsession.Session,
	network.Scope) ([]kubecluster.Cluster, error) {
	stub.calls = append(stub.calls, "list")
	if stub.failure != nil {
		return nil, stub.failure
	}
	return []kubecluster.Cluster{kubernetesTestClusterValue(&testing.T{})}, nil
}

func (stub *kubernetesClusterStub) Read(context.Context, accountsession.Session, network.Scope,
	kubecluster.ID) (kubecluster.Detail, error) {
	stub.calls = append(stub.calls, "read")
	if stub.failure != nil {
		return kubecluster.Detail{}, stub.failure
	}
	if stub.readOnly {
		return kubecluster.Detail{Cluster: kubernetesTestClusterValue(&testing.T{}), Replicas: []kubecluster.Replica{}}, nil
	}
	return kubecluster.Detail{
		Cluster:  kubernetesTestClusterValue(&testing.T{}),
		Replicas: []kubecluster.Replica{},
		Keys:     []kubecluster.JoinKey{kubernetesTestKeyValue(&testing.T{}, kubecluster.KeyActive)},
		Requests: []kubecluster.ReplicaRequestView{kubernetesTestRequestValue(&testing.T{}, kubecluster.RequestPending)},
		KeyWarnings: &kubecluster.KeyWarnings{Devices: []kubecluster.KeyWarning{{
			DeviceID: kubernetesTestDevice(), Hostname: "prod-0", Last24h: 1, Last7Days: 3,
			LastAt:     time.Date(2026, time.October, 26, 9, 0, 0, 0, time.UTC),
			LastReason: kubecluster.KeyEventRetiredMachineKey, KeyState: kubecluster.ReportedKeyRotated,
		}}},
	}, nil
}

func (stub *kubernetesClusterStub) IssueJoinKey(_ context.Context,
	request kubecluster.KeyRequest) (kubecluster.IssuedJoinKey, error) {
	stub.calls, stub.keys = append(stub.calls, "issue"), append(stub.keys, request)
	if stub.failure != nil {
		return kubecluster.IssuedJoinKey{}, stub.failure
	}
	var secret [32]byte
	for index := range secret {
		secret[index] = byte(index)
	}
	token, _ := enrollment.NewCredentialToken(secret)
	key := kubernetesTestKeyValue(&testing.T{}, kubecluster.KeyActive)
	presentation, _ := enrollment.NewJoinKeyPresentation(key.ID(), token)
	return kubecluster.IssuedJoinKey{Key: key, Presentation: presentation}, nil
}

func (stub *kubernetesClusterStub) RevokeJoinKey(context.Context, kubecluster.KeyRevocation) (kubecluster.JoinKey,
	error) {
	stub.calls = append(stub.calls, "revoke")
	if stub.failure != nil {
		return kubecluster.JoinKey{}, stub.failure
	}
	return kubernetesTestKeyValue(&testing.T{}, kubecluster.KeyRevoked), nil
}

func (stub *kubernetesClusterStub) Approve(_ context.Context, decision kubecluster.Decision,
	typed string) (kubecluster.ReplicaRequestView, error) {
	stub.calls, stub.decisions, stub.codes = append(stub.calls, "approve"), append(stub.decisions, decision),
		append(stub.codes, typed)
	if stub.failure != nil {
		return kubecluster.ReplicaRequestView{}, stub.failure
	}
	return kubernetesTestRequestValue(&testing.T{}, kubecluster.RequestApproved), nil
}

func (stub *kubernetesClusterStub) Reject(_ context.Context,
	decision kubecluster.Decision) (kubecluster.ReplicaRequestView, error) {
	stub.calls, stub.decisions = append(stub.calls, "reject"), append(stub.decisions, decision)
	if stub.failure != nil {
		return kubecluster.ReplicaRequestView{}, stub.failure
	}
	return kubernetesTestRequestValue(&testing.T{}, kubecluster.RequestRejected), nil
}

func TestParseKubernetesClusterPath(t *testing.T) {
	t.Parallel()
	cluster := "/" + kubernetesTestCluster
	for _, test := range []struct {
		method, path string
		valid        bool
		operation    string
	}{
		{http.MethodGet, kubernetesClustersTestPath(""), true, kubernetesClusterListOperation},
		{http.MethodPost, kubernetesClustersTestPath(""), true, kubernetesClusterCreateOperation},
		{http.MethodGet, kubernetesClustersTestPath(cluster), true, kubernetesClusterReadOperation},
		{http.MethodDelete, kubernetesClustersTestPath(cluster), true, kubernetesClusterDeleteOperation},
		{http.MethodGet, kubernetesClustersTestPath(cluster + "/join-keys"), true, kubernetesJoinKeyListOperation},
		{http.MethodPost, kubernetesClustersTestPath(cluster + "/join-keys"), true, kubernetesJoinKeyIssueOperation},
		{http.MethodGet, kubernetesClustersTestPath(cluster + "/join-keys/" + kubernetesTestKey), true,
			kubernetesJoinKeyReadOperation},
		{http.MethodPost, kubernetesClustersTestPath(cluster + "/join-keys/" + kubernetesTestKey + "/actions/revoke"),
			true, kubernetesJoinKeyRevokeOperation},
		{http.MethodGet, kubernetesClustersTestPath(cluster + "/replica-requests"), true,
			kubernetesRequestListOperation},
		{http.MethodGet, kubernetesClustersTestPath(cluster + "/replica-requests/" + kubernetesTestRequest), true,
			kubernetesRequestReadOperation},
		{http.MethodPost, kubernetesClustersTestPath(cluster + "/replica-requests/" + kubernetesTestRequest +
			"/actions/approve"), true, kubernetesRequestApproveOperation},
		{http.MethodPost, kubernetesClustersTestPath(cluster + "/replica-requests/" + kubernetesTestRequest +
			"/actions/reject"), true, kubernetesRequestRejectOperation},
		{http.MethodGet, kubernetesClustersTestPath("?name=prod"), false, ""},
		{http.MethodPost, kubernetesClustersTestPath(cluster + "/replica-requests/" + kubernetesTestRequest +
			"/actions/delete"), false, ""},
		{http.MethodGet, kubernetesClustersTestPath("/" + strings.ToUpper(kubernetesTestCluster)), false, ""},
		{http.MethodGet, kubernetesClustersTestPath(cluster + "/replicas"), false, ""},
	} {
		request := httptest.NewRequestWithContext(t.Context(), test.method, test.path, nil)
		path, ok := parseKubernetesClusterPath(request)
		if ok != test.valid {
			t.Errorf("%s %s: matched = %t, want %t", test.method, test.path, ok, test.valid)
			continue
		}
		if ok && (path.operation != test.operation || !isKubernetesClusterOperation(request)) {
			t.Errorf("%s %s: operation %q, want %q", test.method, test.path, path.operation, test.operation)
		}
	}
	if isKubernetesClusterOperation(httptest.NewRequestWithContext(t.Context(), http.MethodPatch,
		kubernetesClustersTestPath("/"+kubernetesTestCluster), nil)) {
		t.Error("PATCH on a cluster was admitted")
	}
	if !isKubernetesClusterRead(httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		kubernetesClustersTestPath(""), nil)) || isKubernetesClusterRead(httptest.NewRequestWithContext(t.Context(),
		http.MethodPost, kubernetesClustersTestPath(""), nil)) {
		t.Error("isKubernetesClusterRead admits the wrong requests")
	}
}

func TestKubernetesClusterHTTPBoundary(t *testing.T) {
	t.Parallel()
	cluster := "/" + kubernetesTestCluster
	request := cluster + "/replica-requests/" + kubernetesTestRequest
	secret := base64.RawURLEncoding.EncodeToString([]byte{
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
		30, 31})
	for _, test := range []struct {
		name, method, path, body string
		ifMatch                  string
		failure                  error
		status                   int
		call                     string
		want, absent             string
	}{
		{"list", http.MethodGet, "", "", "", nil, 200, "list", `"name":"prod"`, ""},
		{"create", http.MethodPost, "", `{"name":"prod","description":"EKS Singapore"}`, "", nil, 201, "create",
			`"cluster_id":"` + kubernetesTestCluster + `"`, ""},
		{"create upper case", http.MethodPost, "", `{"name":"Prod"}`, "", nil, 400, "", "invalid_request", ""},
		{"create unknown field", http.MethodPost, "", `{"name":"prod","replicas":2}`, "", nil, 400, "",
			"invalid_request", ""},
		{"create taken", http.MethodPost, "", `{"name":"prod"}`, "", kubecluster.ErrConflict, 409, "create",
			"kubernetes_cluster_conflict", ""},
		{"create forbidden", http.MethodPost, "", `{"name":"prod"}`, "", kubecluster.ErrForbidden, 403, "create",
			"permission_denied", ""},
		{"read", http.MethodGet, cluster, "", "", nil, 200, "read", `"replica_requests":[{`, ""},
		{"read unknown", http.MethodGet, cluster, "", "", kubecluster.ErrNotFound, 404, "read",
			"kubernetes_cluster_not_found", ""},
		{"delete", http.MethodDelete, cluster, "", `"3"`, nil, 200, "delete", `"name":"prod"`, ""},
		{"delete with replicas", http.MethodDelete, cluster, "", `"3"`, kubecluster.ErrConflict, 409, "delete",
			"kubernetes_cluster_conflict", ""},
		{"issue", http.MethodPost, cluster + "/join-keys", `{"uses":2}`, "", nil, 201, "issue",
			`"secret":"mtk1.` + kubernetesTestKey + `.` + secret + `"`, ""},
		{"issue an hour", http.MethodPost, cluster + "/join-keys", `{"uses":1,"key_lifetime_seconds":3600}`, "", nil,
			201, "issue", `"uses":2`, ""},
		{"issue no uses", http.MethodPost, cluster + "/join-keys", `{}`, "", nil, 400, "", "invalid_request", ""},
		{"issue too long", http.MethodPost, cluster + "/join-keys", `{"uses":1,"key_lifetime_seconds":3601}`, "",
			nil, 400, "", "invalid_request", ""},
		{"list keys", http.MethodGet, cluster + "/join-keys", "", "", nil, 200, "read", `"join_keys":[{`, secret},
		{"read a key", http.MethodGet, cluster + "/join-keys/" + kubernetesTestKey, "", "", nil, 200, "read",
			`"key_id":"` + kubernetesTestKey + `"`, secret},
		{"revoke", http.MethodPost, cluster + "/join-keys/" + kubernetesTestKey + "/actions/revoke", `{}`, "", nil,
			200, "revoke", `"state":"revoked"`, ""},
		{"list requests", http.MethodGet, cluster + "/replica-requests", "", "", nil, 200, "read",
			`"reported_by_pod":{"pod":"meshgw-0"}`, ""},
		{"read a request", http.MethodGet, request, "", "", nil, 200, "read",
			`"machine_key_fingerprint":"` + strings.Repeat("a", 64) + `"`, ""},
		{"approve", http.MethodPost, request + "/actions/approve", `{"code":"4KH7I-REC2B"}`, "", nil, 200,
			"approve", `"reserved_name":"prod-0"`, ""},
		{"approve without a code", http.MethodPost, request + "/actions/approve", `{}`, "", nil, 400, "",
			"invalid_request", ""},
		{"approve a malformed code", http.MethodPost, request + "/actions/approve", `{"code":"x"}`, "",
			kubecluster.ErrInvalid, 400, "approve", "invalid_request", ""},
		{"approve a wrong code", http.MethodPost, request + "/actions/approve", `{"code":"AAAAA-AAAAA"}`, "",
			&kubecluster.WrongCodeError{Remaining: 3}, 422, "approve", `"remaining_attempts":3`, ""},
		{"approve the last wrong code", http.MethodPost, request + "/actions/approve", `{"code":"AAAAA-AAAAA"}`, "",
			&kubecluster.WrongCodeError{Remaining: 0}, 409, "approve", "replica_request_cancelled", ""},
		{"approve a decided request", http.MethodPost, request + "/actions/approve", `{"code":"AAAAA-AAAAA"}`, "",
			kubecluster.ErrNotWaiting, 409, "approve", "replica_request_not_waiting", ""},
		{"approve through a spent key", http.MethodPost, request + "/actions/approve", `{"code":"AAAAA-AAAAA"}`, "",
			kubecluster.ErrKeyNotUsable, 409, "approve", "join_key_not_usable", ""},
		{"reject", http.MethodPost, request + "/actions/reject", `{}`, "", nil, 200, "reject",
			`"state":"rejected"`, ""},
		{"reject with a body", http.MethodPost, request + "/actions/reject", `{"why":"x"}`, "", nil, 400, "",
			"invalid_request", ""},
		{"wrong method", http.MethodPut, cluster, "", "", nil, 405, "", "method_not_allowed", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := validManagementHandlerOptions(t)
			stub := &kubernetesClusterStub{failure: test.failure}
			options.KubernetesClusters = stub
			handler, err := NewManagementHandler(options)
			if err != nil {
				t.Fatal(err)
			}
			httpRequest := newManagementRequest(t, test.method, kubernetesClustersTestPath(test.path), test.body)
			httpRequest.Header.Del("If-Match")
			if test.ifMatch != "" {
				httpRequest.Header.Set("If-Match", test.ifMatch)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httpRequest)
			body := response.Body.String()
			called := strings.Join(stub.calls, ",")
			if response.Code != test.status || called != test.call || !strings.Contains(body, test.want) ||
				test.absent != "" && strings.Contains(body, test.absent) {
				t.Fatalf("status %d, calls %q; want %d, %q; %s", response.Code, called, test.status, test.call, body)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("a Kubernetes cluster response may be cached")
			}
		})
	}
}

// The handler passes what the person typed to the service, which parses
// it; delete passes the If-Match version.
func TestKubernetesClusterHandlerPassesInputs(t *testing.T) {
	t.Parallel()
	options := validManagementHandlerOptions(t)
	stub := &kubernetesClusterStub{}
	options.KubernetesClusters = stub
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	approve := newManagementRequest(t, http.MethodPost, kubernetesClustersTestPath("/"+kubernetesTestCluster+
		"/replica-requests/"+kubernetesTestRequest+"/actions/approve"), `{"code":"4kh7i rec2b"}`)
	approve.Header.Del("If-Match")
	handler.ServeHTTP(httptest.NewRecorder(), approve)
	remove := newManagementRequest(t, http.MethodDelete, kubernetesClustersTestPath("/"+kubernetesTestCluster), "")
	remove.Header.Set("If-Match", `"7"`)
	handler.ServeHTTP(httptest.NewRecorder(), remove)
	if len(stub.codes) != 1 || stub.codes[0] != "4kh7i rec2b" ||
		stub.decisions[0].RequestID.String() != kubernetesTestRequest ||
		len(stub.deletions) != 1 || stub.deletions[0].ExpectedVersion != 7 {
		t.Fatalf("codes %v, decisions %+v, deletions %+v", stub.codes, stub.decisions, stub.deletions)
	}
}

func TestKubernetesClustersUnavailableWithoutManager(t *testing.T) {
	t.Parallel()
	handler, err := NewManagementHandler(validManagementHandlerOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	request := newManagementRequest(t, http.MethodGet, kubernetesClustersTestPath(""), "")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d; %s", response.Code, response.Body)
	}
}

func TestClassifyKubernetesClusterError(t *testing.T) {
	t.Parallel()
	for err, code := range map[error]string{
		kubecluster.ErrForbidden:                  "permission_denied",
		kubecluster.ErrNotFound:                   "kubernetes_cluster_not_found",
		kubecluster.ErrConflict:                   "kubernetes_cluster_conflict",
		kubecluster.ErrLimitReached:               "kubernetes_cluster_limit",
		kubecluster.ErrNotWaiting:                 "replica_request_not_waiting",
		kubecluster.ErrKeyNotUsable:               "join_key_not_usable",
		&kubecluster.WrongCodeError{Remaining: 2}: "join_code_wrong",
		&kubecluster.WrongCodeError{Remaining: 0}: "replica_request_cancelled",
		kubecluster.ErrInvalid:                    "invalid_request",
		errors.New("database is down"):            "temporarily_unavailable",
	} {
		if got := classifyKubernetesClusterError(err).Code; got != code {
			t.Errorf("%v: code = %q, want %q", err, got, code)
		}
	}
}

// A caller who may only read the Network sees the cluster and its replicas,
// and is refused its keys and requests alike, listed or one by one.
func TestKubernetesClusterReadOnlyCaller(t *testing.T) {
	t.Parallel()
	cluster := "/" + kubernetesTestCluster
	for path, status := range map[string]int{
		cluster:                200,
		cluster + "/join-keys": 403,
		cluster + "/join-keys/" + kubernetesTestKey:            403,
		cluster + "/replica-requests":                          403,
		cluster + "/replica-requests/" + kubernetesTestRequest: 403,
	} {
		options := validManagementHandlerOptions(t)
		options.KubernetesClusters = &kubernetesClusterStub{readOnly: true}
		handler, err := NewManagementHandler(options)
		if err != nil {
			t.Fatal(err)
		}
		request := newManagementRequest(t, http.MethodGet, kubernetesClustersTestPath(path), "")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != status {
			t.Errorf("GET %s = %d, want %d; %s", path, response.Code, status, response.Body)
		}
		if status == 200 && (!strings.Contains(response.Body.String(), `"join_keys":null`) ||
			!strings.Contains(response.Body.String(), `"key_warnings":null`)) {
			t.Errorf("GET %s showed keys to a reader: %s", path, response.Body)
		}
	}
}

// A wrong method names the methods the path takes; delete needs If-Match.
func TestKubernetesClusterMethodsAndPreconditions(t *testing.T) {
	t.Parallel()
	cluster := "/" + kubernetesTestCluster
	for path, allow := range map[string]string{
		"":                     "GET, POST",
		cluster:                "GET, DELETE",
		cluster + "/join-keys": "GET, POST",
		cluster + "/replica-requests/" + kubernetesTestRequest + "/actions/approve": "POST",
	} {
		options := validManagementHandlerOptions(t)
		options.KubernetesClusters = &kubernetesClusterStub{}
		handler, err := NewManagementHandler(options)
		if err != nil {
			t.Fatal(err)
		}
		request := newManagementRequest(t, http.MethodPut, kubernetesClustersTestPath(path), "{}")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != allow {
			t.Errorf("PUT %q = %d, Allow %q; want 405, %q", path, response.Code, response.Header().Get("Allow"), allow)
		}
	}
	options := validManagementHandlerOptions(t)
	stub := &kubernetesClusterStub{}
	options.KubernetesClusters = stub
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	request := newManagementRequest(t, http.MethodDelete, kubernetesClustersTestPath(cluster), "")
	request.Header.Del("If-Match")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusPreconditionRequired || len(stub.calls) != 0 {
		t.Fatalf("delete without If-Match = %d, calls %v", response.Code, stub.calls)
	}
}

func kubernetesTestDevice() node.ID {
	id, _ := node.ParseID("01890f00-0000-7000-8000-000000000b04")
	return id
}

// An administrator's read sums the gateways' key warnings.
func TestKubernetesClusterReadShowsKeyWarnings(t *testing.T) {
	t.Parallel()
	options := validManagementHandlerOptions(t)
	options.KubernetesClusters = &kubernetesClusterStub{}
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, newManagementRequest(t, http.MethodGet,
		kubernetesClustersTestPath("/"+kubernetesTestCluster), ""))
	want := `"key_warnings":{"devices":[{"device_id":"01890f00-0000-7000-8000-000000000b04","hostname":"prod-0",` +
		`"count_24h":1,"count_7d":3,"last_at":"2026-10-26T09:00:00Z","last_reason":"retired_machine_key",` +
		`"key_state":"rotated"}],"truncated":false}`
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), want) {
		t.Fatalf("read = %d; %s", response.Code, response.Body)
	}
}
