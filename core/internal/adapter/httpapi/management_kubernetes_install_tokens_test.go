package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"meshtransit.net/core/internal/domain/enrollment"
	"meshtransit.net/core/internal/domain/identity/accountsession"
	"meshtransit.net/core/internal/domain/kubecluster"
	"meshtransit.net/core/internal/domain/network"
	"meshtransit.net/core/internal/domain/publicid"
)

// kubernetesTrustStub is the cluster stub with the V1-12 trust manager.
type kubernetesTrustStub struct {
	*kubernetesClusterStub
	t        testing.TB
	err      error
	modes    []kubecluster.TrustModeChange
	tokens   []kubecluster.InstallTokenRequest
	confirms []kubecluster.TrustDecision
	chooses  []kubecluster.TrustDecision
	resets   []kubecluster.TrustReset
}

func (stub *kubernetesTrustStub) ReadClusterTrust(context.Context, accountsession.Session, network.Scope,
	kubecluster.ID) (kubecluster.ClusterTrustView, error) {
	if stub.err != nil {
		return kubecluster.ClusterTrustView{}, stub.err
	}
	trustID, err := publicid.Parse(kubernetesTestKey)
	if err != nil {
		stub.t.Fatal(err)
	}
	side := kubecluster.TrustSide{Digest: [32]byte{0x89}, Issuer: "https://kubernetes.default.svc.cluster.local",
		Namespace: "mt-kube", ServiceAccount: "meshgw", StatefulSet: "meshgw", KeyThumbprints: [][32]byte{{1}}}
	other := side
	other.Digest = [32]byte{0x42}
	return kubecluster.ClusterTrustView{ClusterVersion: 7, Mode: kubecluster.TrustModePrivateTOFU, CanManage: true,
		Trust: &kubecluster.ClusterTrustRead{ID: trustID, Version: 7, Source: kubecluster.TrustFromInstallToken,
			State: kubecluster.TrustContested, Side: side, SetAt: time.Date(2026, 11, 22, 1, 0, 0, 0, time.UTC),
			Contested: &other, ContestedAt: time.Date(2026, 11, 22, 2, 0, 0, 0, time.UTC)},
		Tokens: []kubecluster.InstallTokenState{{KeyID: kubernetesTestKeyValue(stub.t, kubecluster.KeyActive).ID(),
			State: "revoked", Replicas: 2, UsedOrdinals: []int{0}, CreatedBy: trustID,
			CreatedAt: time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC),
			ExpiresAt: time.Date(2026, 11, 22, 1, 0, 0, 0, time.UTC)}}}, nil
}

func (stub *kubernetesTrustStub) SetClusterTrustMode(_ context.Context,
	change kubecluster.TrustModeChange) (kubecluster.TrustModeResult, error) {
	stub.modes = append(stub.modes, change)
	if stub.err != nil {
		return kubecluster.TrustModeResult{}, stub.err
	}
	return kubecluster.TrustModeResult{Cluster: kubernetesTestClusterValue(stub.t), Mode: change.Mode, Changed: true,
		RevokedTokens: 1}, nil
}

func (stub *kubernetesTrustStub) IssueInstallToken(_ context.Context,
	request kubecluster.InstallTokenRequest) (kubecluster.IssuedInstallToken, error) {
	stub.tokens = append(stub.tokens, request)
	if stub.err != nil {
		return kubecluster.IssuedInstallToken{}, stub.err
	}
	key := kubernetesTestKeyValue(stub.t, kubecluster.KeyActive)
	token, err := enrollment.NewCredentialToken([32]byte{9})
	if err != nil {
		stub.t.Fatal(err)
	}
	presentation, err := enrollment.NewJoinKeyPresentation(key.ID(), token)
	if err != nil {
		stub.t.Fatal(err)
	}
	return kubecluster.IssuedInstallToken{Key: key, Replicas: request.Replicas, Presentation: presentation}, nil
}

func (stub *kubernetesTrustStub) decided() (kubecluster.TrustDecisionResult, error) {
	if stub.err != nil {
		return kubecluster.TrustDecisionResult{}, stub.err
	}
	device, err := publicid.Parse(kubernetesTestKey)
	if err != nil {
		stub.t.Fatal(err)
	}
	return kubecluster.TrustDecisionResult{Cluster: kubernetesTestClusterValue(stub.t), Changed: true,
		ResumedDevices: []publicid.ID{device}}, nil
}

func (stub *kubernetesTrustStub) ConfirmClusterTrust(_ context.Context,
	decision kubecluster.TrustDecision) (kubecluster.TrustDecisionResult, error) {
	stub.confirms = append(stub.confirms, decision)
	return stub.decided()
}

func (stub *kubernetesTrustStub) ChooseClusterTrust(_ context.Context,
	decision kubecluster.TrustDecision) (kubecluster.TrustDecisionResult, error) {
	stub.chooses = append(stub.chooses, decision)
	return stub.decided()
}

func (stub *kubernetesTrustStub) ResetClusterTrust(_ context.Context,
	reset kubecluster.TrustReset) (kubecluster.TrustDecisionResult, error) {
	stub.resets = append(stub.resets, reset)
	return stub.decided()
}

func serveKubernetesTrustRequest(t *testing.T, manager KubernetesClusterManager, method, rest, ifMatch,
	body string) *httptest.ResponseRecorder {
	t.Helper()
	options := validManagementHandlerOptions(t)
	options.KubernetesClusters = manager
	handler, err := NewManagementHandler(options)
	if err != nil {
		t.Fatal(err)
	}
	request := newManagementRequest(t, method, kubernetesClustersTestPath("/"+kubernetesTestCluster+rest), body)
	request.Header.Del("If-Match")
	if ifMatch != "" {
		request.Header.Set("If-Match", ifMatch)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

const testTrustDigest = "8981fcf3aa7c75f6496a5df0e760ebf1298e0e98ffb196b7563c7cb748429ed2"

func TestParseKubernetesTrustPaths(t *testing.T) {
	t.Parallel()
	for rest, want := range map[string]string{
		"/trust":                          kubernetesTrustReadOperation,
		"/trust-mode":                     kubernetesTrustModeOperation,
		"/install-tokens":                 kubernetesInstallTokenOperation,
		"/signing-trust/actions/confirm":  kubernetesTrustConfirmOperation,
		"/signing-trust/actions/choose":   kubernetesTrustChooseOperation,
		"/signing-trust/actions/reset":    kubernetesTrustResetOperation,
		"/signing-trust/actions/approve":  "",
		"/signing-trust/actions":          "",
		"/install-tokens/extra":           "",
		"/trust-mode/actions/set":         "",
		"/signing-trust/actions/confirm/": "",
	} {
		method := http.MethodPost
		switch want {
		case kubernetesTrustModeOperation:
			method = http.MethodPut
		case kubernetesTrustReadOperation:
			method = http.MethodGet
		}
		request := httptest.NewRequest(method, kubernetesClustersTestPath("/"+kubernetesTestCluster+rest), nil)
		path, ok := parseKubernetesClusterPath(request)
		if want == "" {
			if ok && path.operation != "" {
				t.Errorf("%s matched %q", rest, path.operation)
			}
			continue
		}
		if !ok || path.operation != want {
			t.Errorf("%s = %q, %t; want %q", rest, path.operation, ok, want)
		}
	}
	put := httptest.NewRequest(http.MethodPut, kubernetesClustersTestPath("/"+kubernetesTestCluster+"/trust-mode"), nil)
	if !isKubernetesTrustModeWrite(put) {
		t.Fatal("the trust mode PUT is not a browser write")
	}
}

func TestKubernetesTrustHandlers(t *testing.T) {
	t.Parallel()
	stub := &kubernetesTrustStub{kubernetesClusterStub: &kubernetesClusterStub{}, t: t}
	read := serveKubernetesTrustRequest(t, stub, http.MethodGet, "/trust", "", "")
	body := read.Body.String()
	if read.Code != http.StatusOK || read.Header().Get("ETag") != `"7"` ||
		!strings.Contains(body, `"state":"contested"`) || !strings.Contains(body, `"source":"install_token"`) ||
		!strings.Contains(body, `"contested":{"digest":"42`) || !strings.Contains(body, `"used_ordinals":[0]`) ||
		!strings.Contains(body, `"trust_mode":"private_tofu"`) {
		t.Fatalf("GET trust = %d %s", read.Code, body)
	}
	response := serveKubernetesTrustRequest(t, stub, http.MethodPut, "/trust-mode", `"3"`,
		`{"trust_mode":"private_tofu"}`)
	if response.Code != http.StatusOK || len(stub.modes) != 1 || stub.modes[0].Version != 3 ||
		stub.modes[0].Mode != kubecluster.TrustModePrivateTOFU || response.Header().Get("ETag") == "" ||
		!strings.Contains(response.Body.String(), `"revoked_tokens":1`) {
		t.Fatalf("PUT trust-mode = %d %s; %+v", response.Code, response.Body, stub.modes)
	}
	response = serveKubernetesTrustRequest(t, stub, http.MethodPost, "/install-tokens", "",
		`{"replicas":3,"lifetime_seconds":7200}`)
	var issued struct {
		Data struct {
			Replicas int    `json:"replicas"`
			Secret   string `json:"secret"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &issued); err != nil || response.Code != http.StatusCreated ||
		issued.Data.Replicas != 3 || !strings.HasPrefix(issued.Data.Secret, "mtk1.") || len(stub.tokens) != 1 ||
		stub.tokens[0].Lifetime != 2*time.Hour {
		t.Fatalf("POST install-tokens = %d %s; %+v", response.Code, response.Body, stub.tokens)
	}
	response = serveKubernetesTrustRequest(t, stub, http.MethodPost, "/install-tokens", "", `{"replicas":2}`)
	if response.Code != http.StatusCreated || stub.tokens[1].Lifetime != kubecluster.DefaultInstallTokenLifetime {
		t.Fatalf("POST install-tokens without a lifetime = %d; %+v", response.Code, stub.tokens)
	}
	for _, action := range []string{"confirm", "choose"} {
		response = serveKubernetesTrustRequest(t, stub, http.MethodPost, "/signing-trust/actions/"+action, `"4"`,
			`{"digest":"`+testTrustDigest+`"}`)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"resumed_device_ids":["`) {
			t.Fatalf("%s = %d %s", action, response.Code, response.Body)
		}
	}
	if len(stub.confirms) != 1 || len(stub.chooses) != 1 || stub.chooses[0].Version != 4 ||
		stub.confirms[0].Digest[0] != 0x89 {
		t.Fatalf("decisions %+v %+v", stub.confirms, stub.chooses)
	}
	response = serveKubernetesTrustRequest(t, stub, http.MethodPost, "/signing-trust/actions/reset", `"5"`,
		`{"reason":"the cluster was rebuilt"}`)
	if response.Code != http.StatusOK || len(stub.resets) != 1 || stub.resets[0].Reason != "the cluster was rebuilt" {
		t.Fatalf("reset = %d %s", response.Code, response.Body)
	}
}

func TestKubernetesTrustHandlerRefusals(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		method, rest, ifMatch, body string
		err                         error
		status                      int
		code                        string
	}{
		"mode without If-Match": {http.MethodPut, "/trust-mode", "", `{"trust_mode":"code"}`, nil,
			http.StatusPreconditionRequired, "precondition_required"},
		"issuer mode later": {http.MethodPut, "/trust-mode", `"1"`, `{"trust_mode":"issuer"}`, nil,
			http.StatusBadRequest, "invalid_request"},
		"six replicas": {http.MethodPost, "/install-tokens", "", `{"replicas":6}`, nil, http.StatusBadRequest,
			"invalid_request"},
		"two days": {http.MethodPost, "/install-tokens", "", `{"replicas":1,"lifetime_seconds":172800}`, nil,
			http.StatusBadRequest, "invalid_request"},
		"tokens off": {http.MethodPost, "/install-tokens", "", `{"replicas":1}`, kubecluster.ErrInstallTokensOff,
			http.StatusConflict, "install_tokens_off"},
		"upper-case digest": {http.MethodPost, "/signing-trust/actions/confirm", `"1"`,
			`{"digest":"` + strings.ToUpper(testTrustDigest) + `"}`, nil, http.StatusBadRequest, "invalid_request"},
		"short digest": {http.MethodPost, "/signing-trust/actions/choose", `"1"`, `{"digest":"8981"}`, nil,
			http.StatusBadRequest, "invalid_request"},
		"contested": {http.MethodPost, "/signing-trust/actions/confirm", `"1"`,
			`{"digest":"` + testTrustDigest + `"}`, kubecluster.ErrTrustContested, http.StatusConflict,
			"kubernetes_trust_contested"},
		"digest mismatch": {http.MethodPost, "/signing-trust/actions/choose", `"1"`,
			`{"digest":"` + testTrustDigest + `"}`, kubecluster.ErrTrustDigest, http.StatusConflict,
			"kubernetes_trust_digest_mismatch"},
		"padded reason": {http.MethodPost, "/signing-trust/actions/reset", `"1"`, `{"reason":" x"}`, nil,
			http.StatusBadRequest, "invalid_request"},
		"no trust": {http.MethodPost, "/signing-trust/actions/reset", `"1"`, `{"reason":"x"}`,
			kubecluster.ErrNoInstallTokenTrust, http.StatusConflict, "no_install_token_trust"},
		"stale version": {http.MethodPost, "/signing-trust/actions/reset", `"1"`, `{"reason":"x"}`,
			kubecluster.ErrConflict, http.StatusConflict, "kubernetes_cluster_conflict"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			stub := &kubernetesTrustStub{kubernetesClusterStub: &kubernetesClusterStub{}, t: t, err: test.err}
			response := serveKubernetesTrustRequest(t, stub, test.method, test.rest, test.ifMatch, test.body)
			var failure struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &failure); err != nil || response.Code != test.status ||
				failure.Error.Code != test.code {
				t.Fatalf("%s %s = %d %s, want %d %s", test.method, test.rest, response.Code, response.Body,
					test.status, test.code)
			}
			if test.err == nil && len(stub.modes)+len(stub.tokens)+len(stub.confirms)+len(stub.chooses)+
				len(stub.resets) != 0 {
				t.Fatal("a refused request reached the manager")
			}
		})
	}
	// A cluster manager without the trust manager answers 503.
	response := serveKubernetesTrustRequest(t, &kubernetesClusterStub{}, http.MethodPost, "/install-tokens", "",
		`{"replicas":1}`)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("without a trust manager = %d %s", response.Code, response.Body)
	}
}
