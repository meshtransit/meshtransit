package kubeproxy

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"meshtransit.net/shared/kubeprofile"
)

// rulesAnswer is the fake API server's SelfSubjectRulesReview: what the
// group's RBAC allows in team-a.
const rulesAnswer = `{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview",
"metadata":{},"spec":{"namespace":"team-a"},"status":{
"resourceRules":[
 {"verbs":["get","list","delete"],"apiGroups":[""],"resources":["pods"]},
 {"verbs":["get","update"],"apiGroups":["apps"],"resources":["deployments"],"resourceNames":["web"]},
 {"verbs":["*"],"apiGroups":["*"],"resources":["*"]},
 {"verbs":["get"],"apiGroups":[""],"resources":["secrets"]},
 {"verbs":["create"],"apiGroups":["authorization.k8s.io"],"resources":["selfsubjectaccessreviews"]}],
"nonResourceRules":[{"verbs":["get"],"nonResourceURLs":["/api","/api/*"]},{"verbs":["get"],"nonResourceURLs":["/healthz"]}],
"incomplete":false}}`

func accessReview(attributes string) string {
	return `{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{` + attributes + `}}`
}

func (f *fixture) post(path, contentType, body string) (*http.Response, string) {
	f.t.Helper()
	request, err := http.NewRequestWithContext(f.t.Context(), http.MethodPost, "https://"+clusterName+path,
		strings.NewReader(body))
	if err != nil {
		f.t.Fatal(err)
	}
	request.Header.Set("Content-Type", contentType)
	response, err := f.client.Do(request)
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	answer, _ := io.ReadAll(response.Body)
	return response, string(answer)
}

func TestDecodeAccessReview(t *testing.T) {
	t.Parallel()
	good, err := decodeAccessReview([]byte(accessReview(
		`"resourceAttributes":{"namespace":"team-a","verb":"get","resource":"pods","unknown":1}`,
	)), "v1")
	if err != nil || good.ResourceAttributes == nil || good.ResourceAttributes.Verb != "get" {
		t.Fatalf("resource review: %+v, %v", good, err)
	}
	path, err := decodeAccessReview([]byte(accessReview(`"nonResourceAttributes":{"path":"/healthz","verb":"get"}`)),
		"v1")
	if err != nil || path.NonResourceAttributes == nil || path.NonResourceAttributes.Path != "/healthz" {
		t.Fatalf("path review: %+v, %v", path, err)
	}
	for name, body := range map[string]string{
		"a key in another case": `{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview",` +
			`"spec":{"resourceAttributes":{"verb":"get","resource":"pods","Namespace":"other"}}}`,
		"spec in another case": `{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview",` +
			`"Spec":{"resourceAttributes":{"verb":"get","resource":"pods"}}}`,
		"both":            accessReview(`"resourceAttributes":{"verb":"get"},"nonResourceAttributes":{"verb":"get"}`),
		"neither":         accessReview(``),
		"field selector":  accessReview(`"resourceAttributes":{"verb":"list","fieldSelector":{"rawSelector":"a=b"}}`),
		"label selector":  accessReview(`"resourceAttributes":{"verb":"list","labelSelector":{"rawSelector":"a"}}`),
		"a number":        accessReview(`"resourceAttributes":{"verb":1}`),
		"another version": strings.Replace(accessReview(`"resourceAttributes":{"verb":"get"}`), "/v1", "/v1beta1", 1),
		"another kind":    strings.Replace(accessReview(`"resourceAttributes":{"verb":"get"}`), "Access", "Rules", 1),
		"not JSON":        `{`,
		"an array":        `[]`,
	} {
		if _, err := decodeAccessReview([]byte(body), "v1"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestProxyAnswersAccessReviewsByTheProfile(t *testing.T) {
	t.Parallel()
	f := profiledFixture(t, nil, enforcing("edit", scopeDeveloper, time.Now().Add(time.Hour)))
	const path = "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews"
	response, body := f.post(path, "application/json",
		accessReview(`"resourceAttributes":{"namespace":"team-a","verb":"delete","resource":"pods"}`))
	var answer struct {
		Status struct {
			Allowed bool   `json:"allowed"`
			Reason  string `json:"reason"`
		} `json:"status"`
	}
	if err := json.Unmarshal([]byte(body), &answer); err != nil || response.StatusCode != http.StatusCreated ||
		answer.Status.Allowed || !strings.Contains(answer.Status.Reason, `profile "developer"`) {
		t.Fatalf("a refused review: %d %s", response.StatusCode, body)
	}
	f.nothingForwarded()
	response, _ = f.post(path, "application/json; charset=utf-8", accessReview(
		`"resourceAttributes":{"namespace":"team-a","verb":"get","resource":"pods","extra":"x"},"other":1`,
	))
	if response.StatusCode != http.StatusCreated && response.StatusCode != http.StatusOK {
		t.Fatalf("an allowed review: %d", response.StatusCode)
	}
	forwarded := f.forwarded()
	if strings.Contains(forwarded.Body, "extra") || strings.Contains(forwarded.Body, "other") ||
		!strings.Contains(forwarded.Body, `"resourceAttributes":{"namespace":"team-a","verb":"get","resource":"pods"}`) {
		t.Fatalf("forwarded body %s", forwarded.Body)
	}
	response, body = f.post(path, "application/vnd.kubernetes.protobuf", "\x6b\x38\x73\x00")
	if response.StatusCode != http.StatusCreated || !strings.Contains(body, reviewUnevaluable) {
		t.Fatalf("a protobuf review: %d %s", response.StatusCode, body)
	}
	f.nothingForwarded()
}

func TestProxyLeavesWholeGroupReviewsAlone(t *testing.T) {
	t.Parallel()
	f := newFixtureAt(t, "", func(options *Options) { options.Discovery = &fakeDiscovery{} })
	body := accessReview(`"resourceAttributes":{"namespace":"team-a","verb":"delete","resource":"pods","extra":"x"}`)
	f.post("/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", "application/json", body)
	if forwarded := f.forwarded(); forwarded.Body != body {
		t.Fatalf("a whole group's review changed: %s", forwarded.Body)
	}
}

func TestProxyNarrowsRulesReviews(t *testing.T) {
	t.Parallel()
	f := profiledFixture(t, nil, enforcing("edit", scopeDeveloper, time.Now().Add(time.Hour)))
	response, body := f.post("/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", "application/json",
		`{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"team-a"}}`)
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("status %d", response.StatusCode)
	}
	forwarded := f.forwarded()
	if forwarded.Header.Get("Accept") != "application/json" {
		t.Fatalf("asked for %q", forwarded.Header.Get("Accept"))
	}
	var answer struct {
		Kind   string      `json:"kind"`
		Status rulesStatus `json:"status"`
	}
	if err := json.Unmarshal([]byte(body), &answer); err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(answer.Status.ResourceRules)
	// pods: get and list, not delete; deployments: get and update by name;
	// wildcards and secrets dropped; self reviews dropped (not in the profile).
	want := `[{"verbs":["get","list"],"apiGroups":[""],"resources":["pods"]},` +
		`{"verbs":["get","update"],"apiGroups":["apps"],"resources":["deployments"],"resourceNames":["web"]}]`
	if answer.Kind != "SelfSubjectRulesReview" || string(got) != want {
		t.Fatalf("rules %s", got)
	}
	if len(answer.Status.NonResourceRules) != 0 || !answer.Status.Incomplete ||
		!strings.Contains(answer.Status.EvaluationError, `Narrowed by MeshTransit access profile "developer"`) {
		t.Fatalf("status %+v", answer.Status)
	}
}

func TestNarrowRulesFailsClosed(t *testing.T) {
	t.Parallel()
	server := &Server{options: Options{CoreNow: time.Now}}
	for _, body := range []string{"", "{", `{"status":[]}`} {
		narrowed := server.narrowRules(t.Context(), []byte(body), true, Peer{}, Group{Name: "edit"})
		var answer struct {
			Status rulesStatus `json:"status"`
		}
		if err := json.Unmarshal(narrowed, &answer); err != nil || len(answer.Status.ResourceRules) != 0 ||
			!answer.Status.Incomplete || !strings.Contains(answer.Status.EvaluationError, reviewUnevaluable) {
			t.Fatalf("%q narrowed to %s", body, narrowed)
		}
	}
}

func TestWhoamiShowsProfiles(t *testing.T) {
	t.Parallel()
	until := time.Now().Add(time.Hour)
	f := profiledFixture(t, nil, enforcing("edit", scopeDeveloper, until),
		reporting("edit", scopeReader, until.Add(-30*time.Minute), until))
	_, body := f.do(http.MethodGet, "/mt/v1/whoami", nil)
	var answer whoamiAnswer
	if err := json.Unmarshal([]byte(body), &answer); err != nil {
		t.Fatal(err)
	}
	if len(answer.Profiles) != 2 || answer.Profiles[0].Profile != "developer" || answer.Profiles[0].Mode != "enforce" ||
		strings.Join(answer.Profiles[0].Namespaces, ",") != "team-a,team-b" || answer.Profiles[1].Mode != "report" ||
		answer.Profiles[1].ReportUntil == nil || answer.DefaultGroup != "edit" {
		t.Fatalf("whoami %s", body)
	}
	_, review := f.post("/apis/authentication.k8s.io/v1/selfsubjectreviews", "application/json",
		`{"apiVersion":"authentication.k8s.io/v1","kind":"SelfSubjectReview"}`)
	if !strings.Contains(review, `"meshtransit.net/profile":["developer","reader"]`) {
		t.Fatalf("self subject review %s", review)
	}
}

// An update needs create too (S3), in a review as in the request it asks
// about (review e4–e6 M1).
func TestReviewsOfUpdateNeedCreate(t *testing.T) {
	t.Parallel()
	f := profiledFixture(t, nil, enforcing("edit", [32]byte{0xd4}, time.Now().Add(time.Hour)))
	peer := *f.peer.Load()
	peer.Scopes[[32]byte{0xd4}] = testScope(t, "updater", []string{"team-a"}, false, []kubeprofile.Rule{{
		APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get", "update"},
	}}, nil)
	f.peer.Store(&peer)
	_, body := f.post("/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", "application/json",
		accessReview(`"resourceAttributes":{"namespace":"team-a","verb":"update","group":"apps","resource":"deployments"}`))
	if !strings.Contains(body, `"allowed":false`) {
		t.Fatalf("an update without create: %s", body)
	}
	f.nothingForwarded()
	_, rules := f.post("/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", "application/json",
		`{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"team-a"}}`)
	f.forwarded()
	if !strings.Contains(rules, `{"verbs":["get"],"apiGroups":["apps"],"resources":["deployments"],"resourceNames":["web"]}`) {
		t.Fatalf("rules kept update without create: %s", rules)
	}
}
