package kubecheck

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// fakeAPI answers GETs from a map of paths to JSON and records POSTs.
type fakeAPI struct {
	objects map[string]string
	posts   []string
}

func (api *fakeAPI) Get(_ context.Context, path string, into any) error {
	// Lists are paged; the fake answers a whole list on its first page.
	path = strings.Replace(strings.Replace(path, "?limit=500", "", 1), "&limit=500", "", 1)
	path = strings.TrimSuffix(path, "?")
	if strings.Contains(path, "&") && !strings.Contains(path, "?") {
		path = strings.Replace(path, "&", "?", 1)
	}
	body, ok := api.objects[path]
	if !ok {
		return &StatusError{Code: http.StatusNotFound, Message: "not found"}
	}
	return json.Unmarshal([]byte(body), into)
}

func (api *fakeAPI) Post(_ context.Context, path string, _ any) error {
	api.posts = append(api.posts, path)
	return nil
}

const healthyStatus = `{"ready":true,"reason":"ready","kube":{"listening":true,"groups":[{"name":"view","enabled":true}]}}`

// healthyInstall is a two-replica install on two nodes with every guard in
// place.
func healthyInstall() (*fakeAPI, Config) {
	const base = "/apis/admissionregistration.k8s.io/v1/"
	api := &fakeAPI{objects: map[string]string{
		"/api/v1/namespaces/mt/pods/meshgw-0": `{"metadata":{"name":"meshgw-0"},"spec":{"nodeName":"a"},` +
			`"status":{"phase":"Running","podIP":"10.0.0.1"}}`,
		"/api/v1/namespaces/mt/pods/meshgw-1": `{"metadata":{"name":"meshgw-1"},"spec":{"nodeName":"b"},` +
			`"status":{"phase":"Running","podIP":"10.0.0.2"}}`,
		base + "validatingadmissionpolicies/token":                                             `{"spec":{"failurePolicy":"Fail"}}`,
		base + "validatingadmissionpolicybindings/token":                                       `{"spec":{"policyName":"token","validationActions":["Deny"]}}`,
		base + "validatingadmissionpolicies/broad":                                             `{"spec":{"failurePolicy":"Fail"}}`,
		base + "validatingadmissionpolicybindings/broad":                                       `{"spec":{"policyName":"broad","validationActions":["Deny"]}}`,
		"/api/v1/namespaces/mt":                                                                `{"metadata":{"labels":{"pod-security.kubernetes.io/enforce":"restricted"}}}`,
		"/api/v1/namespaces/mt/events?fieldSelector=" + url.QueryEscape("reason=FailedCreate"): `{"items":[]}`,
		"/apis/rbac.authorization.k8s.io/v1/clusterroles":                                      `{"items":[]}`,
		"/apis/rbac.authorization.k8s.io/v1/clusterrolebindings":                               `{"items":[]}`,
		"/apis/rbac.authorization.k8s.io/v1/namespaces/mt/roles":                               `{"items":[]}`,
		"/apis/rbac.authorization.k8s.io/v1/namespaces/mt/rolebindings":                        `{"items":[]}`,
	}}
	return api, Config{
		Namespace: "mt", StatefulSet: "meshgw", Replicas: 2, StatusPort: 9090,
		APIAudiences:   []string{"https://kubernetes.default.svc"},
		ServiceAccount: "meshgw", CheckServiceAccount: "meshgw-check",
		Policies: []Policy{
			{Name: "token", Binding: "token", Enforcement: MustDeny},
			{Name: "broad", Binding: "broad", Enforcement: MustDeny},
		},
	}
}

// rehash sets the configuration's fingerprints to the fake's objects, as
// the chart renders them.
func rehash(api *fakeAPI, config *Config) {
	const base = "/apis/admissionregistration.k8s.io/v1/"
	spec := func(path string) map[string]any {
		var object struct {
			Spec map[string]any `json:"spec"`
		}
		_ = json.Unmarshal([]byte(api.objects[path]), &object)
		return object.Spec
	}
	for index, policy := range config.Policies {
		config.Policies[index].PolicyHash, _ = policyHash(spec(base + "validatingadmissionpolicies/" + policy.Name))
		config.Policies[index].BindingHash, _ = bindingHash(spec(base + "validatingadmissionpolicybindings/" +
			policy.Binding))
	}
}

func checkerFor(api *fakeAPI, config Config, statuses map[string]string) Checker {
	rehash(api, &config)
	return Checker{
		Config: config, API: api,
		Status: func(_ context.Context, host string, _ int) (ReplicaStatus, error) {
			body, ok := statuses[host]
			if !ok {
				body = healthyStatus
			}
			var status ReplicaStatus
			return status, json.Unmarshal([]byte(body), &status)
		},
		Audiences: func() ([]string, error) { return []string{"https://kubernetes.default.svc"}, nil },
	}
}

// codes lists the findings, leaving out the note every RBAC pass adds.
func codes(report Report) []string {
	var found []string
	for _, finding := range report.Findings {
		if finding.Code == "rbac_webhooks_unseen" {
			continue
		}
		found = append(found, string(finding.Level)+":"+finding.Code)
	}
	return found
}

// A healthy install reports nothing.
func TestCheckHealthyInstall(t *testing.T) {
	t.Parallel()
	api, config := healthyInstall()
	if report := checkerFor(api, config, nil).Run(t.Context()); len(codes(report)) != 0 || report.Failed() {
		t.Fatalf("findings %v", codes(report))
	}
}

// Each fault is reported at its level, with its code.
func TestCheckFindsFaults(t *testing.T) {
	t.Parallel()
	const base = "/apis/admissionregistration.k8s.io/v1/"
	for name, test := range map[string]struct {
		change   func(*fakeAPI, *Config, map[string]string, *Checker)
		want     string
		failures bool
		edited   bool // the objects changed after the chart rendered them
	}{
		"policy edited in place": {change: func(api *fakeAPI, _ *Config, _ map[string]string, _ *Checker) {
			api.objects[base+"validatingadmissionpolicies/token"] = `{"spec":{"failurePolicy":"Fail",` +
				`"matchConstraints":{"excludeResourceRules":[{"resources":["pods"]}]}}}`
		}, want: "fail:policy_changed", failures: true, edited: true},
		"binding narrowed in place": {change: func(api *fakeAPI, _ *Config, _ map[string]string, _ *Checker) {
			api.objects[base+"validatingadmissionpolicybindings/token"] = `{"spec":{"policyName":"token",` +
				`"validationActions":["Deny"],"matchResources":{"namespaceSelector":{"matchLabels":{"x":"y"}}}}}`
		}, want: "fail:binding_changed", failures: true, edited: true},
		"missing replica": {func(api *fakeAPI, _ *Config, _ map[string]string, _ *Checker) {
			delete(api.objects, "/api/v1/namespaces/mt/pods/meshgw-1")
		}, "fail:replica_missing", true, false},
		"pending replica": {func(api *fakeAPI, _ *Config, _ map[string]string, _ *Checker) {
			api.objects["/api/v1/namespaces/mt/pods/meshgw-1"] = `{"status":{"phase":"Pending","conditions":[` +
				`{"type":"PodScheduled","status":"False","reason":"Unschedulable","message":"untolerated taint"}]}}`
		}, "fail:replica_pending", true, false},
		"not ready": {func(_ *fakeAPI, _ *Config, statuses map[string]string, _ *Checker) {
			statuses["10.0.0.1"] = `{"ready":false,"reason":"no valid certificate","kube":{"listening":true}}`
		}, "fail:replica_not_ready", true, false},
		"not listening": {func(_ *fakeAPI, _ *Config, statuses map[string]string, _ *Checker) {
			statuses["10.0.0.1"] = `{"ready":true,"kube":{"listening":false,"closed_reason":"map"}}`
		}, "fail:replica_not_listening", true, false},
		"group off": {func(_ *fakeAPI, _ *Config, statuses map[string]string, _ *Checker) {
			statuses["10.0.0.2"] = `{"ready":true,"kube":{"listening":true,"groups":[` +
				`{"name":"view","enabled":false,"reason":"may * */*"}]}}`
		}, "fail:group_disabled", true, false},
		"one node": {func(api *fakeAPI, _ *Config, _ map[string]string, _ *Checker) {
			api.objects["/api/v1/namespaces/mt/pods/meshgw-1"] = `{"spec":{"nodeName":"a"},` +
				`"status":{"phase":"Running","podIP":"10.0.0.2"}}`
		}, "warn:replicas_one_node", false, false},
		"policy missing": {func(api *fakeAPI, _ *Config, _ map[string]string, _ *Checker) {
			delete(api.objects, base+"validatingadmissionpolicies/token")
		}, "fail:policy_missing", true, false},
		"policy fails open": {func(api *fakeAPI, _ *Config, _ map[string]string, _ *Checker) {
			api.objects[base+"validatingadmissionpolicies/token"] = `{"spec":{"failurePolicy":"Ignore"}}`
		}, "fail:policy_fails_open", true, false},
		"type warning": {func(api *fakeAPI, _ *Config, _ map[string]string, _ *Checker) {
			api.objects[base+"validatingadmissionpolicies/token"] = `{"spec":{"failurePolicy":"Fail"},` +
				`"status":{"typeChecking":{"expressionWarnings":[{"fieldRef":"spec.validations[0]","warning":"x"}]}}}`
		}, "fail:policy_type_warning", true, false},
		"binding warns where it must deny": {func(api *fakeAPI, _ *Config, _ map[string]string, _ *Checker) {
			api.objects[base+"validatingadmissionpolicybindings/broad"] = `{"spec":{"policyName":"broad","validationActions":["Warn","Audit"]}}`
		}, "fail:policy_not_enforced", true, false},
		"binding warns where it may": {func(api *fakeAPI, config *Config, _ map[string]string, _ *Checker) {
			api.objects[base+"validatingadmissionpolicybindings/broad"] = `{"spec":{"policyName":"broad","validationActions":["Warn"]}}`
			config.Policies[1].Enforcement = ShouldDeny
		}, "warn:policy_not_enforced", false, false},
		"binding of another policy": {func(api *fakeAPI, _ *Config, _ map[string]string, _ *Checker) {
			api.objects[base+"validatingadmissionpolicybindings/broad"] = `{"spec":{"policyName":"other","validationActions":["Deny"]}}`
		}, "fail:binding_wrong_policy", true, false},
		"audience mismatch": {func(_ *fakeAPI, _ *Config, _ map[string]string, checker *Checker) {
			checker.Audiences = func() ([]string, error) { return []string{"https://other"}, nil }
		}, "fail:audience_mismatch", true, false},
		"audiences unknown": {func(_ *fakeAPI, _ *Config, _ map[string]string, checker *Checker) {
			checker.Audiences = func() ([]string, error) { return nil, errors.New("no token") }
		}, "warn:audiences_unknown", false, false},
		"namespace not restricted": {func(api *fakeAPI, _ *Config, _ map[string]string, _ *Checker) {
			api.objects["/api/v1/namespaces/mt"] = `{"metadata":{"labels":{}}}`
		}, "warn:namespace_not_restricted", false, false},
		"failed create": {func(api *fakeAPI, _ *Config, _ map[string]string, _ *Checker) {
			api.objects["/api/v1/namespaces/mt/events?fieldSelector="+url.QueryEscape("reason=FailedCreate")] =
				`{"items":[{"involvedObject":{"kind":"StatefulSet","name":"meshgw"},"message":"denied by policy"},` +
					`{"involvedObject":{"kind":"StatefulSet","name":"meshgw"},"message":"again"}]}`
		}, "warn:failed_create", false, false},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			api, config := healthyInstall()
			statuses := map[string]string{}
			checker := checkerFor(api, config, statuses)
			test.change(api, &checker.Config, statuses, &checker)
			if !test.edited {
				rehash(api, &checker.Config)
			}
			report := checker.Run(t.Context())
			found := codes(report)
			if len(found) != 1 || found[0] != test.want || report.Failed() != test.failures {
				t.Fatalf("findings %v, want only %s", found, test.want)
			}
		})
	}
}

// The configuration is read strictly and must name what the check needs.
func TestParseConfig(t *testing.T) {
	t.Parallel()
	good := `{"namespace":"mt","statefulSet":"meshgw","replicas":2,"statusPort":9090,` +
		`"apiAudiences":["a"],"serviceAccount":"meshgw","checkServiceAccount":"meshgw-check","policies":[{"name":"p","binding":"b","enforcement":"deny","policyHash":"h","bindingHash":"g"}]}`
	if _, err := ParseConfig(good); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{
		"empty":           "",
		"unknown field":   strings.Replace(good, `"replicas"`, `"extra":1,"replicas"`, 1),
		"trailing":        good + "{}",
		"no audiences":    strings.Replace(good, `["a"]`, `[]`, 1),
		"bad enforcement": strings.Replace(good, `"deny"`, `"maybe"`, 1),
		"zero replicas":   strings.Replace(good, `"replicas":2`, `"replicas":0`, 1),
	} {
		if _, err := ParseConfig(raw); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
}

// The summary fits a termination message.
func TestSummary(t *testing.T) {
	t.Parallel()
	var report Report
	for index := range 200 {
		report.add(Warn, "w", "finding %d %s", index, strings.Repeat("x", 40))
	}
	summary := report.Summary()
	if len(summary) > 4096 || !strings.HasPrefix(summary, "0 failed, 200 warnings\n") ||
		!strings.HasSuffix(summary, "…\n") {
		t.Fatalf("summary of %d bytes: %.80q", len(summary), summary)
	}
}

// FetchStatus reads /status, and refuses another answer.
func TestFetchStatus(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/status" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(healthyStatus))
	}))
	defer server.Close()
	address, _ := url.Parse(server.URL)
	port, _ := strconv.Atoi(address.Port())
	status, err := FetchStatus(t.Context(), address.Hostname(), port)
	if err != nil || !status.Ready || !status.Kube.Listening || len(status.Kube.Groups) != 1 {
		t.Fatalf("%+v %v", status, err)
	}
	if _, err := FetchStatus(t.Context(), address.Hostname(), port+1); err == nil {
		t.Fatal("a closed port answered")
	}
}

// A missing fingerprint in the configuration is refused.
func TestParseConfigNeedsFingerprints(t *testing.T) {
	t.Parallel()
	raw := `{"namespace":"mt","statefulSet":"meshgw","replicas":2,"statusPort":9090,"apiAudiences":["a"],` +
		`"serviceAccount":"meshgw","checkServiceAccount":"meshgw-check",` +
		`"policies":[{"name":"p","binding":"b","enforcement":"deny"}]}`
	if _, err := ParseConfig(raw); err == nil {
		t.Fatal("a policy without fingerprints was taken")
	}
}

// pagedAPI answers lists in two pages, expiring the continue token once
// or twice.
type pagedAPI struct {
	expire, calls int
}

func (api *pagedAPI) Get(_ context.Context, path string, into any) error {
	api.calls++
	if !strings.Contains(path, "continue=") {
		return json.Unmarshal([]byte(`{"metadata":{"continue":"next"},"items":[{"n":1}]}`), into)
	}
	if api.expire > 0 {
		api.expire--
		return &StatusError{Code: http.StatusGone, Message: "expired"}
	}
	return json.Unmarshal([]byte(`{"metadata":{},"items":[{"n":2}]}`), into)
}

func (*pagedAPI) Post(context.Context, string, any) error { return nil }

// Lists are read page by page, restart once when the token expires, and
// fail when it expires again.
func TestListAllPages(t *testing.T) {
	t.Parallel()
	for expire, want := range map[int]string{0: "1,2", 1: "1,1,2"} {
		var got []string
		api := &pagedAPI{expire: expire}
		err := listAll(t.Context(), api, "/x", func(raw json.RawMessage) error {
			var item struct{ N int }
			_ = json.Unmarshal(raw, &item)
			got = append(got, strconv.Itoa(item.N))
			return nil
		})
		if err != nil || strings.Join(got, ",") != want {
			t.Errorf("expire %d: %v %v", expire, got, err)
		}
	}
	if err := listAll(t.Context(), &pagedAPI{expire: 2}, "/x", func(json.RawMessage) error { return nil }); err == nil {
		t.Error("a twice-expired list was read")
	}
}
