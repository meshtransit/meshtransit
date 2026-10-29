package kubecheck

import (
	"context"
	"strings"
	"testing"
)

const rbacBase = "/apis/rbac.authorization.k8s.io/v1/"

// Subjects as good as the gateway in its namespace or across the cluster
// are warned about; only Kubernetes itself, the gateway and the check are
// trusted (review c2b H1, M1, M2).
func TestCheckRBAC(t *testing.T) {
	t.Parallel()
	api, config := healthyInstall()
	api.objects[rbacBase+"clusterroles"] = `{"items":[
		{"metadata":{"name":"cluster-admin"},"rules":[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]}]},
		{"metadata":{"name":"monitor"},"rules":[{"apiGroups":[""],"resources":["nodes/proxy"],"verbs":["get"]}]},
		{"metadata":{"name":"reader"},"rules":[{"apiGroups":[""],"resources":["pods","pods/log"],"verbs":["get","list"]}]},
		{"metadata":{"name":"wild-sub"},"rules":[{"apiGroups":[""],"resources":["*/exec"],"verbs":["create"]}]},
		{"metadata":{"name":"not-a-match"},"rules":[{"apiGroups":[""],"resources":["pods/*"],"verbs":["create"]}]},
		{"metadata":{"name":"impersonator"},"rules":[{"apiGroups":[""],"resources":["users"],"verbs":["impersonate"]}]}]}`
	api.objects[rbacBase+"clusterrolebindings"] = `{"items":[
		{"metadata":{"name":"masters"},"roleRef":{"kind":"ClusterRole","name":"cluster-admin"},
		 "subjects":[{"kind":"Group","name":"system:masters"}]},
		{"metadata":{"name":"defaults","labels":{"kubernetes.io/bootstrapping":"rbac-defaults"}},
		 "roleRef":{"kind":"ClusterRole","name":"cluster-admin"},
		 "subjects":[{"kind":"ServiceAccount","name":"generic","namespace":"kube-system"}]},
		{"metadata":{"name":"everyone"},"roleRef":{"kind":"ClusterRole","name":"cluster-admin"},
		 "subjects":[{"kind":"Group","name":"system:authenticated"}]},
		{"metadata":{"name":"as-user"},"roleRef":{"kind":"ClusterRole","name":"wild-sub"},
		 "subjects":[{"kind":"User","name":"system:serviceaccount:build:ci"}]},
		{"metadata":{"name":"addon"},"roleRef":{"kind":"ClusterRole","name":"cluster-admin"},
		 "subjects":[{"kind":"ServiceAccount","name":"sealed-secrets","namespace":"kube-system"}]},
		{"metadata":{"name":"prom"},"roleRef":{"kind":"ClusterRole","name":"monitor"},
		 "subjects":[{"kind":"ServiceAccount","name":"prometheus","namespace":"monitoring"}]},
		{"metadata":{"name":"imp"},"roleRef":{"kind":"ClusterRole","name":"impersonator"},
		 "subjects":[{"kind":"User","name":"carol"}]},
		{"metadata":{"name":"readers"},"roleRef":{"kind":"ClusterRole","name":"reader"},
		 "subjects":[{"kind":"Group","name":"devs"}]},
		{"metadata":{"name":"odd"},"roleRef":{"kind":"ClusterRole","name":"not-a-match"},
		 "subjects":[{"kind":"User","name":"dave"}]}]}`
	api.objects[rbacBase+"namespaces/mt/roles"] = `{"items":[
		{"metadata":{"name":"state"},"rules":[{"apiGroups":[""],"resources":["secrets"],"resourceNames":["meshgw-state-0"],"verbs":["get","update"]}]}]}`
	api.objects[rbacBase+"namespaces/mt/rolebindings"] = `{"items":[
		{"metadata":{"name":"state"},"roleRef":{"kind":"Role","name":"state"},
		 "subjects":[{"kind":"ServiceAccount","name":"meshgw","namespace":"mt"},{"kind":"ServiceAccount","name":"deploy","namespace":"build"}]}]}`
	report := checkerFor(api, config, nil).Run(t.Context())
	text := ""
	for _, finding := range report.Findings {
		text += string(finding.Level) + " " + finding.Code + " " + finding.Message + "\n"
	}
	for _, want := range []string{
		"namespace_access Group system:authenticated may create pods",
		"cluster_access Group system:authenticated may get nodes/proxy",
		"namespace_access ServiceAccount build/ci may create pods/exec in namespace mt",
		"kube_system_access ServiceAccount kube-system/sealed-secrets may create pods",
		"cluster_access ServiceAccount monitoring/prometheus may get nodes/proxy",
		"cluster_access User carol may impersonate users",
		"namespace_access ServiceAccount build/deploy may get secrets",
		"rbac_webhooks_unseen",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
	for _, unwanted := range []string{"system:masters", "kube-system/generic", "mt/meshgw", "devs", "dave"} {
		if strings.Contains(text, unwanted) {
			t.Errorf("%q reported in\n%s", unwanted, text)
		}
	}
	if report.Failed() {
		t.Fatalf("RBAC findings failed the check:\n%s", text)
	}
}

// A refused read fails the check (the chart's Role is wrong); another
// warns (review c2b M4).
func TestCheckRefusedReads(t *testing.T) {
	t.Parallel()
	api, config := healthyInstall()
	delete(api.objects, rbacBase+"clusterroles")
	forbidden := &forbiddenAPI{fakeAPI: api, path: rbacBase + "clusterroles"}
	checker := checkerFor(api, config, nil)
	checker.API = forbidden
	if report := checker.Run(t.Context()); !report.Failed() || !strings.Contains(strings.Join(codes(report), " "),
		"fail:check_forbidden") {
		t.Fatalf("findings %v", codes(report))
	}
}

type forbiddenAPI struct {
	*fakeAPI
	path string
}

func (api *forbiddenAPI) Get(ctx context.Context, path string, into any) error {
	if strings.HasPrefix(path, api.path) {
		return &StatusError{Code: 403, Message: "forbidden"}
	}
	return api.fakeAPI.Get(ctx, path, into)
}

// The preflight fails on what enforcing would refuse, outside the exempt
// namespaces, and passes a clean cluster.
func TestPreflight(t *testing.T) {
	t.Parallel()
	api, config := healthyInstall()
	config.Preflight = PreflightConfig{
		ExemptNamespaces: []string{"kube-system"}, BindingEnforced: true,
		TrustedSchedulerNames: []string{"volcano"},
	}
	empty := `{"items":[]}`
	for _, path := range []string{
		"/apis/apps/v1/daemonsets", "/apis/apps/v1/deployments",
		"/apis/apps/v1/statefulsets", "/apis/apps/v1/replicasets", "/apis/batch/v1/jobs",
		"/apis/batch/v1/cronjobs", "/api/v1/pods", "/api/v1/replicationcontrollers",
	} {
		api.objects[path] = empty
	}
	checker := checkerFor(api, config, nil)
	if report := checker.Preflight(t.Context()); len(report.Findings) != 0 {
		t.Fatalf("clean cluster: %v", codes(report))
	}
	api.objects["/apis/apps/v1/daemonsets"] = `{"items":[
		{"metadata":{"name":"kube-proxy","namespace":"kube-system"},"spec":{"template":{"spec":{"tolerations":[{"operator":"Exists"}]}}}},
		{"metadata":{"name":"agent","namespace":"monitoring"},"spec":{"template":{"spec":{"tolerations":[{"operator":"Exists"}]}}}},
		{"metadata":{"name":"cni","namespace":"calico-system"},"spec":{"template":{"spec":{"tolerations":[{"key":"x","operator":"Exists"}]}}}}]}`
	api.objects["/apis/batch/v1/cronjobs"] = `{"items":[
		{"metadata":{"name":"batch","namespace":"jobs"},"spec":{"jobTemplate":{"spec":{"template":{"spec":{"schedulerName":"yunikorn"}}}}}},
		{"metadata":{"name":"gang","namespace":"jobs"},"spec":{"jobTemplate":{"spec":{"template":{"spec":{"schedulerName":"volcano"}}}}}}]}`
	api.objects["/apis/apps/v1/replicasets"] = `{"items":[
		{"metadata":{"name":"owned","namespace":"app","ownerReferences":[{"kind":"Deployment"}]},"spec":{"template":{"spec":{"nodeName":"n1"}}}},
		{"metadata":{"name":"bare","namespace":"app"},"spec":{"template":{"spec":{"nodeName":"n1"}}}}]}`
	api.objects["/api/v1/pods"] = `{"items":[
		{"metadata":{"name":"scheduled","namespace":"app"},"spec":{"nodeName":"n2"}},
		{"metadata":{"name":"tolerant","namespace":"app"},"spec":{"tolerations":[{"operator":"Exists"}]}}]}`
	report := checker.Preflight(t.Context())
	got := strings.Join(codes(report), " ")
	want := "fail:tolerates_every_taint fail:names_a_node fail:other_scheduler fail:tolerates_every_taint"
	if got != want || !report.Failed() {
		t.Fatalf("findings %s\nwant %s", got, want)
	}
	for _, finding := range report.Findings {
		if strings.Contains(finding.Message, "kube-system") || strings.Contains(finding.Message, "volcano") ||
			strings.Contains(finding.Message, "owned") || strings.Contains(finding.Message, "scheduled") {
			t.Errorf("exempt or trusted reported: %s", finding.Message)
		}
	}
}

// A bad call or configuration exits 2 before touching the cluster.
func TestMainRefusesBadCalls(t *testing.T) {
	t.Parallel()
	var out, errs strings.Builder
	none := func(string) string { return "" }
	if code := Main(t.Context(), []string{"--force"}, none, &out, &errs, nil); code != 2 {
		t.Fatalf("unknown flag: %d", code)
	}
	if code := Main(t.Context(), nil, none, &out, &errs, nil); code != 2 ||
		!strings.Contains(errs.String(), "MESHGW_CHECK_CONFIG") {
		t.Fatalf("no configuration: %d %s", code, errs.String())
	}
}

// The result is left on the gateway's StatefulSet as an Event.
func TestRecordEvent(t *testing.T) {
	t.Parallel()
	api, config := healthyInstall()
	checker := checkerFor(api, config, nil)
	var report Report
	report.add(Fail, "x", "y")
	if err := checker.recordEvent(t.Context(), true, report, strings.Repeat("s", 2000)); err != nil {
		t.Fatal(err)
	}
	if len(api.posts) != 1 || api.posts[0] != "/api/v1/namespaces/mt/events" {
		t.Fatalf("posts %v", api.posts)
	}
}
