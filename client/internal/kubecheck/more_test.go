package kubecheck

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Items of a controller the preflight does not list are checked, once per
// owner; finished Jobs are not; binding does not exempt the gateway's
// namespace (review c2b H3, L2, M5).
func TestPreflightOwnersAndExemptions(t *testing.T) {
	t.Parallel()
	api, config := healthyInstall()
	config.Preflight = PreflightConfig{ExemptNamespaces: []string{"kube-system"}, BindingEnforced: true}
	for _, path := range []string{
		"/apis/apps/v1/daemonsets", "/apis/apps/v1/deployments", "/apis/apps/v1/statefulsets",
		"/apis/batch/v1/cronjobs", "/api/v1/replicationcontrollers",
	} {
		api.objects[path] = `{"items":[]}`
	}
	api.objects["/apis/apps/v1/replicasets"] = `{"items":[
		{"metadata":{"name":"r1","namespace":"app","ownerReferences":[{"kind":"Rollout","name":"web"}]},
		 "spec":{"template":{"spec":{"tolerations":[{"operator":"Exists"}]}}}},
		{"metadata":{"name":"r2","namespace":"app","ownerReferences":[{"kind":"Rollout","name":"web"}]},
		 "spec":{"template":{"spec":{"tolerations":[{"operator":"Exists"}]}}}}]}`
	api.objects["/apis/batch/v1/jobs"] = `{"items":[
		{"metadata":{"name":"done","namespace":"app"},"spec":{"template":{"spec":{"tolerations":[{"operator":"Exists"}]}}},
		 "status":{"conditions":[{"type":"Complete","status":"True"}]}}]}`
	api.objects["/api/v1/pods"] = `{"items":[
		{"metadata":{"name":"g","namespace":"mt"},"spec":{"schedulerName":"other"}}]}`
	report := checkerFor(api, config, nil).Preflight(t.Context())
	got := strings.Join(codes(report), " ")
	if got != "fail:tolerates_every_taint fail:other_scheduler" ||
		!strings.Contains(report.Findings[0].Message, "ReplicaSets of Rollout app/web") {
		t.Fatalf("findings %s: %+v", got, report.Findings)
	}
}

// The fingerprints ignore what the API server fills in: a rule's "*"
// scope, empty selectors.
func TestPolicyFingerprints(t *testing.T) {
	t.Parallel()
	rendered := map[string]any{
		"validations":      []any{map[string]any{"expression": "a && b"}},
		"matchConstraints": map[string]any{"resourceRules": []any{map[string]any{"resources": []any{"pods"}}}},
	}
	live := map[string]any{
		"validations":   []any{map[string]any{"expression": "a && b"}},
		"failurePolicy": "Fail",
		"matchConstraints": map[string]any{
			"matchPolicy": "Equivalent", "namespaceSelector": map[string]any{},
			"resourceRules": []any{map[string]any{"resources": []any{"pods"}, "scope": "*"}},
		},
	}
	a, _ := policyHash(rendered)
	b, _ := policyHash(live)
	if a != b {
		t.Fatal("defaults changed the policy's fingerprint")
	}
	live["validations"] = []any{map[string]any{"expression": "true"}}
	if c, _ := policyHash(live); c == a {
		t.Fatal("an edited validation kept the fingerprint")
	}
	binding := map[string]any{
		"policyName": "p", "validationActions": []any{"Deny"},
		"matchResources": map[string]any{"namespaceSelector": map[string]any{"matchLabels": map[string]any{"k": "v"}}},
	}
	defaulted := map[string]any{
		"policyName": "p", "validationActions": []any{"Deny"},
		"matchResources": map[string]any{
			"matchPolicy": "Equivalent", "objectSelector": map[string]any{},
			"namespaceSelector": map[string]any{"matchLabels": map[string]any{"k": "v"}},
		},
	}
	x, _ := bindingHash(binding)
	y, _ := bindingHash(defaulted)
	if x != y {
		t.Fatal("defaults changed the binding's fingerprint")
	}
}

// The in-cluster client sends the pod's token, follows no redirect, caps
// answers and reports the API server's refusal.
func TestInClusterClient(t *testing.T) {
	t.Parallel()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			if r.Header.Get("Authorization") != "Bearer the-token" {
				http.Error(w, "no token", http.StatusUnauthorized)
				return
			}
			_, _ = w.Write([]byte(`{"a":1}`))
		case "/redirect":
			http.Redirect(w, r, "https://example.com/", http.StatusFound)
		case "/big":
			_, _ = w.Write([]byte(strings.Repeat("x", maximumResponse+1)))
		default:
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"message":"forbidden\nline"}`))
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	caFile, tokenFile := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "token")
	certificate := server.Certificate()
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}),
		0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenFile, []byte("the-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	host, port, _ := strings.Cut(strings.TrimPrefix(server.URL, "https://"), ":")
	client, err := NewInCluster(func(name string) string {
		return map[string]string{"KUBERNETES_SERVICE_HOST": host, "KUBERNETES_SERVICE_PORT": port}[name]
	}, caFile, tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]int
	if err := client.Get(t.Context(), "/ok", &got); err != nil || got["a"] != 1 {
		t.Fatalf("%v %v", got, err)
	}
	if err := client.Get(t.Context(), "/redirect", &got); err == nil {
		t.Fatal("a redirect was followed")
	}
	if err := client.Get(t.Context(), "/big", &got); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("an oversized answer: %v", err)
	}
	err = client.Get(t.Context(), "/denied", &got)
	if err == nil || NotFound(err) || strings.Contains(err.Error(), "\n") {
		t.Fatalf("a refusal: %v", err)
	}
}
