//go:build difftest

package kubeprofileoracle

// The oracle test (K2b, K2-I10): every sample profile becomes RBAC of its
// own ServiceAccount — the namespaced part a ClusterRole bound in each of the
// rule's namespaces (a ClusterRoleBinding for "*"), the cluster part a
// ClusterRole bound cluster-wide — both expanded over the cluster's
// discovery so that each part covers only resources of its own scope, as the
// profile does. For each request of the corpus, what kubeprofile decides on
// kubereq's reading of it must equal what the API server's
// SubjectAccessReviews decide for that account (every verb the API server
// checks). The profile may refuse what RBAC allows only where the design is
// stricter on purpose, and only for that reason: once every rule covering
// the request through a wildcard names it exactly, the request must pass
// (S2, S4, S6); or it is a PUT that would pass without S3's create.
// Requests an account may make with no binding at all are left out.
//
// Lab clusters only: it binds wide rights to throwaway accounts and refuses
// any cluster whose nodes are not kind's (MT_ORACLE_KIND_CLUSTER names the
// one). A Lease keeps two runs apart. A run killed before its cleanup (a
// -timeout panic) leaves its bindings until the next run removes them.
//
//	MT_ORACLE_LAB=1 MT_ORACLE_SERVER=https://127.0.0.1:6443 MT_ORACLE_CA=/abs/ca.crt MT_ORACLE_TOKEN=... \
//	[MT_ORACLE_KIND_CLUSTER=lab MT_ORACLE_KUBECTL=kubectl MT_ORACLE_PAUSE=registry.k8s.io/pause:3.10] \
//	go test -tags difftest -run TestProfileOracle -v ./client/internal/kubeprofileoracle

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"meshtransit.net/client/internal/kubereq"
	"meshtransit.net/shared/kubeprofile"
)

const (
	oracleNamespace = "mt-k2b-oracle"
	oracleLabel     = "meshtransit.net/k2b"
	teamA           = "mt-k2b-a"
	teamB           = "mt-k2b-b"
	widgetGroup     = "k2b.meshtransit.net"
	widgetCRD       = "widgets." + widgetGroup
	lockName        = "mt-k2b-oracle"
	lockSeconds     = 1800
)

// corpusNamespaces are the namespaces requests name; the rules name some.
var corpusNamespaces = []string{teamA, teamB, "kube-system"}

type cluster struct {
	t      *testing.T
	server string
	token  string
	ca     []byte
	client *http.Client
	// scopes maps "group/resource" (a subresource included) to its scope;
	// a resource two versions disagree on is absent.
	scopes map[string]kubeprofile.ResourceScope
}

func connect(t *testing.T) *cluster {
	server, caFile, token := os.Getenv("MT_ORACLE_SERVER"), os.Getenv("MT_ORACLE_CA"), os.Getenv("MT_ORACLE_TOKEN")
	if os.Getenv("MT_ORACLE_LAB") != "1" || server == "" || caFile == "" || token == "" {
		t.Skip("MT_ORACLE_LAB=1, MT_ORACLE_SERVER, MT_ORACLE_CA and MT_ORACLE_TOKEN name a lab cluster")
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		t.Fatal("MT_ORACLE_CA holds no certificate")
	}
	c := &cluster{t: t, server: strings.TrimSuffix(server, "/"), token: token, ca: pem,
		client: &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, MaxIdleConnsPerHost: 32}}}
	c.requireLab()
	return c
}

// requireLab refuses a cluster that is not kind's (or not the one
// MT_ORACLE_KIND_CLUSTER names), or whose test namespaces someone else owns.
func (c *cluster) requireLab() {
	var nodes struct {
		Items []struct {
			Spec struct {
				ProviderID string `json:"providerID"`
			} `json:"spec"`
		} `json:"items"`
	}
	if json.Unmarshal(c.must(http.MethodGet, "/api/v1/nodes", nil), &nodes) != nil || len(nodes.Items) == 0 {
		c.t.Fatal("no nodes")
	}
	prefix := "kind://"
	if name := os.Getenv("MT_ORACLE_KIND_CLUSTER"); name != "" {
		prefix = "kind://docker/" + name + "/"
	}
	for _, node := range nodes.Items {
		if !strings.HasPrefix(node.Spec.ProviderID, prefix) {
			c.t.Fatalf("node %q is not under %s: not the lab cluster", node.Spec.ProviderID, prefix)
		}
	}
	for _, namespace := range []string{oracleNamespace, teamA, teamB} {
		status, out := c.call(http.MethodGet, "/api/v1/namespaces/"+namespace, nil)
		if status == http.StatusOK && !bytes.Contains(out, []byte(`"`+oracleLabel+`":"oracle"`)) {
			c.t.Fatalf("namespace %s exists without the oracle's label", namespace)
		}
	}
}

// lock takes a Lease so that two runs never clean each other up. A lease
// of the oracle's past its duration is a dead run's: it is taken over by a
// delete that names its uid and version, so of two runs only one wins.
func (c *cluster) lock() {
	path := "/apis/coordination.k8s.io/v1/namespaces/kube-system/leases"
	holder := make([]byte, 8)
	_, _ = rand.Read(holder)
	lease := map[string]any{"apiVersion": "coordination.k8s.io/v1", "kind": "Lease", "metadata": metadata(lockName),
		"spec": map[string]any{"holderIdentity": hex.EncodeToString(holder), "leaseDurationSeconds": lockSeconds,
			"acquireTime": time.Now().UTC().Format("2006-01-02T15:04:05.000000Z07:00")}}
	type held struct {
		Metadata struct {
			UID             string            `json:"uid"`
			ResourceVersion string            `json:"resourceVersion"`
			Labels          map[string]string `json:"labels"`
		} `json:"metadata"`
		Spec struct {
			AcquireTime time.Time `json:"acquireTime"`
		} `json:"spec"`
	}
	deleteExactly := func(lease held) int {
		status, _ := c.call(http.MethodDelete, path+"/"+lockName, map[string]any{"preconditions": map[string]string{
			"uid": lease.Metadata.UID, "resourceVersion": lease.Metadata.ResourceVersion}})
		return status
	}
	for range 3 {
		status, out := c.call(http.MethodPost, path, lease)
		if status == http.StatusCreated {
			var mine held
			if json.Unmarshal(out, &mine) != nil || mine.Metadata.UID == "" {
				c.t.Fatalf("lock: %s", out)
			}
			c.t.Cleanup(func() { deleteExactly(mine) })
			return
		}
		if status != http.StatusConflict {
			c.t.Fatalf("lock: %d %s", status, out)
		}
		status, out = c.call(http.MethodGet, path+"/"+lockName, nil)
		if status == http.StatusNotFound {
			continue // its holder finished meanwhile
		}
		var current held
		if status != http.StatusOK || json.Unmarshal(out, &current) != nil ||
			current.Metadata.Labels[oracleLabel] != "oracle" || current.Spec.AcquireTime.IsZero() ||
			time.Since(current.Spec.AcquireTime) < lockSeconds*time.Second {
			c.t.Fatal("another oracle run holds the lab, or the lease is not the oracle's")
		}
		if status := deleteExactly(current); status != http.StatusOK && status != http.StatusNotFound {
			c.t.Fatal("another run took the lab over first")
		}
	}
	c.t.Fatal("lock: could not take the lease")
}

// call sends a request with the admin token and returns its status and body.
// It runs on many goroutines: a failure is an error, never Fatal.
func (c *cluster) call(method, path string, body any) (int, []byte) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			c.t.Errorf("%s %s: %v", method, path, err)
			return 0, nil
		}
		reader = bytes.NewReader(encoded)
	}
	return c.send(c.token, method, path, "application/json", reader)
}

func (c *cluster) send(token, method, path, contentType string, body io.Reader) (int, []byte) {
	request, err := http.NewRequestWithContext(context.Background(), method, c.server+path, body)
	if err != nil {
		c.t.Errorf("%s %s: %v", method, path, err)
		return 0, nil
	}
	request.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := c.client.Do(request)
	if err != nil {
		c.t.Errorf("%s %s: %v", method, path, err)
		return 0, nil
	}
	defer func() { _ = response.Body.Close() }()
	out, err := io.ReadAll(io.LimitReader(response.Body, 16<<20))
	if err != nil {
		c.t.Errorf("%s %s: %v", method, path, err)
		return 0, nil
	}
	return response.StatusCode, out
}

// must sends a request from the test goroutine that must succeed.
func (c *cluster) must(method, path string, body any) []byte {
	c.t.Helper()
	status, out := c.call(method, path, body)
	if status < 200 || status >= 300 {
		c.t.Fatalf("%s %s: %d %s", method, path, status, out)
	}
	return out
}

// remove deletes what a path or label selector names; gone already is fine.
func (c *cluster) remove(path string) {
	c.t.Helper()
	status, out := c.call(http.MethodDelete, path, nil)
	if status != http.StatusOK && status != http.StatusAccepted && status != http.StatusNotFound {
		c.t.Errorf("DELETE %s: %d %s", path, status, out)
	}
}

// accountToken mints a short token for an oracle account.
func (c *cluster) accountToken(account string) string {
	c.t.Helper()
	out := c.must(http.MethodPost, "/api/v1/namespaces/"+oracleNamespace+"/serviceaccounts/"+account+"/token",
		map[string]any{"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest",
			"spec": map[string]any{"expirationSeconds": 600}})
	var answer struct {
		Status struct {
			Token string `json:"token"`
		} `json:"status"`
	}
	if json.Unmarshal(out, &answer) != nil || answer.Status.Token == "" {
		c.t.Fatal("no token for " + account)
	}
	return answer.Status.Token
}

type apiResource struct {
	Name       string `json:"name"`
	Namespaced bool   `json:"namespaced"`
}

// discover reads every group version the cluster serves, as the gateway
// will (K2 §10.2); an aggregated API that does not answer leaves its
// resources unknown (K2-I11).
func (c *cluster) discover() {
	scopes := map[string]kubeprofile.ResourceScope{}
	conflict := map[string]bool{}
	add := func(group, groupVersionPath string) {
		status, out := c.call(http.MethodGet, groupVersionPath, nil)
		if status != http.StatusOK {
			c.t.Logf("discovery %s: %d, its resources stay unknown", groupVersionPath, status)
			return
		}
		var list struct {
			Resources []apiResource `json:"resources"`
		}
		if json.Unmarshal(out, &list) != nil {
			c.t.Fatalf("discovery %s", groupVersionPath)
		}
		for _, resource := range list.Resources {
			scope := kubeprofile.ScopeCluster
			if resource.Namespaced {
				scope = kubeprofile.ScopeNamespaced
			}
			key := group + "/" + resource.Name
			if previous, ok := scopes[key]; ok && previous != scope {
				conflict[key] = true
			}
			scopes[key] = scope
		}
	}
	add("", "/api/v1")
	var groups struct {
		Groups []struct {
			Name     string `json:"name"`
			Versions []struct {
				GroupVersion string `json:"groupVersion"`
			} `json:"versions"`
		} `json:"groups"`
	}
	if json.Unmarshal(c.must(http.MethodGet, "/apis", nil), &groups) != nil {
		c.t.Fatal("discovery /apis")
	}
	for _, group := range groups.Groups {
		for _, version := range group.Versions {
			add(group.Name, "/apis/"+version.GroupVersion)
		}
	}
	for key := range conflict {
		delete(scopes, key)
	}
	c.scopes = scopes
}

// scopeOf is the gateway's lookup: a subresource takes its resource's scope.
func (c *cluster) scopeOf(group, resource string) kubeprofile.ResourceScope {
	return c.scopes[group+"/"+resource]
}

// sample is one profile as one Policy rule applies it.
type sample struct {
	name        string
	profile     kubeprofile.Profile
	namespaces  []string
	clusterPart bool
}

func rule(groups, resources, verbs []string, names ...string) kubeprofile.Rule {
	return kubeprofile.Rule{APIGroups: groups, Resources: resources, Verbs: verbs, ResourceNames: names}
}

var (
	readVerbs  = []string{"get", "list", "watch"}
	writeVerbs = []string{"create", "update", "patch", "delete"}
	allVerbs   = []string{"*"}
	core       = []string{""}
	anyGroup   = []string{"*"}
	anything   = []string{"*"}
)

func samples() []sample {
	profile := func(name string, namespaced, clusterRules []kubeprofile.Rule) kubeprofile.Profile {
		return kubeprofile.Profile{Name: name, Namespaced: namespaced, Cluster: clusterRules}
	}
	developer := profile("developer", []kubeprofile.Rule{
		rule([]string{"", "apps", "batch"}, []string{"pods", "pods/log", "deployments", "replicasets", "jobs",
			"configmaps", "services"}, append(slices.Clone(readVerbs), writeVerbs...)),
	}, []kubeprofile.Rule{
		rule(core, []string{"namespaces", "nodes"}, readVerbs),
		{NonResourceURLs: []string{"/metrics"}, Verbs: []string{"get"}},
	})
	wildcard := profile("wildcard", []kubeprofile.Rule{rule(anyGroup, anything, allVerbs)},
		[]kubeprofile.Rule{rule(anyGroup, anything, allVerbs), {NonResourceURLs: anything, Verbs: allVerbs}})
	// kubectl reads the pod before it opens a session.
	readPod := rule(core, []string{"pods"}, []string{"get"})
	return []sample{
		{"developer two namespaces", developer, []string{teamA, teamB}, true},
		{"developer everywhere", developer, []string{"*"}, false},
		{"read only", profile("read-only", []kubeprofile.Rule{rule(anyGroup, anything, readVerbs)}, nil),
			[]string{teamA}, false},
		{"read everything", profile("read-all", []kubeprofile.Rule{rule(anyGroup, anything, readVerbs)},
			[]kubeprofile.Rule{rule(anyGroup, anything, readVerbs)}), []string{"*"}, true},
		{"wildcard everywhere", wildcard, []string{"*"}, true},
		{"wildcard in a namespace", wildcard, []string{teamA}, false},
		{"on-call", profile("oncall", []kubeprofile.Rule{
			rule(core, []string{"pods/exec", "pods/portforward", "pods/attach"}, []string{"get", "create"}),
			rule(core, []string{"pods", "pods/log"}, readVerbs),
		}, nil), []string{teamA}, false},
		{"exec by create only", profile("exec-create", []kubeprofile.Rule{
			rule(core, []string{"pods/exec"}, []string{"create"}), readPod}, nil), []string{teamA}, false},
		{"exec by get only", profile("exec-get", []kubeprofile.Rule{
			rule(core, []string{"pods/exec"}, []string{"get"}), readPod}, nil), []string{teamA}, false},
		{"exec one pod", profile("exec-web", []kubeprofile.Rule{
			rule(core, []string{"pods/exec"}, allVerbs, "web-0")}, nil), []string{teamA}, false},
		{"proxies", profile("proxies", []kubeprofile.Rule{
			rule(core, []string{"services/proxy", "pods/proxy"}, []string{"get", "create"}),
			rule(core, []string{"pods"}, []string{"proxy"}),
		}, nil), []string{teamA}, false},
		{"namespace admin", profile("ns-admin", []kubeprofile.Rule{
			rule(core, []string{"namespaces"}, []string{"get", "patch", "delete"}),
			rule(core, []string{"namespaces/finalize", "namespaces/status"}, []string{"get", "update"}),
		}, nil), []string{teamA}, false},
		{"rbac writer", profile("rbac-writer", nil, []kubeprofile.Rule{
			rule([]string{"rbac.authorization.k8s.io"}, []string{"clusterroles", "clusterrolebindings"},
				[]string{"get", "list", "create", "patch"}),
		}), []string{teamA}, true},
		{"volumes", profile("volumes", nil, []kubeprofile.Rule{rule(core, []string{"persistentvolumes"}, allVerbs)}),
			[]string{teamA}, true},
		{"nodes", profile("nodes", nil, []kubeprofile.Rule{
			rule(core, []string{"nodes"}, []string{"get", "list", "patch"}),
			rule(core, []string{"nodes/proxy"}, []string{"get"}),
		}), []string{teamA}, true},
		{"named config", profile("config-a", []kubeprofile.Rule{
			rule(core, []string{"configmaps"}, []string{"get", "list", "watch", "update", "patch", "delete"}, "cfg-a"),
		}, nil), []string{teamA}, false},
		{"scale", profile("scale", []kubeprofile.Rule{rule(anyGroup, []string{"*/scale"},
			[]string{"get", "update", "patch"})}, nil), []string{teamA, teamB}, false},
		{"update without create", profile("updates", []kubeprofile.Rule{
			rule([]string{"apps", ""}, []string{"deployments", "configmaps"}, []string{"get", "update", "patch"}),
		}, nil), []string{teamA}, false},
		{"update with create", profile("creates", []kubeprofile.Rule{
			rule([]string{"apps", ""}, []string{"deployments", "configmaps"}, []string{"get", "update", "patch", "create"}),
		}, nil), []string{teamA}, false},
		{"paths", profile("paths", nil, []kubeprofile.Rule{
			{NonResourceURLs: []string{"/metrics", "/logs/*"}, Verbs: []string{"get"}},
		}), []string{teamA}, true},
		{"paths, cluster part off", profile("paths-off", nil, []kubeprofile.Rule{
			{NonResourceURLs: []string{"/metrics"}, Verbs: []string{"get"}},
		}), []string{teamA}, false},
		{"widgets", profile("widgets", []kubeprofile.Rule{rule([]string{widgetGroup}, []string{"widgets", "widgets/status"},
			allVerbs)}, nil), []string{teamB}, false},
		{"certificates", profile("certificates", nil, []kubeprofile.Rule{
			rule([]string{"certificates.k8s.io"}, []string{"certificatesigningrequests", "certificatesigningrequests/approval"},
				[]string{"get", "list", "update"}),
		}), []string{teamA}, true},
		{"admission read", profile("admission-read", nil, []kubeprofile.Rule{
			rule([]string{"admissionregistration.k8s.io", "apiextensions.k8s.io", "apiregistration.k8s.io"}, anything, allVerbs),
		}), []string{teamA}, true},
		{"secrets", profile("secrets", []kubeprofile.Rule{rule(core, []string{"secrets"}, readVerbs)}, nil),
			[]string{teamA, teamB}, false},
	}
}

// request is one request of the corpus as a client sends it.
type request struct {
	method, path, contentType string
	upgrade                   bool
}

func corpus() []request {
	var set []request
	add := func(method string, paths ...string) {
		for _, path := range paths {
			set = append(set, request{method: method, path: path})
		}
	}
	upgrade := func(method string, paths ...string) {
		for _, path := range paths {
			set = append(set, request{method: method, path: path, upgrade: true})
		}
	}
	apply := func(paths ...string) {
		for _, path := range paths {
			set = append(set, request{method: http.MethodPatch, path: path, contentType: "application/apply-patch+yaml"})
		}
	}
	for _, namespace := range corpusNamespaces {
		ns := "/api/v1/namespaces/" + namespace
		apps := "/apis/apps/v1/namespaces/" + namespace
		widgets := "/apis/" + widgetGroup + "/v1/namespaces/" + namespace + "/widgets"
		add(http.MethodGet, ns+"/pods", ns+"/pods?watch=true", ns+"/pods/web-0", ns+"/pods/web-0/log",
			ns+"/pods?watch=true&fieldSelector=metadata.name%3Dweb-0", "/api/v1/watch/namespaces/"+namespace+"/pods",
			ns+"/configmaps", ns+"/configmaps/cfg-a", ns+"/configmaps/cfg-b",
			ns+"/configmaps?fieldSelector=metadata.name%3Dcfg-a",
			ns+"/configmaps?watch=1&fieldSelector=metadata.name%3Dcfg-a", ns+"/secrets", ns+"/secrets/s1",
			ns+"/services/svc/proxy/", ns+"/pods/web-0/proxy", apps+"/deployments", apps+"/deployments/web",
			apps+"/deployments/web/scale", widgets, widgets+"/w1", widgets+"/w1/status", widgets+"/w1/scale",
			ns, ns+"/status", "/api/v1/proxy/namespaces/"+namespace+"/pods/web-0")
		add(http.MethodPost, ns+"/pods", ns+"/configmaps", apps+"/deployments", widgets, ns+"/pods/web-0/exec",
			ns+"/pods/db-0/exec", ns+"/pods/web-0/attach", ns+"/pods/web-0/portforward", ns+"/services/svc/proxy/")
		add(http.MethodPut, ns+"/pods/web-0", ns+"/configmaps/cfg-a", apps+"/deployments/web",
			apps+"/deployments/web/scale", widgets+"/w1/status", widgets+"/w1/scale", ns+"/finalize", ns)
		add(http.MethodPatch, ns+"/configmaps/cfg-a", ns+"/configmaps/cfg-b", apps+"/deployments/web",
			apps+"/deployments/web/scale", widgets+"/w1/scale", ns)
		apply(ns+"/configmaps/cfg-new", apps+"/deployments/new", ns+"/configmaps/cfg-a", widgets+"/w2")
		add(http.MethodDelete, ns+"/pods/web-0", ns+"/configmaps", ns+"/configmaps/cfg-a", widgets, ns)
		// A WebSocket opens a session by GET, SPDY by POST.
		upgrade(http.MethodGet, ns+"/pods/web-0/exec", ns+"/pods/db-0/exec", ns+"/pods/web-0/attach",
			ns+"/pods/web-0/portforward", ns+"/pods?watch=true",
			"/apis/fake.meshtransit.net/v1alpha1/namespaces/"+namespace+"/things/x/shell")
		upgrade(http.MethodPost, ns+"/pods/web-0/exec", ns+"/pods/web-0/attach", ns+"/pods/web-0/portforward")
	}
	// Across namespaces, cluster-scoped resources and paths.
	add(http.MethodGet, "/api/v1/pods", "/api/v1/pods?watch=true", "/api/v1/watch/pods", "/apis/apps/v1/deployments",
		"/api/v1/secrets", "/api/v1/configmaps", "/apis/"+widgetGroup+"/v1/widgets", "/api/v1/nodes",
		"/api/v1/nodes/n1", "/api/v1/nodes/n1/status", "/api/v1/nodes/n1/proxy/metrics", "/api/v1/namespaces",
		"/api/v1/persistentvolumes", "/apis/rbac.authorization.k8s.io/v1/clusterroles",
		"/apis/rbac.authorization.k8s.io/v1/clusterroles/view",
		"/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations",
		"/apis/apiextensions.k8s.io/v1/customresourcedefinitions", "/apis/certificates.k8s.io/v1/certificatesigningrequests",
		"/apis/apiregistration.k8s.io/v1/apiservices", "/metrics", "/logs/", "/logs/kube-apiserver.log", "/healthz",
		"/version", "/api", "/apis", "/debug/pprof/", "/api/v1/namespaces/"+teamA+"/nodes/n1")
	add(http.MethodPost, "/api/v1/namespaces", "/api/v1/persistentvolumes",
		"/apis/rbac.authorization.k8s.io/v1/clusterroles", "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
		"/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations",
		"/apis/apiextensions.k8s.io/v1/customresourcedefinitions", "/apis/apiregistration.k8s.io/v1/apiservices",
		"/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", "/apis/authentication.k8s.io/v1/tokenreviews",
		"/metrics")
	add(http.MethodPatch, "/api/v1/nodes/n1", "/api/v1/persistentvolumes/pv1",
		"/apis/rbac.authorization.k8s.io/v1/clusterroles/view")
	add(http.MethodPut, "/apis/certificates.k8s.io/v1/certificatesigningrequests/c1/approval",
		"/api/v1/persistentvolumes/pv1")
	add(http.MethodDelete, "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/"+widgetCRD)
	apply("/api/v1/persistentvolumes/pv-new")
	upgrade(http.MethodGet, "/metrics")
	return set
}

// attributes is what the gateway will hand kubeprofile for a request.
// MayCreate is derived here until the gateway computes it; K2e makes the
// oracle call the gateway's own function.
func (c *cluster) attributes(sent request) (kubeprofile.Attributes, bool) {
	target, err := url.Parse(sent.path)
	if err != nil {
		c.t.Fatal(err)
	}
	info, err := kubereq.Parse(sent.method, target)
	if err != nil {
		return kubeprofile.Attributes{}, false
	}
	attributes := kubeprofile.Attributes{ResourceRequest: info.IsResourceRequest, Verb: info.Verb,
		APIGroup: info.APIGroup, Resource: info.Resource, Subresource: info.Subresource,
		Namespace: info.Namespace, Name: info.Name, Path: info.Path, Upgrade: sent.upgrade,
		MayCreate: info.Subresource == "" && (sent.method == http.MethodPut ||
			strings.HasPrefix(sent.contentType, "application/apply-patch"))}
	if info.IsResourceRequest {
		attributes.Scope = c.scopeOf(info.APIGroup, info.Resource)
	}
	return attributes, true
}

// checkedVerbs are the verbs the API server itself checks: the request's,
// and create for a session or an apply. A PUT is checked for create only by
// the few resources that create on update, so the server's side leaves it
// out and S3's PUT is counted on its own.
func checkedVerbs(attributes kubeprofile.Attributes, sent request) []string {
	verbs := []string{attributes.Verb}
	interactive := attributes.ResourceRequest &&
		slices.Contains([]string{"exec", "attach", "portforward"}, attributes.Subresource)
	applying := attributes.MayCreate && sent.method == http.MethodPatch
	if (interactive || applying) && attributes.Verb != "create" {
		verbs = append(verbs, "create")
	}
	return verbs
}

// expand narrows a part to resources of one scope, as concrete rules, the
// cluster part also keeping its path rules. Rules on the namespace object
// are kept apart (namespaceObjectRules): a RoleBinding grants it in its own
// namespace.
func (c *cluster) expand(rules []kubeprofile.Rule, scope kubeprofile.ResourceScope) []map[string]any {
	var out []map[string]any
	keys := make([]string, 0, len(c.scopes))
	for key := range c.scopes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, policy := range rules {
		if len(policy.NonResourceURLs) > 0 {
			out = append(out, map[string]any{"nonResourceURLs": policy.NonResourceURLs, "verbs": policy.Verbs})
			continue
		}
		for _, key := range keys {
			group, resource, _ := strings.Cut(key, "/")
			base, subresource, _ := strings.Cut(resource, "/")
			if c.scopes[group+"/"+base] != scope || !groupMatches(policy.APIGroups, group) ||
				!resourceMatches(policy.Resources, resource, subresource) {
				continue
			}
			concrete := map[string]any{"apiGroups": []string{group}, "resources": []string{resource}, "verbs": policy.Verbs}
			if len(policy.ResourceNames) > 0 {
				concrete["resourceNames"] = policy.ResourceNames
			}
			out = append(out, concrete)
		}
	}
	return out
}

// namespaceObjectRules are a namespaced part's rules on the namespace
// object, which a RoleBinding grants in its own namespace.
func namespaceObjectRules(rules []kubeprofile.Rule) []map[string]any {
	var out []map[string]any
	for _, policy := range rules {
		if !groupMatches(policy.APIGroups, "") {
			continue
		}
		var resources []string
		for _, resource := range []string{"namespaces", "namespaces/status", "namespaces/finalize"} {
			_, subresource, _ := strings.Cut(resource, "/")
			if resourceMatches(policy.Resources, resource, subresource) {
				resources = append(resources, resource)
			}
		}
		if len(resources) > 0 {
			concrete := map[string]any{"apiGroups": []string{""}, "resources": resources, "verbs": policy.Verbs}
			if len(policy.ResourceNames) > 0 {
				concrete["resourceNames"] = policy.ResourceNames
			}
			out = append(out, concrete)
		}
	}
	return out
}

func groupMatches(groups []string, group string) bool {
	return slices.Contains(groups, "*") || slices.Contains(groups, group)
}

func resourceMatches(resources []string, combined, subresource string) bool {
	for _, resource := range resources {
		if resource == "*" || resource == combined ||
			subresource != "" && resource == "*/"+subresource {
			return true
		}
	}
	return false
}

func pathMatches(urls []string, path string) bool {
	for _, pattern := range urls {
		if pattern == "*" || pattern == path ||
			strings.HasSuffix(pattern, "*") && strings.HasPrefix(path, strings.TrimRight(pattern, "*")) {
			return true
		}
	}
	return false
}

// named rewrites the rules that cover the request only through a wildcard
// (group, resource, path pattern, or "*" for the proxy verb) to name it
// exactly; verbs, names and namespaces stay. changed reports whether any
// rule was rewritten: a refusal the named profile lifts is the design's
// naming rule (S2, S4, S6), not a mistake in matching.
func named(profile kubeprofile.Profile, attributes kubeprofile.Attributes) (kubeprofile.Profile, bool) {
	changed := false
	combined := attributes.Resource
	if attributes.Subresource != "" {
		combined += "/" + attributes.Subresource
	}
	rewrite := func(rules []kubeprofile.Rule) []kubeprofile.Rule {
		out := make([]kubeprofile.Rule, 0, len(rules))
		for _, policy := range rules {
			rewritten := policy
			switch {
			case !attributes.ResourceRequest && len(policy.NonResourceURLs) > 0 &&
				pathMatches(policy.NonResourceURLs, attributes.Path) && !slices.Contains(policy.NonResourceURLs, attributes.Path):
				rewritten.NonResourceURLs = append(slices.Clone(policy.NonResourceURLs), attributes.Path)
				changed = true
			case attributes.ResourceRequest && len(policy.NonResourceURLs) == 0 &&
				groupMatches(policy.APIGroups, attributes.APIGroup) &&
				resourceMatches(policy.Resources, combined, attributes.Subresource):
				exact := slices.Contains(policy.APIGroups, attributes.APIGroup) && slices.Contains(policy.Resources, combined)
				if !exact {
					rewritten.APIGroups, rewritten.Resources = []string{attributes.APIGroup}, []string{combined}
					changed = true
				}
				if attributes.Verb == "proxy" && slices.Contains(policy.Verbs, "*") && !slices.Contains(policy.Verbs, "proxy") {
					rewritten.Verbs = append(slices.Clone(policy.Verbs), "proxy")
					changed = true
				}
			}
			out = append(out, rewritten)
		}
		return out
	}
	return kubeprofile.Profile{Name: profile.Name, Namespaced: rewrite(profile.Namespaced),
		Cluster: rewrite(profile.Cluster)}, changed
}

// stricter names the design's naming rule a refusal falls under.
func stricter(attributes kubeprofile.Attributes) string {
	switch {
	case !attributes.ResourceRequest && attributes.Upgrade:
		return "S2 path upgrade"
	case !attributes.ResourceRequest:
		return ""
	case attributes.Upgrade || slices.Contains([]string{"exec", "attach", "portforward", "proxy"}, attributes.Subresource) ||
		attributes.Verb == "proxy":
		return "S2 sensitive"
	case attributes.APIGroup == "" && attributes.Resource == "namespaces" && attributes.Namespace != "":
		return "S4 namespace object"
	case attributes.Scope == kubeprofile.ScopeCluster && !slices.Contains([]string{"get", "list", "watch"}, attributes.Verb) &&
		(attributes.APIGroup == "" && slices.Contains([]string{"namespaces", "persistentvolumes"}, attributes.Resource) ||
			slices.Contains([]string{"rbac.authorization.k8s.io", "admissionregistration.k8s.io",
				"apiextensions.k8s.io", "certificates.k8s.io", "apiregistration.k8s.io"}, attributes.APIGroup)):
		return "S6 cluster takeover"
	}
	return ""
}

func labels() map[string]any {
	return map[string]any{"labels": map[string]string{oracleLabel: "oracle"}}
}

func metadata(name string) map[string]any {
	meta := labels()
	meta["name"] = name
	return meta
}

// grant writes one sample's RBAC for account.
func (c *cluster) grant(index int, sample sample, account string) {
	subject := []map[string]string{{"kind": "ServiceAccount", "name": account, "namespace": oracleNamespace}}
	roleRef := func(name string) map[string]string {
		return map[string]string{"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": name}
	}
	role := func(name string, rules []map[string]any) {
		if rules == nil {
			rules = []map[string]any{}
		}
		c.must(http.MethodPost, "/apis/rbac.authorization.k8s.io/v1/clusterroles",
			map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole", "metadata": metadata(name), "rules": rules})
	}
	bindCluster := func(name string) {
		c.must(http.MethodPost, "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
			map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": metadata(name),
				"roleRef": roleRef(name), "subjects": subject})
	}
	bindIn := func(namespace, name string) {
		c.must(http.MethodPost, "/apis/rbac.authorization.k8s.io/v1/namespaces/"+namespace+"/rolebindings",
			map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": metadata(name),
				"roleRef": roleRef(name), "subjects": subject})
	}
	prefix := fmt.Sprintf("mt-k2b-%02d", index)
	role(prefix+"-ns", c.expand(sample.profile.Namespaced, kubeprofile.ScopeNamespaced))
	role(prefix+"-nsobj", namespaceObjectRules(sample.profile.Namespaced))
	namespaces := sample.namespaces
	if slices.Equal(namespaces, []string{"*"}) {
		bindCluster(prefix + "-ns")
		namespaces = corpusNamespaces
	} else {
		for _, namespace := range namespaces {
			bindIn(namespace, prefix+"-ns")
		}
	}
	for _, namespace := range namespaces {
		bindIn(namespace, prefix+"-nsobj")
	}
	if sample.clusterPart {
		role(prefix+"-cl", c.expand(sample.profile.Cluster, kubeprofile.ScopeCluster))
		bindCluster(prefix + "-cl")
	}
}

// review asks the API server whether account may do what attributes name
// with verb.
func (c *cluster) review(account string, attributes kubeprofile.Attributes, verb string) bool {
	spec := map[string]any{"user": "system:serviceaccount:" + oracleNamespace + ":" + account,
		"groups": []string{"system:serviceaccounts", "system:serviceaccounts:" + oracleNamespace, "system:authenticated"}}
	if attributes.ResourceRequest {
		spec["resourceAttributes"] = map[string]string{"namespace": attributes.Namespace, "verb": verb,
			"group": attributes.APIGroup, "resource": attributes.Resource, "subresource": attributes.Subresource,
			"name": attributes.Name}
	} else {
		spec["nonResourceAttributes"] = map[string]string{"path": attributes.Path, "verb": verb}
	}
	status, out := c.call(http.MethodPost, "/apis/authorization.k8s.io/v1/subjectaccessreviews",
		map[string]any{"apiVersion": "authorization.k8s.io/v1", "kind": "SubjectAccessReview", "spec": spec})
	var answer struct {
		Status struct {
			Allowed bool `json:"allowed"`
		} `json:"status"`
	}
	if status != http.StatusCreated || json.Unmarshal(out, &answer) != nil {
		c.t.Errorf("review %+v: %d %s", attributes, status, out)
		return false
	}
	return answer.Status.Allowed
}

// oracle is the API server's decision: every verb it checks allowed.
func (c *cluster) oracle(account string, attributes kubeprofile.Attributes, sent request) bool {
	for _, verb := range checkedVerbs(attributes, sent) {
		if !c.review(account, attributes, verb) {
			return false
		}
	}
	return true
}

// installWidgets serves the oracle's own namespaced custom resource with
// status and scale, and waits for discovery to list it.
func (c *cluster) installWidgets() {
	crd := map[string]any{"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
		"metadata": metadata(widgetCRD),
		"spec": map[string]any{"group": widgetGroup, "scope": "Namespaced",
			"names": map[string]any{"plural": "widgets", "singular": "widget", "kind": "Widget"},
			"versions": []map[string]any{{"name": "v1", "served": true, "storage": true,
				"schema": map[string]any{"openAPIV3Schema": map[string]any{"type": "object",
					"x-kubernetes-preserve-unknown-fields": true}},
				"subresources": map[string]any{"status": map[string]any{}, "scale": map[string]any{
					"specReplicasPath": ".spec.replicas", "statusReplicasPath": ".status.replicas"}}}}}}
	c.must(http.MethodPost, "/apis/apiextensions.k8s.io/v1/customresourcedefinitions", crd)
	for range 60 {
		if status, _ := c.call(http.MethodGet, "/apis/"+widgetGroup+"/v1", nil); status == http.StatusOK {
			return
		}
		time.Sleep(time.Second)
	}
	c.t.Fatal("widgets never served")
}

// await waits for an earlier run's namespaces and custom resource to be
// gone if they are being deleted.
func (c *cluster) await() {
	paths := []string{"/apis/apiextensions.k8s.io/v1/customresourcedefinitions/" + widgetCRD}
	for _, namespace := range []string{oracleNamespace, teamA, teamB} {
		paths = append(paths, "/api/v1/namespaces/"+namespace)
	}
	for _, path := range paths {
		for attempt := 0; ; attempt++ {
			status, out := c.call(http.MethodGet, path, nil)
			if status == http.StatusNotFound {
				break
			}
			if status != http.StatusOK {
				c.t.Fatalf("GET %s: %d %s", path, status, out)
			}
			if !bytes.Contains(out, []byte(`"deletionTimestamp"`)) {
				break
			}
			if attempt == 120 {
				c.t.Fatal(path + " is still being deleted")
			}
			time.Sleep(time.Second)
		}
	}
}

func (c *cluster) cleanup() {
	selector := "?labelSelector=" + url.QueryEscape(oracleLabel+"=oracle")
	c.remove("/apis/rbac.authorization.k8s.io/v1/clusterrolebindings" + selector)
	c.remove("/apis/rbac.authorization.k8s.io/v1/clusterroles" + selector)
	c.remove("/apis/rbac.authorization.k8s.io/v1/namespaces/kube-system/rolebindings" + selector)
	status, out := c.call(http.MethodGet, "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/"+widgetCRD, nil)
	switch {
	case status == http.StatusOK && bytes.Contains(out, []byte(`"`+oracleLabel+`":"oracle"`)):
		c.remove("/apis/apiextensions.k8s.io/v1/customresourcedefinitions/" + widgetCRD)
	case status != http.StatusNotFound:
		c.t.Fatalf("custom resource %s: %d (not the oracle's, or unreadable): %s", widgetCRD, status, out)
	}
	for _, namespace := range []string{oracleNamespace, teamA, teamB} {
		c.remove("/api/v1/namespaces/" + namespace)
	}
}

// canary is one request a binding alone lets an account make.
type canary struct {
	account    string
	attributes kubeprofile.Attributes
	sent       request
}

// awaitBindings waits until the RBAC authorizer allows each canary: it
// reads RoleBindings, ClusterRoleBindings and ClusterRoles through
// separate informers.
func (c *cluster) awaitBindings(canaries []canary) {
	deadline := time.Now().Add(60 * time.Second)
	for _, check := range canaries {
		for !c.oracle(check.account, check.attributes, check.sent) {
			if time.Now().After(deadline) {
				c.t.Fatalf("%s: RBAC never allowed %s %s, which its profile allows: wider than RBAC, or bindings "+
					"not taken", check.account, check.sent.method, check.sent.path)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
}

type parsed struct {
	request    request
	attributes kubeprofile.Attributes
}

// canariesFor picks, for each binding a sample's grant writes, a request
// only that binding lets the account make and its profile allows.
func canariesFor(account string, sample sample, scope kubeprofile.Scope, reviewed []parsed) []canary {
	var out []canary
	pick := func(match func(kubeprofile.Attributes) bool) {
		for _, item := range reviewed {
			if match(item.attributes) && scope.Allows(item.attributes) {
				out = append(out, canary{account, item.attributes, item.request})
				return
			}
		}
	}
	namespaces := sample.namespaces
	if slices.Equal(namespaces, []string{"*"}) {
		namespaces = corpusNamespaces
	}
	for _, namespace := range namespaces {
		pick(func(attributes kubeprofile.Attributes) bool {
			return attributes.Scope == kubeprofile.ScopeNamespaced && attributes.Namespace == namespace
		})
		pick(func(attributes kubeprofile.Attributes) bool {
			return attributes.Resource == "namespaces" && attributes.Namespace == namespace
		})
	}
	if sample.clusterPart {
		pick(func(attributes kubeprofile.Attributes) bool {
			return attributes.Scope == kubeprofile.ScopeCluster && attributes.Namespace == "" || !attributes.ResourceRequest
		})
	}
	return out
}

func TestProfileOracle(t *testing.T) {
	c := connect(t)
	c.lock()
	c.await()
	c.cleanup()
	c.await()
	t.Cleanup(c.cleanup)
	for _, namespace := range []string{oracleNamespace, teamA, teamB} {
		c.must(http.MethodPost, "/api/v1/namespaces", map[string]any{"apiVersion": "v1", "kind": "Namespace",
			"metadata": metadata(namespace)})
	}
	c.installWidgets()
	c.discover()
	set := samples()
	for index := range len(set) + 1 {
		c.must(http.MethodPost, "/api/v1/namespaces/"+oracleNamespace+"/serviceaccounts",
			map[string]any{"apiVersion": "v1", "kind": "ServiceAccount", "metadata": metadata(fmt.Sprintf("oracle-%02d", index))})
	}
	for index, sample := range set {
		c.grant(index, sample, fmt.Sprintf("oracle-%02d", index))
	}

	requests := corpus()
	var reviewed []parsed
	blank := fmt.Sprintf("oracle-%02d", len(set)) // bound to nothing
	for _, sent := range requests {
		attributes, ok := c.attributes(sent)
		if !ok {
			continue
		}
		// Left out when it needs no binding at all (discovery, public paths,
		// self reviews).
		if !c.oracle(blank, attributes, sent) {
			reviewed = append(reviewed, parsed{sent, attributes})
		}
	}
	scopes := make([]kubeprofile.Scope, len(set))
	var canaries []canary
	for index, sample := range set {
		scope, err := kubeprofile.NewScope(sample.profile, sample.namespaces, sample.clusterPart)
		if err != nil {
			t.Fatalf("%s: %v", sample.name, err)
		}
		scopes[index] = scope
		canaries = append(canaries, canariesFor(fmt.Sprintf("oracle-%02d", index), sample, scope, reviewed)...)
	}
	c.awaitBindings(canaries)

	var (
		mutex      sync.Mutex
		failures   []string
		deviations = map[string]int{}
		agreements int
		allowed    int
	)
	var group sync.WaitGroup
	limit := make(chan struct{}, 16)
	for index, sample := range set {
		scope, account := scopes[index], fmt.Sprintf("oracle-%02d", index)
		for _, item := range reviewed {
			group.Add(1)
			limit <- struct{}{}
			go func() {
				defer func() { <-limit; group.Done() }()
				ours := scope.Allows(item.attributes)
				theirs := c.oracle(account, item.attributes, item.request)
				reason := ""
				if !ours && theirs {
					reason = excuse(sample, scope, item)
				}
				mutex.Lock()
				defer mutex.Unlock()
				describe := fmt.Sprintf("%s: %s %s (upgrade %v, %s)", sample.name, item.request.method,
					item.request.path, item.request.upgrade, item.request.contentType)
				switch {
				case ours == theirs:
					agreements++
					if ours {
						allowed++
					}
				case ours:
					failures = append(failures, "WIDER than RBAC: "+describe)
				case reason != "":
					deviations[reason]++
				default:
					failures = append(failures, "stricter with no reason: "+describe)
				}
			}()
		}
	}
	group.Wait()
	failures = append(failures, c.applyForReal(set)...)
	failures = append(failures, c.execForReal(set)...)
	sort.Strings(failures)
	for _, failure := range failures {
		t.Error(failure)
	}
	t.Logf("%d profiles × %d requests (%d left out as allowed with no binding): %d agree (%d allowed), "+
		"stricter on purpose %v, %d failures", len(set), len(reviewed), len(requests)-len(reviewed), agreements,
		allowed, deviations, len(failures))
}

// excuse names the design's reason the profile refuses what RBAC allows,
// or nothing: S3 for a PUT that passes without its create; a naming rule
// when naming exactly the rules that covered the request by a wildcard lets
// it pass.
func excuse(sample sample, scope kubeprofile.Scope, item parsed) string {
	if item.request.method == http.MethodPut && item.attributes.MayCreate {
		withoutCreate, create := item.attributes, item.attributes
		withoutCreate.MayCreate = false
		create.Verb, create.MayCreate = "create", false
		// Only for want of create: the profile must refuse create itself.
		if scope.Allows(withoutCreate) && !scope.Allows(create) {
			return "S3 put may create"
		}
	}
	profile, changed := named(sample.profile, item.attributes)
	if !changed {
		return ""
	}
	namedScope, err := kubeprofile.NewScope(profile, sample.namespaces, sample.clusterPart)
	if err != nil || !namedScope.Allows(item.attributes) {
		return ""
	}
	return stricter(item.attributes)
}

// applyForReal checks S3 on the API server itself: an apply that would
// create needs create, which the API server checks on the account — the
// reason the gateway, whose group may create, checks it first.
func (c *cluster) applyForReal(set []sample) []string {
	var failures []string
	for index, sample := range set {
		want, check := map[string]int{"update without create": http.StatusForbidden,
			"update with create": http.StatusCreated}[sample.name]
		if !check {
			continue
		}
		status, out := c.send(c.accountToken(fmt.Sprintf("oracle-%02d", index)), http.MethodPatch,
			"/api/v1/namespaces/"+teamA+"/configmaps/cfg-k2b?fieldManager=k2b&dryRun=All",
			"application/apply-patch+yaml", strings.NewReader("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cfg-k2b\n"))
		c.t.Logf("apply for real, %s: %d", sample.name, status)
		if status != want {
			failures = append(failures, fmt.Sprintf("%s: an apply that creates got %d, want %d: %s",
				sample.name, status, want, out))
		}
	}
	return failures
}

// execForReal checks S1 on the API server itself (MT_ORACLE_KUBECTL set),
// over both transports: SPDY opens a session by POST, which needs create;
// a WebSocket by GET, which needs get, and create too where the API server
// enforces AuthorizePodWebsocketUpgradeCreatePermission. The profile asks
// both either way. The pod runs pause, which has no command to run: the
// container runtime's own refusal of /no-such-command means the session
// opened.
func (c *cluster) execForReal(set []sample) []string {
	kubectl := os.Getenv("MT_ORACLE_KUBECTL")
	if kubectl == "" {
		c.t.Log("MT_ORACLE_KUBECTL unset: no exec for real")
		return nil
	}
	image := os.Getenv("MT_ORACLE_PAUSE")
	if image == "" {
		image = "registry.k8s.io/pause:3.10"
	}
	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	pod := "k2b-pause-" + hex.EncodeToString(suffix)
	c.must(http.MethodPost, "/api/v1/namespaces/"+teamA+"/pods", map[string]any{"apiVersion": "v1", "kind": "Pod",
		"metadata": metadata(pod), "spec": map[string]any{"terminationGracePeriodSeconds": 0,
			"containers": []map[string]any{{"name": "pause", "image": image, "imagePullPolicy": "IfNotPresent"}}}})
	running := false
	for range 90 {
		if _, out := c.call(http.MethodGet, "/api/v1/namespaces/"+teamA+"/pods/"+pod, nil); bytes.Contains(out, []byte(`"phase":"Running"`)) {
			running = true
			break
		}
		time.Sleep(time.Second)
	}
	if !running {
		return []string{"exec for real: pod " + pod + " never ran"}
	}
	// The child gets no admin token, no proxy and no kubeconfig but its own.
	environment := slices.DeleteFunc(os.Environ(), func(entry string) bool {
		name, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(name)
		return strings.HasPrefix(name, "MT_ORACLE_") || name == "KUBECONFIG" ||
			name == "KUBECTL_REMOTE_COMMAND_WEBSOCKETS" || strings.HasSuffix(upper, "_PROXY")
	})
	directory := c.t.TempDir()
	var failures []string
	verdicts := map[string]string{}
	for index, sample := range set {
		if !slices.Contains([]string{"on-call", "exec by create only", "exec by get only"}, sample.name) {
			continue
		}
		// A kubeconfig of its own, 0600, the CA embedded.
		config := filepath.Join(directory, fmt.Sprintf("kubeconfig-%02d", index))
		if err := os.WriteFile(config, []byte(fmt.Sprintf(`apiVersion: v1
kind: Config
clusters: [{name: lab, cluster: {server: %q, certificate-authority-data: %q}}]
users: [{name: oracle, user: {token: %q}}]
contexts: [{name: lab, context: {cluster: lab, user: oracle}}]
current-context: lab
`, c.server, base64.StdEncoding.EncodeToString(c.ca), c.accountToken(fmt.Sprintf("oracle-%02d", index)))), 0o600); err != nil {
			c.t.Fatal(err)
		}
		for _, websocket := range []bool{true, false} {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			command := exec.CommandContext(ctx, kubectl, "-v=6", "--request-timeout=30s", "exec", "--namespace", teamA,
				pod, "--", "/no-such-command")
			command.Env = append(slices.Clone(environment), "KUBECONFIG="+config, "KUBERC=off",
				fmt.Sprintf("KUBECTL_REMOTE_COMMAND_WEBSOCKETS=%v", websocket))
			output, _ := command.CombinedOutput()
			cancel()
			lower := strings.ToLower(string(output))
			// The runtime's refusal, which kubectl relays as an internal
			// error: only a session that opened gets that far.
			ran := strings.Contains(lower, "oci runtime exec failed") && strings.Contains(lower, "/no-such-command")
			forbidden := !ran && strings.Contains(lower, "forbidden")
			// The methods kubectl sent to the exec path, in order.
			var sent []string
			for _, line := range strings.Split(string(output), "\n") {
				if !strings.Contains(line, "/"+pod+"/exec") {
					continue
				}
				for _, method := range []string{"GET", "POST"} {
					if strings.Contains(line, `verb="`+method+`"`) || strings.Contains(line, method+" https") {
						sent = append(sent, method)
					}
				}
			}
			transport := map[bool]string{true: "websocket", false: "spdy"}[websocket]
			c.t.Logf("exec for real, %s over %s: sent %v, forbidden %v, ran %v", sample.name, transport, sent,
				forbidden, ran)
			switch {
			case !forbidden && !ran:
				failures = append(failures, fmt.Sprintf("%s over %s: neither forbidden nor run: %s",
					sample.name, transport, strings.TrimSpace(string(output))))
				continue
			case len(sent) == 0:
				failures = append(failures, fmt.Sprintf("%s over %s: no exec request in kubectl's log", sample.name, transport))
				continue
			case websocket && sent[0] != "GET", !websocket && slices.Contains(sent, "GET"):
				failures = append(failures, fmt.Sprintf("%s over %s: kubectl sent %v", sample.name, transport, sent))
				continue
			}
			outcome := map[bool]string{true: "ran", false: "forbidden"}[ran]
			// A WebSocket refused and run after kubectl fell back to SPDY.
			if websocket && ran && slices.Contains(sent, "POST") {
				outcome = "ran over spdy"
			}
			verdicts[sample.name+" "+transport] = outcome
		}
	}
	// Whatever the cluster enforces: get and create run over both; SPDY needs
	// create, so get alone never runs over it.
	for key, want := range map[string]string{"on-call websocket": "ran", "on-call spdy": "ran",
		"exec by create only spdy": "ran", "exec by get only spdy": "forbidden"} {
		if verdicts[key] != want {
			failures = append(failures, fmt.Sprintf("exec for real, %s: %s, want %s", key, verdicts[key], want))
		}
	}
	c.t.Logf("exec for real: this API server lets get alone open a WebSocket session: %v; create alone: %s",
		verdicts["exec by get only websocket"] == "ran", verdicts["exec by create only websocket"])
	return failures
}
