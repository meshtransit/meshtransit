//go:build difftest

package kubeproxy

// The differential test (K1b design §5, criterion 7; b7b): requests go
// through the proxy to a real API server whose audit log records them.
// For each, what the gateway logged and what it had Core record (class,
// verb, group, resource, subresource, namespace, name) must match what the
// API server understood, joined by Audit-ID; the class must be the one §5
// gives what the API server saw, judged apart from kubereq; and every
// request must reach the API server as the group's account, never with the
// client's credentials or impersonation (K1-I3). Run against a lab cluster
// only:
//
//	MT_DIFF_SERVER=https://127.0.0.1:6443 MT_DIFF_CA=ca.crt MT_DIFF_TOKEN=... \
//	MT_DIFF_USER=system:serviceaccount:mt-kube-k1:mt-diff \
//	MT_DIFF_AUDIT='cat /var/log/kubernetes/audit/audit.log' [MT_DIFF_KUBECTL=kubectl] \
//	go test -tags difftest -run TestDifferential -v ./internal/kubeproxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/kubeaudit"
	"meshtransit.net/client/internal/kubereq"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/rbaccheck"
)

// sample is one request of the set.
type sample struct {
	method, path, body string
	header             http.Header
}

// secretLike is the resource the test has read like a secret.
var secretLike = kubereq.GroupResource{Group: "diff.meshtransit.net", Resource: "widgets"}

func samples() []sample {
	upgrade := func(protocol string) http.Header {
		return http.Header{"Connection": {"Upgrade"}, "Upgrade": {protocol}}
	}
	set := []sample{}
	get := func(paths ...string) {
		for _, path := range paths {
			set = append(set, sample{method: http.MethodGet, path: path})
		}
	}
	// Non-resource: the safe ones read, the rest unparsed (§5).
	get("/api", "/apis", "/api/v1", "/apis/apps", "/apis/apps/v1", "/version", "/openapi/v2", "/openapi/v3",
		"/openapi/v3/apis/apps/v1", "/.well-known/openid-configuration", "/openid/v1/jwks", "/healthz", "/livez",
		"/readyz", "/readyz/etcd", "/apis/fake.meshtransit.net/v1alpha1", "/apis/diff.meshtransit.net/v1",
		"/metrics", "/logs/", "/debug/pprof/")
	set = append(set,
		sample{method: http.MethodHead, path: "/version"},
		sample{method: http.MethodPost, path: "/api", body: `{}`},
		sample{method: http.MethodPost, path: "/version", body: `{}`},
	)
	// Resources, watches and selectors.
	get("/api/v1/namespaces/default/pods", "/api/v1/pods", "/api/v1/namespaces/default/pods/x",
		"/api/v1/namespaces/default/pods?watch=true&timeoutSeconds=1",
		"/api/v1/namespaces/default/pods?watch=1&timeoutSeconds=1",
		"/api/v1/namespaces/default/pods?watch=&timeoutSeconds=1",
		"/api/v1/namespaces/default/pods?watch=FALSE&timeoutSeconds=1",
		"/api/v1/namespaces/default/pods?watch=1&watch=0&timeoutSeconds=1",
		"/api/v1/namespaces/default/pods?fieldSelector=metadata.name%3Dx&watch=1&timeoutSeconds=1",
		"/api/v1/namespaces/default/pods?fieldSelector=metadata.name%3D%3Dx&labelSelector=a%3Db&watch=1&timeoutSeconds=1",
		"/api/v1/watch/namespaces/default/pods?timeoutSeconds=1", "/api/v1/watch/namespaces/default/pods/x?timeoutSeconds=1",
		"/api/v1/namespaces/default/pods?labelSelector=a&limit=5", "/api/v1/nodes",
		"/api/v1/nodes/meshgw-a-control-plane", "/api/v1/namespaces", "/api/v1/namespaces/default",
		"/apis/apps/v1/namespaces/kube-system/deployments", "/apis/apps/v1/namespaces/kube-system/deployments/coredns/scale",
		"/api/v1/namespaces/default/secrets", "/api/v1/namespaces/default/secrets/x",
		"/api/v1/namespaces/default/secrets?watch=true&timeoutSeconds=1", "/api/v1/secrets",
		"/api/v1/namespaces/default/pods/x/log", "/api/v1/namespaces/default/pods/x/log?follow=true",
		"/api/v1/namespaces/default/services/kubernetes/proxy/", "/api/v1/namespaces/default/pods/x/proxy/healthz",
		"/api/v1/nodes/meshgw-a-control-plane/proxy/metrics",
		"/apis/diff.meshtransit.net/v1/namespaces/default/widgets", "/apis/diff.meshtransit.net/v1/widgets",
		"/apis/diff.meshtransit.net/v1/namespaces/default/widgets/w",
		"/apis/diff.meshtransit.net/v1/namespaces/default/widgets/w/status",
		"/apis/diff.meshtransit.net/v1/namespaces/default/widgets/w/scale",
		"/apis/fake.meshtransit.net/v1alpha1/namespaces/default/things",
		"/apis/fake.meshtransit.net/v1alpha1/namespaces/default/things/t",
		"/apis/rbac.authorization.k8s.io/v1/clusterroles/view",
		// The gateway's own group path names a group.
		"/mt/g/diff/api/v1/namespaces/default/pods", "/mt/g/other/api/v1/namespaces/default/configmaps")
	jsonType := http.Header{"Content-Type": {"application/json"}}
	set = append(set,
		sample{method: http.MethodHead, path: "/api/v1/namespaces/default/pods"},
		sample{method: http.MethodPost, path: "/api/v1/namespaces/default/configmaps", header: jsonType,
			body: `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"diff"}}`},
		sample{method: http.MethodPut, path: "/api/v1/namespaces/default/configmaps/diff", header: jsonType,
			body: `{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"diff"}}`},
		sample{method: http.MethodPatch, path: "/api/v1/namespaces/default/configmaps/diff", body: `{"data":{}}`,
			header: http.Header{"Content-Type": {"application/merge-patch+json"}}},
		sample{method: http.MethodDelete, path: "/api/v1/namespaces/default/configmaps/diff"},
		sample{method: http.MethodDelete, path: "/mt/g/other/api/v1/namespaces/default/configmaps/diff"},
		sample{method: http.MethodDelete, path: "/api/v1/namespaces/default/configmaps"},
		sample{method: http.MethodDelete, path: "/api/v1/namespaces/default/pods"},
		sample{method: http.MethodPost, path: "/api/v1/watch/namespaces/default/pods", header: jsonType, body: `{}`},
		sample{method: http.MethodPost, path: "/api/v1/namespaces/default/pods/x/eviction", header: jsonType,
			body: `{"apiVersion":"policy/v1","kind":"Eviction","metadata":{"name":"x"}}`},
		sample{method: http.MethodPatch, path: "/api/v1/namespaces/default/pods/x/ephemeralcontainers", body: `{}`,
			header: http.Header{"Content-Type": {"application/strategic-merge-patch+json"}}},
		sample{method: http.MethodPost, path: "/api/v1/namespaces/default/pods/x/exec?command=ls&stdout=true",
			header: upgrade("SPDY/3.1")},
		sample{method: http.MethodGet, path: "/api/v1/namespaces/default/pods/x/exec?command=ls&stdout=true",
			header: upgrade("websocket")},
		// An exec without an upgrade, and an upgrade on another path.
		sample{method: http.MethodPost, path: "/api/v1/namespaces/default/pods/x/exec?command=ls&stdout=true"},
		sample{method: http.MethodGet, path: "/api/v1/namespaces/default/pods/x/proxy/ws", header: upgrade("websocket")},
		sample{method: http.MethodPost, path: "/api/v1/namespaces/default/pods/x/attach?stdout=true",
			header: upgrade("SPDY/3.1")},
		sample{method: http.MethodPost, path: "/api/v1/namespaces/default/pods/x/portforward?ports=80",
			header: upgrade("SPDY/3.1")},
		sample{method: http.MethodGet, path: "/apis/fake.meshtransit.net/v1alpha1/namespaces/default/things/t/console",
			header: upgrade("websocket")},
		sample{method: http.MethodPost, path: "/apis/authorization.k8s.io/v1/selfsubjectaccessreviews", header: jsonType,
			body: `{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectAccessReview","spec":{"resourceAttributes":{"verb":"get","resource":"pods"}}}`},
		sample{method: http.MethodPost, path: "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews", header: jsonType,
			body: `{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}`},
		sample{method: http.MethodPost, path: "/apis/authentication.k8s.io/v1/tokenreviews", header: jsonType,
			body: `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenReview","spec":{"token":"x"}}`},
		sample{method: http.MethodPost, path: "/api/v1/namespaces/mt-kube-k1/serviceaccounts/mt-view/token",
			header: jsonType, body: `{"apiVersion":"authentication.k8s.io/v1","kind":"TokenRequest","spec":{}}`},
		sample{method: http.MethodPost, path: "/apis/diff.meshtransit.net/v1/namespaces/default/widgets", header: jsonType,
			body: `{"apiVersion":"diff.meshtransit.net/v1","kind":"Widget","metadata":{"name":"w"}}`},
		sample{method: http.MethodPut, path: "/apis/diff.meshtransit.net/v1/namespaces/default/widgets/w/scale",
			header: jsonType, body: `{"apiVersion":"autoscaling/v1","kind":"Scale","metadata":{"name":"w"},"spec":{"replicas":2}}`},
		sample{method: http.MethodPost, path: "/apis/fake.meshtransit.net/v1alpha1/namespaces/default/things",
			header: jsonType, body: `{}`},
		sample{method: http.MethodPost, path: "/api/v1/namespaces/default/services/kubernetes/proxy/x",
			header: jsonType, body: `{}`},
		// kubectl's port-forward over WebSocket: the ports in a subprotocol.
		sample{method: http.MethodGet, path: "/api/v1/namespaces/default/pods/x/portforward", header: http.Header{
			"Connection": {"Upgrade"}, "Upgrade": {"websocket"}, "Sec-Websocket-Version": {"13"},
			"Sec-Websocket-Key":      {"dGhlIHNhbXBsZSBub25jZQ=="},
			"Sec-Websocket-Protocol": {"SPDY/3.1+portforward.k8s.io"}}},
		// The client's credentials never reach the API server (K1-I3).
		sample{method: http.MethodGet, path: "/api/v1/namespaces/default/configmaps", header: http.Header{
			"Authorization": {"Bearer client-token"}, "Impersonate-User": {"admin"},
			"Impersonate-Group": {"system:masters"}, "X-Remote-User": {"admin"},
			"Proxy-Authorization": {"Basic eDp5"}}},
		sample{method: http.MethodGet, path: "/api/v1/namespaces/default/pods/x/exec?command=ls&stdout=true",
			header: http.Header{"Connection": {"Upgrade"}, "Upgrade": {"websocket"},
				"Sec-Websocket-Protocol": {"v5.channel.k8s.io, base64url.bearer.authorization.k8s.io.Y2xpZW50"}}},
	)
	return set
}

// logged is what the gateway logged of one request.
type logged struct {
	auditID, class, verb, group, resource, subresource, namespace, name string
}

// captureHandler keeps the proxy's "kube request" lines.
type captureHandler struct {
	mu    sync.Mutex
	rows  []logged
	other func(string)
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *captureHandler) WithGroup(string) slog.Handler            { return h }

func (h *captureHandler) Handle(_ context.Context, record slog.Record) error {
	if record.Message != "kube request" {
		if h.other != nil {
			text := record.Message
			record.Attrs(func(attr slog.Attr) bool {
				text += " " + attr.Key + "=" + attr.Value.String()
				return true
			})
			h.other(text)
		}
		return nil
	}
	row := logged{}
	record.Attrs(func(attr slog.Attr) bool {
		value := attr.Value.String()
		switch attr.Key {
		case "audit_id":
			row.auditID = value
		case "class":
			row.class = value
		case "verb":
			row.verb = value
		case "api_group":
			row.group = value
		case "resource":
			row.resource = value
		case "subresource":
			row.subresource = value
		case "namespace":
			row.namespace = value
		case "name":
			row.name = value
		}
		return true
	})
	h.mu.Lock()
	h.rows = append(h.rows, row)
	h.mu.Unlock()
	return nil
}

type staticTokens struct{ value string }

func (tokens staticTokens) For(context.Context, string, string, string) (Bearer, error) {
	return bearer{value: tokens.value}, nil
}
func (staticTokens) Forget(string, string, string, Bearer) {}

// intents keeps what Core would record, by the audit ID it gave.
type intents struct {
	mu   sync.Mutex
	byID map[string]controlplane.KubeAuditIntent
}

func (recorded *intents) Record(_ context.Context, _ string, intent controlplane.KubeAuditIntent) kubeaudit.Answer {
	var id [16]byte
	_, _ = rand.Read(id[:])
	id[6] = id[6]&0x0f | 0x40
	id[8] = id[8]&0x3f | 0x80
	recorded.mu.Lock()
	recorded.byID[formatAuditID(id)] = intent
	recorded.mu.Unlock()
	return kubeaudit.Answer{Recorded: true, AuditID: id}
}
func (*intents) Finished([16]byte, int, time.Duration) {}
func (*intents) Denied(string, string)                 {}

// auditEvent is what the API server's audit log holds of a request.
type auditEvent struct {
	AuditID    string `json:"auditID"`
	Verb       string `json:"verb"`
	RequestURI string `json:"requestURI"`
	User       struct {
		Username string `json:"username"`
	} `json:"user"`
	ImpersonatedUser *struct {
		Username string `json:"username"`
	} `json:"impersonatedUser"`
	ObjectRef *struct {
		Resource, Namespace, Name, APIGroup, Subresource string
	} `json:"objectRef"`
}

func TestDifferential(t *testing.T) {
	server, ca, token, audit, user := os.Getenv("MT_DIFF_SERVER"), os.Getenv("MT_DIFF_CA"),
		os.Getenv("MT_DIFF_TOKEN"), os.Getenv("MT_DIFF_AUDIT"), os.Getenv("MT_DIFF_USER")
	if server == "" || ca == "" || token == "" || audit == "" || user == "" {
		t.Skip("MT_DIFF_SERVER, MT_DIFF_CA, MT_DIFF_TOKEN, MT_DIFF_USER and MT_DIFF_AUDIT name the lab cluster")
	}
	capture := &captureHandler{other: func(line string) { t.Log("gateway: " + line) }}
	recorded := &intents{byID: map[string]controlplane.KubeAuditIntent{}}
	certificate, pool := testCertificate(t)
	grants := []networkmap.KubernetesGrant{{Group: "diff", ValidUntil: time.Now().Add(time.Hour)},
		{Group: "other", ValidUntil: time.Now().Add(time.Hour)}}
	proxy, err := New(Options{
		Cluster: "diff", Namespace: "mt-kube-k1",
		Groups:  []Group{{Name: "diff", Default: true}, {Name: "other"}},
		Backend: server, BackendCA: ca,
		Peer: func(netip.Addr) (Peer, bool) {
			return Peer{DeviceID: "device-diff", Name: "diff", Key: [32]byte{1},
				Access: &networkmap.KubernetesAccess{OwnerRef: "person-diff", Grants: grants}}, true
		},
		Certificate: func() (*tls.Certificate, bool) { return certificate, true },
		MapFreshAt:  time.Now, StaleAfter: 5 * time.Minute, CoreNow: time.Now,
		Verdict: func(string) rbaccheck.Verdict { return rbaccheck.Verdict{Enabled: true} },
		Records: recorded, Tokens: staticTokens{value: token}, SecretResources: []kubereq.GroupResource{secretLike},
		Version: "difftest", Logger: slog.New(capture),
	})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() { _ = proxy.Serve(ctx, listener) }()
	client := &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: clusterName},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
		},
	}}

	// Each sample's audit ID, from the answer: the expectation follows the
	// request sent, not a name known in advance.
	sent := map[string]sample{}
	for _, request := range samples() {
		outgoing, err := http.NewRequestWithContext(t.Context(), request.method, "https://"+clusterName+request.path,
			strings.NewReader(request.body))
		if err != nil {
			t.Fatal(err)
		}
		for name, values := range request.header {
			outgoing.Header[name] = values
		}
		response, err := client.Do(outgoing)
		if err != nil {
			t.Errorf("%s %s: %v", request.method, request.path, err)
			continue
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if id := response.Header.Get("Audit-Id"); id != "" {
			sent[id] = request
		} else {
			t.Errorf("%s %s: answered %d without an Audit-Id", request.method, request.path, response.StatusCode)
		}
	}
	kubectlRuns := runKubectl(t, listener.Addr().String())

	events := waitAudit(t, audit, sent)
	capture.mu.Lock()
	rows := slices.Clone(capture.rows)
	capture.mu.Unlock()
	mismatches := 0
	fail := func(format string, args ...any) {
		t.Errorf(format, args...)
		mismatches++
	}
	for _, row := range rows {
		event, found := events[row.auditID]
		if !found {
			fail("%s %s/%s: not in the audit log", row.verb, row.resource, row.subresource)
			continue
		}
		// As the group's account, never as the client or someone it named.
		if event.User.Username != user || event.ImpersonatedUser != nil {
			fail("%s: reached the API server as %q, impersonating %v", event.RequestURI, event.User.Username,
				event.ImpersonatedUser)
		}
		var want logged
		want.verb = event.Verb
		if ref := event.ObjectRef; ref != nil {
			want.group, want.resource, want.subresource, want.namespace, want.name = ref.APIGroup, ref.Resource,
				ref.Subresource, ref.Namespace, ref.Name
		}
		got := logged{verb: row.verb, group: row.group, resource: row.resource, subresource: row.subresource,
			namespace: row.namespace, name: row.name}
		if got != want {
			fail("%s: gateway %+v\n  api server %+v", event.RequestURI, got, want)
			continue
		}
		request, ours := sent[row.auditID]
		class := expectedClass(event, request, ours)
		if class != kubereq.Class(row.class) {
			fail("%s: class %s, want %s", event.RequestURI, row.class, class)
			continue
		}
		// What Core records is what the API server saw.
		recorded.mu.Lock()
		intent, recordedIt := recorded.byID[row.auditID]
		recorded.mu.Unlock()
		if class.TypeA() != recordedIt {
			fail("%s: type A %t, recorded %t", event.RequestURI, class.TypeA(), recordedIt)
			continue
		}
		// A request on a group's path is the group's (re-review b7b L1).
		wantGroup := "diff"
		if ours && strings.HasPrefix(request.path, "/mt/g/other/") {
			wantGroup = "other"
		}
		if recordedIt && !slices.Equal(intent.Groups, []string{wantGroup}) {
			fail("%s: recorded for groups %v, want %s", event.RequestURI, intent.Groups, wantGroup)
			continue
		}
		if recordedIt && (intent.Class != string(class) || intent.Verb != want.verb ||
			intent.APIGroup != want.group || intent.Resource != want.resource ||
			intent.Subresource != want.subresource || intent.Namespace != want.namespace || intent.Name != want.name) {
			fail("%s: Core would record %+v", event.RequestURI, intent)
			continue
		}
		t.Logf("match %-12s %-16s %s", row.class, row.verb, event.RequestURI)
	}
	if len(sent) == 0 || len(rows) < len(sent) {
		t.Errorf("%d samples answered, %d logged", len(sent), len(rows))
	}
	// kubectl's own requests came through: at least one per run (re-review
	// b7b L3).
	if kubectlRows := len(rows) - len(sent); kubectlRows < kubectlRuns {
		t.Errorf("only %d requests of %d kubectl runs", kubectlRows, kubectlRuns)
	}
	t.Logf("%d samples, %d kubectl runs, %d requests compared, %d mismatches", len(sent), kubectlRuns, len(rows),
		mismatches)
}

// safeNonResource is §5's list, written apart from kubereq.
func safeNonResource(method, path string) bool {
	if method != http.MethodGet && method != http.MethodHead {
		return false
	}
	parts := strings.Split(strings.Trim(path, "/"), "/")
	switch {
	case path == "/api" || path == "/apis" || path == "/version" || path == "/openapi/v2" ||
		path == "/.well-known/openid-configuration" || path == "/openid/v1/jwks":
		return true
	case parts[0] == "api" && len(parts) == 2, parts[0] == "apis" && (len(parts) == 2 || len(parts) == 3):
		return true
	case path == "/openapi/v3" || strings.HasPrefix(path, "/openapi/v3/"):
		return true
	case slices.Contains([]string{"healthz", "livez", "readyz"}, parts[0]):
		return true
	}
	return false
}

// expectedClass is the class §5 gives what the API server saw and the
// request sent, written apart from kubereq: an upgrade is exec whatever its
// path; a non-resource path not on the safe list is unparsed.
func expectedClass(event auditEvent, request sample, ours bool) kubereq.Class {
	if ours && request.header.Get("Upgrade") != "" {
		return kubereq.ClassExec
	}
	ref := event.ObjectRef
	if ref == nil {
		parsed, _ := url.Parse(event.RequestURI)
		method := strings.ToUpper(event.Verb)
		if ours {
			method = request.method
		}
		if safeNonResource(method, parsed.Path) {
			return kubereq.ClassRead
		}
		return kubereq.ClassUnparsed
	}
	reading := slices.Contains([]string{"get", "list", "watch"}, event.Verb)
	method := request.method
	if !ours {
		method = http.MethodGet
	}
	switch {
	// A reading verb a path names (watch/...) sent with another method is
	// not trusted as a read: an aggregated server may take it as a write.
	case reading && method != http.MethodGet && method != http.MethodHead &&
		!slices.Contains([]string{"exec", "attach", "portforward", "proxy"}, ref.Subresource):
		return kubereq.ClassUnparsed
	case slices.Contains([]string{"exec", "attach", "portforward"}, ref.Subresource):
		return kubereq.ClassExec
	case ref.Subresource == "proxy" || event.Verb == "proxy":
		return kubereq.ClassProxy
	// Any subresource of a secret-like resource may return the object.
	case reading && (ref.Resource == "secrets" && ref.APIGroup == "" ||
		ref.Resource == secretLike.Resource && ref.APIGroup == secretLike.Group):
		return kubereq.ClassSecretRead
	case slices.Contains([]string{"selfsubjectaccessreviews", "selfsubjectrulesreviews"}, ref.Resource):
		return kubereq.ClassRead
	case slices.Contains([]string{"create", "update", "patch", "delete", "deletecollection"}, event.Verb):
		return kubereq.ClassWrite
	}
	return kubereq.ClassRead
}

// runKubectl drives the proxy with real kubectl commands, when
// MT_DIFF_KUBECTL names one: real clients' paths and headers (WebSocket
// subprotocols, discovery). It returns how many ran.
func runKubectl(t *testing.T, address string) int {
	t.Helper()
	kubectl := os.Getenv("MT_DIFF_KUBECTL")
	if kubectl == "" {
		return 0
	}
	pod := os.Getenv("MT_DIFF_POD")
	if pod == "" {
		pod = "x"
	}
	// The cluster's name, as real clients use it, is to resolve to the
	// listener (an /etc/hosts line on the lab host).
	_, port, _ := net.SplitHostPort(address)
	dir := t.TempDir()
	// No credentials: the gateway is the authority (its test certificate is
	// not worth trusting here, so verification is skipped).
	kubeconfig := filepath.Join(dir, "kubeconfig")
	if err := os.WriteFile(kubeconfig, []byte("apiVersion: v1\nkind: Config\nclusters:\n- name: diff\n  cluster:\n"+
		"    server: https://"+clusterName+":"+port+"\n    insecure-skip-tls-verify: true\n"+
		"contexts:\n- name: diff\n  context: {cluster: diff, user: nobody}\nusers:\n- name: nobody\n  user: {token: none}\n"+
		"current-context: diff\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runs := [][]string{
		{"get", "pods", "-n", "default"}, {"get", "secrets", "-A"}, {"get", "widgets.diff.meshtransit.net", "-A"},
		// MT_DIFF_POD names a pod that exists, so exec, cp and debug send
		// their real upgrades and patches.
		{"logs", "-n", "default", pod}, {"exec", "-n", "default", pod, "--", "ls"},
		{"auth", "can-i", "list", "pods"}, {"delete", "configmap", "-n", "default", "nosuch"},
		{"debug", "-n", "default", pod, "--image=busybox"}, {"cp", "-n", "default", pod + ":/etc/hosts", filepath.Join(dir, "h")},
		{"port-forward", "-n", "default", "pod/" + pod, "18080:80", "--pod-running-timeout=2s"},
	}
	for _, args := range runs {
		time.Sleep(time.Second) // under the source's 10 handshakes a second
		command := exec.Command(kubectl, append([]string{"--kubeconfig", kubeconfig, "--request-timeout=10s"}, args...)...)
		output, _ := command.CombinedOutput()
		text := strings.ReplaceAll(string(output), "\n", " ")
		if len(text) > 120 && os.Getenv("MT_DIFF_VERBOSE") == "" {
			text = text[:120]
		}
		t.Logf("kubectl %s: %s", strings.Join(args, " "), text)
	}
	return len(runs)
}

// waitAudit reads the audit log until every sample's event is there.
func waitAudit(t *testing.T, command string, sent map[string]sample) map[string]auditEvent {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		events := readAudit(t, command)
		missing := 0
		for id := range sent {
			if _, found := events[id]; !found {
				missing++
			}
		}
		if missing == 0 || time.Now().After(deadline) {
			return events
		}
		time.Sleep(time.Second)
	}
}

// readAudit runs command and indexes its audit events by ID, keeping the
// latest stage.
func readAudit(t *testing.T, command string) map[string]auditEvent {
	t.Helper()
	output, err := exec.Command("sh", "-c", command).Output() //nolint:gosec // the lab's own command
	if err != nil {
		t.Fatalf("reading the audit log: %v", err)
	}
	events := map[string]auditEvent{}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	scanner.Buffer(make([]byte, 1<<20), 1<<24)
	for scanner.Scan() {
		var event auditEvent
		if json.Unmarshal(scanner.Bytes(), &event) == nil && event.AuditID != "" {
			events[event.AuditID] = event
		}
	}
	if len(events) == 0 {
		t.Fatalf("no audit events from %q", command)
	}
	return events
}
