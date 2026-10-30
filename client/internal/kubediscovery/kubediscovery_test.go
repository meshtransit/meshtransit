package kubediscovery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"meshtransit.net/shared/kubeprofile"
)

const testToken = "gateway-token-never-logged"

type resource struct{ name, scope string }

// version is one group version's resources.
type version struct {
	group, version string
	resources      []resource
}

func aggregated(versions ...version) []byte {
	type item struct {
		Metadata struct {
			Name string `json:"name"`
		} `json:"metadata"`
		Versions []map[string]any `json:"versions"`
	}
	byGroup := map[string]*item{}
	var order []string
	for _, v := range versions {
		held, found := byGroup[v.group]
		if !found {
			held = &item{}
			held.Metadata.Name = v.group
			byGroup[v.group] = held
			order = append(order, v.group)
		}
		resources := []map[string]any{}
		for _, r := range v.resources {
			resources = append(resources, map[string]any{
				"resource": r.name, "scope": r.scope,
				"verbs": []string{"get"}, "subresources": []map[string]any{{"subresource": "status"}},
			})
		}
		held.Versions = append(held.Versions, map[string]any{
			"version": v.version, "resources": resources,
			"freshness": "Current",
		})
	}
	items := []*item{}
	for _, group := range order {
		items = append(items, byGroup[group])
	}
	payload, err := json.Marshal(map[string]any{
		"apiVersion": discoveryVersion, "kind": discoveryKind,
		"items": items,
	})
	if err != nil {
		panic(err)
	}
	return payload
}

// apiServer serves both documents, counting fetches and checking each
// request as the API server would see it.
type apiServer struct {
	mu      sync.Mutex
	core    []byte
	groups  []byte
	fail    bool
	gets    atomic.Int64
	hold    chan struct{}
	headers http.Header
}

func (s *apiServer) set(core, groups []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.core, s.groups = core, groups
}

func (s *apiServer) setFail(fail bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = fail
}

func (s *apiServer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	s.gets.Add(1)
	if s.hold != nil {
		<-s.hold
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.headers = request.Header.Clone()
	if request.Method != http.MethodGet || request.Header.Get("Authorization") != "Bearer "+testToken ||
		request.Header.Get("Accept") != acceptAggregated {
		writer.WriteHeader(http.StatusForbidden)
		return
	}
	if s.fail {
		writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	var payload []byte
	switch request.URL.Path {
	case "/api":
		payload = s.core
	case "/apis":
		payload = s.groups
	default:
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	sum := sha256.Sum256(payload)
	etag := `"` + hex.EncodeToString(sum[:8]) + `"`
	if request.Header.Get("If-None-Match") == etag {
		writer.WriteHeader(http.StatusNotModified)
		return
	}
	writer.Header().Set("ETag", etag)
	writer.Header().Set("Content-Type", acceptAggregated)
	_, _ = writer.Write(payload)
}

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(by time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(by)
}

type fixture struct {
	server    *apiServer
	discovery *Discovery
	clock     *clock
	logs      *bytes.Buffer
	tokenFile string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	server := &apiServer{}
	server.set(aggregated(version{"", "v1", []resource{
		{"pods", "Namespaced"},
		{"nodes", "Cluster"},
		{"namespaces", "Cluster"},
	}}), aggregated(version{"apps", "v1", []resource{{"deployments", "Namespaced"}}}))
	tls := httptest.NewTLSServer(server)
	t.Cleanup(tls.Close)
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	logs := &bytes.Buffer{}
	fake := &clock{now: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
	discovery, err := New(Options{
		Server: tls.URL, TokenFile: tokenFile, Now: fake.Now,
		Logger: slog.New(slog.NewTextHandler(&lockedWriter{buffer: logs}, nil)), Transport: tls.Client().Transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{server: server, discovery: discovery, clock: fake, logs: logs, tokenFile: tokenFile}
}

type lockedWriter struct {
	mu     sync.Mutex
	buffer *bytes.Buffer
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buffer.Write(p)
}

func (f *fixture) refresh(t *testing.T) error {
	t.Helper()
	return f.discovery.refresh(t.Context(), true)
}

func TestNewRefusesInvalidOptions(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	for name, options := range map[string]Options{
		"http":           {Server: "http://api:6443", TokenFile: "t", Logger: logger},
		"path":           {Server: "https://api:6443/x", TokenFile: "t", Logger: logger},
		"user":           {Server: "https://u@api:6443", TokenFile: "t", Logger: logger},
		"no token":       {Server: "https://api:6443", Logger: logger},
		"no logger":      {Server: "https://api:6443", TokenFile: "t"},
		"refresh>stale":  {Server: "https://api:6443", TokenFile: "t", Logger: logger, Refresh: time.Hour},
		"missing CA":     {Server: "https://api:6443", TokenFile: "t", Logger: logger, CAFile: "/nonexistent"},
		"query in URL":   {Server: "https://api:6443?a=b", TokenFile: "t", Logger: logger},
		"host is absent": {Server: "https://", TokenFile: "t", Logger: logger},
	} {
		if _, err := New(options); err == nil {
			t.Errorf("%s: New accepted invalid options", name)
		}
	}
}

func TestScopesFromBothDocuments(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	if got := f.discovery.lookup("", "pods"); got != kubeprofile.ScopeUnknown {
		t.Fatalf("before any fetch: %v, want unknown", got)
	}
	if err := f.refresh(t); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		group, resource string
		want            kubeprofile.ResourceScope
	}{
		{"", "pods", kubeprofile.ScopeNamespaced},
		{"", "nodes", kubeprofile.ScopeCluster},
		{"apps", "deployments", kubeprofile.ScopeNamespaced},
		{"", "deployments", kubeprofile.ScopeUnknown},
		{"apps", "pods", kubeprofile.ScopeUnknown},
		{"", "Pods", kubeprofile.ScopeUnknown},
	} {
		if got := f.discovery.Scope(ctx, test.group, test.resource); got != test.want {
			t.Errorf("Scope(%q, %q) = %v, want %v", test.group, test.resource, got, test.want)
		}
	}
	if strings.Contains(f.logs.String(), testToken) {
		t.Fatal("the token was logged")
	}
}

func TestVersionsThatDisagreeAreUnknown(t *testing.T) {
	f := newFixture(t)
	f.server.set(aggregated(version{"", "v1", []resource{{"pods", "Namespaced"}}}), aggregated(
		version{"example.com", "v1", []resource{
			{"widgets", "Namespaced"},
			{"gadgets", "Cluster"},
			{"oddities", "Elsewhere"},
			{"", "Cluster"},
		}},
		version{"example.com", "v2", []resource{{"widgets", "Cluster"}, {"gadgets", "Cluster"}}},
		version{"example.com", "v3", []resource{{"widgets", "Namespaced"}}},
	))
	if err := f.refresh(t); err != nil {
		t.Fatal(err)
	}
	for resource, want := range map[string]kubeprofile.ResourceScope{
		"widgets": kubeprofile.ScopeUnknown, "gadgets": kubeprofile.ScopeCluster,
		"oddities": kubeprofile.ScopeUnknown, "": kubeprofile.ScopeUnknown,
	} {
		if got := f.discovery.lookup("example.com", resource); got != want {
			t.Errorf("%s: %v, want %v", resource, got, want)
		}
	}
}

func TestETagKeepsTableAndConfirmsIt(t *testing.T) {
	f := newFixture(t)
	if err := f.refresh(t); err != nil {
		t.Fatal(err)
	}
	first := f.discovery.current.Load()
	f.clock.advance(4 * time.Minute)
	if err := f.refresh(t); err != nil {
		t.Fatal(err)
	}
	if f.server.headers.Get("If-None-Match") == "" {
		t.Fatal("the second fetch sent no ETag")
	}
	second := f.discovery.current.Load()
	if !second.confirmedAt.After(first.confirmedAt) || len(second.scopes) != len(first.scopes) {
		t.Fatalf("a 304 did not confirm the table: %v -> %v", first.confirmedAt, second.confirmedAt)
	}
	f.clock.advance(4 * time.Minute)
	if got := f.discovery.lookup("", "pods"); got != kubeprofile.ScopeNamespaced {
		t.Fatalf("a confirmed table went stale: %v", got)
	}
}

func TestUnknownResourceFetchesAgainAtMostEachMinimum(t *testing.T) {
	f := newFixture(t)
	if err := f.refresh(t); err != nil {
		t.Fatal(err)
	}
	f.server.set(f.server.core, aggregated(version{"apps", "v1", []resource{{"deployments", "Namespaced"}}},
		version{"example.com", "v1", []resource{{"widgets", "Namespaced"}}}))
	// Within MinimumRefetch of the last fetch: no fetch, unknown.
	before := f.server.gets.Load()
	if got := f.discovery.Scope(t.Context(), "example.com", "widgets"); got != kubeprofile.ScopeUnknown {
		t.Fatalf("fetched again too soon: %v", got)
	}
	if f.server.gets.Load() != before {
		t.Fatal("an unknown resource fetched within MinimumRefetch")
	}
	f.clock.advance(DefaultMinimumRefetch)
	if got := f.discovery.Scope(t.Context(), "example.com", "widgets"); got != kubeprofile.ScopeNamespaced {
		t.Fatalf("a new CRD stayed unknown: %v", got)
	}
	// Still unknown after the fetch: nothing more until the minimum passes.
	before = f.server.gets.Load()
	if got := f.discovery.Scope(t.Context(), "example.com", "missing"); got != kubeprofile.ScopeUnknown {
		t.Fatalf("missing: %v", got)
	}
	if f.server.gets.Load() != before {
		t.Fatal("a missing resource fetched again at once")
	}
}

func TestConcurrentUnknownLookupsShareOneFetch(t *testing.T) {
	f := newFixture(t)
	f.server.hold = make(chan struct{})
	var wait sync.WaitGroup
	results := make([]kubeprofile.ResourceScope, 16)
	for index := range results {
		wait.Go(func() { results[index] = f.discovery.Scope(t.Context(), "", "pods") })
	}
	time.Sleep(50 * time.Millisecond)
	close(f.server.hold)
	wait.Wait()
	if gets := f.server.gets.Load(); gets != int64(len(documents)) {
		t.Fatalf("%d lookups made %d requests, want one fetch of %d", len(results), gets, len(documents))
	}
	for _, got := range results {
		if got != kubeprofile.ScopeNamespaced {
			t.Fatalf("a waiting lookup got %v", got)
		}
	}
}

func TestWaitIsBoundedByTheRequest(t *testing.T) {
	f := newFixture(t)
	f.server.hold = make(chan struct{})
	defer close(f.server.hold)
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if got := f.discovery.Scope(ctx, "", "pods"); got != kubeprofile.ScopeUnknown {
		t.Fatalf("a lookup past its deadline got %v", got)
	}
}

func TestFailureKeepsTableUntilStale(t *testing.T) {
	f := newFixture(t)
	if err := f.refresh(t); err != nil {
		t.Fatal(err)
	}
	f.server.setFail(true)
	f.clock.advance(time.Minute)
	if err := f.refresh(t); err == nil {
		t.Fatal("a failed fetch reported success")
	}
	if got := f.discovery.lookup("", "pods"); got != kubeprofile.ScopeNamespaced {
		t.Fatalf("a failure dropped the table at once: %v", got)
	}
	f.clock.advance(DefaultStaleAfter)
	if got := f.discovery.lookup("", "pods"); got != kubeprofile.ScopeUnknown || f.discovery.Fresh() {
		t.Fatalf("a stale table still answers: %v", got)
	}
	if !strings.Contains(f.logs.String(), "kubernetes_discovery_stale") ||
		!strings.Contains(f.logs.String(), "kubernetes_discovery_failed") {
		t.Fatalf("missing logs: %s", f.logs.String())
	}
	f.server.setFail(false)
	if err := f.refresh(t); err != nil {
		t.Fatal(err)
	}
	if got := f.discovery.lookup("", "pods"); got != kubeprofile.ScopeNamespaced {
		t.Fatalf("a fetch after recovery: %v", got)
	}
	_, resources, successes, failures := f.discovery.Status()
	if resources != 4 || successes != 2 || failures != 1 {
		t.Fatalf("status: %d resources, %d successes, %d failures", resources, successes, failures)
	}
}

func TestAnswersThatAreNotAggregatedDiscoveryFail(t *testing.T) {
	legacy := []byte(`{"kind":"APIGroupList","apiVersion":"v1","groups":[]}`)
	beta := bytes.Replace(aggregated(), []byte(discoveryVersion), []byte("apidiscovery.k8s.io/v2beta1"), 1)
	big := append([]byte(`{"x":"`), bytes.Repeat([]byte("a"), maximumDocument)...)
	for name, payload := range map[string][]byte{
		"legacy": legacy, "v2beta1": beta, "garbage": []byte("<html>"),
		"oversized": big,
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			if err := f.refresh(t); err != nil {
				t.Fatal(err)
			}
			f.server.set(f.server.core, payload)
			if err := f.refresh(t); err == nil {
				t.Fatal("accepted")
			}
			if got := f.discovery.lookup("apps", "deployments"); got != kubeprofile.ScopeNamespaced {
				t.Fatalf("a bad answer replaced the table: %v", got)
			}
		})
	}
}

func TestOneDocumentFailingKeepsBoth(t *testing.T) {
	f := newFixture(t)
	if err := f.refresh(t); err != nil {
		t.Fatal(err)
	}
	f.server.set(aggregated(version{"", "v1", []resource{{"pods", "Cluster"}}}), []byte("nope"))
	if err := f.refresh(t); err == nil {
		t.Fatal("accepted")
	}
	if got := f.discovery.lookup("", "pods"); got != kubeprofile.ScopeNamespaced {
		t.Fatalf("half a fetch was published: %v", got)
	}
}

func TestUnreadableTokenFails(t *testing.T) {
	f := newFixture(t)
	if err := os.Remove(f.tokenFile); err != nil {
		t.Fatal(err)
	}
	if err := f.refresh(t); err == nil {
		t.Fatal("fetched without a token")
	}
	if f.server.gets.Load() != 0 {
		t.Fatal("called the API server without a token")
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		t.Error("the redirect was followed")
		writer.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL+request.URL.Path, //nolint:gosec // G710: a test's own redirect
			http.StatusFound)
	}))
	defer redirect.Close()
	tokenFile := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenFile, []byte(testToken), 0o600); err != nil {
		t.Fatal(err)
	}
	discovery, err := New(Options{
		Server: redirect.URL, TokenFile: tokenFile,
		Logger: slog.New(slog.DiscardHandler), Transport: redirect.Client().Transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := discovery.refresh(t.Context(), true); err == nil {
		t.Fatal("a redirect counted as discovery")
	}
}

func TestRunFetchesAndStops(t *testing.T) {
	f := newFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		f.discovery.Run(ctx)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for f.discovery.current.Load() == nil {
		if time.Now().After(deadline) {
			t.Fatal("Run fetched nothing")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}
