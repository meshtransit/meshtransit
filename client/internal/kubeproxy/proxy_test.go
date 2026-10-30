package kubeproxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/kubeaudit"
	"meshtransit.net/client/internal/kubeevent"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/rbaccheck"
)

const clusterName = "kinda-k1.kube.test"

// seen is what the fake API server saw of a request.
type seen struct {
	Method, Path, Query string
	Header              http.Header
}

type fakeRecords struct {
	mu       sync.Mutex
	intents  []controlplane.KubeAuditIntent
	finished []int
	denied   []string
	samples  []controlplane.KubeAuditDenialSample
	answer   kubeaudit.Answer
}

func (records *fakeRecords) Record(_ context.Context, _ string, intent controlplane.KubeAuditIntent) kubeaudit.Answer {
	records.mu.Lock()
	defer records.mu.Unlock()
	records.intents = append(records.intents, intent)
	return records.answer
}

func (records *fakeRecords) Finished(_ [16]byte, status int, _ time.Duration) {
	records.mu.Lock()
	defer records.mu.Unlock()
	records.finished = append(records.finished, status)
}

func (records *fakeRecords) Denied(_, reason string) {
	records.mu.Lock()
	defer records.mu.Unlock()
	records.denied = append(records.denied, reason)
}

func (records *fakeRecords) ProfileDenied(_ string, wouldDeny bool, sample controlplane.KubeAuditDenialSample) {
	records.mu.Lock()
	defer records.mu.Unlock()
	reason := "profile_denied"
	if wouldDeny {
		reason = "profile_would_deny"
	}
	records.denied = append(records.denied, reason)
	records.samples = append(records.samples, sample)
}

type bearer struct{ value string }

func (token bearer) Value() string { return token.value }
func (bearer) ID() []byte          { return []byte{1, 2} }

type fakeTokens struct {
	forgotten atomic.Int64
}

func (*fakeTokens) For(_ context.Context, device, owner, group string) (Bearer, error) {
	return bearer{value: "tok-" + group + "-" + owner}, nil
}

func (tokens *fakeTokens) Forget(string, string, string, Bearer) { tokens.forgotten.Add(1) }

// fixture is a proxy on 127.0.0.1 in front of a fake API server.
type fixture struct {
	t        *testing.T
	server   *Server
	client   *http.Client
	address  string
	records  *fakeRecords
	tokens   *fakeTokens
	peer     atomic.Pointer[Peer]
	stranger atomic.Bool // the source holds no Device
	fresh    atomic.Pointer[time.Time]
	verdicts sync.Map // group -> rbaccheck.Verdict
	seen     chan seen
	events   *fakeEvents
	wake     chan struct{}
}

// fakeEvents records privileged uses; fail refuses the next ones.
type fakeEvents struct {
	mu   sync.Mutex
	uses []kubeevent.Use
	fail atomic.Bool
}

func (events *fakeEvents) Privileged(_ context.Context, use kubeevent.Use) (bool, error) {
	if events.fail.Load() {
		return false, errors.New("the API server answered 403")
	}
	events.mu.Lock()
	defer events.mu.Unlock()
	events.uses = append(events.uses, use)
	return true, nil
}

func newFixture(t *testing.T) *fixture { t.Helper(); return newFixtureAt(t, "") }

// newFixtureAt is newFixture with the proxy sent to backendURL instead,
// when not empty.
func newFixtureAt(t *testing.T, backendURL string, configure ...func(*Options)) *fixture {
	t.Helper()
	f := &fixture{
		t: t, records: &fakeRecords{answer: kubeaudit.Answer{Recorded: true, AuditID: [16]byte{7}}},
		tokens: &fakeTokens{}, seen: make(chan seen, 16), events: &fakeEvents{}, wake: make(chan struct{}, 1),
	}
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.seen <- seen{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Header: r.Header.Clone()}
		switch {
		case strings.HasSuffix(r.URL.Path, "/slow"):
			<-r.Context().Done() // answers nothing until the gateway gives up
			return
		case strings.HasSuffix(r.URL.Path, "/unauthorized"):
			w.WriteHeader(http.StatusUnauthorized)
		case strings.HasSuffix(r.URL.Path, "/stream") || r.URL.Query().Get("watch") == "true":
			w.WriteHeader(http.StatusOK)
			for {
				if _, err := io.WriteString(w, strings.Repeat("x", 1024)+"\n"); err != nil {
					return
				}
				http.NewResponseController(w).Flush()
				select {
				case <-r.Context().Done():
					return
				case <-time.After(10 * time.Millisecond):
				}
			}
		case r.Header.Get("Upgrade") != "":
			conn, buffered, err := http.NewResponseController(w).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: " + r.Header.Get("Upgrade") +
				"\r\nConnection: Upgrade\r\n\r\n")
			_ = buffered.Flush()
			line, _ := buffered.ReadString('\n')
			_, _ = conn.Write([]byte("echo " + line))
		default:
			_, _ = io.WriteString(w, `{"kind":"PodList"}`)
		}
	}))
	t.Cleanup(backend.Close)
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: backend.Certificate().Raw,
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	certificate, pool := testCertificate(t)
	if backendURL == "" {
		backendURL = backend.URL
	}
	f.peer.Store(&Peer{DeviceID: "device-a", Name: "laptop", Key: [32]byte{1}, Access: &networkmap.KubernetesAccess{
		Grants: []networkmap.KubernetesGrant{
			{Group: "edit", ValidUntil: time.Now().Add(time.Hour)},
			{Group: "sre", ValidUntil: time.Now().Add(time.Hour)},
			{Group: "view", ValidUntil: time.Now().Add(time.Hour)},
		},
		OwnerRef: "person-1", OwnerChangedAt: time.Now().Add(-30 * 24 * time.Hour),
	}})
	now := time.Now()
	f.fresh.Store(&now)
	for _, group := range []string{"view", "edit", "sre"} {
		f.verdicts.Store(group, rbaccheck.Verdict{Enabled: true, Impersonation: group == "sre"})
	}
	options := Options{
		Cluster: clusterName, Namespace: "meshtransit", Backend: backendURL, BackendCA: ca,
		Groups: []Group{
			{Name: "view", Default: true},
			{Name: "edit"},
			{Name: "sre", Privileged: true, AllowedPrincipals: []string{"person-1"}, AllowImpersonation: true},
		},
		Peer: func(source netip.Addr) (Peer, bool) {
			if source != netip.MustParseAddr("127.0.0.1") || f.stranger.Load() {
				return Peer{}, false
			}
			return *f.peer.Load(), true
		},
		Certificate: func() (*tls.Certificate, bool) { return certificate, certificate != nil },
		MapFreshAt:  func() time.Time { return *f.fresh.Load() },
		StaleAfter:  5 * time.Minute, CoreNow: time.Now,
		Verdict: func(group string) rbaccheck.Verdict {
			verdict, _ := f.verdicts.Load(group)
			held, _ := verdict.(rbaccheck.Verdict)
			return held
		},
		Records: f.records, Tokens: f.tokens, Events: f.events, Wake: f.wake, Version: "test",
		Logger: slog.New(slog.DiscardHandler),
	}
	for _, change := range configure {
		change(&options)
	}
	server, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	f.server = server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	swept := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve(ctx, listener)
	}()
	go func() {
		defer close(swept)
		_ = server.Run(ctx)
	}()
	t.Cleanup(func() { cancel(); <-done; <-swept })
	f.address = listener.Addr().String()
	f.client = &http.Client{Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: pool, ServerName: clusterName},
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, f.address)
		},
	}}
	return f
}

func testCertificate(t *testing.T) (*tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: clusterName},
		DNSNames: []string{clusterName}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

func (f *fixture) do(method, path string, header http.Header) (*http.Response, string) {
	f.t.Helper()
	request, err := http.NewRequest(method, "https://"+clusterName+path, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	for name, values := range header {
		request.Header[name] = values
	}
	response, err := f.client.Do(request)
	if err != nil {
		f.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	return response, string(body)
}

func (f *fixture) forwarded() seen {
	f.t.Helper()
	select {
	case got := <-f.seen:
		return got
	case <-time.After(5 * time.Second):
		f.t.Fatal("nothing forwarded")
		return seen{}
	}
}

func (f *fixture) nothingForwarded() {
	f.t.Helper()
	select {
	case got := <-f.seen:
		f.t.Fatalf("forwarded %s %s", got.Method, got.Path)
	default:
	}
}

// A read goes on with the default group's token, without any credential
// of the client's, with the gateway's own headers; nothing is recorded.
func TestProxyForwardsAReadWithoutClientCredentials(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	response, _ := f.do(http.MethodGet, "/api/v1/namespaces/default/pods?limit=5", http.Header{
		"Authorization": {"Bearer stolen"}, "Impersonate-User": {"admin"}, "X-Remote-User": {"x"},
		"X-Forwarded-For": {"1.2.3.4"}, "Sec-Websocket-Protocol": {"v4.channel.k8s.io, BASE64URL.bearer.authorization.k8s.io.abc"},
		"User-Agent": {"kubectl/v1.31 (linux/amd64)"},
	})
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status %d", response.StatusCode)
	}
	got := f.forwarded()
	header := got.Header
	if got.Path != "/api/v1/namespaces/default/pods" || got.Query != "limit=5" ||
		header.Get("Authorization") != "Bearer tok-view-person-1" || header.Get("Impersonate-User") != "" ||
		header.Get("X-Remote-User") != "" || header.Get("X-Forwarded-For") != "127.0.0.1" ||
		header.Get("Sec-Websocket-Protocol") != "v4.channel.k8s.io" || len(header.Get("Audit-Id")) != 36 ||
		!strings.HasPrefix(header.Get("User-Agent"), "meshgw/test device/device-a (client: kubectl/v1.31 linux/amd64") {
		t.Fatalf("forwarded %+v", got)
	}
	if len(f.records.intents) != 0 {
		t.Fatal("a read was recorded")
	}
}

// A write is recorded first and forwarded with Core's audit_id; its
// outcome is reported. One Core does not record never goes on.
func TestProxyRecordsTypeABeforeForwarding(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	response, _ := f.do(http.MethodDelete, "/api/v1/namespaces/default/pods/web-0", nil)
	got := f.forwarded()
	if response.StatusCode != http.StatusOK || got.Header.Get("Audit-Id") != formatAuditID([16]byte{7}) {
		t.Fatalf("status %d, audit %q", response.StatusCode, got.Header.Get("Audit-Id"))
	}
	f.records.mu.Lock()
	intent := f.records.intents[0]
	finished := f.records.finished
	f.records.mu.Unlock()
	if intent.Class != "write" || intent.Verb != "delete" || intent.Name != "web-0" || intent.Peer != "device-a" ||
		intent.Groups[0] != "view" || len(intent.TokenID) != 2 || len(finished) != 1 || finished[0] != 200 {
		t.Fatalf("intent %+v, finished %v", intent, finished)
	}
	for _, test := range []struct {
		answer kubeaudit.Answer
		code   int
	}{
		{kubeaudit.Answer{Err: kubeaudit.ErrTimeout}, http.StatusServiceUnavailable},
		{kubeaudit.Answer{Refused: "limited", RetryAfter: 3 * time.Second}, http.StatusTooManyRequests},
		{kubeaudit.Answer{Refused: "not_granted"}, http.StatusForbidden},
		{kubeaudit.Answer{Refused: "stale"}, http.StatusServiceUnavailable},
	} {
		f.records.mu.Lock()
		f.records.answer = test.answer
		f.records.mu.Unlock()
		response, body := f.do(http.MethodPost, "/api/v1/namespaces/default/configmaps", nil)
		if response.StatusCode != test.code || !strings.Contains(body, `"kind":"Status"`) {
			t.Fatalf("%+v: %d %s", test.answer, response.StatusCode, body)
		}
		if test.code == http.StatusTooManyRequests && response.Header.Get("Retry-After") != "3" {
			t.Fatalf("Retry-After %q", response.Header.Get("Retry-After"))
		}
		f.nothingForwarded()
	}
}

// Groups: a named one the peer holds; a privileged one only for its
// principal on a Device that kept its owner; a group turned off is refused
// by name and skipped by default.
func TestProxyChoosesGroups(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.do(http.MethodGet, "/mt/g/edit/api/v1/pods", nil)
	if got := f.forwarded(); got.Path != "/api/v1/pods" || got.Header.Get("Authorization") != "Bearer tok-edit-person-1" {
		t.Fatalf("named group: %+v", got)
	}
	// A privileged group's every request is recorded.
	f.do(http.MethodGet, "/mt/g/sre/api/v1/pods", nil)
	if got := f.forwarded(); got.Header.Get("Authorization") != "Bearer tok-sre-person-1" {
		t.Fatalf("privileged: %+v", got)
	}
	f.records.mu.Lock()
	class := f.records.intents[len(f.records.intents)-1].Class
	f.records.mu.Unlock()
	if class != "privileged" {
		t.Fatalf("privileged class %q", class)
	}
	f.verdicts.Store("view", rbaccheck.Verdict{Reason: "may list secrets in the cluster"})
	f.do(http.MethodGet, "/api/v1/pods", nil)
	if got := f.forwarded(); got.Header.Get("Authorization") != "Bearer tok-edit-person-1" {
		t.Fatalf("default past a group turned off: %+v", got)
	}
	response, body := f.do(http.MethodGet, "/mt/g/view/api/v1/pods", nil)
	if response.StatusCode != http.StatusForbidden || !strings.Contains(body, "list secrets") {
		t.Fatalf("a group turned off by name: %d %s", response.StatusCode, body)
	}
	// Every group it would use off: the reason, not "holds none".
	f.verdicts.Store("edit", rbaccheck.Verdict{Reason: "the RBAC check fails"})
	response, body = f.do(http.MethodGet, "/api/v1/pods", nil)
	if response.StatusCode != http.StatusForbidden || !strings.Contains(body, `group \"view\" is turned off`) {
		t.Fatalf("every default group off: %d %s", response.StatusCode, body)
	}
	f.verdicts.Store("edit", rbaccheck.Verdict{Enabled: true})
	for name, change := range map[string]func(*Peer){
		"recent owner": func(peer *Peer) { peer.Access.OwnerChangedAt = time.Now().Add(-time.Hour) },
		"not listed":   func(peer *Peer) { peer.Access.OwnerRef = "person-2" },
		"Workspace":    func(peer *Peer) { peer.Access.OwnerRef = "" },
	} {
		peer := *f.peer.Load()
		access := *peer.Access
		peer.Access = &access
		change(&peer)
		f.peer.Store(&peer)
		if response, _ := f.do(http.MethodGet, "/mt/g/sre/api/v1/pods", nil); response.StatusCode != http.StatusForbidden {
			t.Fatalf("%s: %d", name, response.StatusCode)
		}
	}
	f.nothingForwarded()
	if response, _ := f.do(http.MethodGet, "/mt/g/admin/api/v1/pods", nil); response.StatusCode != http.StatusForbidden {
		t.Fatalf("a group not held: %d", response.StatusCode)
	}
}

// Requests the gateway refuses itself never go on, and are counted.
func TestProxyRefuses(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	for name, test := range map[string]struct {
		method, path string
		header       http.Header
		code         int
	}{
		"browser":      {http.MethodGet, "/api/v1/pods", http.Header{"Origin": {"https://evil.example"}}, 403},
		"escaped path": {http.MethodGet, "/api/v1/namespaces/a%2Fb/pods", nil, 400},
		"dot segment":  {http.MethodGet, "/api/v1/namespaces/./pods", nil, 400},
		"options":      {http.MethodOptions, "/api/v1/pods", nil, 405},
		"trace":        {http.MethodTrace, "/api/v1/pods", nil, 405},
		"gateway path": {http.MethodGet, "/mt/other", nil, 404},
		"system impersonation": {
			http.MethodGet, "/mt/g/sre/api/v1/pods",
			http.Header{"Impersonate-User": {"system:admin"}},
			403,
		},
	} {
		if response, _ := f.do(test.method, test.path, test.header); response.StatusCode != test.code {
			t.Errorf("%s: %d, want %d", name, response.StatusCode, test.code)
		}
	}
	// HTTP/1.1 only: a Connection header naming a credential.
	conn, err := tls.Dial("tcp", f.address, &tls.Config{
		RootCAs:    f.client.Transport.(*http.Transport).TLSClientConfig.RootCAs,
		ServerName: clusterName, NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(conn, "GET /api/v1/pods HTTP/1.1\r\nHost: "+clusterName+"\r\nConnection: Authorization\r\n\r\n")
	if status, _ := bufio.NewReader(conn).ReadString('\n'); !strings.Contains(status, "400") {
		t.Fatalf("Connection naming Authorization: %q", status)
	}
	conn.Close()
	f.nothingForwarded()
	stale := time.Now().Add(-10 * time.Minute)
	f.fresh.Store(&stale)
	if response, _ := f.do(http.MethodGet, "/api/v1/pods", nil); response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("stale map: %d", response.StatusCode)
	}
	f.records.mu.Lock()
	denied := len(f.records.denied)
	f.records.mu.Unlock()
	if denied < 5 {
		t.Fatalf("%d denials counted", denied)
	}
}

// A privileged group allowed to impersonate keeps the client's headers.
func TestProxyImpersonation(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.do(http.MethodGet, "/mt/g/sre/api/v1/pods", http.Header{
		"Impersonate-User":  {"alice"},
		"Impersonate-Group": {"ops", "dev"}, "Impersonate-Uid": {"1"},
	})
	got := f.forwarded()
	if got.Header.Get("Impersonate-User") != "alice" || len(got.Header.Values("Impersonate-Group")) != 2 ||
		got.Header.Get("Impersonate-Uid") != "" {
		t.Fatalf("forwarded %+v", got.Header)
	}
	f.records.mu.Lock()
	impersonated := f.records.intents[len(f.records.intents)-1].Impersonated
	f.records.mu.Unlock()
	if impersonated != "alice,ops,dev" {
		t.Fatalf("recorded %q", impersonated)
	}
	f.verdicts.Store("sre", rbaccheck.Verdict{Enabled: true})
	f.do(http.MethodGet, "/mt/g/sre/api/v1/pods", http.Header{"Impersonate-User": {"alice"}})
	if got := f.forwarded(); got.Header.Get("Impersonate-User") != "" {
		t.Fatal("impersonation kept without the verdict's leave")
	}
}

// A connection whose address became another key's is closed; a source of
// no Device gets no TLS handshake, so not the cluster's name.
func TestProxyIdentity(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.stranger.Store(true)
	roots := f.client.Transport.(*http.Transport).TLSClientConfig.RootCAs
	if conn, err := tls.Dial("tcp", f.address, &tls.Config{RootCAs: roots, ServerName: clusterName}); err == nil {
		conn.Close()
		t.Fatal("a stranger completed the TLS handshake")
	}
	f.stranger.Store(false)
	f.do(http.MethodGet, "/api/v1/pods", nil)
	f.forwarded()
	peer := *f.peer.Load()
	peer.Key = [32]byte{2}
	f.peer.Store(&peer)
	request, _ := http.NewRequest(http.MethodGet, "https://"+clusterName+"/api/v1/pods", nil)
	if response, err := f.client.Do(request); err == nil {
		response.Body.Close()
		t.Fatalf("answered %d on a connection of another key", response.StatusCode)
	}
	f.nothingForwarded()
}

// whoami and SelfSubjectReview are answered by the gateway.
func TestProxyWhoami(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	response, body := f.do(http.MethodGet, "/mt/v1/whoami", nil)
	var answer whoamiAnswer
	if err := json.Unmarshal([]byte(body), &answer); err != nil || response.StatusCode != http.StatusOK ||
		answer.Device != "device-a" || answer.DefaultGroup != "view" || answer.Person != "person-1" ||
		answer.Username != "system:serviceaccount:meshtransit:mt-view" {
		t.Fatalf("whoami %d %s", response.StatusCode, body)
	}
	response, body = f.do(http.MethodPost, "/apis/authentication.k8s.io/v1/selfsubjectreviews", nil)
	if response.StatusCode != http.StatusCreated || !strings.Contains(body, `"username":"system:serviceaccount:meshtransit:mt-view"`) ||
		!strings.Contains(body, "device-a") {
		t.Fatalf("SelfSubjectReview %d %s", response.StatusCode, body)
	}
	f.nothingForwarded()
}

// A 401 from the API server forgets the token; an upgrade passes through
// on HTTP/1.1 and is recorded as an interactive session.
func TestProxyUpstreamAnswers(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	// A 401 is tried once more with a new token, then answered.
	if response, _ := f.do(http.MethodGet, "/api/v1/namespaces/a/configmaps/unauthorized", nil); response.StatusCode != 401 ||
		f.tokens.forgotten.Load() < 1 {
		t.Fatalf("401: %d, %d forgotten", response.StatusCode, f.tokens.forgotten.Load())
	}
	f.forwarded()
	f.forwarded()
	conn, err := tls.Dial("tcp", f.address, &tls.Config{
		RootCAs:    f.client.Transport.(*http.Transport).TLSClientConfig.RootCAs,
		ServerName: clusterName, NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "POST /api/v1/namespaces/default/pods/web-0/exec?command=sh HTTP/1.1\r\nHost: "+
		clusterName+"\r\nConnection: Upgrade\r\nUpgrade: SPDY/3.1\r\nContent-Length: 0\r\n\r\n")
	reader := bufio.NewReader(conn)
	status, _ := reader.ReadString('\n')
	if !strings.Contains(status, "101") {
		t.Fatalf("status line %q", status)
	}
	for line, _ := reader.ReadString('\n'); line != "\r\n" && line != ""; line, _ = reader.ReadString('\n') {
	}
	_, _ = io.WriteString(conn, "hello\n")
	if echoed, _ := reader.ReadString('\n'); echoed != "echo hello\n" {
		t.Fatalf("echoed %q", echoed)
	}
	f.records.mu.Lock()
	class := f.records.intents[len(f.records.intents)-1].Class
	f.records.mu.Unlock()
	if class != "exec" {
		t.Fatalf("class %q", class)
	}
}

// A type A request the API server answers 401 is not sent again with a
// new token: Core's record names the token it went out with (re-review b5a
// M-a). The token is forgotten.
func TestProxyTypeAUnauthorizedNotRetried(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	response, _ := f.do(http.MethodGet, "/api/v1/namespaces/a/secrets/unauthorized", nil)
	if response.StatusCode != http.StatusUnauthorized || f.tokens.forgotten.Load() != 1 {
		t.Fatalf("%d, %d forgotten", response.StatusCode, f.tokens.forgotten.Load())
	}
	f.forwarded()
	f.nothingForwarded()
	f.records.mu.Lock()
	defer f.records.mu.Unlock()
	if len(f.records.intents) != 1 || len(f.records.finished) != 1 || f.records.finished[0] != 401 {
		t.Fatalf("intents %d, finished %v", len(f.records.intents), f.records.finished)
	}
}

// An h2 request whose :authority is not the cluster's is refused, though
// TLS named the cluster.
func TestProxyRefusesAnotherAuthorityOverH2(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	request, _ := http.NewRequest(http.MethodGet, "https://other.test/api/v1/pods", nil)
	response, err := f.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.ProtoMajor != 2 || response.StatusCode != http.StatusBadRequest {
		t.Fatalf("HTTP/%d %d", response.ProtoMajor, response.StatusCode)
	}
	f.nothingForwarded()
}

// TLS takes only the cluster's name, and only with a valid certificate.
func TestProxyTLS(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	roots := f.client.Transport.(*http.Transport).TLSClientConfig.RootCAs
	if _, err := tls.Dial("tcp", f.address, &tls.Config{
		RootCAs: roots, ServerName: "other.test",
		InsecureSkipVerify: true,
	}); err == nil { //nolint:gosec // the handshake itself must fail
		t.Fatal("an unknown server name was served")
	}
	conn, err := tls.Dial("tcp", f.address, &tls.Config{RootCAs: roots, ServerName: clusterName})
	if err != nil {
		t.Fatal(err)
	}
	if conn.ConnectionState().Version != tls.VersionTLS13 {
		t.Fatal("not TLS 1.3")
	}
	conn.Close()
}

func TestNewRefusesBadOptions(t *testing.T) {
	t.Parallel()
	for name, groups := range map[string][]Group{
		"privileged default":      {{Name: "a", Default: true, Privileged: true, AllowedPrincipals: []string{"p"}}},
		"privileged without list": {{Name: "a", Privileged: true}},
		"impersonating plain":     {{Name: "a", AllowImpersonation: true}},
		"two defaults":            {{Name: "a", Default: true}, {Name: "b", Default: true}},
		"bad name":                {{Name: "A"}},
	} {
		if err := ValidateGroups(groups); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
}

// A streamed type A answer the client ends still reports its outcome
// (review b5a H1).
func TestProxyReportsAStreamTheClientEnds(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	ctx, cancel := context.WithCancel(t.Context())
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://"+clusterName+"/api/v1/namespaces/a/secrets/stream", nil)
	response, err := f.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = response.Body.Read(make([]byte, 2048))
	cancel()
	response.Body.Close()
	f.forwarded()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		f.records.mu.Lock()
		finished := len(f.records.finished)
		f.records.mu.Unlock()
		if finished == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no outcome for the stream the client ended")
		}
	}
}

// An API server that cannot be reached is a 502, reported as answered.
func TestProxyUnreachableAPIServer(t *testing.T) {
	t.Parallel()
	f := newFixtureAt(t, "https://127.0.0.1:1")
	response, body := f.do(http.MethodDelete, "/api/v1/namespaces/a/pods/b", nil)
	f.records.mu.Lock()
	finished := f.records.finished
	f.records.mu.Unlock()
	if response.StatusCode != http.StatusBadGateway || !strings.Contains(body, `"kind":"Status"`) ||
		len(finished) != 1 || finished[0] != http.StatusBadGateway {
		t.Fatalf("%d %s, finished %v", response.StatusCode, body, finished)
	}
}

// A Host not the cluster's and an upgrade to another protocol are refused.
func TestProxyRefusesHostsAndUpgrades(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	roots := f.client.Transport.(*http.Transport).TLSClientConfig.RootCAs
	for name, request := range map[string]string{
		"host":    "GET /api/v1/pods HTTP/1.1\r\nHost: other.test\r\n\r\n",
		"upgrade": "GET /api/v1/pods HTTP/1.1\r\nHost: " + clusterName + "\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n",
	} {
		conn, err := tls.Dial("tcp", f.address, &tls.Config{
			RootCAs: roots, ServerName: clusterName,
			NextProtos: []string{"http/1.1"},
		})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(conn, request)
		if status, _ := bufio.NewReader(conn).ReadString('\n'); !strings.Contains(status, "400") {
			t.Errorf("%s: %q", name, status)
		}
		conn.Close()
	}
	f.nothingForwarded()
}

// whoami of a Device of the Workspace names no person.
func TestProxyWhoamiOfAWorkspaceDevice(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	peer := *f.peer.Load()
	access := *peer.Access
	access.OwnerRef = ""
	peer.Access = &access
	f.peer.Store(&peer)
	_, body := f.do(http.MethodGet, "/mt/v1/whoami", nil)
	if strings.Contains(body, `"person"`) || !strings.Contains(body, `"default_group":"view"`) {
		t.Fatalf("whoami %s", body)
	}
}
