package flowloginternal

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/protobuf/proto"

	flowlogv1 "meshtransit.net/api/flowlog/v1"
	"meshtransit.net/shared/flowlog"
)

const receiverURI = "spiffe://01890f00-0000-7000-8000-000000000123/meshflow"

// authority is a test CA.
type authority struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	pem         []byte
}

func newAuthority(t *testing.T, name string) authority {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return authority{certificate: certificate, key: key, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issue signs a leaf for usage, naming uri (a client) or localhost (a
// server).
func (ca authority) issue(t *testing.T, uri string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	return ca.issueWith(t, uri, func(template *x509.Certificate) {
		template.ExtKeyUsage = []x509.ExtKeyUsage{usage}
	})
}

// issueWith signs a leaf naming uri after change edits its template.
func (ca authority) issueWith(t *testing.T, uri string, change func(*x509.Certificate)) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	template := &x509.Certificate{
		SerialNumber: serial, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if uri != "" {
		parsed, err := url.Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
		template.URIs = []*url.URL{parsed}
	} else {
		template.DNSNames = []string{"localhost"}
	}
	change(template)
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func writeKeyPair(t *testing.T, dir string, certificate tls.Certificate) (string, string) {
	t.Helper()
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	keyDER, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

// clock is a settable time.
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
	server   *Server
	metrics  *Metrics
	certFile string
	keyFile  string
	serverCA authority
	clientCA authority
	caFile   string
	clock    *clock
	key      ed25519.PublicKey
	base     string
}

func startServer(t *testing.T) fixture {
	t.Helper()
	return startServerWith(t, &fakeReader{})
}

func startServerWith(t *testing.T, reader Reader) fixture {
	t.Helper()
	dir := t.TempDir()
	serverCA, clientCA := newAuthority(t, "server CA"), newAuthority(t, "receiver CA")
	certFile, keyFile := writeKeyPair(t, dir, serverCA.issue(t, "", x509.ExtKeyUsageServerAuth))
	caFile := filepath.Join(dir, "client-ca.pem")
	if err := os.WriteFile(caFile, clientCA.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	next, _, _ := ed25519.GenerateKey(rand.Reader)
	moment := &clock{now: time.Now()}
	metrics := NewMetrics()
	server, err := NewServer(Options{
		Address: "127.0.0.1:0", CertFile: certFile, KeyFile: keyFile, ClientCAFile: caFile,
		ClientURI: must(url.Parse(receiverURI)), Metrics: metrics, Logger: slog.New(slog.DiscardHandler), Now: moment.Now,
		Reader: reader, Status: reader.(StatusWriter),
		TokenKeys: []TokenKey{{State: "current", Key: public}, {State: "next", Key: next}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Shutdown(t.Context()) })
	return fixture{
		server: server, metrics: metrics, certFile: certFile, keyFile: keyFile, serverCA: serverCA, clientCA: clientCA, caFile: caFile, clock: moment, key: public,
		base: "https://" + server.Address().String(),
	}
}

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

// client trusts only the server CA and presents certificate.
func (f fixture) client(certificate *tls.Certificate, configure func(*tls.Config)) *http.Client {
	roots := x509.NewCertPool()
	roots.AddCert(f.serverCA.certificate)
	config := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: "localhost"}
	if certificate != nil {
		config.Certificates = []tls.Certificate{*certificate}
	}
	if configure != nil {
		configure(config)
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: config, ForceAttemptHTTP2: true}, Timeout: 5 * time.Second}
}

// answer is what a GET returned, its body read and closed.
type answer struct {
	status int
	header http.Header
	close  bool
	proto  int
}

// http1 is client without HTTP/2, whose errors keep the TLS alert.
func (f fixture) http1(certificate *tls.Certificate) *http.Client {
	client := f.client(certificate, func(config *tls.Config) { config.NextProtos = []string{"http/1.1"} })
	client.Transport.(*http.Transport).ForceAttemptHTTP2 = false //nolint:forcetypeassert // built by client
	return client
}

func get(t *testing.T, client *http.Client, target string, header http.Header) (answer, []byte, error) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, values := range header {
		request.Header[name] = values
	}
	response, err := client.Do(request)
	if err != nil {
		return answer{}, nil, err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	return answer{
		status: response.StatusCode, header: response.Header, close: response.Close, proto: response.ProtoMajor,
	}, body, err
}

// The receiver, and only the receiver, reads the token keys; a poll with
// the same ETag is 304.
func TestReceiverReadsTheTokenKeys(t *testing.T) {
	f := startServer(t)
	good := f.clientCA.issue(t, receiverURI, x509.ExtKeyUsageClientAuth)
	client := f.client(&good, nil)
	response, body, err := get(t, client, f.base+keysPath, nil)
	if err != nil || response.status != http.StatusOK || response.header.Get("Content-Type") != contentType ||
		response.proto != 2 {
		t.Fatalf("GET keys = %v, %v", response, err)
	}
	var keys flowlogv1.FlowSigningKeys
	if err := proto.Unmarshal(body, &keys); err != nil || len(keys.GetKeys()) != 2 || keys.GetGeneratedAtMs() == 0 {
		t.Fatalf("keys = %v, %v", &keys, err)
	}
	current := keys.GetKeys()[0]
	if current.GetState() != flowlogv1.FlowSigningKeys_CURRENT || !bytes.Equal(current.GetPublicKey(), f.key) ||
		current.GetKid() != flowlog.SigningKeyID(f.key) {
		t.Fatalf("current key = %v", current)
	}
	tag := response.header.Get("ETag")
	f.clock.advance(time.Second)
	for _, condition := range []string{tag, "W/" + tag, "*", `"other", ` + tag} {
		again, _, err := get(t, client, f.base+keysPath, http.Header{"If-None-Match": {condition}})
		if err != nil || again.status != http.StatusNotModified {
			t.Fatalf("conditional GET %q = %v, %v", condition, again, err)
		}
	}
	if other, _, err := get(t, client, f.base+"/internal/v1/flowlog/other", nil); err != nil ||
		other.status != http.StatusNotFound {
		t.Fatalf("unknown path = %v, %v", other, err)
	}
	postRequest, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.base+keysPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	post, err := client.Do(postRequest)
	if err != nil {
		t.Fatal(err)
	}
	_ = post.Body.Close()
	if post.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d", post.StatusCode)
	}
}

// A certificate that does not name the receiver, comes from another CA,
// is not for client authentication, or is missing, gets no answer; nor does
// TLS 1.2.
func TestOnlyTheReceiverConnects(t *testing.T) {
	f := startServer(t)
	other := newAuthority(t, "another CA")
	second := must(url.Parse("spiffe://01890f00-0000-7000-8000-000000000123/other"))
	for name, certificate := range map[string]*tls.Certificate{
		"another identity": ptr(f.clientCA.issue(t, second.String(), x509.ExtKeyUsageClientAuth)),
		"another CA":       ptr(other.issue(t, receiverURI, x509.ExtKeyUsageClientAuth)),
		"server usage":     ptr(f.clientCA.issue(t, receiverURI, x509.ExtKeyUsageServerAuth)),
		"no usage": ptr(f.clientCA.issueWith(t, receiverURI, func(template *x509.Certificate) {
			template.ExtKeyUsage = nil
		})),
		"any usage": ptr(f.clientCA.issueWith(t, receiverURI, func(template *x509.Certificate) {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
		})),
		"two identities": ptr(f.clientCA.issueWith(t, receiverURI, func(template *x509.Certificate) {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			template.URIs = append(template.URIs, second)
		})),
		"a CA certificate": ptr(f.clientCA.issueWith(t, receiverURI, func(template *x509.Certificate) {
			template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			template.IsCA, template.BasicConstraintsValid = true, true
			template.KeyUsage |= x509.KeyUsageCertSign
		})),
		"no certificate": nil,
	} {
		response, _, err := get(t, f.http1(certificate), f.base+keysPath, nil)
		if err == nil {
			t.Errorf("%s: answered %d", name, response.status)
			continue
		}
		if !strings.Contains(err.Error(), "tls:") {
			t.Errorf("%s: refused without a TLS alert: %v", name, err)
		}
	}
	if rejected := metricTotal(t, f.metrics, "meshtransit_flowlog_internal_client_rejections_total"); rejected < 4 {
		t.Errorf("rejections counted: %v", rejected)
	}
	good := f.clientCA.issue(t, receiverURI, x509.ExtKeyUsageClientAuth)
	legacy := f.client(&good, func(config *tls.Config) {
		config.MinVersion, config.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
	})
	if _, _, err := get(t, legacy, f.base+keysPath, nil); err == nil {
		t.Error("TLS 1.2 answered")
	}
}

func ptr[T any](value T) *T { return &value }

// No connection resumes a session, so each verifies the receiver again; an
// old connection is asked to close; a replaced CA takes effect within a
// reload.
func TestRevocationTakesEffect(t *testing.T) {
	f := startServer(t)
	good := f.clientCA.issue(t, receiverURI, x509.ExtKeyUsageClientAuth)
	cache := tls.NewLRUClientSessionCache(4)
	resumes := 0
	client := f.client(&good, func(config *tls.Config) {
		config.ClientSessionCache = cache
		config.VerifyConnection = func(state tls.ConnectionState) error {
			if state.DidResume {
				resumes++
			}
			return nil
		}
	})
	for range 2 {
		if _, _, err := get(t, client, f.base+keysPath, nil); err != nil {
			t.Fatal(err)
		}
		client.CloseIdleConnections()
	}
	if resumes != 0 {
		t.Fatalf("resumed %d sessions", resumes)
	}

	plain := f.client(&good, func(config *tls.Config) { config.NextProtos = []string{"http/1.1"} })
	plain.Transport.(*http.Transport).ForceAttemptHTTP2 = false //nolint:forcetypeassert // built above
	if response, _, err := get(t, plain, f.base+keysPath, nil); err != nil || response.header.Get("Connection") == "close" {
		t.Fatalf("a young connection: %v, %v", response, err)
	}
	f.clock.advance(maxConnectionAge)
	f.server.source.reload() // as the ticker does
	if response, _, err := get(t, plain, f.base+keysPath, nil); err != nil || !response.close {
		t.Fatalf("an old connection was not closed: %v, %v", response, err)
	}
	// HTTP/2: the old connection goes away and the next request opens a
	// new one.
	h2 := f.client(&good, nil)
	if _, _, err := get(t, h2, f.base+keysPath, nil); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(maxConnectionAge)
	f.server.source.reload()
	if _, _, err := get(t, h2, f.base+keysPath, nil); err != nil {
		t.Fatal(err)
	}
	reused := true
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused }}
	request, err := http.NewRequestWithContext(httptrace.WithClientTrace(t.Context(), trace), http.MethodGet,
		f.base+keysPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := h2.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.ProtoMajor != 2 || reused {
		t.Fatalf("HTTP/%d, reused %v after the age", response.ProtoMajor, reused)
	}

	replacement := newAuthority(t, "new receiver CA")
	if err := os.WriteFile(f.caFile, replacement.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	f.server.source.reload()
	client.CloseIdleConnections()
	if _, _, err := get(t, f.client(&good, nil), f.base+keysPath, nil); err == nil {
		t.Fatal("a certificate of the removed CA connected")
	}
	renewed := replacement.issue(t, receiverURI, x509.ExtKeyUsageClientAuth)
	if response, _, err := get(t, f.client(&renewed, nil), f.base+keysPath, nil); err != nil ||
		response.status != http.StatusOK {
		t.Fatalf("the new CA's certificate: %v, %v", response, err)
	}
	// A key that does not read keeps the last good material for the
	// grace, then nothing serves.
	if err := os.WriteFile(f.keyFile, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	f.server.source.reload()
	if response, _, err := get(t, f.client(&renewed, nil), f.base+keysPath, nil); err != nil ||
		response.status != http.StatusOK {
		t.Fatalf("within the grace: %v, %v", response, err)
	}
	if failures := metricTotal(t, f.metrics, "meshtransit_flowlog_internal_tls_reload_failures_total"); failures != 1 {
		t.Fatalf("reload failures counted: %v", failures)
	}
	f.clock.advance(reloadGrace + time.Second)
	if _, _, err := get(t, f.client(&renewed, nil), f.base+keysPath, nil); err == nil {
		t.Fatal("stale material served past the grace")
	}
}

// A receiver CA that is removed, or emptied, trusts no one at the next
// reload (review s4c1a H1).
func TestRemovingTheReceiverCARevokes(t *testing.T) {
	for name, remove := range map[string]func(string) error{
		"deleted": os.Remove,
		"emptied": func(path string) error { return os.WriteFile(path, nil, 0o600) },
	} {
		t.Run(name, func(t *testing.T) {
			f := startServer(t)
			good := f.clientCA.issue(t, receiverURI, x509.ExtKeyUsageClientAuth)
			if _, _, err := get(t, f.client(&good, nil), f.base+keysPath, nil); err != nil {
				t.Fatal(err)
			}
			if err := remove(f.caFile); err != nil {
				t.Fatal(err)
			}
			f.server.source.reload()
			if _, _, err := get(t, f.client(&good, nil), f.base+keysPath, nil); err == nil {
				t.Fatal("trusted after the CA was removed")
			}
		})
	}
}

func TestNewServerRefusesBadOptions(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ca := newAuthority(t, "CA")
	certFile, keyFile := writeKeyPair(t, dir, ca.issue(t, "", x509.ExtKeyUsageServerAuth))
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, ca.pem, 0o600); err != nil {
		t.Fatal(err)
	}
	receiverCAFile := filepath.Join(dir, "receiver-ca.pem")
	if err := os.WriteFile(receiverCAFile, newAuthority(t, "receiver CA").pem, 0o600); err != nil {
		t.Fatal(err)
	}
	key, _, _ := ed25519.GenerateKey(rand.Reader)
	base := Options{
		Address: "127.0.0.1:0", CertFile: certFile, KeyFile: keyFile, ClientCAFile: receiverCAFile,
		ClientURI: must(url.Parse(receiverURI)), Metrics: NewMetrics(), Logger: slog.New(slog.DiscardHandler),
		Now: time.Now, TokenKeys: []TokenKey{{State: "current", Key: key}}, Reader: &fakeReader{}, Status: &fakeReader{},
	}
	for name, change := range map[string]func(*Options){
		"no current key": func(o *Options) { o.TokenKeys = []TokenKey{{State: "next", Key: key}} },
		"unknown state":  func(o *Options) { o.TokenKeys = []TokenKey{{State: "spare", Key: key}} },
		"missing CA":     func(o *Options) { o.ClientCAFile = filepath.Join(dir, "absent.pem") },
		"no identity":    func(o *Options) { o.ClientURI = nil },
		"no metrics":     func(o *Options) { o.Metrics = nil },
		"no logger":      func(o *Options) { o.Logger = nil },
		"no reader":      func(o *Options) { o.Reader = nil },
		"server cert of the receiver CA": func(o *Options) {
			// The receiver CA issued the server certificate too.
			o.ClientCAFile = caFile
		},
	} {
		options := base
		change(&options)
		if _, err := NewServer(options); err == nil {
			t.Errorf("%s: built", name)
		}
	}
	if _, err := NewServer(base); err != nil {
		t.Fatal(err)
	}
}

// metricTotal sums a counter family across its labels.
func metricTotal(t *testing.T, metrics *Metrics, name string) float64 {
	t.Helper()
	registry := prometheus.NewRegistry()
	registry.MustRegister(metrics)
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	total := 0.0
	for _, family := range families {
		if family.GetName() == name {
			for _, metric := range family.GetMetric() {
				total += metric.GetCounter().GetValue()
			}
		}
	}
	return total
}

// Peers that open connections and say nothing do not lock the receiver out
// (review s4c1a): the cap counts before the handshake, so it only bounds
// file descriptors.
func TestIdleConnectionsDoNotLockTheReceiverOut(t *testing.T) {
	f := startServer(t)
	dialer := &net.Dialer{Timeout: time.Second}
	for range 200 {
		connection, err := dialer.DialContext(t.Context(), "tcp", f.server.Address().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = connection.Close() })
	}
	good := f.clientCA.issue(t, receiverURI, x509.ExtKeyUsageClientAuth)
	if response, _, err := get(t, f.client(&good, nil), f.base+keysPath, nil); err != nil ||
		response.status != http.StatusOK {
		t.Fatalf("the receiver behind idle peers: %v, %v", response, err)
	}
}

// A removed CA revokes even when the server key does not read.
func TestRemovedCAWinsOverABrokenKey(t *testing.T) {
	f := startServer(t)
	if err := os.WriteFile(f.keyFile, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(f.caFile); err != nil {
		t.Fatal(err)
	}
	f.server.source.reload()
	good := f.clientCA.issue(t, receiverURI, x509.ExtKeyUsageClientAuth)
	if _, _, err := get(t, f.client(&good, nil), f.base+keysPath, nil); err == nil {
		t.Fatal("trusted after the CA was removed")
	}
}
