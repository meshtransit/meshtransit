package httpapi

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"
)

func loginServerTestCertificate(t *testing.T, change func(*x509.Certificate)) ([]byte, []byte, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate owned fixture key", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"console.example.test"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if change != nil {
		change(template)
	}
	encoded, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal("create owned fixture certificate", err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal("encode owned fixture key", err)
	}
	defer clear(private)
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: encoded})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
	t.Cleanup(func() { clear(keyPEM) })
	leaf, err := x509.ParseCertificate(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return certificatePEM, keyPEM, leaf
}

func loginServerTestOptions(t *testing.T) (LoginServerOptions, *loginHTTPFixture, *completionTestPort) {
	t.Helper()
	dispatcher, fixture, callback := dispatcherTestGraph(t)
	certificate, key, _ := loginServerTestCertificate(t, nil)
	return LoginServerOptions{Address: "127.0.0.1:0", CertificatePEM: certificate, PrivateKeyPEM: key,
		Dispatcher: dispatcher, MaxConnections: 2}, fixture, callback
}

func startLoginTestServer(t *testing.T, options LoginServerOptions) (*LoginServer, *http.Client) {
	t.Helper()
	server, err := NewLoginServer(options)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(options.CertificatePEM) {
		t.Fatal("owned fixture root rejected")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: roots, ServerName: "console.example.test", MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	}}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			t.Error("owned TLS shutdown failed", err)
		}
		select {
		case err := <-server.Done():
			if err != nil {
				t.Error("owned TLS serving failed", err)
			}
		case <-ctx.Done():
			t.Error("owned TLS handler join timed out")
		}
	})
	return server, client
}

func loginServerTestRequest(t *testing.T, server *LoginServer, method, path string) *http.Request {
	t.Helper()
	server.mu.Lock()
	address := server.boundAddress
	server.mu.Unlock()
	request, err := http.NewRequestWithContext(t.Context(), method, "https://"+address+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "console.example.test"
	return request
}

func TestNewLoginServerRejectsUnsafeProfiles(t *testing.T) {
	t.Parallel()
	_, otherKey, _ := loginServerTestCertificate(t, nil)
	for _, test := range []struct {
		name   string
		change func(*LoginServerOptions)
	}{
		{name: "absent bind", change: func(o *LoginServerOptions) { o.Address = "" }},
		{name: "wildcard bind", change: func(o *LoginServerOptions) { o.Address = "0.0.0.0:443" }},
		{name: "ipv6 wildcard", change: func(o *LoginServerOptions) { o.Address = "[::]:443" }},
		{name: "multicast bind", change: func(o *LoginServerOptions) { o.Address = "224.0.0.1:443" }},
		{name: "dns bind", change: func(o *LoginServerOptions) { o.Address = "console.example.test:443" }},
		{name: "noncanonical port", change: func(o *LoginServerOptions) { o.Address = "127.0.0.1:0443" }},
		{name: "missing graph", change: func(o *LoginServerOptions) { o.Dispatcher = nil }},
		{name: "zero graph", change: func(o *LoginServerOptions) { o.Dispatcher = &LoginDispatcher{} }},
		{name: "missing management", change: func(o *LoginServerOptions) { o.Dispatcher.management = nil }},
		{name: "zero capacity", change: func(o *LoginServerOptions) { o.MaxConnections = 0 }},
		{name: "oversized capacity", change: func(o *LoginServerOptions) { o.MaxConnections = maximumLoginConnections + 1 }},
		{name: "missing certificate", change: func(o *LoginServerOptions) { o.CertificatePEM = nil }},
		{name: "oversized certificate", change: func(o *LoginServerOptions) { o.CertificatePEM = make([]byte, 64*1024+1) }},
		{name: "oversized key", change: func(o *LoginServerOptions) { o.PrivateKeyPEM = make([]byte, 64*1024+1) }},
		{name: "missing key", change: func(o *LoginServerOptions) { o.PrivateKeyPEM = nil }},
		{name: "mismatched key", change: func(o *LoginServerOptions) { o.PrivateKeyPEM = otherKey }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options, fixture, callback := loginServerTestOptions(t)
			test.change(&options)
			if server, err := NewLoginServer(options); server != nil || !errors.Is(err, ErrInvalidLoginServer) {
				t.Fatal("unsafe listener input released an owner")
			}
			if len(fixture.calls) != 0 || callback.calls != 0 {
				t.Fatal("constructor performed authority/budget effects")
			}
		})
	}
}

func TestLoginServerServesNoGrantLandingOverOwnedTLS(t *testing.T) {
	t.Parallel()
	options, fixture, callback := loginServerTestOptions(t)
	server, client := startLoginTestServer(t, options)
	// Parsing owns the keypair; caller erasure cannot change the serving graph.
	clear(options.CertificatePEM)
	clear(options.PrivateKeyPEM)
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(strings.ToLower(method), func(t *testing.T) {
			request := loginServerTestRequest(t, server, method, LoginCallbackContinuePath)
			response, err := client.Do(request)
			if err != nil {
				t.Fatal("actual TLS landing failed", err)
			}
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 32*1024))
			closeErr := response.Body.Close()
			if readErr != nil || closeErr != nil {
				t.Fatal("landing response not consumed/closed")
			}
			if response.StatusCode != http.StatusOK || response.ProtoMajor != 1 || response.TLS.Version < tls.VersionTLS12 {
				t.Fatal("landing crossed another transport profile")
			}
			if response.Header.Get("Set-Cookie") != "" || response.Header.Get("Location") != "" || response.Header.Get("Cache-Control") != "no-store" {
				t.Fatal("landing granted credentials or lost no-store")
			}
			if method == http.MethodGet && !bytes.Contains(body, []byte(`data-return-path="/console"`)) {
				t.Fatal("fixed Core return mapping absent")
			}
			if method == http.MethodHead && len(body) != 0 {
				t.Fatal("HEAD released active content")
			}
		})
	}
	if len(fixture.calls) != 0 || callback.calls != 0 {
		t.Fatal("landing reached authority or provider effects")
	}
}

func TestLoginServerServesSessionPrepareOverOwnedTLS(t *testing.T) {
	t.Parallel()
	options, fixture, callback := loginServerTestOptions(t)
	server, client := startLoginTestServer(t, options)
	server.mu.Lock()
	address := server.boundAddress
	server.mu.Unlock()
	request, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"https://"+address+AccountSessionCSRFPreparePath,
		strings.NewReader("{}"),
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "console.example.test"
	request.Header.Set("Origin", "https://console.example.test")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-MeshTransit-Session", "v1")
	request.AddCookie(&http.Cookie{Name: AccountSessionCookieName, Value: managementTokenFixture})
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("actual TLS session preparation failed", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maximumBrowserManagementResponseBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		t.Fatal("session preparation response not consumed/closed")
	}
	var payload map[string]json.RawMessage
	if err := json.Unmarshal(body, &payload); err != nil || len(payload) != 2 ||
		payload["csrf_token"] == nil || payload["expires_at"] == nil {
		t.Fatal("session preparation changed its bounded response", err)
	}
	invalidResponse := response.StatusCode != http.StatusOK || response.ProtoMajor != 1 ||
		response.TLS.Version < tls.VersionTLS12 || response.Header.Get("Set-Cookie") != "" ||
		response.Header.Get("Cache-Control") != "no-store" || bytes.Contains(body, []byte(managementTokenFixture))
	if invalidResponse || len(fixture.calls) != 0 || callback.calls != 0 {
		t.Fatal("session preparation crossed transport, cookie or authority boundaries")
	}
}

func TestLoginServerRejectsTargetsWithoutImplicitSuccess(t *testing.T) {
	t.Parallel()
	options, fixture, callback := loginServerTestOptions(t)
	server, client := startLoginTestServer(t, options)
	for _, test := range []struct{ name, method, path, host string }{
		{name: "wrong host", method: http.MethodGet, path: LoginCallbackContinuePath, host: "foreign.example.test"},
		{name: "trailing slash", method: http.MethodGet, path: LoginCallbackContinuePath + "/"},
		{name: "dot path", method: http.MethodGet, path: "/auth/v1/../callback/continue"},
		{name: "encoded path", method: http.MethodGet, path: "/auth/%63allback/continue"},
		{name: "callback head", method: http.MethodHead, path: "/auth/callback"},
		{name: "options", method: http.MethodOptions, path: LoginCallbackContinuePath},
		{name: "management", method: http.MethodGet, path: AccountSessionCSRFPreparePath},
		{name: "client", method: http.MethodGet, path: "/machine/register"},
		{name: "metrics", method: http.MethodGet, path: "/metrics"},
		{name: "docs", method: http.MethodGet, path: "/openapi.json"},
		{name: "query outside callback", method: http.MethodGet, path: LoginCallbackContinuePath + "?code=synthetic-private"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := loginServerTestRequest(t, server, test.method, test.path)
			if test.host != "" {
				request.Host = test.host
			}
			response, err := client.Do(request)
			if response != nil {
				if closeErr := response.Body.Close(); closeErr != nil {
					t.Error(closeErr)
				}
			}
			if err == nil || response != nil {
				t.Fatal("dispatch failure flushed an implicit success/redirect")
			}
		})
	}
	if len(fixture.calls) != 0 || callback.calls != 0 {
		t.Fatal("rejected target reached dependency effects")
	}
}

func TestLoginServerRejectsPlaintextAndNegotiatesOnlyHTTP1(t *testing.T) {
	t.Parallel()
	options, fixture, callback := loginServerTestOptions(t)
	server, client := startLoginTestServer(t, options)
	server.mu.Lock()
	address := server.boundAddress
	server.mu.Unlock()
	dialer := &net.Dialer{Timeout: time.Second}
	plain, err := dialer.DialContext(t.Context(), "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_, writeErr := io.WriteString(plain, "GET "+LoginCallbackContinuePath+" HTTP/1.1\r\nHost: console.example.test\r\n\r\n")
	if writeErr != nil {
		t.Fatal("owned plaintext probe did not submit", writeErr)
	}
	input, readErr := io.ReadAll(io.LimitReader(plain, 4096))
	if err := plain.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if readErr != nil {
		t.Fatal("plaintext rejection did not finish", readErr)
	}
	if bytes.Contains(input, []byte("200 OK")) || bytes.Contains(input, []byte("Set-Cookie:")) || bytes.Contains(input, []byte("data-return-path")) {
		t.Fatal("plaintext entered the login graph")
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("fixture transport changed")
	}
	profile := transport.TLSClientConfig.Clone()
	profile.NextProtos = []string{"h2", "http/1.1"}
	tlsDialer := &tls.Dialer{NetDialer: dialer, Config: profile}
	connection, err := tlsDialer.DialContext(t.Context(), "tcp", address)
	if err != nil {
		t.Fatal("checked ALPN handshake failed", err)
	}
	checked, ok := connection.(*tls.Conn)
	if !ok {
		t.Fatal("fixture TLS connection changed")
	}
	if checked.ConnectionState().NegotiatedProtocol != "http/1.1" {
		t.Fatal("another protocol was negotiated")
	}
	if err := checked.Close(); err != nil {
		t.Fatal(err)
	}
	if len(fixture.calls) != 0 || callback.calls != 0 {
		t.Fatal("transport probes entered authority effects")
	}
}

func TestLoginServerAbortsStagedAndPartialDispatchFailure(t *testing.T) {
	t.Parallel()
	options, _, _ := loginServerTestOptions(t)
	server, err := NewLoginServer(options)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		writer func() http.ResponseWriter
	}{
		{name: "staged headers", writer: func() http.ResponseWriter {
			response := httptest.NewRecorder()
			response.Header().Set("Set-Cookie", "synthetic-private-cookie")
			return response
		}},
		{name: "partial write", writer: func() http.ResponseWriter {
			response := &loginPartialWriter{loginHTTPRecorder: newLoginHTTPRecorder()}
			return response
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := test.writer()
			socket, peer := net.Pipe()
			t.Cleanup(func() {
				if err := peer.Close(); err != nil {
					t.Error(err)
				}
			})
			t.Cleanup(func() {
				if err := socket.Close(); err != nil {
					t.Error(err)
				}
			})
			request := landingTestRequest()
			request = request.WithContext(loginConnectionContext(request.Context(), socket))
			if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			server.handle(response, request)
			var input [1]byte
			if count, err := peer.Read(input[:]); count != 0 || !errors.Is(err, io.EOF) {
				t.Fatal("failure did not abort the owned transport")
			}
			if test.name == "staged headers" {
				staged, ok := response.(*httptest.ResponseRecorder)
				if !ok || staged.Body.Len() != 0 || staged.Header().Get("Set-Cookie") != "synthetic-private-cookie" {
					t.Fatal("abort rewrote staged response ownership")
				}
			} else {
				partial, ok := response.(*loginPartialWriter)
				if !ok || partial.Code != http.StatusOK || partial.Body.Len() != 1 {
					t.Fatal("partial submission was overwritten or not exercised")
				}
			}
		})
	}
}

type loginFailingCloseConnection struct{ net.Conn }

func (connection *loginFailingCloseConnection) Close() error {
	return errors.Join(connection.Conn.Close(), errors.New("synthetic private close detail"))
}

func TestLoginServerAbortCloseFailureIsClosedServiceResult(t *testing.T) {
	t.Parallel()
	options, _, _ := loginServerTestOptions(t)
	server, err := NewLoginServer(options)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	guard, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), time.Second)
	defer cancel()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil && !errors.Is(err, ErrLoginListenerUnavailable) {
			t.Error(err)
		}
		select {
		case <-server.Done():
		case <-ctx.Done():
			t.Error("failed-abort owner did not join")
		}
	})
	socket, peer := net.Pipe()
	t.Cleanup(func() {
		if err := socket.Close(); err != nil {
			t.Error(err)
		}
		if err := peer.Close(); err != nil {
			t.Error(err)
		}
	})
	request := landingTestRequest()
	request.Host = "foreign.example.test"
	request = request.WithContext(loginConnectionContext(request.Context(), &loginFailingCloseConnection{Conn: socket}))
	server.handle(httptest.NewRecorder(), request)
	err = server.Shutdown(guard)
	if !errors.Is(err, ErrLoginListenerUnavailable) || err.Error() != ErrLoginListenerUnavailable.Error() {
		t.Fatal("close failure was swallowed or disclosed")
	}
	select {
	case err := <-server.Done():
		if !errors.Is(err, ErrLoginListenerUnavailable) || err.Error() != ErrLoginListenerUnavailable.Error() {
			t.Fatal("Done lost closed abort failure")
		}
	case <-guard.Done():
		t.Fatal("failed-abort service did not join")
	}
}

func TestLoginConnectionContextPreservesParentAndOwnsRawSocket(t *testing.T) {
	t.Parallel()
	type parentKey struct{}
	parent, cancel := context.WithTimeout(context.WithValue(t.Context(), parentKey{}, "closed fixture value"), time.Second)
	defer cancel()
	raw, peer := net.Pipe()
	t.Cleanup(func() {
		if err := raw.Close(); err != nil {
			t.Error(err)
		}
		if err := peer.Close(); err != nil {
			t.Error(err)
		}
	})
	wrapped := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS12})
	ctx := loginConnectionContext(parent, wrapped)
	owner, ok := ctx.Value(loginSocketContextKey{}).(*loginSocketOwner)
	if !ok || owner.raw != raw || ctx.Value(parentKey{}) != "closed fixture value" {
		t.Fatal("connection custody replaced parent values or retained TLS close writes")
	}
	expected, expectedPresent := parent.Deadline()
	actual, actualPresent := ctx.Deadline()
	if expectedPresent != actualPresent || !actual.Equal(expected) {
		t.Fatal("connection custody changed the parent deadline")
	}
	cancel()
	select {
	case <-ctx.Done():
	default:
		t.Fatal("connection custody detached cancellation")
	}
}

func TestLoginServerStartIsOneShotAndFailClosed(t *testing.T) {
	t.Parallel()
	options, _, _ := loginServerTestOptions(t)
	server, err := NewLoginServer(options)
	if err != nil {
		t.Fatal(err)
	}
	if server.Done() != nil || !errors.Is(server.Shutdown(t.Context()), ErrLoginServerNotStarted) {
		t.Fatal("unstarted listener claimed a completed service")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if !errors.Is(server.Start(ctx), context.Canceled) || server.Done() != nil {
		t.Fatal("canceled start opened serving ownership")
	}
	if !errors.Is(server.Start(t.Context()), ErrLoginServerStarted) {
		t.Fatal("failed start was retried on the same owner")
	}
	var absent *LoginServer
	for _, invalid := range []*LoginServer{nil, {}} {
		if !errors.Is(invalid.Start(t.Context()), ErrInvalidLoginServer) || !errors.Is(invalid.Shutdown(t.Context()), ErrInvalidLoginServer) {
			t.Fatal("zero serving owner is unsafe")
		}
	}
	if absent.Done() != nil {
		t.Fatal("absent owner returned a join channel")
	}
}

func TestLoginServerStartConcealsBindFailure(t *testing.T) {
	t.Parallel()
	listenConfig := &net.ListenConfig{}
	occupied, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := occupied.Close(); err != nil {
			t.Error(err)
		}
	})
	options, _, _ := loginServerTestOptions(t)
	options.Address = occupied.Addr().String()
	server, err := NewLoginServer(options)
	if err != nil {
		t.Fatal(err)
	}
	err = server.Start(t.Context())
	if !errors.Is(err, ErrLoginListenerUnavailable) || err.Error() != ErrLoginListenerUnavailable.Error() || server.Done() != nil {
		t.Fatal("bind failure exposed topology or serving ownership")
	}
}

func TestLoginServerShutdownJoinsBlockedRequest(t *testing.T) {
	// Real socket lifecycle plus process-wide leak verification runs serially.
	defer goleak.VerifyNone(t)
	for _, name := range []string{"graceful", "forced"} {
		t.Run(name, func(t *testing.T) {
			options, fixture, _ := loginServerTestOptions(t)
			entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var enteredOnce, releaseOnce sync.Once
			guard, guardCancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer guardCancel()
			fixture.hook = func(ctx context.Context, operation string) {
				if operation != "rate" {
					return
				}
				enteredOnce.Do(func() { close(entered) })
				select {
				case <-release:
				case <-ctx.Done():
					close(canceled)
					// Hold a bounded cleanup barrier to test Done, not just cancellation.
					select {
					case <-release:
					case <-guard.Done():
					}
				case <-guard.Done():
				}
			}
			server, client := startLoginTestServer(t, options)
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			request := loginServerTestRequest(t, server, http.MethodPost, LoginPreparePath)
			request.Body = io.NopCloser(strings.NewReader("{}"))
			request.ContentLength = 2
			request.Header.Set("Origin", "https://console.example.test")
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("X-Meshtransit-Login", "v1")
			clientDone := make(chan struct{})
			go func() {
				defer close(clientDone)
				response, err := client.Do(request)
				if response != nil {
					if closeErr := response.Body.Close(); closeErr != nil {
						t.Error(closeErr)
					}
				}
				if name == "graceful" && (err != nil || response == nil || response.StatusCode != http.StatusOK) {
					t.Error("graceful drain did not retain the component-owned response")
				}
			}()
			t.Cleanup(func() {
				releaseOnce.Do(func() { close(release) })
				ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
				defer cancel()
				select {
				case <-clientDone:
				case <-ctx.Done():
					t.Error("owned request did not join cleanup")
				}
			})
			select {
			case <-entered:
			case <-guard.Done():
				t.Fatal("request did not enter actual dispatch")
			}
			stopDone := make(chan error, 1)
			if name == "forced" {
				stop, cancel := context.WithCancel(guard)
				cancel()
				if !errors.Is(server.Shutdown(stop), context.Canceled) {
					t.Fatal("forced shutdown concealed timeout")
				}
				select {
				case <-canceled:
				case <-guard.Done():
					t.Fatal("request ownership was not canceled")
				}
				select {
				case <-server.Done():
					t.Fatal("Done preceded blocked handler cleanup")
				default:
				}
			} else {
				go func() { stopDone <- server.Shutdown(guard) }()
				// Observe the actual admission fence before releasing request work.
				ticker := time.NewTicker(time.Millisecond)
				defer ticker.Stop()
				for {
					server.mu.Lock()
					isStopping := server.isStopping
					server.mu.Unlock()
					if isStopping {
						break
					}
					select {
					case <-ticker.C:
					case <-guard.Done():
						t.Fatal("graceful admission did not stop")
					}
				}
				select {
				case <-stopDone:
					t.Fatal("Shutdown preceded blocked handler return")
				default:
				}
				select {
				case <-server.Done():
					t.Fatal("Done preceded graceful drain")
				default:
				}
			}
			releaseOnce.Do(func() { close(release) })
			if name == "graceful" {
				select {
				case err := <-stopDone:
					if err != nil {
						t.Fatal("graceful request join failed", err)
					}
				case <-guard.Done():
					t.Fatal("graceful shutdown did not join")
				}
			} else if err := server.Shutdown(guard); err != nil {
				t.Fatal("forced request join failed", err)
			}
			select {
			case <-clientDone:
			case <-guard.Done():
				t.Fatal("owned client did not join")
			}
		})
	}
}

func TestLoginServerConnectionCapIncludesHandshakes(t *testing.T) {
	t.Cleanup(func() { goleak.VerifyNone(t) })
	options, _, _ := loginServerTestOptions(t)
	options.MaxConnections = 1
	server, client := startLoginTestServer(t, options)
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("fixture transport changed")
	}
	server.mu.Lock()
	address := server.boundAddress
	server.mu.Unlock()
	dialer := &net.Dialer{Timeout: time.Second}
	tlsDialer := &tls.Dialer{NetDialer: dialer, Config: transport.TLSClientConfig}
	first, err := tlsDialer.DialContext(t.Context(), "tcp", address)
	if err != nil {
		t.Fatal("first checked handshake failed", err)
	}
	t.Cleanup(func() {
		if err := first.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
	})
	second, err := dialer.DialContext(t.Context(), "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := second.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Error(err)
		}
	})
	blocked := tls.Client(second, transport.TLSClientConfig)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if !errors.Is(blocked.HandshakeContext(ctx), context.DeadlineExceeded) {
		t.Fatal("connection cap did not include the incomplete HTTP request")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	request := loginServerTestRequest(t, server, http.MethodGet, LoginCallbackContinuePath)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("released connection capacity did not recover", err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
}

type loginPartialWriter struct{ *loginHTTPRecorder }

func (writer *loginPartialWriter) Write(body []byte) (int, error) {
	if len(body) == 0 {
		return 0, errors.New("synthetic failed submission")
	}
	written, err := writer.loginHTTPRecorder.Write(body[:1])
	return written, errors.Join(err, errors.New("synthetic failed submission"))
}

func TestLoginServerDiagnosticsConcealResidentServingProfile(t *testing.T) {
	t.Parallel()
	options, _, _ := loginServerTestOptions(t)
	server, err := NewLoginServer(options)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{options, server} {
		text := fmt.Sprint(value) + fmt.Sprintf("%#v", value)
		if strings.Contains(text, options.Address) || strings.Contains(text, "PRIVATE KEY") || strings.Contains(text, "console.example.test") {
			t.Fatal("serving profile entered diagnostics")
		}
		if body, err := json.Marshal(value); body != nil || err == nil {
			t.Fatal("serving profile serialized")
		}
		valuer, ok := value.(slog.LogValuer)
		if !ok || valuer.LogValue().String() != "[REDACTED]" {
			t.Fatal("structured serving profile disclosed")
		}
	}
}
