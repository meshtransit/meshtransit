package httpapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const identityTestIssuer = "https://id.example.test/oauth2"

type identityTestHandler struct {
	handle func(http.ResponseWriter, *http.Request)
}

func (handler *identityTestHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	handler.handle(response, request)
}

func identityServerTestOptions(t *testing.T, handler http.Handler) IdentityServerOptions {
	t.Helper()
	certificate, privateKey, _ := loginServerTestCertificate(t, func(template *x509.Certificate) {
		template.DNSNames = []string{"id.example.test"}
	})
	return IdentityServerOptions{
		Address: "127.0.0.1:0", Issuer: identityTestIssuer,
		CertificatePEM: certificate, PrivateKeyPEM: privateKey,
		Handler: handler, ConnectorIDs: []string{"google-v1"},
		RequestTimeout: 2 * time.Second, MaxConnections: 8, MaxConcurrentRequests: 4,
	}
}

func identityServerTestRequest(t *testing.T, method, target string, body io.Reader) *http.Request {
	t.Helper()
	request := httptest.NewRequestWithContext(
		t.Context(),
		method,
		"https://id.example.test"+target,
		body,
	)
	request.Host = "id.example.test"
	request.URL.Scheme = ""
	request.URL.Host = ""
	return request
}

func TestNewIdentityServerRejectsUnsafeProfiles(t *testing.T) {
	t.Parallel()

	validHandler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	_, otherKey, _ := loginServerTestCertificate(t, func(template *x509.Certificate) {
		template.DNSNames = []string{"id.example.test"}
	})
	var nilHandler *identityTestHandler
	for _, test := range []struct {
		name   string
		change func(*IdentityServerOptions)
	}{
		{name: "absent bind", change: func(options *IdentityServerOptions) { options.Address = "" }},
		{name: "wildcard bind", change: func(options *IdentityServerOptions) { options.Address = "0.0.0.0:9443" }},
		{name: "public bind", change: func(options *IdentityServerOptions) { options.Address = "203.0.113.1:9443" }},
		{name: "link local bind", change: func(options *IdentityServerOptions) { options.Address = "169.254.1.1:9443" }},
		{name: "dns bind", change: func(options *IdentityServerOptions) { options.Address = "identity.internal:9443" }},
		{name: "noncanonical bind", change: func(options *IdentityServerOptions) { options.Address = "127.0.0.1:09443" }},
		{name: "http issuer", change: func(options *IdentityServerOptions) { options.Issuer = "http://id.example.test/oauth2" }},
		{name: "issuer query", change: func(options *IdentityServerOptions) { options.Issuer += "?tenant=one" }},
		{name: "issuer trailing slash", change: func(options *IdentityServerOptions) { options.Issuer += "/" }},
		{name: "issuer dot segment", change: func(options *IdentityServerOptions) { options.Issuer = "https://id.example.test/a/../oauth2" }},
		{name: "missing handler", change: func(options *IdentityServerOptions) { options.Handler = nil }},
		{name: "typed nil handler", change: func(options *IdentityServerOptions) { options.Handler = nilHandler }},
		{name: "missing connector", change: func(options *IdentityServerOptions) { options.ConnectorIDs = nil }},
		{name: "invalid connector", change: func(options *IdentityServerOptions) { options.ConnectorIDs = []string{"Google"} }},
		{name: "duplicate connector", change: func(options *IdentityServerOptions) { options.ConnectorIDs = []string{"google-v1", "google-v1"} }},
		{name: "short timeout", change: func(options *IdentityServerOptions) { options.RequestTimeout = time.Millisecond }},
		{name: "fractional timeout", change: func(options *IdentityServerOptions) { options.RequestTimeout = 1500 * time.Millisecond }},
		{name: "long timeout", change: func(options *IdentityServerOptions) { options.RequestTimeout = 31 * time.Second }},
		{name: "zero connections", change: func(options *IdentityServerOptions) { options.MaxConnections = 0 }},
		{name: "excess connections", change: func(options *IdentityServerOptions) { options.MaxConnections = maximumIdentityConnections + 1 }},
		{name: "zero concurrency", change: func(options *IdentityServerOptions) { options.MaxConcurrentRequests = 0 }},
		{name: "concurrency exceeds connections", change: func(options *IdentityServerOptions) { options.MaxConcurrentRequests = 9 }},
		{name: "missing certificate", change: func(options *IdentityServerOptions) { options.CertificatePEM = nil }},
		{name: "missing private key", change: func(options *IdentityServerOptions) { options.PrivateKeyPEM = nil }},
		{name: "mismatched private key", change: func(options *IdentityServerOptions) { options.PrivateKeyPEM = otherKey }},
		{name: "foreign certificate", change: func(options *IdentityServerOptions) {
			certificate, key, _ := loginServerTestCertificate(t, nil)
			options.CertificatePEM, options.PrivateKeyPEM = certificate, key
		}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			options := identityServerTestOptions(t, validHandler)
			test.change(&options)
			server, err := NewIdentityServer(options)
			if server != nil || !errors.Is(err, ErrInvalidIdentityServer) {
				t.Fatalf("NewIdentityServer() = (%v, %v), want concealed rejection", server, err)
			}
		})
	}
}

func TestIdentityServerAllowsOnlyRequiredOIDCRoutes(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	handler := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		response.Header().Set("Cache-Control", "public")
		response.WriteHeader(http.StatusNoContent)
	})
	server, err := NewIdentityServer(identityServerTestOptions(t, handler))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, method, target, contentType string
	}{
		{name: "discovery get", method: http.MethodGet, target: "/oauth2/.well-known/openid-configuration"},
		{name: "discovery head", method: http.MethodHead, target: "/oauth2/.well-known/openid-configuration"},
		{name: "authorization", method: http.MethodGet, target: "/oauth2/auth?client_id=core"},
		{name: "connector", method: http.MethodGet, target: "/oauth2/auth/google-v1?req=opaque"},
		{name: "callback", method: http.MethodGet, target: "/oauth2/callback?code=opaque&state=opaque"},
		{name: "token", method: http.MethodPost, target: "/oauth2/token", contentType: identityFormContentType},
		{name: "keys get", method: http.MethodGet, target: "/oauth2/keys"},
		{name: "keys head", method: http.MethodHead, target: "/oauth2/keys"},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			request := identityServerTestRequest(t, test.method, test.target, nil)
			if test.contentType != "" {
				request.Header.Set("Content-Type", test.contentType)
			}
			response := httptest.NewRecorder()
			server.ServeHTTP(response, request)
			if response.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want 204", response.Code)
			}
			for _, header := range []string{
				"Cache-Control", "Pragma", "Referrer-Policy", "X-Content-Type-Options",
				"X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security",
				"Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy",
			} {
				if response.Header().Get(header) == "" {
					t.Fatalf("security header %s absent", header)
				}
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("handler replaced immutable cache policy")
			}
		})
	}
	if calls.Load() != 8 {
		t.Fatalf("handler calls = %d, want 8", calls.Load())
	}
}

func TestIdentityServerRejectsUnownedTargetsBeforeHandler(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) })
	server, err := NewIdentityServer(identityServerTestOptions(t, handler))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, method, target string
		change               func(*http.Request)
		want                 int
	}{
		{name: "root", method: http.MethodGet, target: "/", want: http.StatusNotFound},
		{name: "userinfo", method: http.MethodGet, target: "/oauth2/userinfo", want: http.StatusNotFound},
		{name: "introspection", method: http.MethodPost, target: "/oauth2/token/introspect", want: http.StatusNotFound},
		{name: "device flow", method: http.MethodPost, target: "/oauth2/device/code", want: http.StatusNotFound},
		{name: "health", method: http.MethodGet, target: "/oauth2/healthz", want: http.StatusNotFound},
		{name: "static", method: http.MethodGet, target: "/oauth2/static/main.css", want: http.StatusNotFound},
		{name: "foreign connector", method: http.MethodGet, target: "/oauth2/auth/other", want: http.StatusNotFound},
		{name: "trailing slash", method: http.MethodGet, target: "/oauth2/auth/", want: http.StatusNotFound},
		{name: "wrong host", method: http.MethodGet, target: "/oauth2/keys", want: http.StatusNotFound,
			change: func(request *http.Request) { request.Host = "foreign.example.test" }},
		{name: "plaintext", method: http.MethodGet, target: "/oauth2/keys", want: http.StatusNotFound,
			change: func(request *http.Request) { request.TLS = nil }},
		{name: "encoded path", method: http.MethodGet, target: "/oauth2/keys", want: http.StatusNotFound,
			change: func(request *http.Request) { request.URL.RawPath = "/oauth2/%6beys" }},
		{name: "absolute form", method: http.MethodGet, target: "/oauth2/keys", want: http.StatusNotFound,
			change: func(request *http.Request) {
				request.URL.Scheme, request.URL.Host = "https", "id.example.test"
			}},
		{name: "query on keys", method: http.MethodGet, target: "/oauth2/keys?x=1", want: http.StatusBadRequest},
		{name: "body on get", method: http.MethodGet, target: "/oauth2/keys", want: http.StatusBadRequest,
			change: func(request *http.Request) { request.ContentLength = 1 }},
		{name: "post discovery", method: http.MethodPost, target: "/oauth2/.well-known/openid-configuration", want: http.StatusMethodNotAllowed},
		{name: "token query", method: http.MethodPost, target: "/oauth2/token?x=1", want: http.StatusBadRequest,
			change: func(request *http.Request) { request.Header.Set("Content-Type", identityFormContentType) }},
		{name: "token wrong media", method: http.MethodPost, target: "/oauth2/token", want: http.StatusUnsupportedMediaType,
			change: func(request *http.Request) { request.Header.Set("Content-Type", "application/json") }},
		{name: "token media parameter", method: http.MethodPost, target: "/oauth2/token", want: http.StatusUnsupportedMediaType,
			change: func(request *http.Request) {
				request.Header.Set("Content-Type", identityFormContentType+"; charset=utf-8")
			}},
		{name: "token oversized length", method: http.MethodPost, target: "/oauth2/token", want: http.StatusRequestEntityTooLarge,
			change: func(request *http.Request) {
				request.Header.Set("Content-Type", identityFormContentType)
				request.ContentLength = maximumIdentityTokenBodyBytes + 1
			}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			request := identityServerTestRequest(t, test.method, test.target, nil)
			if test.change != nil {
				test.change(request)
			}
			response := httptest.NewRecorder()
			server.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d", response.Code, test.want)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatalf("rejected requests reached broker: %d", calls.Load())
	}
}

func TestIdentityServerStripsForwardingHeadersAndBoundsBody(t *testing.T) {
	t.Parallel()

	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		for name := range request.Header {
			lower := strings.ToLower(name)
			if lower == "forwarded" || lower == "x-original-url" || lower == "x-rewrite-url" ||
				lower == "x-real-ip" || strings.HasPrefix(lower, "x-forwarded-") ||
				strings.HasPrefix(lower, "x-remote-") {
				t.Errorf("forwarded assertion reached broker: %s", name)
			}
		}
		_, err := io.ReadAll(request.Body)
		var tooLarge *http.MaxBytesError
		if !errors.As(err, &tooLarge) {
			t.Errorf("body read error = %v, want MaxBytesError", err)
		}
		response.WriteHeader(http.StatusRequestEntityTooLarge)
	})
	server, err := NewIdentityServer(identityServerTestOptions(t, handler))
	if err != nil {
		t.Fatal(err)
	}
	request := identityServerTestRequest(
		t,
		http.MethodPost,
		"/oauth2/token",
		strings.NewReader(strings.Repeat("x", maximumIdentityTokenBodyBytes+1)),
	)
	request.ContentLength = -1
	request.TransferEncoding = []string{"chunked"}
	request.Header.Set("Content-Type", identityFormContentType)
	for _, name := range []string{
		"Forwarded", "X-Forwarded-For", "X-Forwarded-Proto", "X-Original-URL",
		"X-Rewrite-URL", "X-Real-IP", "X-Remote-User",
	} {
		request.Header.Set(name, "untrusted")
	}
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", response.Code)
	}
}

func TestIdentityServerConcurrencyDoesNotQueue(t *testing.T) {
	t.Parallel()

	entered, release := make(chan struct{}), make(chan struct{})
	handler := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		response.WriteHeader(http.StatusNoContent)
	})
	options := identityServerTestOptions(t, handler)
	options.MaxConcurrentRequests = 1
	server, err := NewIdentityServer(options)
	if err != nil {
		t.Fatal(err)
	}
	firstResponse := httptest.NewRecorder()
	firstDone := make(chan struct{})
	go func() {
		server.ServeHTTP(
			firstResponse,
			identityServerTestRequest(t, http.MethodGet, "/oauth2/keys", nil),
		)
		close(firstDone)
	}()
	<-entered
	secondResponse := httptest.NewRecorder()
	server.ServeHTTP(
		secondResponse,
		identityServerTestRequest(t, http.MethodGet, "/oauth2/keys", nil),
	)
	if secondResponse.Code != http.StatusTooManyRequests ||
		secondResponse.Header().Get("Retry-After") != "1" {
		t.Fatalf("busy response = (%d, %q)", secondResponse.Code, secondResponse.Header().Get("Retry-After"))
	}
	close(release)
	<-firstDone
	if firstResponse.Code != http.StatusNoContent {
		t.Fatalf("first status = %d", firstResponse.Code)
	}
}

func TestIdentityServerAddsRequestDeadline(t *testing.T) {
	t.Parallel()

	handler := http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		deadline, ok := request.Context().Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 1100*time.Millisecond {
			t.Errorf("request deadline = (%v, %v)", deadline, ok)
		}
		response.WriteHeader(http.StatusNoContent)
	})
	options := identityServerTestOptions(t, handler)
	options.RequestTimeout = time.Second
	server, err := NewIdentityServer(options)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.ServeHTTP(response, identityServerTestRequest(t, http.MethodGet, "/oauth2/keys", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestIdentityServerServesDirectTLSWithHTTP1Only(t *testing.T) {
	t.Parallel()

	handler := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(response, "{}")
	})
	options := identityServerTestOptions(t, handler)
	server, err := NewIdentityServer(options)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	address := server.boundAddress
	server.mu.Unlock()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(options.CertificatePEM) {
		t.Fatal("fixture certificate rejected")
	}
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{
			RootCAs: roots, ServerName: "id.example.test", MinVersion: tls.VersionTLS12,
		},
	}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	request, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"https://"+address+"/oauth2/.well-known/openid-configuration",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "id.example.test"
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("direct TLS request failed", err)
	}
	if closeErr := response.Body.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if response.StatusCode != http.StatusOK || response.ProtoMajor != 1 ||
		response.TLS == nil || response.TLS.Version < tls.VersionTLS12 {
		t.Fatalf("transport result = (%d, %s, %v)", response.StatusCode, response.Proto, response.TLS)
	}
	plain, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	if err := plain.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(plain, "GET /oauth2/keys HTTP/1.1\r\nHost: id.example.test\r\n\r\n")
	plaintextResponse, _ := io.ReadAll(io.LimitReader(plain, 4096))
	_ = plain.Close()
	if strings.Contains(string(plaintextResponse), "200 OK") {
		t.Fatal("plaintext request reached broker")
	}
	transport.CloseIdleConnections()
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
	if err := <-server.Done(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityServerShutdownDrainsBeforeJoin(t *testing.T) {
	t.Parallel()

	entered, release := make(chan struct{}), make(chan struct{})
	handler := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		response.WriteHeader(http.StatusNoContent)
	})
	options := identityServerTestOptions(t, handler)
	server, err := NewIdentityServer(options)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	address := server.boundAddress
	server.mu.Unlock()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(options.CertificatePEM) {
		t.Fatal("fixture certificate rejected")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: roots, ServerName: "id.example.test", MinVersion: tls.VersionTLS12,
	}}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+address+"/oauth2/keys", nil)
	request.Host = "id.example.test"
	requestDone := make(chan error, 1)
	go func() {
		response, requestErr := client.Do(request)
		if response != nil {
			requestErr = errors.Join(requestErr, response.Body.Close())
		}
		requestDone <- requestErr
	}()
	<-entered
	shutdownDone := make(chan error, 1)
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
	defer cancel()
	go func() { shutdownDone <- server.Shutdown(shutdownCtx) }()
	select {
	case err := <-shutdownDone:
		t.Fatalf("shutdown returned before handler drained: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-requestDone; err != nil {
		t.Fatal(err)
	}
	if err := <-shutdownDone; err != nil {
		t.Fatal(err)
	}
	if err := <-server.Done(); err != nil {
		t.Fatal(err)
	}
	transport.CloseIdleConnections()
}

func TestIdentityServerRejectsExpiredCertificateAtStart(t *testing.T) {
	t.Parallel()

	options := identityServerTestOptions(t, http.NotFoundHandler())
	certificate, privateKey, _ := loginServerTestCertificate(t, func(template *x509.Certificate) {
		template.DNSNames = []string{"id.example.test"}
		template.NotBefore = time.Now().Add(-2 * time.Hour)
		template.NotAfter = time.Now().Add(-time.Hour)
	})
	options.CertificatePEM, options.PrivateKeyPEM = certificate, privateKey
	server, err := NewIdentityServer(options)
	if err != nil {
		t.Fatal("constructor must remain clock-free", err)
	}
	if err := server.Start(t.Context()); !errors.Is(err, ErrInvalidIdentityServer) {
		t.Fatalf("Start() error = %v, want invalid certificate time", err)
	}
	if server.Done() != nil {
		t.Fatal("failed start published a join channel")
	}
}

func TestIdentityServerLifecycleAndFormatting(t *testing.T) {
	t.Parallel()

	options := identityServerTestOptions(t, http.NotFoundHandler())
	server, err := NewIdentityServer(options)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Shutdown(t.Context()); !errors.Is(err, ErrIdentityServerNotStarted) {
		t.Fatalf("pre-start Shutdown() error = %v", err)
	}
	if fmt.Sprint(server) != "[REDACTED]" || fmt.Sprintf("%#v", server) != "httpapi.IdentityServer([REDACTED])" ||
		fmt.Sprint(options) != "[REDACTED]" || fmt.Sprintf("%#v", options) != "[REDACTED]" {
		t.Fatal("formatting disclosed identity serving state")
	}
	if server.LogValue().String() != "[REDACTED]" || options.LogValue().String() != "[REDACTED]" {
		t.Fatal("structured formatting disclosed identity serving state")
	}
	if _, err := json.Marshal(server); !errors.Is(err, ErrInvalidIdentityServer) {
		t.Fatalf("json.Marshal(server) error = %v", err)
	}
	if _, err := json.Marshal(options); !errors.Is(err, ErrInvalidIdentityServer) {
		t.Fatalf("json.Marshal(options) error = %v", err)
	}
	var _ slog.LogValuer = server
	if err := server.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := server.Start(t.Context()); !errors.Is(err, ErrIdentityServerStarted) {
		t.Fatalf("second Start() error = %v", err)
	}
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		t.Fatal(err)
	}
	if err := <-server.Done(); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityServerConcurrentHeaderStripping(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	handler := http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		response.WriteHeader(http.StatusNoContent)
	})
	server, err := NewIdentityServer(identityServerTestOptions(t, handler))
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for range 4 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			request := identityServerTestRequest(t, http.MethodGet, "/oauth2/keys", nil)
			request.Header.Set("X-Forwarded-For", "198.51.100.1")
			server.ServeHTTP(httptest.NewRecorder(), request)
		}()
	}
	wait.Wait()
	if calls.Load() != 4 {
		t.Fatalf("handler calls = %d, want 4", calls.Load())
	}
}
