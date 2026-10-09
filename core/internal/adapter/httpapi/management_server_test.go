package httpapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestManagementServerServesTLSOnly(t *testing.T) {
	t.Parallel()

	certificate := managementTLSCertificate(t)
	var requests atomic.Int64
	server := managementServerFixture(t, certificate, http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		response.WriteHeader(http.StatusNoContent)
	}))
	listenConfig := &net.ListenConfig{}
	socket, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	server.listen = func(context.Context, string, string) (net.Listener, error) { return socket, nil }
	if err := server.Start(t.Context()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		<-server.Done()
	})

	roots := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatalf("x509.ParseCertificate() error = %v", err)
	}
	roots.AddCert(parsed)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: "example.com",
		RootCAs:    roots,
		NextProtos: []string{"http/1.1"},
	}}}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+socket.Addr().String()+"/probe", nil)
	if err != nil {
		t.Fatalf("http.NewRequestWithContext() error = %v", err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("client.Do() error = %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusNoContent || requests.Load() != 1 {
		t.Fatalf("status/requests = %d/%d, want %d/1", response.StatusCode, requests.Load(), http.StatusNoContent)
	}
}

func TestManagementServerOwnsServingGoroutine(t *testing.T) {
	t.Parallel()

	server := managementServerFixture(t, managementTLSCertificate(t), http.NotFoundHandler())
	listener := newBlockingListener()
	server.listen = func(context.Context, string, string) (net.Listener, error) { return listener, nil }
	if err := server.Start(t.Context()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := server.Start(t.Context()); !errors.Is(err, ErrManagementServerStarted) {
		t.Fatalf("second Start() error = %v, want ErrManagementServerStarted", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	select {
	case err := <-server.Done():
		if err != nil {
			t.Fatalf("Done() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("serving goroutine did not join")
	}
}

func TestNewManagementServerRejectsInvalidOptions(t *testing.T) {
	t.Parallel()

	valid := ManagementServerOptions{
		Address: "127.0.0.1:8444", Certificate: managementTLSCertificate(t),
		Handler: http.NotFoundHandler(), MaxConnections: 2,
	}
	for _, mutate := range []func(*ManagementServerOptions){
		func(options *ManagementServerOptions) { options.Address = "" },
		func(options *ManagementServerOptions) { options.Certificate = tls.Certificate{} },
		func(options *ManagementServerOptions) { options.Handler = nil },
		func(options *ManagementServerOptions) { options.MaxConnections = 0 },
		func(options *ManagementServerOptions) { options.MaxConnections = maximumManagementConnections + 1 },
	} {
		invalid := valid
		mutate(&invalid)
		if _, err := NewManagementServer(invalid); !errors.Is(err, ErrInvalidManagementServer) {
			t.Fatalf("NewManagementServer() error = %v, want ErrInvalidManagementServer", err)
		}
	}
}

func managementServerFixture(t *testing.T, certificate tls.Certificate, handler http.Handler) *ManagementServer {
	t.Helper()
	server, err := NewManagementServer(ManagementServerOptions{
		Address: "127.0.0.1:8444", Certificate: certificate, Handler: handler, MaxConnections: 2,
	})
	if err != nil {
		t.Fatalf("NewManagementServer() error = %v", err)
	}
	return server
}

func managementTLSCertificate(t testing.TB) tls.Certificate {
	t.Helper()
	server := httptest.NewTLSServer(http.NotFoundHandler())
	server.Close()
	return server.TLS.Certificates[0]
}
