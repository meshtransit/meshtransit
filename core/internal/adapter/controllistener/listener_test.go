package controllistener

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestListenerServesTLSOnly(t *testing.T) {
	t.Parallel()

	certificate := testTLSCertificate(t)
	sessions := &fakeRoutes{}
	listener := newListenerFixture(t, certificate, sessions)
	listenConfig := &net.ListenConfig{}
	socket, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() error = %v", err)
	}
	listener.listen = func(context.Context, string, string) (net.Listener, error) {
		return socket, nil
	}
	if err := listener.Start(t.Context()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = listener.Shutdown(shutdownCtx)
		<-listener.Done()
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
	request, err := http.NewRequestWithContext(
		t.Context(),
		http.MethodGet,
		"https://"+socket.Addr().String()+"/probe",
		nil,
	)
	if err != nil {
		t.Fatalf("http.NewRequestWithContext() error = %v", err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("client.Do() error = %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusNoContent)
	}
	if got := sessions.requests.Load(); got != 1 {
		t.Fatalf("session requests = %d, want 1", got)
	}
}

func TestListenerOwnsAndJoinsServingGoroutine(t *testing.T) {
	t.Parallel()

	sessions := &fakeRoutes{}
	listener := newListenerFixture(t, testTLSCertificate(t), sessions)
	socket := newQueuedListener()
	listener.listen = func(context.Context, string, string) (net.Listener, error) {
		return socket, nil
	}
	if err := listener.Start(t.Context()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := listener.Start(t.Context()); !errors.Is(err, ErrStarted) {
		t.Fatalf("second Start() error = %v, want ErrStarted", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := listener.Shutdown(shutdownCtx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	select {
	case err := <-listener.Done():
		if err != nil {
			t.Fatalf("Done() error = %v", err)
		}
	case <-shutdownCtx.Done():
		t.Fatal("serving goroutine did not join")
	}
	if got := sessions.shutdowns.Load(); got != 1 {
		t.Fatalf("session shutdowns = %d, want 1", got)
	}
}

func TestListenerShutdownDuringStartPreventsLateSocket(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		listener := newListenerFixture(
			t,
			testTLSCertificate(t),
			&fakeRoutes{},
		)
		listenStarted := make(chan struct{})
		releaseListen := make(chan struct{})
		socket := newQueuedListener()
		listener.listen = func(context.Context, string, string) (net.Listener, error) {
			close(listenStarted)
			<-releaseListen
			return socket, nil
		}

		startResult := make(chan error, 1)
		go func() { startResult <- listener.Start(t.Context()) }()
		<-listenStarted
		shutdownResult := make(chan error, 1)
		go func() { shutdownResult <- listener.Shutdown(t.Context()) }()
		synctest.Wait()

		close(releaseListen)
		synctest.Wait()
		if err := <-shutdownResult; err != nil {
			t.Fatalf("Shutdown() error = %v", err)
		}
		if err := <-startResult; !errors.Is(err, context.Canceled) {
			t.Fatalf("Start() error = %v, want context canceled", err)
		}
		select {
		case <-socket.closed:
		default:
			t.Fatal("socket remained open after canceled startup")
		}
		if listener.Done() != nil {
			t.Fatal("Done() != nil after canceled startup")
		}
	})
}

func TestListenerRejectsInvalidOptions(t *testing.T) {
	t.Parallel()

	valid := Options{
		Address:          "127.0.0.1:8443",
		Certificate:      testTLSCertificate(t),
		Routes:           &fakeRoutes{},
		Telemetry:        telemetryFixture(t),
		MaxConnections:   2,
		HandshakeTimeout: time.Second,
		IdleTimeout:      time.Minute,
	}
	tests := map[string]func(*Options){
		"address":     func(options *Options) { options.Address = "" },
		"certificate": func(options *Options) { options.Certificate = tls.Certificate{} },
		"routes":      func(options *Options) { options.Routes = nil },
		"telemetry":   func(options *Options) { options.Telemetry = nil },
		"telemetry limit": func(options *Options) {
			options.MaxConnections++
		},
		"connections": func(options *Options) { options.MaxConnections = 0 },
		"handshake":   func(options *Options) { options.HandshakeTimeout = 0 },
		"idle":        func(options *Options) { options.IdleTimeout = 0 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			options := valid
			mutate(&options)
			if _, err := New(options); !errors.Is(err, ErrInvalid) {
				t.Fatalf("New() error = %v, want ErrInvalid", err)
			}
		})
	}
}

func newListenerFixture(
	t testing.TB,
	certificate tls.Certificate,
	routes Routes,
) *Listener {
	t.Helper()
	telemetry := telemetryFixture(t)
	listener, err := New(Options{
		Address:          "127.0.0.1:8443",
		Certificate:      certificate,
		Routes:           routes,
		Telemetry:        telemetry,
		MaxConnections:   2,
		HandshakeTimeout: 2 * time.Second,
		IdleTimeout:      time.Minute,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return listener
}

func testTLSCertificate(t testing.TB) tls.Certificate {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Close()
	return server.TLS.Certificates[0]
}

func telemetryFixture(t testing.TB) *Telemetry {
	t.Helper()
	telemetry, err := NewTelemetry(2)
	if err != nil {
		t.Fatalf("NewTelemetry() error = %v", err)
	}
	return telemetry
}

type fakeRoutes struct {
	requests  atomic.Int64
	shutdowns atomic.Int64
}

func (server *fakeRoutes) ServeHTTP(response http.ResponseWriter, _ *http.Request) {
	server.requests.Add(1)
	response.WriteHeader(http.StatusNoContent)
}

func (server *fakeRoutes) Shutdown(context.Context) error {
	server.shutdowns.Add(1)
	return nil
}

type queuedListener struct {
	connections chan net.Conn
	closed      chan struct{}
	once        sync.Once
}

func newQueuedListener() *queuedListener {
	return &queuedListener{
		connections: make(chan net.Conn),
		closed:      make(chan struct{}),
	}
}

func (listener *queuedListener) Accept() (net.Conn, error) {
	select {
	case connection := <-listener.connections:
		return connection, nil
	case <-listener.closed:
		return nil, net.ErrClosed
	}
}

func (listener *queuedListener) Close() error {
	listener.once.Do(func() { close(listener.closed) })
	return nil
}

func (*queuedListener) Addr() net.Addr { return controlListenerTestAddress("control-test") }

type controlListenerTestAddress string

func (address controlListenerTestAddress) Network() string { return "tcp" }
func (address controlListenerTestAddress) String() string  { return string(address) }

var (
	_ Routes    = (*fakeRoutes)(nil)
	_ io.Closer = (*queuedListener)(nil)
)
