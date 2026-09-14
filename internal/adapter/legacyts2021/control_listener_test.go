package legacyts2021

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

func TestControlListenerServesTLSOnly(t *testing.T) {
	t.Parallel()

	certificate := testTLSCertificate(t)
	sessions := &fakeControlSessionServer{}
	listener := newControlListenerFixture(t, certificate, sessions)
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

func TestControlListenerOwnsAndJoinsServingGoroutine(t *testing.T) {
	t.Parallel()

	sessions := &fakeControlSessionServer{}
	listener := newControlListenerFixture(t, testTLSCertificate(t), sessions)
	socket := newQueuedListener()
	listener.listen = func(context.Context, string, string) (net.Listener, error) {
		return socket, nil
	}
	if err := listener.Start(t.Context()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := listener.Start(t.Context()); !errors.Is(err, ErrControlListenerStarted) {
		t.Fatalf("second Start() error = %v, want ErrControlListenerStarted", err)
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

func TestControlListenerShutdownDuringStartPreventsLateSocket(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		listener := newControlListenerFixture(
			t,
			testTLSCertificate(t),
			&fakeControlSessionServer{},
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

func TestControlListenerRejectsInvalidOptions(t *testing.T) {
	t.Parallel()

	valid := ControlListenerOptions{
		Address:          "127.0.0.1:8443",
		Certificate:      testTLSCertificate(t),
		Sessions:         &fakeControlSessionServer{},
		Telemetry:        controlTelemetryFixture(t),
		MaxConnections:   2,
		HandshakeTimeout: time.Second,
		IdleTimeout:      time.Minute,
	}
	tests := map[string]func(*ControlListenerOptions){
		"address":     func(options *ControlListenerOptions) { options.Address = "" },
		"certificate": func(options *ControlListenerOptions) { options.Certificate = tls.Certificate{} },
		"sessions":    func(options *ControlListenerOptions) { options.Sessions = nil },
		"telemetry":   func(options *ControlListenerOptions) { options.Telemetry = nil },
		"telemetry limit": func(options *ControlListenerOptions) {
			options.MaxConnections++
		},
		"connections": func(options *ControlListenerOptions) { options.MaxConnections = 0 },
		"handshake":   func(options *ControlListenerOptions) { options.HandshakeTimeout = 0 },
		"idle":        func(options *ControlListenerOptions) { options.IdleTimeout = 0 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			options := valid
			mutate(&options)
			if _, err := NewControlListener(options); !errors.Is(err, ErrInvalidControlListener) {
				t.Fatalf("NewControlListener() error = %v, want ErrInvalidControlListener", err)
			}
		})
	}
}

func newControlListenerFixture(
	t testing.TB,
	certificate tls.Certificate,
	sessions ControlSessionServer,
) *ControlListener {
	t.Helper()
	telemetry := controlTelemetryFixture(t)
	listener, err := NewControlListener(ControlListenerOptions{
		Address:          "127.0.0.1:8443",
		Certificate:      certificate,
		Sessions:         sessions,
		Telemetry:        telemetry,
		MaxConnections:   2,
		HandshakeTimeout: 2 * time.Second,
		IdleTimeout:      time.Minute,
	})
	if err != nil {
		t.Fatalf("NewControlListener() error = %v", err)
	}
	return listener
}

func testTLSCertificate(t testing.TB) tls.Certificate {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Close()
	return server.TLS.Certificates[0]
}

func controlTelemetryFixture(t testing.TB) *ControlTelemetry {
	t.Helper()
	telemetry, err := NewControlTelemetry(2, 2)
	if err != nil {
		t.Fatalf("NewControlTelemetry() error = %v", err)
	}
	return telemetry
}

type fakeControlSessionServer struct {
	requests  atomic.Int64
	shutdowns atomic.Int64
}

func (server *fakeControlSessionServer) ServeHTTP(response http.ResponseWriter, _ *http.Request) {
	server.requests.Add(1)
	response.WriteHeader(http.StatusNoContent)
}

func (server *fakeControlSessionServer) Shutdown(context.Context) error {
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
	_ ControlSessionServer = (*fakeControlSessionServer)(nil)
	_ io.Closer            = (*queuedListener)(nil)
)
