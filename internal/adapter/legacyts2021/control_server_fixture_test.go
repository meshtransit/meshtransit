package legacyts2021

import (
	"bufio"
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/meshtransit/meshtransit/internal/control"
)

type recordingAuthenticatedHandlerFactory struct {
	machines chan<- control.AuthenticatedMachine
	handler  http.Handler
	err      error
}

func (factory *recordingAuthenticatedHandlerFactory) Handler(
	machine control.AuthenticatedMachine,
) (http.Handler, error) {
	if factory.machines != nil {
		factory.machines <- machine
	}
	return factory.handler, factory.err
}

func respondingSessionFactory() AuthenticatedHandlerFactory {
	return &recordingAuthenticatedHandlerFactory{
		handler: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			response.WriteHeader(http.StatusNoContent)
		}),
	}
}

func newControlServerFixture(
	t testing.TB,
	sessions AuthenticatedHandlerFactory,
) *ControlServer {
	t.Helper()

	server, err := NewControlServer(controlServerOptionsFixture(t, sessions))
	if err != nil {
		t.Fatalf("NewControlServer() error = %v", err)
	}
	return server
}

func controlServerOptionsFixture(
	t testing.TB,
	sessions AuthenticatedHandlerFactory,
) ControlServerOptions {
	t.Helper()

	privateKey, _ := newControlPrivateKeyFixture(t)
	telemetry, err := NewControlTelemetry(2, 2)
	if err != nil {
		t.Fatalf("NewControlTelemetry() error = %v", err)
	}
	return ControlServerOptions{
		PrivateKey:           privateKey,
		Sessions:             sessions,
		Logger:               slog.New(slog.NewJSONHandler(io.Discard, nil)),
		Telemetry:            telemetry,
		MaxSessions:          2,
		MaxConcurrentStreams: 4,
		HandshakeTimeout:     2 * time.Second,
		ReadIdleTimeout:      2 * time.Second,
		PingTimeout:          500 * time.Millisecond,
		WriteTimeout:         2 * time.Second,
	}
}

func newNoiseUpgradeRequest(t testing.TB) *http.Request {
	t.Helper()
	return newNoiseUpgradeRequestWithInitial(t, []byte{1})
}

func newNoiseUpgradeRequestWithInitial(
	t testing.TB,
	initial []byte,
) *http.Request {
	t.Helper()

	request := httptest.NewRequestWithContext(
		t.Context(),
		http.MethodPost,
		"http://control.example/ts2021",
		nil,
	)
	request.Header.Set("Connection", "keep-alive, Upgrade")
	request.Header.Set("Upgrade", noiseUpgradeProtocol)
	request.Header.Set(noiseHandshakeHeader, base64.StdEncoding.EncodeToString(initial))
	return request
}

type pipeHijacker struct {
	connection net.Conn
	header     http.Header
}

func newPipeHijacker(connection net.Conn) *pipeHijacker {
	return &pipeHijacker{connection: connection, header: make(http.Header)}
}

func (writer *pipeHijacker) Header() http.Header {
	return writer.header
}

func (*pipeHijacker) Write(buffer []byte) (int, error) {
	return len(buffer), nil
}

func (*pipeHijacker) WriteHeader(int) {}

func (writer *pipeHijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return writer.connection, bufio.NewReadWriter(
		bufio.NewReader(writer.connection),
		bufio.NewWriter(writer.connection),
	), nil
}

var (
	_ AuthenticatedHandlerFactory = (*recordingAuthenticatedHandlerFactory)(nil)
	_ http.Hijacker               = (*pipeHijacker)(nil)
	_ http.ResponseWriter         = (*pipeHijacker)(nil)
)
