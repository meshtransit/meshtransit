package legacyts2021

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestControlServerShutdownClosesAndJoinsHijackedSessions(t *testing.T) {
	t.Parallel()

	testCtx, cancelTest := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancelTest()
	server := newControlServerFixture(t, respondingSessionFactory())
	clientConnection, rawServerConnection := net.Pipe()
	writeStarted := make(chan struct{})
	serverConnection := &writeSignalConn{
		Conn:    rawServerConnection,
		started: writeStarted,
	}
	handlerDone := make(chan struct{})
	var handlers sync.WaitGroup
	handlers.Go(func() {
		defer close(handlerDone)
		server.ServeHTTP(newPipeHijacker(serverConnection), newNoiseUpgradeRequest(t))
	})

	select {
	case <-writeStarted:
	case <-testCtx.Done():
		_ = clientConnection.Close()
		t.Fatalf("control session did not reach tracked write: %v", testCtx.Err())
	}
	shutdownCtx, cancel := context.WithTimeout(testCtx, time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		_ = clientConnection.Close()
		t.Fatalf("ControlServer.Shutdown() error = %v", err)
	}
	_ = clientConnection.Close()
	select {
	case <-handlerDone:
	case <-shutdownCtx.Done():
		t.Fatalf("hijacked handler did not return: %v", shutdownCtx.Err())
	}
	handlers.Wait()
	if err := server.Shutdown(t.Context()); err != nil {
		t.Fatalf("ControlServer.Shutdown(second) error = %v", err)
	}

	response := httptest.NewRecorder()
	server.ServeHTTP(
		response,
		httptest.NewRequestWithContext(
			t.Context(),
			http.MethodGet,
			"http://control.example/key?v=142",
			nil,
		),
	)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("post-shutdown status = %d, want 503", response.Code)
	}
}

type writeSignalConn struct {
	net.Conn
	started chan struct{}
	once    sync.Once
}

func (connection *writeSignalConn) Write(buffer []byte) (int, error) {
	connection.once.Do(func() {
		close(connection.started)
	})
	return connection.Conn.Write(buffer)
}
