package profile

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestServerServesProfilesUntilShutdown(t *testing.T) {
	t.Parallel()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	server, err := NewServer(address)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(t.Context()); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+address+"/debug/pprof/heap?debug=1", nil)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("GET heap profile: %v", err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || len(body) == 0 {
		t.Fatalf("heap profile = %d, %d bytes", response.StatusCode, len(body))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}
	if err := <-server.Done(); err != nil {
		t.Fatalf("Done() = %v", err)
	}
	if _, err := NewServer(""); err == nil {
		t.Fatal("NewServer(\"\") accepted no address")
	}
}
