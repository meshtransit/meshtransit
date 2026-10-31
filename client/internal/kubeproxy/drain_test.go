package kubeproxy

import (
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// A stopping gateway refuses new connections while it answers the request
// in flight, so kubectl tries the next replica at once (TD-CLI-94).
func TestServeDrainsWhenStopped(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	type answer struct {
		status int
		err    error
	}
	answered := make(chan answer, 1)
	go func() {
		request, err := http.NewRequest(http.MethodGet,
			"https://"+clusterName+"/mt/g/view/api/v1/namespaces/default/pods/linger", nil)
		if err != nil {
			answered <- answer{err: err}
			return
		}
		response, err := f.client.Do(request)
		if err != nil {
			answered <- answer{err: err}
			return
		}
		defer response.Body.Close()
		_, err = io.ReadAll(response.Body)
		answered <- answer{status: response.StatusCode, err: err}
	}()
	// The backend has the request: it answers 300 ms later.
	for got := f.forwarded(); !strings.HasSuffix(got.Path, "/linger"); got = f.forwarded() {
	}
	f.stop()
	refused := false
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		conn, err := net.DialTimeout("tcp", f.address, 100*time.Millisecond)
		if err != nil {
			refused = true
			break
		}
		_ = conn.Close()
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case got := <-answered:
		if got.err != nil || got.status != http.StatusOK {
			t.Fatalf("the request in flight got %d, %v", got.status, got.err)
		}
	case <-time.After(DrainTimeout):
		t.Fatal("the request in flight was not answered")
	}
	if !refused {
		t.Fatal("new connections were taken while draining")
	}
	select {
	case <-f.served:
	case <-time.After(DrainTimeout):
		t.Fatal("Serve did not return once drained")
	}
}
