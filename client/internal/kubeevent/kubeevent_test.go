package kubeevent

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeAPI takes Event creates and patches.
type fakeAPI struct {
	mu      sync.Mutex
	created []map[string]any
	patched []map[string]any
	paths   []string
	auth    []string
	refuse  atomic.Bool
	// gone answers patches 404; hold delays creates until closed.
	gone atomic.Bool
	hold chan struct{}
}

// wait polls until ok, under the API's lock.
func (api *fakeAPI) wait(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		api.mu.Lock()
		done := ok()
		api.mu.Unlock()
		if done {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
	}
}

func newRecorder(t *testing.T) (*Recorder, *fakeAPI, *atomic.Pointer[time.Time]) {
	t.Helper()
	return newRecorderWith(t, &fakeAPI{})
}

func newRecorderWith(t *testing.T, api *fakeAPI) (*Recorder, *fakeAPI, *atomic.Pointer[time.Time]) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var decoded map[string]any
		_ = json.Unmarshal(body, &decoded)
		if hold := api.hold; hold != nil && r.Method == http.MethodPost {
			<-hold
		}
		api.mu.Lock()
		defer api.mu.Unlock()
		api.paths = append(api.paths, r.Method+" "+r.URL.Path+" "+r.Header.Get("Content-Type"))
		api.auth = append(api.auth, r.Header.Get("Authorization"))
		if api.refuse.Load() {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		switch r.Method {
		case http.MethodPost:
			api.created = append(api.created, decoded)
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"metadata":{"name":"meshgw-privileged-abc"}}`)
		case http.MethodPatch:
			if api.gone.Load() {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			api.patched = append(api.patched, decoded)
			_, _ = io.WriteString(w, `{}`)
		}
	}))
	t.Cleanup(server.Close)
	dir := t.TempDir()
	ca, token := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "token")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE",
		Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(token, []byte("gateway-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var now atomic.Pointer[time.Time]
	start := time.Date(2026, 10, 29, 8, 0, 0, 0, time.UTC)
	now.Store(&start)
	recorder, err := New(Options{Server: server.URL, CAFile: ca, TokenFile: token, Namespace: "mt-kube",
		Instance: "meshgw-0", Window: 5 * time.Minute, Now: func() time.Time { return *now.Load() }})
	if err != nil {
		t.Fatal(err)
	}
	return recorder, api, &now
}

func advance(now *atomic.Pointer[time.Time], by time.Duration) {
	next := now.Load().Add(by)
	now.Store(&next)
}

var use = Use{Device: "device-a", DeviceName: "laptop", Owner: "person-1", Group: "sre", Source: "100.64.1.9",
	AuditID: "01a1-audit"}

// The first use of a window makes an Event on the group's account; later
// uses raise its count; a new window makes a new Event.
func TestPrivilegedMakesThenCounts(t *testing.T) {
	t.Parallel()
	recorder, api, now := newRecorder(t)
	ctx := context.Background()
	if counted, err := recorder.Privileged(ctx, use); !counted || err != nil {
		t.Fatalf("first: %t %v", counted, err)
	}
	advance(now, time.Minute)
	if counted, err := recorder.Privileged(ctx, use); !counted || err != nil {
		t.Fatalf("second: %t %v", counted, err)
	}
	api.wait(t, "count never raised", func() bool { return len(api.patched) == 1 })
	advance(now, 5*time.Minute)
	if counted, err := recorder.Privileged(ctx, use); !counted || err != nil {
		t.Fatalf("next window: %t %v", counted, err)
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.created) != 2 || len(api.patched) != 1 {
		t.Fatalf("created %d, patched %d", len(api.created), len(api.patched))
	}
	made := api.created[0]
	involved, _ := made["involvedObject"].(map[string]any)
	message, _ := made["message"].(string)
	if made["reason"] != Reason || involved["kind"] != "ServiceAccount" || involved["name"] != "mt-sre" ||
		involved["namespace"] != "mt-kube" || made["reportingInstance"] != "meshgw-0" ||
		!strings.Contains(message, "device-a") || !strings.Contains(message, "person-1") ||
		!strings.Contains(message, "01a1-audit") {
		t.Fatalf("event %+v", made)
	}
	if api.patched[0]["count"] != float64(2) {
		t.Fatalf("patch %+v", api.patched[0])
	}
	if !strings.HasPrefix(api.paths[1], "PATCH /api/v1/namespaces/mt-kube/events/meshgw-privileged-abc "+
		"application/merge-patch+json") || api.auth[0] != "Bearer gateway-token" {
		t.Fatalf("calls %v %v", api.paths, api.auth)
	}
}

// A window's first Event that cannot be made refuses the use; once made, a
// failed count is reported but the use goes on.
func TestPrivilegedFailsClosedOnlyWithoutAnEvent(t *testing.T) {
	t.Parallel()
	recorder, api, now := newRecorder(t)
	ctx := context.Background()
	api.refuse.Store(true)
	if counted, err := recorder.Privileged(ctx, use); counted || err == nil {
		t.Fatalf("refused create: %t %v", counted, err)
	}
	api.refuse.Store(false)
	if counted, err := recorder.Privileged(ctx, use); !counted || err != nil {
		t.Fatalf("create: %t %v", counted, err)
	}
	// A count not raised does not hold the use back.
	api.refuse.Store(true)
	advance(now, time.Second)
	if counted, err := recorder.Privileged(ctx, use); !counted || err != nil {
		t.Fatalf("refused patch: %t %v", counted, err)
	}
}

// Uses at once make one Event and count every use; one that stops waiting
// leaves.
func TestPrivilegedConcurrentUsesMakeOneEvent(t *testing.T) {
	t.Parallel()
	hold := make(chan struct{})
	recorder, api, _ := newRecorderWith(t, &fakeAPI{hold: hold})
	var started sync.WaitGroup
	results := make(chan bool, 8)
	for range 8 {
		started.Go(func() {
			counted, err := recorder.Privileged(context.Background(), use)
			results <- counted && err == nil
		})
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	time.Sleep(20 * time.Millisecond) // the first use is making the Event
	if counted, err := recorder.Privileged(cancelled, use); counted || err == nil {
		t.Fatalf("a cancelled wait: %t %v", counted, err)
	}
	close(hold)
	started.Wait()
	close(results)
	for ok := range results {
		if !ok {
			t.Fatal("a use was refused")
		}
	}
	api.wait(t, "the count never reached 8", func() bool {
		return len(api.patched) > 0 && api.patched[len(api.patched)-1]["count"] == float64(8)
	})
	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.created) != 1 {
		t.Fatalf("%d Events made", len(api.created))
	}
}

// An Event deleted within its window is made again by the next use.
func TestPrivilegedMakesADeletedEventAgain(t *testing.T) {
	t.Parallel()
	recorder, api, _ := newRecorder(t)
	ctx := context.Background()
	_, _ = recorder.Privileged(ctx, use)
	api.gone.Store(true)
	_, _ = recorder.Privileged(ctx, use)
	api.wait(t, "the 404 never came", func() bool { return len(api.paths) == 2 })
	held := recorder.window(key{use.Device, use.Group})
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		held.mu.Lock()
		forgotten := held.name == "" && !held.raising
		held.mu.Unlock()
		if forgotten {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a deleted Event was kept")
		}
	}
	if counted, err := recorder.Privileged(ctx, use); !counted || err != nil {
		t.Fatalf("after delete: %t %v", counted, err)
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.created) != 2 {
		t.Fatalf("%d Events made", len(api.created))
	}
}

func TestNewRefusesBadOptions(t *testing.T) {
	t.Parallel()
	for name, options := range map[string]Options{
		"http":         {Server: "http://api", TokenFile: "t", Namespace: "n", Instance: "i", Window: time.Minute},
		"short window": {Server: "https://api", TokenFile: "t", Namespace: "n", Instance: "i", Window: time.Second},
		"no instance":  {Server: "https://api", TokenFile: "t", Namespace: "n", Window: time.Minute},
	} {
		if _, err := New(options); err == nil {
			t.Errorf("%s: taken", name)
		}
	}
}
