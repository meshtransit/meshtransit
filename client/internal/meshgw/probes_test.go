package meshgw

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"meshtransit.net/client/internal/daemon"
	"meshtransit.net/client/internal/dataplane"
)

func TestReadiness(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		status daemon.Status
		ready  bool
	}{
		"direct":       {daemon.Status{ControlSession: daemon.ControlSessionSynchronized, DataPlane: string(dataplane.StateEncrypted)}, true},
		"relay":        {daemon.Status{ControlSession: daemon.ControlSessionSynchronized, DataPlane: string(dataplane.StateEncryptedRelay)}, true},
		"no peers yet": {daemon.Status{ControlSession: daemon.ControlSessionSynchronized, DataPlane: string(dataplane.StateIdle)}, true},
		"connecting":   {daemon.Status{ControlSession: daemon.ControlSessionConnecting, DataPlane: string(dataplane.StateEncrypted)}, false},
		"reconnecting": {daemon.Status{ControlSession: daemon.ControlSessionReconnecting, DataPlane: string(dataplane.StateEncrypted)}, true},
		"failed":       {daemon.Status{ControlSession: daemon.ControlSessionSynchronized, DataPlane: string(dataplane.StateFailed)}, false},
		"unsupported":  {daemon.Status{ControlSession: daemon.ControlSessionSynchronized, DataPlane: string(dataplane.StatePolicyUnsupported)}, false},
	} {
		if got, _ := readiness(tc.status); got != tc.ready {
			t.Errorf("%s: readiness() = %v, want %v", name, got, tc.ready)
		}
	}
}

// The probe endpoints answer from the last status the poller saw, so a
// store busy writing to the API server never makes the kubelet time out.
func TestProbesAnswerFromTheLastStatus(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	status := atomic.Pointer[daemon.Status]{}
	status.Store(&daemon.Status{ControlSession: daemon.ControlSessionConnecting})
	probes := NewProbes(func(context.Context) (daemon.Status, error) {
		calls.Add(1)
		return *status.Load(), nil
	}, 100*time.Millisecond, Counter{Name: "meshgw_test_total", Help: "A test counter.", Value: func() uint64 { return 7 }})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go probes.Poll(ctx)
	server := httptest.NewServer(probes.Handler())
	defer server.Close()

	if code, _ := get(t, server.URL+"/healthz"); code != http.StatusOK {
		t.Fatalf("/healthz = %d, want 200", code)
	}
	if code, _ := get(t, server.URL+"/readyz"); code != http.StatusServiceUnavailable {
		t.Fatalf("/readyz while connecting = %d, want 503", code)
	}
	status.Store(&daemon.Status{
		ControlSession: daemon.ControlSessionSynchronized, DataPlane: string(dataplane.StateEncrypted),
		PeerCount: 3, NetmapRevision: 9,
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if code, _ := get(t, server.URL+"/readyz"); code == http.StatusOK {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("/readyz never became ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	code, body := get(t, server.URL+"/metrics")
	if code != http.StatusOK {
		t.Fatalf("/metrics = %d", code)
	}
	for _, line := range []string{"meshgw_ready 1", "meshgw_peers 3", "meshgw_netmap_revision 9", "meshgw_test_total 7"} {
		if !strings.Contains(body, line) {
			t.Errorf("/metrics lacks %q:\n%s", line, body)
		}
	}
	if code, _ := get(t, server.URL+"/other"); code != http.StatusNotFound {
		t.Fatalf("/other = %d, want 404", code)
	}
	if calls.Load() == 0 {
		t.Fatal("the poller never read the status")
	}
}

func get(t *testing.T, url string) (int, string) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("NewRequest(%s) error = %v", url, err)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("GET %s error = %v", url, err)
	}
	defer func() { _ = response.Body.Close() }()
	body, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(body)
}

// A ready result the poller has not renewed for three intervals, as when a
// status read hangs, no longer counts; nor does anything once it stops.
func TestProbesForgetAStaleResult(t *testing.T) {
	t.Parallel()
	now := time.Now()
	var clock atomic.Pointer[time.Time]
	clock.Store(&now)
	probes := NewProbes(func(context.Context) (daemon.Status, error) {
		return daemon.Status{ControlSession: daemon.ControlSessionSynchronized}, nil
	}, time.Second)
	probes.clock = func() time.Time { return *clock.Load() }
	probes.observe(t.Context())
	if !probes.current().ready {
		t.Fatal("a fresh result is not ready")
	}
	later := now.Add(4 * time.Second)
	clock.Store(&later)
	if probes.current().ready {
		t.Fatal("a stale result still counts as ready")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	clock.Store(&now)
	probes.Poll(ctx)
	if last := probes.current(); last.ready || last.reason != "stopping" {
		t.Fatalf("after Poll stops: %+v, want not ready", last)
	}
}

// A condition the gateway requires, such as the kubectl listener, holds the
// replica unready while it fails.
func TestProbesRequireTheirConditions(t *testing.T) {
	t.Parallel()
	var listening atomic.Bool
	probes := NewProbes(func(context.Context) (daemon.Status, error) {
		return daemon.Status{ControlSession: daemon.ControlSessionSynchronized}, nil
	}, time.Second)
	probes.Require("kube API not listening", listening.Load)
	probes.observe(t.Context())
	if last := probes.current(); last.ready || last.reason != "kube API not listening" {
		t.Fatalf("current() = %+v, want not ready for the listener", last)
	}
	listening.Store(true)
	probes.observe(t.Context())
	if !probes.current().ready {
		t.Fatal("current() not ready once the listener is up")
	}
}
