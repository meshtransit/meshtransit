package daemon

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/pathdiscovery"
	"meshtransit.net/shared/disco"
	"meshtransit.net/shared/netcheck"
)

var (
	natTestSocket  = pathdiscovery.Socket{Port: 41641, Generation: 1}
	natTestServers = []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.1:3478"),
		netip.MustParseAddrPort("192.0.2.2:3478"),
	}
)

// fakeNATPlane is a packet engine whose classifications can be blocked,
// failed or moved to another socket.
type fakeNATPlane struct {
	mu     sync.Mutex
	calls  int
	err    error
	socket pathdiscovery.Socket
	gate   chan struct{} // when set, each classification waits for a receive
}

func (f *fakeNATPlane) DiscoverySocket() pathdiscovery.Socket { return natTestSocket }

func (f *fakeNATPlane) DiscoverEndpoints(context.Context, uint64, []netip.AddrPort) (pathdiscovery.DiscoveryResult, error) {
	return pathdiscovery.DiscoveryResult{}, nil
}

func (f *fakeNATPlane) PrepareNATClassification(
	servers []netip.AddrPort,
) (pathdiscovery.Socket, dataplane.NATClassification, error) {
	f.mu.Lock()
	socket, err, gate := f.socket, f.err, f.gate
	f.mu.Unlock()
	if !socket.IsOpen() {
		socket = natTestSocket
	}

	return socket, func(ctx context.Context) (pathdiscovery.NATReport, error) {
		f.mu.Lock()
		f.calls++
		f.mu.Unlock()
		if gate != nil {
			select {
			case <-gate:
			case <-ctx.Done():
				return pathdiscovery.NATReport{}, ctx.Err()
			}
		}
		if err != nil {
			return pathdiscovery.NATReport{}, err
		}
		report := netcheck.Report{
			NAT:    disco.NATInfo{Mapping: disco.MappingEndpointIndependent, Allocation: disco.AllocationPreserving},
			Mapped: netip.MustParseAddrPort("198.51.100.9:41641"),
			At:     time.Now(),
		}
		for _, server := range servers {
			report.Observations = append(report.Observations, netcheck.Observation{Server: server, Mapped: report.Mapped})
		}

		return pathdiscovery.NATReport{Socket: socket, Report: report}, nil
	}, nil
}

func (f *fakeNATPlane) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.calls
}

func (f *fakeNATPlane) setErr(err error) {
	f.mu.Lock()
	f.err = err
	f.mu.Unlock()
}

type natHarness struct {
	s        *Service
	plane    *fakeNATPlane
	requests chan natRequest
	network  chan struct{}
	stop     func()
}

func startNATHarness(t *testing.T, plane *fakeNATPlane, schedule natSchedule) *natHarness {
	t.Helper()
	s := &Service{nat: newNATState(), clock: time.Now}
	s.nat.schedule = schedule
	requests, network, stop := s.startNATClassification(t.Context(), plane)
	if requests == nil {
		t.Fatal("classification loop not started")
	}
	t.Cleanup(stop)

	return &natHarness{s: s, plane: plane, requests: requests, network: network, stop: stop}
}

func (h *natHarness) request(socket pathdiscovery.Socket) {
	offerLatest(h.requests, natRequest{socket: socket, servers: natTestServers})
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

var slowSchedule = natSchedule{refresh: time.Hour, minInterval: time.Hour, retry: time.Hour}

func TestNATLoopRequestsAndManualRefresh(t *testing.T) {
	t.Parallel()
	h := startNATHarness(t, &fakeNATPlane{}, slowSchedule)
	if got := h.s.nat.get().State; got != NATPending {
		t.Fatalf("state before the first request = %q", got)
	}
	if _, err := h.s.RefreshNAT(t.Context()); !errors.Is(err, ErrNATInactive) {
		t.Fatalf("refresh before any request = %v", err)
	}

	h.request(natTestSocket)
	eventually(t, "first classification", func() bool { return h.s.nat.get().State == NATReady })
	got := h.s.nat.get()
	if got.ServersAnswered != 2 || got.PublicEndpoint != netip.MustParseAddrPort("198.51.100.9:41641") {
		t.Fatalf("status = %+v", got)
	}

	h.request(natTestSocket) // unchanged: no run
	status, err := h.s.RefreshNAT(t.Context())
	if err != nil || status.State != NATReady {
		t.Fatalf("RefreshNAT = %+v, %v", status, err)
	}
	if n := h.plane.count(); n != 2 {
		t.Fatalf("classifications = %d, want 2", n)
	}

	// A socket change runs at once, even inside the minimum interval.
	moved := pathdiscovery.Socket{Port: 41641, Generation: 2}
	h.plane.mu.Lock()
	h.plane.socket = moved
	h.plane.mu.Unlock()
	h.request(moved)
	eventually(t, "socket change", func() bool { return h.plane.count() == 3 })
}

func TestNATLoopNetworkChangeIsSpacedNotLost(t *testing.T) {
	t.Parallel()
	gate := make(chan struct{})
	plane := &fakeNATPlane{gate: gate}
	h := startNATHarness(t, plane, natSchedule{refresh: time.Hour, minInterval: 50 * time.Millisecond, retry: time.Hour})
	h.request(natTestSocket)
	eventually(t, "first run started", func() bool { return plane.count() == 1 })

	// While the loop is busy, a network change and a newer periodic request
	// arrive; the change must still trigger a run afterwards.
	signalNetworkChange(h.network)
	h.request(natTestSocket)
	gate <- struct{}{}
	eventually(t, "network-change run", func() bool { return plane.count() == 2 })
	gate <- struct{}{}
	eventually(t, "ready", func() bool { return h.s.nat.get().State == NATReady })
}

func TestNATLoopFailureKeepsResultAndRetries(t *testing.T) {
	t.Parallel()
	plane := &fakeNATPlane{}
	h := startNATHarness(t, plane, natSchedule{refresh: time.Hour, minInterval: time.Hour, retry: 30 * time.Millisecond})
	h.request(natTestSocket)
	eventually(t, "first result", func() bool { return h.s.nat.get().State == NATReady })

	plane.setErr(netcheck.ErrNoResponse)
	status, err := h.s.RefreshNAT(t.Context())
	if err != nil || status.State != NATFailed || status.Error != "no_response" {
		t.Fatalf("failed refresh = %+v, %v", status, err)
	}
	if kept := h.s.nat.get(); kept.State != NATReady {
		t.Fatalf("a failure replaced the good result for the same socket: %+v", kept)
	}
	before := plane.count()
	eventually(t, "retry after failure", func() bool { return plane.count() > before })
}

func TestNATLoopSocketChangedDuringPrepare(t *testing.T) {
	t.Parallel()
	plane := &fakeNATPlane{socket: pathdiscovery.Socket{Port: 41641, Generation: 9}}
	h := startNATHarness(t, plane, slowSchedule)
	h.request(natTestSocket)
	eventually(t, "failed status", func() bool { return h.s.nat.get().State == NATFailed })
	if got := h.s.nat.get().Error; got != "socket_changed" {
		t.Fatalf("error = %q", got)
	}
}

func TestNATLoopStopDuringClassification(t *testing.T) {
	t.Parallel()
	plane := &fakeNATPlane{gate: make(chan struct{})}
	h := startNATHarness(t, plane, slowSchedule)
	h.request(natTestSocket)
	eventually(t, "first run", func() bool { return plane.count() == 1 })

	refreshed := make(chan error, 1)
	go func() {
		_, err := h.s.RefreshNAT(context.Background())
		refreshed <- err
	}()
	h.stop()
	if err := <-refreshed; !errors.Is(err, ErrNATInactive) {
		t.Fatalf("waiting refresh after stop = %v", err)
	}
	if got := h.s.nat.get().State; got != NATInactive {
		t.Fatalf("state after stop = %q", got)
	}
	if _, err := h.s.RefreshNAT(t.Context()); !errors.Is(err, ErrNATInactive) {
		t.Fatalf("refresh without a loop = %v", err)
	}
}

func TestNATStatusAndHelpers(t *testing.T) {
	t.Parallel()
	if got := (&Service{}).natStatus(); got.State != NATUnavailable {
		t.Fatalf("no state = %+v", got)
	}
	s := &Service{nat: newNATState(), clock: time.Now}
	if got := s.natStatus(); got.State != NATUnavailable {
		t.Fatalf("no packet engine = %+v", got)
	}
	var nilService *Service
	if _, err := nilService.RefreshNAT(t.Context()); !errors.Is(err, ErrNATInactive) {
		t.Fatalf("nil service = %v", err)
	}
	if _, ok := s.classifyNAT(t.Context(), &fakeNATPlane{}, natRequest{}); ok || s.nat.get().Error != "no_stun_servers" {
		t.Fatalf("no servers = %+v", s.nat.get())
	}
	for err, want := range map[error]string{
		context.Canceled:                 "cancelled",
		netcheck.ErrNoResponse:           "no_response",
		pathdiscovery.ErrNoSTUNServers:   "no_stun_servers",
		pathdiscovery.ErrSocketChanged:   "socket_changed",
		pathdiscovery.ErrTransportClosed: "socket_closed",
		errors.New("other"):              "error",
	} {
		if got := natErrorCode(err); got != want {
			t.Errorf("natErrorCode(%v) = %q, want %q", err, got, want)
		}
	}
}
