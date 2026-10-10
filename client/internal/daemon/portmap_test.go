package daemon

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/pathdiscovery"
	"meshtransit.net/client/internal/portmap"
)

// fakePortMapper records what the refresh loop tells it and serves a
// candidate the test sets.
type fakePortMapper struct {
	mu        sync.Mutex
	port      uint16
	network   int
	running   int
	candidate netip.AddrPort
	changes   chan struct{}
	ports     chan uint16
}

func newFakePortMapper() *fakePortMapper {
	return &fakePortMapper{changes: make(chan struct{}, 1), ports: make(chan uint16, 8)}
}

func (m *fakePortMapper) SetPort(port uint16) {
	m.mu.Lock()
	changed := m.port != port
	m.port = port
	m.mu.Unlock()
	if changed {
		m.ports <- port
	}
}

func (m *fakePortMapper) NetworkChanged() {
	m.mu.Lock()
	m.network++
	m.mu.Unlock()
}

func (m *fakePortMapper) Changes() <-chan struct{} { return m.changes }

func (m *fakePortMapper) Candidate() (netip.AddrPort, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.candidate, m.candidate.IsValid()
}

func (m *fakePortMapper) Status() portmap.Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.candidate.IsValid() {
		return portmap.Status{State: portmap.StateMapped, Protocol: portmap.ProtocolPCP, External: m.candidate}
	}

	return portmap.Status{State: portmap.StateIdle}
}

func (m *fakePortMapper) Run(ctx context.Context) {
	m.mu.Lock()
	m.running++
	m.mu.Unlock()
	<-ctx.Done()
	m.mu.Lock()
	m.running--
	m.mu.Unlock()
}

func (m *fakePortMapper) set(candidate netip.AddrPort) {
	m.mu.Lock()
	m.candidate = candidate
	m.mu.Unlock()
	select {
	case m.changes <- struct{}{}:
	default:
	}
}

func hasSource(set pathdiscovery.Set, endpoint netip.AddrPort, source pathdiscovery.Source) bool {
	for _, candidate := range set.Candidates() {
		if candidate.Endpoint() == endpoint && candidate.Source() == source {
			return true
		}
	}

	return false
}

func TestEndpointRefreshPublishesThePortMapping(t *testing.T) {
	t.Parallel()
	srflx, err := pathdiscovery.NewCandidate(netip.MustParseAddrPort("198.51.100.51:41641"), pathdiscovery.SourceServerReflexive)
	if err != nil {
		t.Fatal(err)
	}
	discovered, err := pathdiscovery.NewSet([]pathdiscovery.Candidate{srflx})
	if err != nil {
		t.Fatal(err)
	}
	discoverer := &refreshDiscoverer{
		calls:  make(chan struct{}, 4),
		result: pathdiscovery.DiscoveryResult{Candidates: discovered},
	}
	mapper := newFakePortMapper()
	networkChanges := make(chan struct{}, 1)
	service := &Service{
		clock:                time.Now,
		endpointRefreshDelay: func() time.Duration { return time.Hour },
		networkChanges:       networkChanges,
		portMapper:           mapper,
	}
	requests := make(chan endpointRefreshRequest, 1)
	updates := make(chan controlplane.EndpointUpdate, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- service.runEndpointRefresh(ctx, 15, discoverer, requests, updates) }()

	socket := pathdiscovery.Socket{Port: 41641, Generation: 1}
	requests <- endpointRefreshRequest{active: true, socket: socket}
	select {
	case port := <-mapper.ports:
		if port != 41641 {
			t.Fatalf("mapper port %d", port)
		}
	case <-time.After(time.Second):
		t.Fatal("the mapper was not given the packet port")
	}
	select {
	case <-updates:
	case <-time.After(time.Second):
		t.Fatal("no initial endpoint update")
	}

	// A mapping whose address meshd never observed is not offered: replies
	// from the gateway are unauthenticated.
	mapper.set(netip.MustParseAddrPort("203.0.113.7:50000"))
	select {
	case update := <-updates:
		t.Fatalf("an unobserved mapping was published: %v", update.Candidates.Candidates())
	case <-time.After(100 * time.Millisecond):
	}
	mapped := netip.MustParseAddrPort("198.51.100.51:50000") // the STUN-observed address
	mapper.set(mapped)
	select {
	case update := <-updates:
		if !hasSource(update.Candidates, mapped, pathdiscovery.SourcePortMapping) ||
			!hasSource(update.Candidates, srflx.Endpoint(), pathdiscovery.SourceServerReflexive) {
			t.Fatalf("candidates %v", update.Candidates.Candidates())
		}
	case <-time.After(time.Second):
		t.Fatal("the new mapping was not published")
	}
	if status := service.portMappingStatus(); status.State != portmap.StateMapped || status.Protocol != "pcp" {
		t.Fatalf("status %+v", status)
	}

	networkChanges <- struct{}{}
	deadline := time.Now().Add(time.Second)
	for {
		mapper.mu.Lock()
		network := mapper.network
		mapper.mu.Unlock()
		if network == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the network change did not reach the mapper")
		}
		time.Sleep(5 * time.Millisecond)
	}

	requests <- endpointRefreshRequest{active: false}
	select {
	case port := <-mapper.ports:
		if port != 0 {
			t.Fatalf("mapper port %d after the session went inactive", port)
		}
	case <-time.After(time.Second):
		t.Fatal("the mapper kept its port without an active session")
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("runEndpointRefresh() = %v", err)
	}
	mapper.mu.Lock()
	running := mapper.running
	mapper.mu.Unlock()
	if running != 0 {
		t.Fatal("the session's mapper is still running")
	}
}

func TestPortMappingStatusWithoutMapper(t *testing.T) {
	t.Parallel()
	if status := (&Service{}).portMappingStatus(); status.State != PortMappingOff {
		t.Fatalf("status %+v", status)
	}
}
