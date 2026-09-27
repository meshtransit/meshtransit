package daemon

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/meshtransit/meshd/internal/networkmap"
	"github.com/meshtransit/meshd/internal/pathdiscovery"
)

func TestPathEndpointControllerAppliesSelectionAndExactExpiry(t *testing.T) {
	t.Parallel()

	now := time.Now()
	generation := pathEndpointGeneration()
	endpoint := netip.MustParseAddrPort("203.0.113.10:41641")
	selection := pathdiscovery.PathSelection{
		PeerID:                2,
		Generation:            generation,
		RemoteEndpoint:        endpoint,
		ObservedLocalEndpoint: netip.MustParseAddrPort("198.51.100.10:41641"),
		RoundTrip:             time.Millisecond,
		ConfirmedAt:           now,
		ExpiresAt:             now.Add(20 * time.Millisecond),
	}
	selector := &scriptedPathSelector{
		observeResult: pathdiscovery.PathSelectionResult{
			Changes: []pathdiscovery.PathChange{{
				PeerID:  2,
				Current: selection,
			}},
			ExpiresAt: selection.ExpiresAt,
		},
		expireResult: pathdiscovery.PathSelectionResult{
			Changes: []pathdiscovery.PathChange{{
				PeerID:   2,
				Previous: selection,
			}},
		},
	}
	dataPlane := newRecordingPreferredEndpointDataPlane()
	telemetry := pathdiscovery.NewProbeTelemetry()
	ctx, cancel := context.WithCancel(t.Context())
	controller, err := newPathEndpointController(
		ctx,
		selector,
		dataPlane,
		&sync.Mutex{},
		telemetry,
		time.Now,
		cancel,
	)
	if err != nil {
		t.Fatalf("newPathEndpointController() error = %v", err)
	}
	t.Cleanup(controller.Close)
	if err := controller.Activate(
		t.Context(),
		networkmap.Snapshot{Revision: generation.MapRevision},
		generation,
	); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	controller.ObservePath(pathdiscovery.PathObservation{Generation: generation})
	selected := waitForEndpointUpdate(t, dataPlane.updates)
	if selected.restore || selected.revision != generation.MapRevision ||
		selected.peerID != 2 || selected.endpoint != endpoint {
		t.Fatalf("selected endpoint update = %#v", selected)
	}
	restored := waitForEndpointUpdate(t, dataPlane.updates)
	if !restored.restore || restored.revision != generation.MapRevision ||
		restored.peerID != 2 {
		t.Fatalf("expiry endpoint update = %#v", restored)
	}
	_, expireCalls := selector.calls()
	if expireCalls != 1 || controller.Err() != nil {
		t.Fatalf(
			"expiry calls=%d controller error=%v",
			expireCalls,
			controller.Err(),
		)
	}
	snapshot := telemetry.Snapshot()
	if snapshot.ObservationsQueued != 1 || snapshot.ObservationsAccepted != 1 ||
		snapshot.DirectExpirations != 1 {
		t.Fatalf("path telemetry = %#v", snapshot)
	}
}

func TestPathEndpointControllerFailsSessionOnEndpointUpdateError(t *testing.T) {
	t.Parallel()

	generation := pathEndpointGeneration()
	now := time.Now()
	selection := pathdiscovery.PathSelection{
		PeerID:                2,
		Generation:            generation,
		RemoteEndpoint:        netip.MustParseAddrPort("203.0.113.11:41641"),
		ObservedLocalEndpoint: netip.MustParseAddrPort("198.51.100.11:41641"),
		RoundTrip:             time.Millisecond,
		ConfirmedAt:           now,
		ExpiresAt:             now.Add(time.Second),
	}
	selector := &scriptedPathSelector{observeResult: pathdiscovery.PathSelectionResult{
		Changes: []pathdiscovery.PathChange{{
			PeerID:  2,
			Current: selection,
		}},
		ExpiresAt: selection.ExpiresAt,
	}}
	dataPlane := newRecordingPreferredEndpointDataPlane()
	dataPlane.setErr = errors.New("test endpoint failure")
	ctx, cancel := context.WithCancel(t.Context())
	controller, err := newPathEndpointController(
		ctx,
		selector,
		dataPlane,
		&sync.Mutex{},
		pathdiscovery.NewProbeTelemetry(),
		time.Now,
		cancel,
	)
	if err != nil {
		t.Fatalf("newPathEndpointController() error = %v", err)
	}
	t.Cleanup(controller.Close)
	if err := controller.Activate(
		t.Context(),
		networkmap.Snapshot{Revision: generation.MapRevision},
		generation,
	); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	controller.ObservePath(pathdiscovery.PathObservation{Generation: generation})
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for failed endpoint update to stop the session")
	}
	if !errors.Is(controller.Err(), dataPlane.setErr) {
		t.Fatalf("controller error = %v, want endpoint failure", controller.Err())
	}
}

func TestPathEndpointControllerPauseDropsQueuedProof(t *testing.T) {
	t.Parallel()

	generation := pathEndpointGeneration()
	selector := &scriptedPathSelector{}
	dataPlane := newRecordingPreferredEndpointDataPlane()
	ctx, cancel := context.WithCancel(t.Context())
	controller, err := newPathEndpointController(
		ctx,
		selector,
		dataPlane,
		&sync.Mutex{},
		pathdiscovery.NewProbeTelemetry(),
		time.Now,
		cancel,
	)
	if err != nil {
		t.Fatalf("newPathEndpointController() error = %v", err)
	}
	t.Cleanup(controller.Close)
	if err := controller.Activate(
		t.Context(),
		networkmap.Snapshot{Revision: generation.MapRevision},
		generation,
	); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	if err := controller.Pause(t.Context()); err != nil {
		t.Fatalf("Pause() error = %v", err)
	}
	controller.ObservePath(pathdiscovery.PathObservation{Generation: generation})
	time.Sleep(10 * time.Millisecond)
	observeCalls, _ := selector.calls()
	if observeCalls != 0 {
		t.Fatalf("paused selector observe calls = %d, want 0", observeCalls)
	}
}

func TestPathEndpointControllerActivationReconcilesRetiredSelection(t *testing.T) {
	t.Parallel()

	generation := pathEndpointGeneration()
	retiredGeneration := generation
	retiredGeneration.MapRevision--
	now := time.Now()
	selector := &scriptedPathSelector{
		activateResult: pathdiscovery.PathSelectionResult{
			Activation: pathdiscovery.PathActivationSummary{
				SelectionsRetired:   1,
				PeerSetChanges:      2,
				NodeKeyChanges:      3,
				DiscoveryKeyChanges: 4,
				EndpointSetChanges:  5,
				SocketChanged:       true,
			},
			Changes: []pathdiscovery.PathChange{{
				PeerID: 2,
				Previous: pathdiscovery.PathSelection{
					PeerID:                2,
					Generation:            retiredGeneration,
					RemoteEndpoint:        netip.MustParseAddrPort("203.0.113.20:41641"),
					ObservedLocalEndpoint: netip.MustParseAddrPort("198.51.100.20:41641"),
					RoundTrip:             time.Millisecond,
					ConfirmedAt:           now,
					ExpiresAt:             now.Add(time.Second),
				},
			}},
		},
	}
	dataPlane := newRecordingPreferredEndpointDataPlane()
	telemetry := pathdiscovery.NewProbeTelemetry()
	ctx, cancel := context.WithCancel(t.Context())
	controller, err := newPathEndpointController(
		ctx,
		selector,
		dataPlane,
		&sync.Mutex{},
		telemetry,
		time.Now,
		cancel,
	)
	if err != nil {
		t.Fatalf("newPathEndpointController() error = %v", err)
	}
	t.Cleanup(controller.Close)
	if err := controller.Activate(
		t.Context(),
		networkmap.Snapshot{Revision: generation.MapRevision},
		generation,
	); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	restored := waitForEndpointUpdate(t, dataPlane.updates)
	if !restored.restore || restored.revision != generation.MapRevision ||
		restored.peerID != 2 {
		t.Fatalf("activation endpoint update = %#v", restored)
	}
	if snapshot := telemetry.Snapshot(); snapshot.ActivationRetired != 1 ||
		snapshot.ActivationPreserved != 0 ||
		snapshot.AuthorityPeerChanges != 2 ||
		snapshot.AuthorityNodeKeyChanges != 3 ||
		snapshot.AuthorityDiscoveryKeyChanges != 4 ||
		snapshot.AuthorityEndpointChanges != 5 || snapshot.SocketChanges != 1 {
		t.Fatalf("activation telemetry = %#v", snapshot)
	}
}

func TestValidRetiredPathGeneration(t *testing.T) {
	t.Parallel()

	active := pathEndpointGeneration()
	tests := []struct {
		name    string
		mutate  func(*pathdiscovery.ProbeGeneration)
		allowed bool
	}{
		{
			name: "older map on same socket",
			mutate: func(value *pathdiscovery.ProbeGeneration) {
				value.MapRevision--
			},
			allowed: true,
		},
		{
			name: "same map on older socket",
			mutate: func(value *pathdiscovery.ProbeGeneration) {
				value.Socket.Generation--
			},
			allowed: true,
		},
		{name: "exact active generation"},
		{
			name: "different scope",
			mutate: func(value *pathdiscovery.ProbeGeneration) {
				value.Scope++
			},
		},
		{
			name: "newer map",
			mutate: func(value *pathdiscovery.ProbeGeneration) {
				value.MapRevision++
			},
		},
		{
			name: "newer socket",
			mutate: func(value *pathdiscovery.ProbeGeneration) {
				value.Socket.Generation++
			},
		},
		{
			name: "changed port on same socket generation",
			mutate: func(value *pathdiscovery.ProbeGeneration) {
				value.Socket.Port++
			},
		},
		{
			name: "incomplete",
			mutate: func(value *pathdiscovery.ProbeGeneration) {
				*value = pathdiscovery.ProbeGeneration{}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			retired := active
			if test.mutate != nil {
				test.mutate(&retired)
			}
			if got := validRetiredPathGeneration(retired, active); got != test.allowed {
				t.Fatalf("validRetiredPathGeneration() = %v, want %v", got, test.allowed)
			}
		})
	}
}

type scriptedPathSelector struct {
	mu             sync.Mutex
	activateResult pathdiscovery.PathSelectionResult
	activateErr    error
	observeResult  pathdiscovery.PathSelectionResult
	observeErr     error
	expireResult   pathdiscovery.PathSelectionResult
	expireErr      error
	observeCalls   int
	expireCalls    int
	deactivate     int
}

func (s *scriptedPathSelector) Activate(
	networkmap.Snapshot,
	pathdiscovery.ProbeGeneration,
) (pathdiscovery.PathSelectionResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.activateResult, s.activateErr
}

func (s *scriptedPathSelector) Deactivate() pathdiscovery.PathSelectionResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deactivate++

	return pathdiscovery.PathSelectionResult{}
}

func (s *scriptedPathSelector) Observe(
	pathdiscovery.PathObservation,
) (pathdiscovery.PathSelectionResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.observeCalls++

	return s.observeResult, s.observeErr
}

func (s *scriptedPathSelector) Expire(
	time.Time,
) (pathdiscovery.PathSelectionResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireCalls++

	return s.expireResult, s.expireErr
}

func (s *scriptedPathSelector) calls() (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.observeCalls, s.expireCalls
}

type endpointUpdate struct {
	revision uint64
	peerID   uint64
	endpoint netip.AddrPort
	restore  bool
}

type recordingPreferredEndpointDataPlane struct {
	updates    chan endpointUpdate
	setErr     error
	restoreErr error
}

func newRecordingPreferredEndpointDataPlane() *recordingPreferredEndpointDataPlane {
	return &recordingPreferredEndpointDataPlane{
		updates: make(chan endpointUpdate, 8),
	}
}

func (d *recordingPreferredEndpointDataPlane) SetPreferredEndpoint(
	revision uint64,
	peerID uint64,
	endpoint netip.AddrPort,
) error {
	d.updates <- endpointUpdate{
		revision: revision,
		peerID:   peerID,
		endpoint: endpoint,
	}

	return d.setErr
}

func (d *recordingPreferredEndpointDataPlane) RestorePreferredEndpoint(
	revision uint64,
	peerID uint64,
) error {
	d.updates <- endpointUpdate{
		revision: revision,
		peerID:   peerID,
		restore:  true,
	}

	return d.restoreErr
}

func waitForEndpointUpdate(
	t *testing.T,
	updates <-chan endpointUpdate,
) endpointUpdate {
	t.Helper()
	select {
	case update := <-updates:
		return update
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for endpoint update")

		return endpointUpdate{}
	}
}

func pathEndpointGeneration() pathdiscovery.ProbeGeneration {
	return pathdiscovery.ProbeGeneration{
		Scope:       1,
		MapRevision: 7,
		Socket: pathdiscovery.Socket{
			Port:       41641,
			Generation: 3,
		},
	}
}
