package daemon

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/meshtransit/meshd/internal/compat/ts2021"
	"github.com/meshtransit/meshd/internal/dataplane"
	"github.com/meshtransit/meshd/internal/identity"
	"github.com/meshtransit/meshd/internal/networkmap"
	"github.com/meshtransit/meshd/internal/pathdiscovery"
	"github.com/meshtransit/meshd/internal/profile"
	"github.com/meshtransit/meshd/internal/version"
)

func TestService_TrustAndBrowserRegistration(t *testing.T) {
	t.Parallel()

	service, identities, control, profileID, _ := newTestService(t)
	status, err := service.Status(t.Context())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if status.ControlTrust != ControlTrustUnconfigured || status.Registration != RegistrationUnregistered {
		t.Fatalf("initial status = %#v, want unconfigured/unregistered", status)
	}

	trusted, err := service.TrustControl(t.Context(), testFingerprint)
	if err != nil {
		t.Fatalf("TrustControl() error = %v", err)
	}
	if trusted.ProfileID != profileID || trusted.AlreadyTrusted {
		t.Fatalf("TrustControl() = %#v, want newly trusted profile", trusted)
	}
	trustedAgain, err := service.TrustControl(t.Context(), strings.ToUpper(testFingerprint))
	if err != nil {
		t.Fatalf("second TrustControl() error = %v", err)
	}
	if !trustedAgain.AlreadyTrusted || control.bootstrapCalls != 1 || control.verifyCalls != 1 {
		t.Fatalf("repeat trust = %#v, calls bootstrap=%d verify=%d", trustedAgain, control.bootstrapCalls, control.verifyCalls)
	}

	control.registrationResults = []ts2021.RegistrationResult{
		{
			State:   ts2021.RegistrationStateAuthorizationRequired,
			AuthURL: "https://control.example.com/register/opaque",
		},
		{
			State:             ts2021.RegistrationStateAuthorized,
			MachineAuthorized: true,
		},
	}
	login, err := service.StartLogin(t.Context(), "")
	if err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}
	if login.State != RegistrationPending || login.AuthURL == "" {
		t.Fatalf("StartLogin() = %#v, want browser authorization", login)
	}
	completed, err := service.CompleteLogin(t.Context())
	if err != nil {
		t.Fatalf("CompleteLogin() error = %v", err)
	}
	if completed.State != RegistrationRegistered || completed.AuthURL != "" {
		t.Fatalf("CompleteLogin() = %#v, want registered", completed)
	}

	record, err := identities.Get(t.Context(), profileID)
	if err != nil {
		t.Fatalf("identity Get() error = %v", err)
	}
	if !record.IsRegistered() || record.HasPendingAuth() {
		t.Fatalf("persisted registration = %s, want registered", record)
	}
}

func TestService_AuthKeyIsNotPersisted(t *testing.T) {
	t.Parallel()

	service, _, control, profileID, stateDir := newTestService(t)
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatalf("TrustControl() error = %v", err)
	}
	control.registrationResults = []ts2021.RegistrationResult{{
		State:             ts2021.RegistrationStateAuthorized,
		MachineAuthorized: true,
	}}
	const authKey = "sensitive-auth-key-value"
	if _, err := service.StartLogin(t.Context(), authKey); err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}
	if got := control.registerOptions[0].AuthKey; got != authKey {
		t.Fatalf("adapter auth key = %q, want in-memory value", got)
	}

	//nolint:gosec // The test reads a file under its own temporary directory.
	encoded, err := os.ReadFile(filepath.Join(stateDir, "identities", profileID+".json"))
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if strings.Contains(string(encoded), authKey) {
		t.Fatal("persisted identity contains auth key")
	}
}

func TestService_LoginRequiresTrust(t *testing.T) {
	t.Parallel()

	service, _, _, _, _ := newTestService(t)
	if _, err := service.StartLogin(t.Context(), ""); !errors.Is(err, ErrControlNotTrusted) {
		t.Fatalf("StartLogin() error = %v, want ErrControlNotTrusted", err)
	}
}

func TestService_RunPublishesLatestValidatedSnapshot(t *testing.T) {
	t.Parallel()

	service, _, control, _, _ := newTestService(t)
	dataPlane := &fakeDataPlane{}
	dns := &fakeDNS{configured: true}
	service.dataPlane = dataPlane
	service.dns = dns
	service.setSyncStatus(syncStatus{
		state:     ControlSessionInactive,
		dataPlane: string(dataplane.StateIdle),
	})
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatalf("TrustControl() error = %v", err)
	}
	control.registrationResults = []ts2021.RegistrationResult{{
		State:             ts2021.RegistrationStateAuthorized,
		MachineAuthorized: true,
	}}
	if _, err := service.StartLogin(t.Context(), "credential"); err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}
	control.streamSnapshot = &networkmap.Snapshot{
		Revision:    7,
		NetworkName: "network.example.mesh",
		Self: networkmap.Node{
			Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
		},
		Peers:  make([]networkmap.Node, 2),
		Policy: make([]networkmap.Rule, 3),
		DNS:    &networkmap.DNSConfig{},
	}

	ctx, cancel := context.WithCancel(t.Context())
	runResult := make(chan error, 1)
	go func() { runResult <- service.Run(ctx) }()
	select {
	case <-control.streamPublished:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for network snapshot")
	}
	status, err := service.Status(t.Context())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if status.ControlSession != ControlSessionSynchronized ||
		status.NetmapRevision != 7 ||
		status.NetworkName != "network.example.mesh" ||
		len(status.SelfAddresses) != 1 ||
		status.SelfAddresses[0] != "100.64.0.1/32" ||
		status.PeerCount != 2 || status.PolicyRuleCount != 3 ||
		status.DataPlane != string(dataplane.StateTUNReady) ||
		status.DNS != DNSConfigured {
		t.Fatalf("sync status = %#v", status)
	}
	status.SelfAddresses[0] = "mutated"
	secondStatus, err := service.Status(t.Context())
	if err != nil {
		t.Fatalf("second Status() error = %v", err)
	}
	if secondStatus.SelfAddresses[0] != "100.64.0.1/32" {
		t.Fatalf("status self addresses leaked mutable state: %#v", secondStatus.SelfAddresses)
	}

	cancel()
	if err := <-runResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context cancellation", err)
	}
	if dataPlane.applyCalls != 1 || dataPlane.closeCalls != 1 {
		t.Fatalf("data plane calls apply=%d close=%d, want 1/1", dataPlane.applyCalls, dataPlane.closeCalls)
	}
	if dns.applyCalls != 1 || dns.resetCalls != 0 || dns.closeCalls != 1 {
		t.Fatalf("dns calls apply=%d reset=%d close=%d, want 1/0/1", dns.applyCalls, dns.resetCalls, dns.closeCalls)
	}
}

func TestService_RunDiscoversAndPublishesDirectEndpoint(t *testing.T) {
	t.Parallel()

	service, _, control, _, _ := newTestService(t)
	reflexive, err := pathdiscovery.NewCandidate(
		netip.MustParseAddrPort("198.51.100.20:41641"),
		pathdiscovery.SourceServerReflexive,
	)
	if err != nil {
		t.Fatalf("NewCandidate() error = %v", err)
	}
	candidates, err := pathdiscovery.NewSet([]pathdiscovery.Candidate{reflexive})
	if err != nil {
		t.Fatalf("NewSet() error = %v", err)
	}
	dataPlane := &fakeEndpointDataPlane{
		discoveryResult: pathdiscovery.DiscoveryResult{Candidates: candidates},
	}
	service.dataPlane = dataPlane
	service.setSyncStatus(syncStatus{
		state:     ControlSessionInactive,
		dataPlane: string(dataplane.StateIdle),
	})
	if _, err := service.TrustControl(t.Context(), testFingerprint); err != nil {
		t.Fatalf("TrustControl() error = %v", err)
	}
	control.registrationResults = []ts2021.RegistrationResult{{
		State:             ts2021.RegistrationStateAuthorized,
		MachineAuthorized: true,
	}}
	if _, err := service.StartLogin(t.Context(), "credential"); err != nil {
		t.Fatalf("StartLogin() error = %v", err)
	}
	control.streamSnapshot = &networkmap.Snapshot{
		Revision: 1,
		Self: networkmap.Node{
			Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
		},
		Peers: []networkmap.Node{{
			Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.2/32")},
		}},
		Relays: map[int]networkmap.RelayRegion{
			1: {
				ID: 1,
				Nodes: []networkmap.RelayNode{{
					Name: "relay-1",
					IPv4: "192.0.2.10",
				}},
			},
		},
	}

	ctx, cancel := context.WithCancel(t.Context())
	runResult := make(chan error, 1)
	go func() { runResult <- service.Run(ctx) }()
	select {
	case <-control.endpointPublished:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for endpoint publication")
	}

	control.mu.Lock()
	updates := append([]pathdiscovery.Set(nil), control.endpointUpdates...)
	control.mu.Unlock()
	if len(updates) != 1 || !updates[0].Equal(candidates) {
		t.Fatalf("endpoint updates = %#v", updates)
	}
	if dataPlane.discoveryScope == 0 ||
		!slices.Equal(dataPlane.discoveryServers, []netip.AddrPort{
			netip.MustParseAddrPort("192.0.2.10:3478"),
		}) {
		t.Fatalf(
			"discovery scope=%d servers=%v",
			dataPlane.discoveryScope,
			dataPlane.discoveryServers,
		)
	}

	cancel()
	if err := <-runResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context cancellation", err)
	}
}

func TestEndpointRefreshRunsPeriodicallyWithoutDuplicatePublication(t *testing.T) {
	t.Parallel()

	candidate, err := pathdiscovery.NewCandidate(
		netip.MustParseAddrPort("198.51.100.50:41641"),
		pathdiscovery.SourceServerReflexive,
	)
	if err != nil {
		t.Fatalf("NewCandidate() error = %v", err)
	}
	candidates, err := pathdiscovery.NewSet([]pathdiscovery.Candidate{candidate})
	if err != nil {
		t.Fatalf("NewSet() error = %v", err)
	}
	discoverer := &refreshDiscoverer{
		calls:  make(chan struct{}, 4),
		result: pathdiscovery.DiscoveryResult{Candidates: candidates},
	}
	service := &Service{
		clock:                time.Now,
		endpointRefreshDelay: func() time.Duration { return 5 * time.Millisecond },
	}
	requests := make(chan endpointRefreshRequest, 1)
	updates := make(chan pathdiscovery.Set, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- service.runEndpointRefresh(ctx, 11, discoverer, requests, updates)
	}()
	requests <- endpointRefreshRequest{
		active:  true,
		servers: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.50:3478")},
	}

	select {
	case update := <-updates:
		if !update.Equal(candidates) {
			t.Fatalf("first endpoint update = %#v", update)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for first endpoint update")
	}
	for range 2 {
		select {
		case <-discoverer.calls:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for periodic discovery")
		}
	}
	select {
	case duplicate := <-updates:
		t.Fatalf("received duplicate endpoint update %#v", duplicate)
	default:
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("runEndpointRefresh() error = %v, want context cancellation", err)
	}
}

func TestEndpointRefreshResetWithdrawsDynamicCandidate(t *testing.T) {
	t.Parallel()

	candidate, err := pathdiscovery.NewCandidate(
		netip.MustParseAddrPort("198.51.100.60:41641"),
		pathdiscovery.SourceServerReflexive,
	)
	if err != nil {
		t.Fatalf("NewCandidate() error = %v", err)
	}
	candidates, err := pathdiscovery.NewSet([]pathdiscovery.Candidate{candidate})
	if err != nil {
		t.Fatalf("NewSet() error = %v", err)
	}
	discoverer := &refreshDiscoverer{
		calls:  make(chan struct{}, 1),
		result: pathdiscovery.DiscoveryResult{Candidates: candidates},
	}
	service := &Service{
		clock:                time.Now,
		endpointRefreshDelay: func() time.Duration { return time.Hour },
	}
	requests := make(chan endpointRefreshRequest, 1)
	updates := make(chan pathdiscovery.Set, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- service.runEndpointRefresh(ctx, 12, discoverer, requests, updates)
	}()
	requests <- endpointRefreshRequest{active: true}
	select {
	case <-updates:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for discovered endpoint")
	}
	requests <- endpointRefreshRequest{}
	select {
	case update := <-updates:
		if update.Len() != 0 {
			t.Fatalf("withdrawal contains %d candidates", update.Len())
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for endpoint withdrawal")
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("runEndpointRefresh() error = %v, want context cancellation", err)
	}
}

func TestEndpointRefreshSocketChangeDropsOldDynamicCandidate(t *testing.T) {
	t.Parallel()

	candidate, err := pathdiscovery.NewCandidate(
		netip.MustParseAddrPort("198.51.100.61:41641"),
		pathdiscovery.SourceServerReflexive,
	)
	if err != nil {
		t.Fatalf("NewCandidate() error = %v", err)
	}
	candidates, err := pathdiscovery.NewSet([]pathdiscovery.Candidate{candidate})
	if err != nil {
		t.Fatalf("NewSet() error = %v", err)
	}
	discoverer := &refreshDiscoverer{
		calls:  make(chan struct{}, 2),
		result: pathdiscovery.DiscoveryResult{Candidates: candidates},
	}
	service := &Service{
		clock:                time.Now,
		endpointRefreshDelay: func() time.Duration { return time.Hour },
	}
	requests := make(chan endpointRefreshRequest, 1)
	updates := make(chan pathdiscovery.Set, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- service.runEndpointRefresh(ctx, 13, discoverer, requests, updates)
	}()
	requests <- endpointRefreshRequest{
		active: true,
		socket: pathdiscovery.Socket{Port: 41641, Generation: 1},
	}
	select {
	case update := <-updates:
		if !update.Equal(candidates) {
			t.Fatalf("first endpoint update = %#v", update)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for discovered endpoint")
	}

	discoverer.err = pathdiscovery.ErrNoSTUNResponse
	requests <- endpointRefreshRequest{
		active: true,
		socket: pathdiscovery.Socket{Port: 41641, Generation: 2},
	}
	select {
	case update := <-updates:
		if update.Len() != 0 {
			t.Fatalf("socket-change withdrawal contains %d candidates", update.Len())
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for socket-change withdrawal")
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("runEndpointRefresh() error = %v, want context cancellation", err)
	}
}

func TestRandomEndpointRefreshDelayBounds(t *testing.T) {
	t.Parallel()

	for range 100 {
		delay := randomEndpointRefreshDelay()
		if delay < minEndpointRefresh || delay >= maxEndpointRefresh {
			t.Fatalf("randomEndpointRefreshDelay() = %v", delay)
		}
	}
}

type refreshDiscoverer struct {
	calls  chan struct{}
	result pathdiscovery.DiscoveryResult
	err    error
}

func (d *refreshDiscoverer) DiscoverySocket() pathdiscovery.Socket {
	return pathdiscovery.Socket{Port: 41641, Generation: 1}
}

func (d *refreshDiscoverer) DiscoverEndpoints(
	_ context.Context,
	_ uint64,
	_ []netip.AddrPort,
) (pathdiscovery.DiscoveryResult, error) {
	select {
	case d.calls <- struct{}{}:
	default:
	}

	return d.result, d.err
}

func TestService_StatusReportsOnlineForEncryptedDataPlane(t *testing.T) {
	t.Parallel()

	service, _, _, profileID, _ := newTestService(t)
	service.setSyncStatus(syncStatus{
		profileID: profileID,
		state:     ControlSessionSynchronized,
		dataPlane: string(dataplane.StateEncrypted),
	})

	status, err := service.Status(t.Context())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}
	if status.State != StateOnline || status.DataPlane != string(dataplane.StateEncrypted) {
		t.Fatalf("Status() = %#v, want online encrypted data plane", status)
	}
}

const testFingerprint = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type fakeControl struct {
	mu                  sync.Mutex
	bootstrapCalls      int
	verifyCalls         int
	registrationResults []ts2021.RegistrationResult
	registerOptions     []ts2021.RegisterOptions
	streamSnapshot      *networkmap.Snapshot
	streamPublished     chan struct{}
	endpointPublished   chan struct{}
	endpointUpdates     []pathdiscovery.Set
}

type fakeDataPlane struct {
	applyCalls int
	closeCalls int
}

type fakeDNS struct {
	applyCalls int
	resetCalls int
	closeCalls int
	configured bool
}

func (f *fakeDNS) Apply(context.Context, networkmap.Snapshot) (bool, error) {
	f.applyCalls++

	return f.configured, nil
}

func (f *fakeDNS) Reset(context.Context) error {
	f.resetCalls++

	return nil
}

func (f *fakeDNS) Close(context.Context) error {
	f.closeCalls++

	return nil
}

func (f *fakeDataPlane) Apply(
	_ context.Context,
	_ networkmap.Snapshot,
	_ dataplane.NodePrivateKey,
) (dataplane.State, error) {
	f.applyCalls++

	return dataplane.StateTUNReady, nil
}

func (f *fakeDataPlane) Close() error {
	f.closeCalls++

	return nil
}

func (f *fakeControl) Probe(context.Context, string) (ts2021.Result, error) {
	return ts2021.Result{}, nil
}

func (f *fakeControl) BootstrapTrust(context.Context, string, string) (ts2021.TrustResult, error) {
	f.bootstrapCalls++

	return ts2021.TrustResult{
		Fingerprint: testFingerprint,
		Material: ts2021.KeyMaterial{
			MachinePrivateKey: []byte("machine-private"),
			NodePrivateKey:    []byte("privkey:" + strings.Repeat("01", 32)),
			ControlPublicKey:  []byte("control-public"),
		},
	}, nil
}

func (f *fakeControl) VerifyTrust(context.Context, string, ts2021.KeyMaterial, string) error {
	f.verifyCalls++

	return nil
}

func (f *fakeControl) Register(
	_ context.Context,
	_ string,
	_ ts2021.KeyMaterial,
	options ts2021.RegisterOptions,
) (ts2021.RegistrationResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.registerOptions = append(f.registerOptions, options)
	if len(f.registrationResults) == 0 {
		return ts2021.RegistrationResult{}, errors.New("unexpected registration call")
	}
	result := f.registrationResults[0]
	f.registrationResults = f.registrationResults[1:]

	return result, nil
}

func (f *fakeControl) StreamNetmap(
	ctx context.Context,
	_ string,
	_ ts2021.KeyMaterial,
	options ts2021.NetmapOptions,
	handler ts2021.NetmapHandler,
) error {
	f.mu.Lock()
	snapshot := f.streamSnapshot
	published := f.streamPublished
	f.mu.Unlock()
	if snapshot != nil {
		if err := handler(ctx, *snapshot); err != nil {
			return err
		}
		select {
		case published <- struct{}{}:
		default:
		}
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case candidates, open := <-options.EndpointUpdates:
			if !open {
				options.EndpointUpdates = nil

				continue
			}
			f.mu.Lock()
			f.endpointUpdates = append(f.endpointUpdates, candidates)
			endpointPublished := f.endpointPublished
			f.mu.Unlock()
			select {
			case endpointPublished <- struct{}{}:
			default:
			}
		}
	}
}

type fakeEndpointDataPlane struct {
	fakeDataPlane
	discoveryScope   uint64
	discoveryServers []netip.AddrPort
	discoveryResult  pathdiscovery.DiscoveryResult
	discoveryErr     error
}

func (f *fakeEndpointDataPlane) DiscoverySocket() pathdiscovery.Socket {
	return pathdiscovery.Socket{Port: 41641, Generation: 1}
}

func (f *fakeEndpointDataPlane) DiscoverEndpoints(
	_ context.Context,
	scope uint64,
	servers []netip.AddrPort,
) (pathdiscovery.DiscoveryResult, error) {
	f.discoveryScope = scope
	f.discoveryServers = append([]netip.AddrPort(nil), servers...)

	return f.discoveryResult, f.discoveryErr
}

func newTestService(t *testing.T) (*Service, *identity.Store, *fakeControl, string, string) {
	t.Helper()

	stateDir := t.TempDir()
	profiles, err := profile.Open(stateDir)
	if err != nil {
		t.Fatalf("profile.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = profiles.Close() })
	created, err := profiles.Create(t.Context(), profile.CreateInput{
		Name:       "test",
		ControlURL: "https://control.example.com",
	})
	if err != nil {
		t.Fatalf("profiles.Create() error = %v", err)
	}
	identities, err := identity.Open(stateDir)
	if err != nil {
		t.Fatalf("identity.Open() error = %v", err)
	}
	t.Cleanup(func() { _ = identities.Close() })
	control := &fakeControl{
		streamPublished:   make(chan struct{}, 1),
		endpointPublished: make(chan struct{}, 1),
	}
	service, err := New(
		profiles,
		identities,
		version.Info{Version: "test"},
		control,
		Options{
			Hostname: "node-a",
			Clock:    time.Now,
		},
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	return service, identities, control, created.ID, stateDir
}

var _ controlProber = (*fakeControl)(nil)
