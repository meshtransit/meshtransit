package daemon

import (
	"bytes"
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

	peerwire "github.com/meshtransit/meshd/internal/compat/disco"
	"github.com/meshtransit/meshd/internal/compat/ts2021"
	"github.com/meshtransit/meshd/internal/dataplane"
	"github.com/meshtransit/meshd/internal/identity"
	"github.com/meshtransit/meshd/internal/networkmap"
	"github.com/meshtransit/meshd/internal/pathdiscovery"
	"github.com/meshtransit/meshd/internal/profile"
	"github.com/meshtransit/meshd/internal/relay"
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

func TestService_RunRotatesAndClosesPeerProbeIdentity(t *testing.T) {
	t.Parallel()

	service, _, control, _, _ := newTestService(t)
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

	created := make(chan *peerwire.Identity, 2)
	service.newPeerProbeIdentity = func() (*peerwire.Identity, error) {
		identity, err := peerwire.NewIdentity()
		if err == nil {
			created <- identity
		}

		return identity, err
	}
	ctx, cancel := context.WithCancel(t.Context())
	runResult := make(chan error, 1)
	go func() { runResult <- service.Run(ctx) }()

	firstIdentity := waitForPeerProbeIdentity(t, created)
	waitForStreamStart(t, control)
	firstOptions := latestStreamOptions(t, control)
	firstPublic, err := firstIdentity.Public()
	if err != nil || firstOptions.PeerProbePublicKey != firstPublic.String() {
		t.Fatalf(
			"first peer-probe key = %q, public=%q, error=%v",
			firstOptions.PeerProbePublicKey,
			firstPublic.String(),
			err,
		)
	}

	service.signalControlSync()
	secondIdentity := waitForPeerProbeIdentity(t, created)
	waitForStreamStart(t, control)
	secondOptions := latestStreamOptions(t, control)
	secondPublic, err := secondIdentity.Public()
	if err != nil || secondOptions.PeerProbePublicKey != secondPublic.String() {
		t.Fatalf(
			"second peer-probe key = %q, public=%q, error=%v",
			secondOptions.PeerProbePublicKey,
			secondPublic.String(),
			err,
		)
	}
	if firstOptions.PeerProbePublicKey == secondOptions.PeerProbePublicKey {
		t.Fatal("peer-probe identity did not rotate with the control session")
	}
	if _, err := firstIdentity.Public(); !errors.Is(err, peerwire.ErrClosed) {
		t.Fatalf("first identity after rotation error = %v, want ErrClosed", err)
	}

	cancel()
	if err := <-runResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context cancellation", err)
	}
	if _, err := secondIdentity.Public(); !errors.Is(err, peerwire.ErrClosed) {
		t.Fatalf("second identity after shutdown error = %v, want ErrClosed", err)
	}
}

func TestService_RunFailsClosedWithoutPeerProbeIdentity(t *testing.T) {
	t.Parallel()

	service, _, control, _, _ := newTestService(t)
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

	identityErr := errors.New("test entropy unavailable")
	service.newPeerProbeIdentity = func() (*peerwire.Identity, error) {
		return nil, identityErr
	}
	if err := service.Run(t.Context()); !errors.Is(err, identityErr) {
		t.Fatalf("Run() error = %v, want identity failure", err)
	}
	control.mu.Lock()
	streamCalls := len(control.streamOptions)
	control.mu.Unlock()
	if streamCalls != 0 {
		t.Fatalf("control stream calls = %d, want 0", streamCalls)
	}
}

func TestService_RunAttachesAndSchedulesLivePeerProbes(t *testing.T) {
	t.Parallel()

	service, _, control, _, _ := newTestService(t)
	dataPlane := newFakeLiveProbeDataPlane()
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

	localProbe, err := peerwire.NewIdentity()
	if err != nil {
		t.Fatalf("NewIdentity(local) error = %v", err)
	}
	remoteProbe, err := peerwire.NewIdentity()
	if err != nil {
		localProbe.Close()

		t.Fatalf("NewIdentity(remote) error = %v", err)
	}
	t.Cleanup(remoteProbe.Close)
	service.newPeerProbeIdentity = func() (*peerwire.Identity, error) {
		return localProbe, nil
	}
	remotePublic, err := remoteProbe.Public()
	if err != nil {
		t.Fatalf("remote Public() error = %v", err)
	}
	peerEndpoint := netip.MustParseAddrPort("203.0.113.80:41641")
	control.mu.Lock()
	control.echoPeerProbeKey = true
	control.streamSnapshot = &networkmap.Snapshot{
		Revision: 1,
		Self: networkmap.Node{
			ID:                1,
			PublicKey:         "nodekey:" + strings.Repeat("11", 32),
			MachineAuthorized: true,
		},
		Peers: []networkmap.Node{{
			ID:                2,
			PublicKey:         "nodekey:" + strings.Repeat("22", 32),
			DiscoveryKey:      remotePublic.String(),
			Endpoints:         []netip.AddrPort{peerEndpoint},
			MachineAuthorized: true,
		}},
	}
	control.mu.Unlock()

	ctx, cancel := context.WithCancel(t.Context())
	runResult := make(chan error, 1)
	go func() { runResult <- service.Run(ctx) }()
	scheduled := waitForLiveProbeSend(t, dataPlane)
	if scheduled.destination != peerEndpoint || scheduled.socket != dataPlane.socket {
		t.Fatalf("scheduled probe = %#v", scheduled)
	}
	localPublic, err := localProbe.Public()
	if err != nil {
		t.Fatalf("local Public() error = %v", err)
	}
	remoteChannel, err := remoteProbe.Peer(localPublic)
	if err != nil {
		t.Fatalf("remote Peer() error = %v", err)
	}
	t.Cleanup(remoteChannel.Close)
	message, err := remoteChannel.Open(scheduled.packet)
	if err != nil {
		t.Fatalf("remote Open(scheduled ping) error = %v", err)
	}
	ping, ok := message.(peerwire.Ping)
	if !ok || ping.NodeKey.String() != control.streamSnapshot.Self.PublicKey {
		t.Fatalf("remote Open(scheduled ping) = %#v", message)
	}
	authenticatedPong, err := remoteChannel.Seal(peerwire.Pong{
		ID:     ping.ID,
		Source: netip.MustParseAddrPort("198.51.100.80:41641"),
	})
	if err != nil {
		t.Fatalf("remote Seal(pong) error = %v", err)
	}
	handler := dataPlane.handlerSnapshot()
	if handler == nil {
		t.Fatal("peer-probe handler was not attached")
	}
	handler.HandleDatagram(authenticatedPong, peerEndpoint, dataPlane.socket)
	endpointUpdate := waitForEndpointUpdate(t, dataPlane.endpointUpdates)
	if endpointUpdate.restore || endpointUpdate.revision != 1 ||
		endpointUpdate.peerID != 2 || endpointUpdate.endpoint != peerEndpoint {
		t.Fatalf("authenticated endpoint update = %#v", endpointUpdate)
	}

	remotePingID := peerwire.TransactionID{9, 8, 7, 6, 5, 4, 3, 2, 1, 4, 5, 6}
	remotePing, err := remoteChannel.Seal(peerwire.Ping{
		ID:      remotePingID,
		NodeKey: mustDaemonNodeKey(t, control.streamSnapshot.Peers[0].PublicKey),
	})
	if err != nil {
		t.Fatalf("remote Seal(ping) error = %v", err)
	}
	handler.HandleDatagram(remotePing, peerEndpoint, dataPlane.socket)
	replied := waitForLiveProbeSend(t, dataPlane)
	if replied.destination != peerEndpoint {
		t.Fatalf("pong destination = %v, want %v", replied.destination, peerEndpoint)
	}
	message, err = remoteChannel.Open(replied.packet)
	if err != nil {
		t.Fatalf("remote Open(pong) error = %v", err)
	}
	pong, ok := message.(peerwire.Pong)
	if !ok || pong.ID != remotePingID || pong.Source != peerEndpoint {
		t.Fatalf("remote Open(pong) = %#v", message)
	}

	cancel()
	if err := <-runResult; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context cancellation", err)
	}
	if dataPlane.handlerSnapshot() != nil {
		t.Fatal("peer-probe handler remained attached after shutdown")
	}
	if _, err := localProbe.Public(); !errors.Is(err, peerwire.ErrClosed) {
		t.Fatalf("local probe identity after shutdown error = %v, want ErrClosed", err)
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
	updates := append([]ts2021.EndpointUpdate(nil), control.endpointUpdates...)
	control.mu.Unlock()
	if len(updates) != 1 || !updates[0].Candidates.Equal(candidates) ||
		updates[0].PreferredRelay != 1 {
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
	updates := make(chan ts2021.EndpointUpdate, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- service.runEndpointRefresh(ctx, 11, discoverer, requests, updates)
	}()
	requests <- endpointRefreshRequest{
		active: true,
		servers: []pathdiscovery.RelayServer{{
			RegionID: 1,
			Endpoint: netip.MustParseAddrPort("192.0.2.50:3478"),
		}},
	}

	select {
	case update := <-updates:
		if !update.Candidates.Equal(candidates) {
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

func TestEndpointRefreshSelectsMeasuredHomeRelay(t *testing.T) {
	t.Parallel()

	firstServer := netip.MustParseAddrPort("192.0.2.71:3478")
	secondServer := netip.MustParseAddrPort("192.0.2.72:3478")
	discoverer := &refreshDiscoverer{
		calls: make(chan struct{}, 4),
		result: pathdiscovery.DiscoveryResult{ServerLatencies: []pathdiscovery.ServerLatency{
			{Server: firstServer, Latency: 100 * time.Millisecond},
			{Server: secondServer, Latency: 20 * time.Millisecond},
		}},
		health: relay.HealthSnapshot{
			Available:  true,
			HomeRegion: 1,
			Regions: []relay.RegionHealth{{
				RegionID:      1,
				Connected:     true,
				LastConnected: time.Now().Add(-time.Second),
				LastActivity:  time.Now(),
			}},
		},
	}
	service := &Service{
		clock:                time.Now,
		endpointRefreshDelay: func() time.Duration { return 5 * time.Millisecond },
	}
	requests := make(chan endpointRefreshRequest, 1)
	updates := make(chan ts2021.EndpointUpdate, 1)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- service.runEndpointRefresh(ctx, 14, discoverer, requests, updates)
	}()
	requests <- endpointRefreshRequest{
		active:           true,
		controlHomeRelay: 1,
		usableRelays:     []int{1, 2},
		servers: []pathdiscovery.RelayServer{
			{RegionID: 1, Endpoint: firstServer},
			{RegionID: 2, Endpoint: secondServer},
		},
	}

	selected := false
	deadline := time.After(time.Second)
	for !selected {
		select {
		case update := <-updates:
			if update.PreferredRelay == 2 && update.HasPreferredRelay {
				selected = true
			}
		case <-deadline:
			t.Fatal("timed out waiting for prepared preferred relay update")
		}
	}
	discoverer.mu.Lock()
	prepared := append([]int(nil), discoverer.prepared...)
	discoverer.mu.Unlock()
	if !slices.Contains(prepared, 2) {
		t.Fatalf("prepared relay regions = %v, want region 2", prepared)
	}

	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("runEndpointRefresh() error = %v, want context cancellation", err)
	}
}

func TestRelayRegionLatenciesRejectsUnknownServer(t *testing.T) {
	t.Parallel()

	_, err := relayRegionLatencies(
		[]pathdiscovery.RelayServer{{
			RegionID: 1,
			Endpoint: netip.MustParseAddrPort("192.0.2.81:3478"),
		}},
		[]pathdiscovery.ServerLatency{{
			Server:  netip.MustParseAddrPort("192.0.2.82:3478"),
			Latency: time.Millisecond,
		}},
		[]int{1},
	)
	if err == nil {
		t.Fatal("relayRegionLatencies() error = nil")
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
	updates := make(chan ts2021.EndpointUpdate, 1)
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
		if update.Candidates.Len() != 0 || update.PreferredRelay != 0 {
			t.Fatalf("withdrawal = %#v", update)
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
	updates := make(chan ts2021.EndpointUpdate, 1)
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
		if !update.Candidates.Equal(candidates) {
			t.Fatalf("first endpoint update = %#v", update)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for discovered endpoint")
	}

	discoverer.mu.Lock()
	discoverer.err = pathdiscovery.ErrNoSTUNResponse
	discoverer.mu.Unlock()
	requests <- endpointRefreshRequest{
		active: true,
		socket: pathdiscovery.Socket{Port: 41641, Generation: 2},
	}
	select {
	case update := <-updates:
		if update.Candidates.Len() != 0 {
			t.Fatalf("socket-change withdrawal = %#v", update)
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
	mu       sync.Mutex
	calls    chan struct{}
	result   pathdiscovery.DiscoveryResult
	err      error
	health   relay.HealthSnapshot
	prepared []int
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
	d.mu.Lock()
	defer d.mu.Unlock()
	result := d.result
	result.ServerLatencies = append(
		[]pathdiscovery.ServerLatency(nil),
		d.result.ServerLatencies...,
	)

	return result, d.err
}

func (d *refreshDiscoverer) RelayHealth() relay.HealthSnapshot {
	d.mu.Lock()
	defer d.mu.Unlock()
	health := d.health
	health.Regions = append([]relay.RegionHealth(nil), d.health.Regions...)

	return health
}

func (d *refreshDiscoverer) PrepareRelayRegion(regionID int) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.prepared = append(d.prepared, regionID)
	now := time.Now()
	for index := range d.health.Regions {
		if d.health.Regions[index].RegionID == regionID {
			d.health.Regions[index].Connected = true
			d.health.Regions[index].LastConnected = now
			d.health.Regions[index].LastActivity = now

			return nil
		}
	}
	d.health.Regions = append(d.health.Regions, relay.RegionHealth{
		RegionID:      regionID,
		Connected:     true,
		LastConnected: now,
		LastActivity:  now,
	})

	return nil
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
	endpointUpdates     []ts2021.EndpointUpdate
	streamOptions       []ts2021.NetmapOptions
	streamStarted       chan struct{}
	echoPeerProbeKey    bool
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
	echoPeerProbeKey := f.echoPeerProbeKey
	published := f.streamPublished
	f.streamOptions = append(f.streamOptions, options)
	started := f.streamStarted
	f.mu.Unlock()
	select {
	case started <- struct{}{}:
	default:
	}
	if snapshot != nil {
		current := *snapshot
		if echoPeerProbeKey {
			current.Self.DiscoveryKey = options.PeerProbePublicKey
		}
		if err := handler(ctx, current); err != nil {
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
		case update, open := <-options.EndpointUpdates:
			if !open {
				options.EndpointUpdates = nil

				continue
			}
			f.mu.Lock()
			f.endpointUpdates = append(f.endpointUpdates, update)
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

type liveProbeSend struct {
	packet      []byte
	destination netip.AddrPort
	socket      pathdiscovery.Socket
}

type fakeLiveProbeDataPlane struct {
	mu              sync.Mutex
	socket          pathdiscovery.Socket
	handler         pathdiscovery.DatagramHandler
	sends           chan liveProbeSend
	endpointUpdates chan endpointUpdate
	closed          int
}

func newFakeLiveProbeDataPlane() *fakeLiveProbeDataPlane {
	return &fakeLiveProbeDataPlane{
		socket:          pathdiscovery.Socket{Port: 41641, Generation: 1},
		sends:           make(chan liveProbeSend, 8),
		endpointUpdates: make(chan endpointUpdate, 8),
	}
}

func (*fakeLiveProbeDataPlane) Apply(
	context.Context,
	networkmap.Snapshot,
	dataplane.NodePrivateKey,
) (dataplane.State, error) {
	return dataplane.StateEncrypted, nil
}

func (d *fakeLiveProbeDataPlane) Close() error {
	d.mu.Lock()
	d.closed++
	d.mu.Unlock()

	return nil
}

func (d *fakeLiveProbeDataPlane) Socket() pathdiscovery.Socket {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.socket
}

func (d *fakeLiveProbeDataPlane) SendDatagram(
	packet []byte,
	destination netip.AddrPort,
) (pathdiscovery.Socket, error) {
	d.mu.Lock()
	socket := d.socket
	d.mu.Unlock()
	d.sends <- liveProbeSend{
		packet:      bytes.Clone(packet),
		destination: destination,
		socket:      socket,
	}

	return socket, nil
}

func (d *fakeLiveProbeDataPlane) SetPeerProbeHandler(
	handler pathdiscovery.DatagramHandler,
) error {
	d.mu.Lock()
	d.handler = handler
	d.mu.Unlock()

	return nil
}

func (d *fakeLiveProbeDataPlane) SetPreferredEndpoint(
	revision uint64,
	peerID uint64,
	endpoint netip.AddrPort,
) error {
	d.endpointUpdates <- endpointUpdate{
		revision: revision,
		peerID:   peerID,
		endpoint: endpoint,
	}

	return nil
}

func (d *fakeLiveProbeDataPlane) RestorePreferredEndpoint(
	revision uint64,
	peerID uint64,
) error {
	d.endpointUpdates <- endpointUpdate{
		revision: revision,
		peerID:   peerID,
		restore:  true,
	}

	return nil
}

func (d *fakeLiveProbeDataPlane) handlerSnapshot() pathdiscovery.DatagramHandler {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.handler
}

func waitForLiveProbeSend(
	t *testing.T,
	dataPlane *fakeLiveProbeDataPlane,
) liveProbeSend {
	t.Helper()

	select {
	case sent := <-dataPlane.sends:
		return sent
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for live peer-probe send")

		return liveProbeSend{}
	}
}

func mustDaemonNodeKey(t *testing.T, text string) peerwire.NodeKey {
	t.Helper()

	key, err := peerwire.ParseNodeKey(text)
	if err != nil {
		t.Fatalf("ParseNodeKey() error = %v", err)
	}

	return key
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
		streamStarted:     make(chan struct{}, 4),
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

func waitForStreamStart(t *testing.T, control *fakeControl) {
	t.Helper()

	select {
	case <-control.streamStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for control stream start")
	}
}

func waitForPeerProbeIdentity(
	t *testing.T,
	created <-chan *peerwire.Identity,
) *peerwire.Identity {
	t.Helper()

	select {
	case identity := <-created:
		return identity
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for peer-probe identity")

		return nil
	}
}

func latestStreamOptions(t *testing.T, control *fakeControl) ts2021.NetmapOptions {
	t.Helper()

	control.mu.Lock()
	defer control.mu.Unlock()
	if len(control.streamOptions) == 0 {
		t.Fatal("control stream options are missing")
	}

	return control.streamOptions[len(control.streamOptions)-1]
}

var _ controlProber = (*fakeControl)(nil)
