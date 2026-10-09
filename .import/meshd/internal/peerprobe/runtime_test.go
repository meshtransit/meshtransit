package peerprobe

import (
	"bytes"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/meshtransit/meshd/internal/compat/disco"
	"github.com/meshtransit/meshd/internal/networkmap"
	"github.com/meshtransit/meshd/internal/pathdiscovery"
)

func TestRuntimeCompletesScheduledProbeAndRepliesToPing(t *testing.T) {
	t.Parallel()

	runtime, transport, observer, local, remote, snapshot, generation := testRuntime(t)
	remoteChannel := testPeerChannel(t, remote, local)
	if channels, probes, err := runtime.Activate(snapshot, generation); err != nil ||
		channels != 1 || probes != 1 {
		t.Fatalf("Activate() = channels %d probes %d error %v", channels, probes, err)
	}

	sentPing := waitForRuntimeSend(t, transport)
	if sentPing.destination != snapshot.Peers[0].Endpoints[0] ||
		sentPing.socket != generation.Socket {
		t.Fatalf("scheduled ping destination=%v socket=%#v", sentPing.destination, sentPing.socket)
	}
	message, err := remoteChannel.Open(sentPing.packet)
	if err != nil {
		t.Fatalf("remote Open(ping) error = %v", err)
	}
	ping, ok := message.(disco.Ping)
	if !ok || ping.NodeKey.String() != snapshot.Self.PublicKey {
		t.Fatalf("remote Open(ping) = %#v", message)
	}

	observedLocal := netip.MustParseAddrPort("198.51.100.10:41641")
	pongPacket, err := remoteChannel.Seal(disco.Pong{
		ID:     ping.ID,
		Source: observedLocal,
	})
	if err != nil {
		t.Fatalf("remote Seal(pong) error = %v", err)
	}
	runtime.HandleDatagram(
		pongPacket,
		snapshot.Peers[0].Endpoints[0],
		generation.Socket,
	)
	select {
	case observation := <-observer.observations:
		if observation.PeerID != snapshot.Peers[0].ID ||
			observation.Generation != generation ||
			observation.RemoteEndpoint != snapshot.Peers[0].Endpoints[0] ||
			observation.ObservedLocalEndpoint != observedLocal ||
			observation.RoundTrip < 0 {
			t.Fatalf("ObservePath() = %#v", observation)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for authenticated path observation")
	}

	remoteSource := netip.MustParseAddrPort("203.0.113.10:51234")
	remotePingID := disco.TransactionID{12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	remotePing, err := remoteChannel.Seal(disco.Ping{
		ID:      remotePingID,
		NodeKey: testNodeKey(t, snapshot.Peers[0].PublicKey),
	})
	if err != nil {
		t.Fatalf("remote Seal(ping) error = %v", err)
	}
	runtime.HandleDatagram(remotePing, remoteSource, generation.Socket)
	sentPong := waitForRuntimeSend(t, transport)
	if sentPong.destination != remoteSource || sentPong.socket != generation.Socket {
		t.Fatalf("pong destination=%v socket=%#v", sentPong.destination, sentPong.socket)
	}
	message, err = remoteChannel.Open(sentPong.packet)
	if err != nil {
		t.Fatalf("remote Open(pong) error = %v", err)
	}
	pong, ok := message.(disco.Pong)
	if !ok || pong.ID != remotePingID || pong.Source != remoteSource {
		t.Fatalf("remote Open(pong) = %#v", message)
	}
	telemetry := runtime.telemetry.Snapshot()
	if telemetry.MapActivations != 1 || telemetry.RoundsStarted != 1 ||
		telemetry.ProbeAttempts != 1 || telemetry.ProbesStarted != 1 ||
		telemetry.ProbesSent != 1 || telemetry.AuthenticatedPongs != 1 ||
		telemetry.ProbeCompletions != 1 || telemetry.AuthenticatedPings != 1 ||
		telemetry.PongsSent != 1 {
		t.Fatalf("probe telemetry = %#v", telemetry)
	}
}

func TestRuntimeRejectsStaleReplyAfterGenerationChange(t *testing.T) {
	t.Parallel()

	runtime, transport, observer, local, remote, snapshot, generation := testRuntime(t)
	remoteChannel := testPeerChannel(t, remote, local)
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatalf("Activate(first) error = %v", err)
	}
	firstSend := waitForRuntimeSend(t, transport)
	firstMessage, err := remoteChannel.Open(firstSend.packet)
	if err != nil {
		t.Fatalf("remote Open(first ping) error = %v", err)
	}
	firstPing, ok := firstMessage.(disco.Ping)
	if !ok {
		t.Fatalf("remote Open(first ping) = %#v", firstMessage)
	}

	replacement := cloneTestSnapshot(snapshot)
	replacement.Revision++
	replacementGeneration := generation
	replacementGeneration.MapRevision = replacement.Revision
	if _, _, err := runtime.Activate(replacement, replacementGeneration); err != nil {
		t.Fatalf("Activate(second) error = %v", err)
	}
	secondSend := waitForRuntimeSend(t, transport)
	secondMessage, err := remoteChannel.Open(secondSend.packet)
	if err != nil {
		t.Fatalf("remote Open(second ping) error = %v", err)
	}
	secondPing, ok := secondMessage.(disco.Ping)
	if !ok {
		t.Fatalf("remote Open(second ping) = %#v", secondMessage)
	}

	oldPong, err := remoteChannel.Seal(disco.Pong{
		ID:     firstPing.ID,
		Source: netip.MustParseAddrPort("198.51.100.20:41641"),
	})
	if err != nil {
		t.Fatalf("remote Seal(old pong) error = %v", err)
	}
	runtime.HandleDatagram(oldPong, snapshot.Peers[0].Endpoints[0], replacementGeneration.Socket)
	select {
	case observation := <-observer.observations:
		t.Fatalf("stale pong produced observation %#v", observation)
	case <-time.After(25 * time.Millisecond):
	}

	newPong, err := remoteChannel.Seal(disco.Pong{
		ID:     secondPing.ID,
		Source: netip.MustParseAddrPort("198.51.100.21:41641"),
	})
	if err != nil {
		t.Fatalf("remote Seal(new pong) error = %v", err)
	}
	runtime.HandleDatagram(newPong, snapshot.Peers[0].Endpoints[0], replacementGeneration.Socket)
	select {
	case observation := <-observer.observations:
		if observation.Generation != replacementGeneration {
			t.Fatalf("new pong generation = %#v", observation.Generation)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for current generation observation")
	}
	telemetry := runtime.telemetry.Snapshot()
	if telemetry.MapActivations != 2 || telemetry.PendingInvalidated == 0 ||
		telemetry.CompletionRejections == 0 || telemetry.ProbeCompletions != 1 {
		t.Fatalf("generation telemetry = %#v", telemetry)
	}
}

func TestRuntimeCancelsTransactionAfterTransportFailure(t *testing.T) {
	t.Parallel()

	runtime, transport, _, _, _, snapshot, generation := testRuntime(t)
	transport.setError(errors.New("test send failure"))
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	waitForRuntimeAttempt(t, transport)
	telemetry := runtime.telemetry.Snapshot()
	if telemetry.ProbeAttempts != 1 || telemetry.ProbesStarted != 1 ||
		telemetry.ProbeSendFailures != 1 || telemetry.ProbesSent != 0 {
		t.Fatalf("failed-send telemetry = %#v", telemetry)
	}
	transport.setError(nil)
	for index := range 8 {
		if _, err := runtime.Probe(
			t.Context(),
			snapshot.Peers[0].ID,
			snapshot.Peers[0].Endpoints[0],
		); err != nil {
			t.Fatalf("Probe(%d) error = %v", index, err)
		}
	}
	if _, err := runtime.Probe(
		t.Context(),
		snapshot.Peers[0].ID,
		snapshot.Peers[0].Endpoints[0],
	); !errors.Is(err, pathdiscovery.ErrPeerProbeCapacity) {
		t.Fatalf("Probe(over capacity) error = %v, want ErrPeerProbeCapacity", err)
	}
}

func TestRuntimeLimitsAuthenticatedPingResponses(t *testing.T) {
	t.Parallel()

	clock := &runtimeClock{now: time.Unix(2_000, 0)}
	local := testIdentity(t)
	remote := testIdentity(t)
	transport := newRuntimeTransport()
	runtime, err := newRuntime(
		t.Context(),
		local,
		transport,
		nil,
		pathdiscovery.NewProbeTelemetry(),
		clock.Now,
		time.Millisecond,
		time.Hour,
	)
	if err != nil {
		t.Fatalf("newRuntime() error = %v", err)
	}
	t.Cleanup(runtime.Close)
	snapshot, generation := runtimeSnapshot(t, local, remote)
	snapshot.Peers[0].Endpoints = nil
	if _, probes, err := runtime.Activate(snapshot, generation); err != nil || probes != 0 {
		t.Fatalf("Activate() probes = %d error %v", probes, err)
	}
	remoteChannel := testPeerChannel(t, remote, local)
	source := netip.MustParseAddrPort("203.0.113.30:41641")
	for index := 0; index < maxIncomingPingsPerPeer+1; index++ {
		packet, err := remoteChannel.Seal(disco.Ping{
			ID:      disco.TransactionID{byte(index + 1)},
			NodeKey: testNodeKey(t, snapshot.Peers[0].PublicKey),
		})
		if err != nil {
			t.Fatalf("remote Seal(%d) error = %v", index, err)
		}
		runtime.processDatagram(receivedDatagram{
			packet: packet,
			source: source,
			socket: generation.Socket,
		})
	}
	if sends := transport.sentSnapshot(); len(sends) != maxIncomingPingsPerPeer {
		t.Fatalf("ping response count = %d, want %d", len(sends), maxIncomingPingsPerPeer)
	}

	clock.Advance(incomingPingWindow)
	packet, err := remoteChannel.Seal(disco.Ping{
		ID:      disco.TransactionID{0xff},
		NodeKey: testNodeKey(t, snapshot.Peers[0].PublicKey),
	})
	if err != nil {
		t.Fatalf("remote Seal(after window) error = %v", err)
	}
	runtime.processDatagram(receivedDatagram{
		packet: packet,
		source: source,
		socket: generation.Socket,
	})
	if sends := transport.sentSnapshot(); len(sends) != maxIncomingPingsPerPeer+1 {
		t.Fatalf("renewed ping response count = %d", len(sends))
	}
	telemetry := runtime.telemetry.Snapshot()
	if telemetry.AuthenticatedPings != maxIncomingPingsPerPeer+2 ||
		telemetry.PingRateLimited != 1 ||
		telemetry.PongsSent != maxIncomingPingsPerPeer+1 {
		t.Fatalf("ping-limit telemetry = %#v", telemetry)
	}
}

func TestBuildProbeTargetsIsBoundedAndRoundRobin(t *testing.T) {
	t.Parallel()

	first := networkmap.Node{
		ID:                1,
		DiscoveryKey:      testDiscoveryKeyText(0x11),
		MachineAuthorized: true,
		Endpoints: []netip.AddrPort{
			netip.MustParseAddrPort("203.0.113.1:41641"),
			netip.MustParseAddrPort("203.0.113.2:41641"),
		},
	}
	second := networkmap.Node{
		ID:                2,
		DiscoveryKey:      testDiscoveryKeyText(0x22),
		MachineAuthorized: true,
		Endpoints: []netip.AddrPort{
			netip.MustParseAddrPort("203.0.113.3:41641"),
			netip.MustParseAddrPort("203.0.113.4:41641"),
		},
	}
	offline := second
	offline.ID = 3
	offline.OnlineKnown = true
	offline.Online = false
	targets := buildProbeTargets(networkmap.Snapshot{
		Peers: []networkmap.Node{first, second, offline},
	})
	want := []probeTarget{
		{peerID: 1, endpoint: first.Endpoints[0]},
		{peerID: 2, endpoint: second.Endpoints[0]},
		{peerID: 1, endpoint: first.Endpoints[1]},
		{peerID: 2, endpoint: second.Endpoints[1]},
	}
	if !slices.Equal(targets, want) {
		t.Fatalf("buildProbeTargets() = %#v, want %#v", targets, want)
	}
}

func TestRuntimeRepeatsProbeRounds(t *testing.T) {
	t.Parallel()

	local := testIdentity(t)
	remote := testIdentity(t)
	transport := newRuntimeTransport()
	runtime, err := newRuntime(
		t.Context(),
		local,
		transport,
		nil,
		pathdiscovery.NewProbeTelemetry(),
		time.Now,
		time.Millisecond,
		20*time.Millisecond,
	)
	if err != nil {
		t.Fatalf("newRuntime() error = %v", err)
	}
	t.Cleanup(runtime.Close)
	snapshot, generation := runtimeSnapshot(t, local, remote)
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	first := waitForRuntimeSend(t, transport)
	second := waitForRuntimeSend(t, transport)
	if first.destination != second.destination || bytes.Equal(first.packet, second.packet) {
		t.Fatalf("repeated probes = %#v then %#v", first, second)
	}
}

func TestRuntimeDeactivateStopsProbeRounds(t *testing.T) {
	t.Parallel()

	local := testIdentity(t)
	remote := testIdentity(t)
	transport := newRuntimeTransport()
	runtime, err := newRuntime(
		t.Context(),
		local,
		transport,
		nil,
		pathdiscovery.NewProbeTelemetry(),
		time.Now,
		time.Millisecond,
		500*time.Millisecond,
	)
	if err != nil {
		t.Fatalf("newRuntime() error = %v", err)
	}
	t.Cleanup(runtime.Close)
	snapshot, generation := runtimeSnapshot(t, local, remote)
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	waitForRuntimeSend(t, transport)
	runtime.Deactivate()
	time.Sleep(30 * time.Millisecond)
	if sends := transport.sentSnapshot(); len(sends) != 1 {
		t.Fatalf("deactivated runtime sent %d probes, want 1", len(sends))
	}
}

func TestNextProbeRoundDelay(t *testing.T) {
	t.Parallel()

	startedAt := time.Unix(2_000, 0)
	interval := 3 * time.Second
	tests := []struct {
		name string
		now  time.Time
		want time.Duration
	}{
		{name: "partial", now: startedAt.Add(time.Second), want: 2 * time.Second},
		{name: "deadline", now: startedAt.Add(interval), want: 0},
		{name: "overdue", now: startedAt.Add(4 * time.Second), want: 0},
		{name: "clock regression", now: startedAt.Add(-time.Second), want: interval},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := nextProbeRoundDelay(startedAt, test.now, interval); got != test.want {
				t.Fatalf("nextProbeRoundDelay() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestRandomProbeRefreshBounds(t *testing.T) {
	t.Parallel()

	for range 100 {
		refresh := randomProbeRefresh()
		if refresh < minProbeRefresh || refresh >= maxProbeRefresh {
			t.Fatalf("randomProbeRefresh() = %v", refresh)
		}
	}
}

func TestRuntimeCloseStopsWorkAndKeepsIdentityOwnedByCaller(t *testing.T) {
	t.Parallel()

	runtime, _, _, local, _, snapshot, generation := testRuntime(t)
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	runtime.Close()
	runtime.Close()
	if _, err := runtime.Probe(
		t.Context(),
		snapshot.Peers[0].ID,
		snapshot.Peers[0].Endpoints[0],
	); !errors.Is(err, ErrInactive) {
		t.Fatalf("Probe() after Close error = %v, want ErrInactive", err)
	}
	if _, err := local.Public(); err != nil {
		t.Fatalf("caller-owned identity after Runtime.Close error = %v", err)
	}
}

func TestRuntimeCloseIsIncomingDatagramBarrier(t *testing.T) {
	t.Parallel()

	runtime, transport, _, local, remote, snapshot, generation := testRuntime(t)
	if _, _, err := runtime.Activate(snapshot, generation); err != nil {
		t.Fatalf("Activate() error = %v", err)
	}
	waitForRuntimeSend(t, transport)
	remoteChannel := testPeerChannel(t, remote, local)
	packet, err := remoteChannel.Seal(disco.Ping{
		ID:      disco.TransactionID{1, 2, 3},
		NodeKey: testNodeKey(t, snapshot.Peers[0].PublicKey),
	})
	if err != nil {
		t.Fatalf("remote Seal(ping) error = %v", err)
	}

	const senders = 8
	started := make(chan struct{}, senders)
	stop := make(chan struct{})
	var sendersDone sync.WaitGroup
	for range senders {
		sendersDone.Go(func() {
			started <- struct{}{}
			for {
				select {
				case <-stop:
					return
				default:
					runtime.HandleDatagram(
						packet,
						snapshot.Peers[0].Endpoints[0],
						generation.Socket,
					)
				}
			}
		})
	}
	for range senders {
		<-started
	}
	runtime.Close()
	close(stop)
	sendersDone.Wait()

	sendsAfterClose := len(transport.sentSnapshot())
	runtime.HandleDatagram(
		packet,
		snapshot.Peers[0].Endpoints[0],
		generation.Socket,
	)
	if queued, slots := len(runtime.datagrams), len(runtime.slots); queued != 0 || slots != 0 {
		t.Fatalf("closed runtime retained queued=%d slots=%d", queued, slots)
	}
	if sends := len(transport.sentSnapshot()); sends != sendsAfterClose {
		t.Fatalf("closed runtime sent %d new datagrams", sends-sendsAfterClose)
	}
}

type runtimeSend struct {
	packet      []byte
	destination netip.AddrPort
	socket      pathdiscovery.Socket
}

type runtimeTransport struct {
	mu       sync.Mutex
	socket   pathdiscovery.Socket
	sends    []runtimeSend
	err      error
	attempts chan struct{}
}

var _ pathdiscovery.DatagramTransport = (*runtimeTransport)(nil)

func newRuntimeTransport() *runtimeTransport {
	return &runtimeTransport{
		socket:   pathdiscovery.Socket{Port: 41641, Generation: 3},
		attempts: make(chan struct{}, 1024),
	}
}

func (t *runtimeTransport) Socket() pathdiscovery.Socket {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.socket
}

func (t *runtimeTransport) SendDatagram(
	packet []byte,
	destination netip.AddrPort,
) (pathdiscovery.Socket, error) {
	t.mu.Lock()
	socket := t.socket
	err := t.err
	if err == nil {
		t.sends = append(t.sends, runtimeSend{
			packet:      bytes.Clone(packet),
			destination: destination,
			socket:      socket,
		})
	}
	t.mu.Unlock()
	select {
	case t.attempts <- struct{}{}:
	default:
	}

	return socket, err
}

func (t *runtimeTransport) setError(err error) {
	t.mu.Lock()
	t.err = err
	t.mu.Unlock()
}

func (t *runtimeTransport) sentSnapshot() []runtimeSend {
	t.mu.Lock()
	defer t.mu.Unlock()
	sends := make([]runtimeSend, len(t.sends))
	for index, sent := range t.sends {
		sends[index] = sent
		sends[index].packet = bytes.Clone(sent.packet)
	}

	return sends
}

type runtimeObserver struct {
	observations chan pathdiscovery.PathObservation
}

func (o *runtimeObserver) ObservePath(observation pathdiscovery.PathObservation) {
	select {
	case o.observations <- observation:
	default:
	}
}

type runtimeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *runtimeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.now
}

func (c *runtimeClock) Advance(duration time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(duration)
	c.mu.Unlock()
}

func testRuntime(
	t *testing.T,
) (
	*Runtime,
	*runtimeTransport,
	*runtimeObserver,
	*disco.Identity,
	*disco.Identity,
	networkmap.Snapshot,
	pathdiscovery.ProbeGeneration,
) {
	t.Helper()

	local := testIdentity(t)
	remote := testIdentity(t)
	transport := newRuntimeTransport()
	observer := &runtimeObserver{
		observations: make(chan pathdiscovery.PathObservation, 8),
	}
	runtime, err := newRuntime(
		t.Context(),
		local,
		transport,
		observer,
		pathdiscovery.NewProbeTelemetry(),
		time.Now,
		time.Millisecond,
		time.Hour,
	)
	if err != nil {
		t.Fatalf("newRuntime() error = %v", err)
	}
	t.Cleanup(runtime.Close)
	snapshot, generation := runtimeSnapshot(t, local, remote)

	return runtime, transport, observer, local, remote, snapshot, generation
}

func runtimeSnapshot(
	t *testing.T,
	local *disco.Identity,
	remote *disco.Identity,
) (networkmap.Snapshot, pathdiscovery.ProbeGeneration) {
	t.Helper()

	localPublic, err := local.Public()
	if err != nil {
		t.Fatalf("local Public() error = %v", err)
	}
	remotePublic, err := remote.Public()
	if err != nil {
		t.Fatalf("remote Public() error = %v", err)
	}
	snapshot := networkmap.Snapshot{
		Revision: 7,
		Self: networkmap.Node{
			ID:                1,
			PublicKey:         testNodeKeyText(0x11),
			DiscoveryKey:      localPublic.String(),
			MachineAuthorized: true,
		},
		Peers: []networkmap.Node{{
			ID:           2,
			PublicKey:    testNodeKeyText(0x22),
			DiscoveryKey: remotePublic.String(),
			Endpoints: []netip.AddrPort{
				netip.MustParseAddrPort("203.0.113.10:41641"),
			},
			MachineAuthorized: true,
		}},
	}
	generation := pathdiscovery.ProbeGeneration{
		Scope:       9,
		MapRevision: snapshot.Revision,
		Socket:      transportSocket(),
	}

	return snapshot, generation
}

func transportSocket() pathdiscovery.Socket {
	return pathdiscovery.Socket{Port: 41641, Generation: 3}
}

func waitForRuntimeSend(t *testing.T, transport *runtimeTransport) runtimeSend {
	t.Helper()

	waitForRuntimeAttempt(t, transport)
	sends := transport.sentSnapshot()
	if len(sends) == 0 {
		t.Fatal("runtime send was attempted but not recorded")
	}

	return sends[len(sends)-1]
}

func waitForRuntimeAttempt(t *testing.T, transport *runtimeTransport) {
	t.Helper()

	select {
	case <-transport.attempts:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for runtime send")
	}
}

var _ PathObserver = (*runtimeObserver)(nil)
