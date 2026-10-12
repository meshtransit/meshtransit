package dataplane

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/tuntest"

	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/relay"
	"meshtransit.net/client/internal/wghandshake"
)

// lazyFakeFactory hands out one fake device that reports traffic, and
// accepts the engine's lazy peer hooks as the real factory does.
type lazyFakeFactory struct {
	device *trafficFakeDevice
	lazy   *lazyPeers
}

func (f *lazyFakeFactory) New(
	context.Context, netadmin.TUN, *policyFilter, PacketObserver, *relay.Config,
) (wireGuardDevice, error) {
	return f.device, nil
}

func (f *lazyFakeFactory) setLazyPeers(lazy *lazyPeers) { f.lazy = lazy }

type trafficFakeDevice struct {
	*fakeWireGuardDevice
	mu      sync.Mutex
	traffic map[[32]byte]peerTraffic
	// failNext fails that many Configure calls; guarded by the engine's mutex.
	failNext int
}

func (d *trafficFakeDevice) Configure(configuration io.Reader) error {
	err := d.fakeWireGuardDevice.Configure(configuration)
	if d.failNext > 0 {
		d.failNext--
		return errTestConfigure
	}
	return err
}

func (d *trafficFakeDevice) PeerTraffic() (map[[32]byte]peerTraffic, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	traffic := make(map[[32]byte]peerTraffic, len(d.traffic))
	for key, counters := range d.traffic {
		traffic[key] = counters
	}
	return traffic, nil
}

// testClock is a settable clock safe to read from the activation worker.
type testClock struct{ now atomic.Int64 }

func newTestClock() *testClock {
	clock := &testClock{}
	clock.now.Store(time.Now().UnixNano())
	return clock
}

func (c *testClock) Now() time.Time              { return time.Unix(0, c.now.Load()) }
func (c *testClock) Advance(delay time.Duration) { c.now.Add(int64(delay)) }

// newLazyTestEngine returns an engine over a fake device that installs maps
// of more than threshold peers lazily, and a map of peers peers.
func newLazyTestEngine(
	t *testing.T,
	threshold, peers int,
) (*WireGuardEngine, *trafficFakeDevice, *testClock, NodePrivateKey, networkmap.Snapshot) {
	t.Helper()
	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.Peers = scalePeers(t, snapshot.Peers[0], 0, peers)
	snapshot.Policy = nil
	fake := &trafficFakeDevice{fakeWireGuardDevice: &fakeWireGuardDevice{}, traffic: map[[32]byte]peerTraffic{}}
	engine, err := newWireGuardEngine(&wireGuardTUNOpener{}, 41641, &lazyFakeFactory{device: fake}, nil)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	clock := newTestClock()
	engine.clock = clock.Now
	engine.lazyThreshold = threshold
	t.Cleanup(func() { _ = engine.Close() })
	return engine, fake, clock, privateKey, snapshot
}

func peerKeyOf(t *testing.T, peer networkmap.Node) [32]byte {
	t.Helper()
	key, err := parseNodePublicKey(peer.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// lastConfiguration returns the device's last configuration, read under the
// engine's mutex so it is ordered after the activation worker's writes.
func lastConfiguration(engine *WireGuardEngine, fake *trafficFakeDevice) string {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	return fake.configuration
}

func TestLazyEngineInstallsPeersOnDemand(t *testing.T) {
	t.Parallel()
	engine, fake, _, privateKey, snapshot := newLazyTestEngine(t, 2, 3)
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if keys := strings.Count(lastConfiguration(engine, fake), "public_key="); keys != 0 {
		t.Fatalf("a lazy map installed %d peers up front", keys)
	}
	if paths := engine.PeerPaths(); paths.PeerCount != 3 || paths.InactiveCount != 3 {
		t.Fatalf("PeerPaths() = %+v, want 3 peers, all inactive", paths)
	}

	target := snapshot.Peers[1]
	engine.lazy.outbound(tuntest.Ping(target.Addresses[0].Addr(), snapshot.Self.Addresses[0].Addr()))
	configuration := lastConfiguration(engine, fake)
	key := peerKeyOf(t, target)
	if !strings.Contains(configuration, "public_key="+hex.EncodeToString(key[:])) ||
		!strings.Contains(configuration, "persistent_keepalive_interval=0\n") ||
		strings.Contains(configuration, "replace_peers") {
		t.Fatalf("activation wrote:\n%s", configuration)
	}
	paths := engine.PeerPaths()
	if paths.InactiveCount != 2 || paths.DirectCount != 1 || paths.LazyActivationCount != 1 {
		t.Fatalf("PeerPaths() after activation = %+v", paths)
	}

	// A packet to an installed peer installs nothing more.
	calls := fake.configureCalls
	engine.lazy.outbound(tuntest.Ping(target.Addresses[0].Addr(), snapshot.Self.Addresses[0].Addr()))
	if engine.PeerPaths(); fake.configureCalls != calls {
		t.Fatal("a packet to an installed peer configured the device")
	}
	// A packet to an address outside the map installs nothing.
	engine.lazy.outbound(tuntest.Ping(netip.MustParseAddr("100.64.9.9"), snapshot.Self.Addresses[0].Addr()))
	if engine.PeerPaths(); fake.configureCalls != calls {
		t.Fatal("a packet outside the map configured the device")
	}

	// The next map keeps the installed peer and its session.
	snapshot.Revision++
	snapshot.Peers = append(snapshot.Peers, scalePeers(t, snapshot.Peers[0], 3, 1)...)
	written := len(fake.configurations)
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply(+1 peer) error = %v", err)
	}
	for _, configuration := range fake.configurations[written:] {
		if strings.Contains(configuration, "remove=true") || strings.Contains(configuration, hex.EncodeToString(key[:])) {
			t.Fatalf("the next map touched the installed peer:\n%s", configuration)
		}
	}
	if paths := engine.PeerPaths(); paths.PeerCount != 4 || paths.InactiveCount != 3 {
		t.Fatalf("PeerPaths() after the next map = %+v", paths)
	}

	// A map without the peer removes it from the device.
	snapshot.Revision++
	snapshot.Peers = append(snapshot.Peers[:1:1], snapshot.Peers[2:]...)
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply(-1 peer) error = %v", err)
	}
	if configuration := lastConfiguration(engine, fake); !strings.Contains(configuration,
		"public_key="+hex.EncodeToString(key[:])+"\nremove=true\n") {
		t.Fatalf("a removed peer stayed installed:\n%s", configuration)
	}
}

func TestLazyEngineAppliesRememberedPathOnActivation(t *testing.T) {
	t.Parallel()
	engine, fake, _, privateKey, snapshot := newLazyTestEngine(t, 0, 2)
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	target := snapshot.Peers[0]
	preferred := netip.MustParseAddrPort("198.51.100.7:50000")
	if err := engine.SetPreferredEndpoint(snapshot.Revision, target.ID, preferred); err != nil {
		t.Fatalf("SetPreferredEndpoint(uninstalled peer) error = %v", err)
	}
	if err := engine.SetPreferredEndpoint(snapshot.Revision, target.ID,
		netip.MustParseAddrPort("127.0.0.1:1")); err == nil {
		t.Fatal("an unauthorized endpoint was remembered")
	}
	if err := engine.SetPreferredEndpoint(snapshot.Revision, 999, preferred); err == nil {
		t.Fatal("a peer outside the map accepted a path")
	}
	if err := engine.SetPreferredEndpoint(snapshot.Revision+1, target.ID, preferred); err == nil {
		t.Fatal("a stale map revision accepted a path")
	}
	engine.lazy.outbound(tuntest.Ping(target.Addresses[0].Addr(), snapshot.Self.Addresses[0].Addr()))
	if configuration := lastConfiguration(engine, fake); !strings.Contains(configuration,
		"endpoint="+preferred.String()+"\n") {
		t.Fatalf("activation ignored the remembered path:\n%s", configuration)
	}

	// Restoring the path of an uninstalled peer forgets the remembered one.
	other := snapshot.Peers[1]
	if err := engine.SetPreferredEndpoint(snapshot.Revision, other.ID, preferred); err != nil {
		t.Fatal(err)
	}
	if err := engine.RestorePreferredEndpoint(snapshot.Revision, other.ID); err != nil {
		t.Fatalf("RestorePreferredEndpoint(uninstalled peer) error = %v", err)
	}
	engine.lazy.outbound(tuntest.Ping(other.Addresses[0].Addr(), snapshot.Self.Addresses[0].Addr()))
	if configuration := lastConfiguration(engine, fake); !strings.Contains(configuration,
		"endpoint="+other.Endpoints[0].String()+"\n") {
		t.Fatalf("activation after restore wrote:\n%s", configuration)
	}
}

func TestLazyEngineEvictsOnlyIdlePeers(t *testing.T) {
	t.Parallel()
	engine, fake, clock, privateKey, snapshot := newLazyTestEngine(t, 0, 3)
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	self := snapshot.Self.Addresses[0].Addr()
	for _, peer := range snapshot.Peers {
		engine.lazy.outbound(tuntest.Ping(peer.Addresses[0].Addr(), self))
	}
	if paths := engine.PeerPaths(); paths.InactiveCount != 0 {
		t.Fatalf("PeerPaths() = %+v, want every peer installed", paths)
	}
	// The first peer took a direct path other than its map endpoint.
	chosen := netip.MustParseAddrPort("198.51.100.7:50000")
	if err := engine.SetPreferredEndpoint(snapshot.Revision, snapshot.Peers[0].ID, chosen); err != nil {
		t.Fatal(err)
	}

	clock.Advance(lazyIdleTimeout + time.Second)
	// Peer 1 keeps sending through the TUN; peer 2 completed a handshake
	// recently; peer 0 is idle both ways.
	engine.lazy.inbound(tuntest.Ping(self, snapshot.Peers[1].Addresses[0].Addr()))
	fake.mu.Lock()
	fake.traffic[peerKeyOf(t, snapshot.Peers[2])] = peerTraffic{handshake: uint64(clock.Now().Add(-time.Minute).Unix())} //nolint:gosec // a positive unix time
	fake.mu.Unlock()
	engine.evictIdleLazyPeers(clock.Now())

	idle := peerKeyOf(t, snapshot.Peers[0])
	configuration := lastConfiguration(engine, fake)
	if configuration != "public_key="+hex.EncodeToString(idle[:])+"\nremove=true\n" {
		t.Fatalf("eviction wrote:\n%s", configuration)
	}
	paths := engine.PeerPaths()
	if paths.InactiveCount != 1 || paths.LazyEvictionCount != 1 {
		t.Fatalf("PeerPaths() after eviction = %+v", paths)
	}

	// The evicted peer comes back on its chosen path.
	engine.lazy.outbound(tuntest.Ping(snapshot.Peers[0].Addresses[0].Addr(), self))
	if configuration := lastConfiguration(engine, fake); !strings.Contains(configuration,
		"endpoint="+chosen.String()+"\n") {
		t.Fatalf("reactivation wrote:\n%s", configuration)
	}
}

func TestLazyEngineSwitchesModesWithMapSize(t *testing.T) {
	t.Parallel()
	engine, fake, _, privateKey, snapshot := newLazyTestEngine(t, 2, 2)
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply(eager) error = %v", err)
	}
	if configuration := lastConfiguration(engine, fake); strings.Count(configuration, "public_key=") != 2 ||
		strings.Count(configuration, "persistent_keepalive_interval=25\n") != 2 {
		t.Fatalf("an eager map wrote:\n%s", configuration)
	}

	// Past the threshold, installed peers stay, without keepalives.
	snapshot.Revision++
	snapshot.Peers = append(snapshot.Peers, scalePeers(t, snapshot.Peers[0], 2, 1)...)
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply(lazy) error = %v", err)
	}
	configuration := lastConfiguration(engine, fake)
	if strings.Contains(configuration, "remove=true") || strings.Count(configuration, "public_key=") != 2 ||
		strings.Count(configuration, "persistent_keepalive_interval=0\n") != 2 {
		t.Fatalf("switching to lazy wrote:\n%s", configuration)
	}
	if paths := engine.PeerPaths(); paths.PeerCount != 3 || paths.InactiveCount != 1 {
		t.Fatalf("PeerPaths() after switching to lazy = %+v", paths)
	}

	// Back at the threshold, it stays lazy (down to 90% of it).
	snapshot.Revision++
	snapshot.Peers = snapshot.Peers[1:]
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply(at the threshold) error = %v", err)
	}
	if paths := engine.PeerPaths(); paths.PeerCount != 2 || paths.InactiveCount != 1 {
		t.Fatalf("PeerPaths() at the threshold = %+v, want still lazy", paths)
	}

	// Under 90% of it, every peer is installed with keepalives.
	snapshot.Revision++
	snapshot.Peers = snapshot.Peers[1:]
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply(eager again) error = %v", err)
	}
	if configuration := lastConfiguration(engine, fake); strings.Count(configuration,
		"persistent_keepalive_interval=25\n") != 1 {
		t.Fatalf("switching back to eager wrote:\n%s", configuration)
	}
	if paths := engine.PeerPaths(); paths.PeerCount != 1 || paths.InactiveCount != 0 {
		t.Fatalf("PeerPaths() after switching back = %+v", paths)
	}
}

func TestLazyEngineDisabledInstallsEveryPeer(t *testing.T) {
	t.Parallel()
	engine, fake, _, privateKey, snapshot := newLazyTestEngine(t, 0, 3)
	engine.SetLazyPeers(LazyPeersOff)
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if keys := strings.Count(lastConfiguration(engine, fake), "public_key="); keys != 3 {
		t.Fatalf("lazy peers off installed %d of 3 peers", keys)
	}
	if engine.lazy.loadIndex() != nil {
		t.Fatal("lazy peers off published an index")
	}
}

func TestLazyEngineCloseForgetsInstalledPeers(t *testing.T) {
	t.Parallel()
	engine, fake, _, privateKey, snapshot := newLazyTestEngine(t, 0, 2)
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	engine.lazy.outbound(tuntest.Ping(snapshot.Peers[0].Addresses[0].Addr(), snapshot.Self.Addresses[0].Addr()))
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	if engine.lazy.loadIndex() != nil || engine.lazy.session.Load() != nil {
		t.Fatal("Close left the lazy index or session")
	}
	// A new device starts with no peers installed.
	snapshot.Revision++
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() after Close error = %v", err)
	}
	if keys := strings.Count(lastConfiguration(engine, fake), "public_key="); keys != 0 {
		t.Fatalf("a new device started with %d peers", keys)
	}
}

func TestLazyEngineRebuildsWhenActivationFails(t *testing.T) {
	t.Parallel()
	engine, fake, _, privateKey, snapshot := newLazyTestEngine(t, 0, 1)
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	engine.mu.Lock()
	fake.configureErr = errTestConfigure
	engine.mu.Unlock()
	engine.lazy.outbound(tuntest.Ping(snapshot.Peers[0].Addresses[0].Addr(), snapshot.Self.Addresses[0].Addr()))
	select {
	case <-engine.DeviceStops():
	case <-time.After(5 * time.Second):
		t.Fatal("a failed activation did not ask for a rebuild")
	}
	if paths := engine.PeerPaths(); paths.Available {
		t.Fatalf("the device stayed open after a failed activation: %+v", paths)
	}
}

var errTestConfigure = &testError{"configure failed"}

type testError struct{ text string }

func (e *testError) Error() string { return e.text }

// TestLazyPeersCloseReleasesWaitingPackets: a packet path waiting on an
// activation returns as soon as the device starts closing.
func TestLazyPeersCloseReleasesWaitingPackets(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	lazy := newLazyPeers(func(*lazyPeer) { <-release }, func(time.Time) {}, time.Now)
	peer := &lazyPeer{id: 1}
	address := netip.MustParseAddr("100.64.0.4")
	lazy.index.Store(&lazyIndex{
		byID: map[uint64]*lazyPeer{1: peer}, byAddr: map[netip.Addr]*lazyPeer{address: peer},
	})
	lazy.attach()
	defer close(release)
	returned := make(chan time.Duration, 1)
	go func() {
		started := time.Now()
		lazy.outbound(tuntest.Ping(address, netip.MustParseAddr("100.64.0.3")))
		returned <- time.Since(started)
	}()
	time.Sleep(10 * time.Millisecond)
	lazy.detach()
	select {
	case waited := <-returned:
		if waited >= lazyActivationWait {
			t.Fatalf("the packet path waited %v after detach", waited)
		}
	case <-time.After(time.Second):
		t.Fatal("the packet path did not return")
	}
	// Without a session, packets do not wait at all.
	lazy.outbound(tuntest.Ping(address, netip.MustParseAddr("100.64.0.3")))
}

func TestLazyPeersRelayedInitiationNeedsNoHandshakeCheck(t *testing.T) {
	t.Parallel()
	installed := make(chan uint64, 1)
	lazy := newLazyPeers(func(peer *lazyPeer) {
		peer.installed.Store(true)
		installed <- peer.id
	}, func(time.Time) {}, time.Now)
	var key [32]byte
	key[0] = 7
	peer := &lazyPeer{id: 5, key: key}
	lazy.index.Store(&lazyIndex{byID: map[uint64]*lazyPeer{5: peer}, byKey: map[[32]byte]*lazyPeer{key: peer}})
	lazy.attach()
	t.Cleanup(lazy.detach)

	initiation := make([]byte, device.MessageInitiationSize)
	binary.LittleEndian.PutUint32(initiation, device.MessageInitiationType)
	unknown := relay.Key{9}
	lazy.initiation(initiation, &unknown, netip.Addr{})
	lazy.initiation(initiation[:100], (*relay.Key)(&key), netip.Addr{})
	select {
	case id := <-installed:
		t.Fatalf("peer %d installed by an unknown key or a short packet", id)
	default:
	}
	lazy.initiation(initiation, (*relay.Key)(&key), netip.Addr{})
	select {
	case id := <-installed:
		if id != 5 {
			t.Fatalf("installed peer %d", id)
		}
	case <-time.After(time.Second):
		t.Fatal("a relayed initiation installed nothing")
	}
}

func TestLazyPeersLimitDirectInitiationChecks(t *testing.T) {
	t.Parallel()
	clock := newTestClock()
	lazy := newLazyPeers(func(*lazyPeer) {}, func(time.Time) {}, clock.Now)
	spend := func(source netip.Addr, attempts int) int {
		allowed := 0
		for range attempts {
			if lazy.allowInitiation(source) {
				allowed++
			}
		}
		return allowed
	}
	// One source spends only its own budget.
	flooder := netip.MustParseAddr("192.0.2.1")
	if allowed := spend(flooder, 1_000); allowed != lazySourceBurst {
		t.Fatalf("one source got %d checks, want %d", allowed, lazySourceBurst)
	}
	if spend(netip.MustParseAddr("192.0.2.2"), 1) != 1 {
		t.Fatal("a flood from one source starved another")
	}
	// Many sources together are bounded by the shared budget.
	allowed := 0
	for index := range 100 {
		allowed += spend(netip.AddrFrom4([4]byte{198, 51, 100, byte(index)}), lazySourceBurst)
	}
	if want := lazyInitiationBurst - lazySourceBurst - 1; allowed != want {
		t.Fatalf("many sources got %d checks, want the shared %d", allowed, want)
	}
	clock.Advance(100 * time.Millisecond)
	if allowed := spend(netip.MustParseAddr("192.0.2.3"), lazySourceBurst); allowed != lazySourceBurst {
		t.Fatalf("100 ms refilled %d checks for a new source", allowed)
	}
	// The remembered sources stay bounded.
	for index := range lazySourceLimit + 10 {
		lazy.allowInitiation(netip.AddrFrom4([4]byte{10, byte(index >> 16), byte(index >> 8), byte(index)}))
	}
	lazy.limiterMu.Lock()
	remembered := len(lazy.sources)
	lazy.limiterMu.Unlock()
	if remembered > lazySourceLimit {
		t.Fatalf("remembered %d sources", remembered)
	}
}

func TestPacketAddresses(t *testing.T) {
	t.Parallel()
	source, destination := netip.MustParseAddr("100.64.0.3"), netip.MustParseAddr("100.64.0.4")
	packet := tuntest.Ping(destination, source)
	if got, ok := packetDestination(packet); !ok || got != destination {
		t.Fatalf("packetDestination() = %v, %v", got, ok)
	}
	if got, ok := packetSource(packet); !ok || got != source {
		t.Fatalf("packetSource() = %v, %v", got, ok)
	}
	v6 := make([]byte, 40)
	v6[0] = 6 << 4
	v6[23], v6[39] = 1, 2
	if got, ok := packetDestination(v6); !ok || got.As16()[15] != 2 || !got.Is6() {
		t.Fatalf("packetDestination(v6) = %v, %v", got, ok)
	}
	if got, ok := packetSource(v6); !ok || got.As16()[15] != 1 {
		t.Fatalf("packetSource(v6) = %v, %v", got, ok)
	}
	for _, short := range [][]byte{nil, packet[:19], v6[:39], {0x50}} {
		if _, ok := packetDestination(short); ok {
			t.Fatalf("packetDestination(%x) accepted", short)
		}
	}
}

// TestLazyPeersJunkInitiationsSpendNoBudget: initiations without a valid MAC1
// are dropped before the rate limit, so floods of them cannot crowd out
// peers that know this node's key.
func TestLazyPeersJunkInitiationsSpendNoBudget(t *testing.T) {
	t.Parallel()
	responder, err := wghandshake.NewResponder([32]byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	lazy := newLazyPeers(func(*lazyPeer) {}, func(time.Time) {}, time.Now)
	lazy.index.Store(&lazyIndex{byKey: map[[32]byte]*lazyPeer{}, responder: responder})
	junk := make([]byte, device.MessageInitiationSize)
	binary.LittleEndian.PutUint32(junk, device.MessageInitiationType)
	for range lazyInitiationBurst * 5 {
		lazy.initiation(junk, nil, netip.MustParseAddr("192.0.2.1"))
	}
	if dropped := lazy.dropped.Load(); dropped != 0 {
		t.Fatalf("junk initiations were rate limited %d times", dropped)
	}
	lazy.limiterMu.Lock()
	spent := !lazy.global.refilledAt.IsZero() || len(lazy.sources) != 0
	lazy.limiterMu.Unlock()
	if spent {
		t.Fatal("junk initiations spent the budget")
	}
}

// TestLazyPeersBoundTheStallOfAWaitingEngine: while the engine cannot install
// (its mutex is held), packets to uninstalled peers wait once, together, and
// then pass without waiting.
func TestLazyPeersBoundTheStallOfAWaitingEngine(t *testing.T) {
	t.Parallel()
	engine, _, _, privateKey, snapshot := newLazyTestEngine(t, 0, 4)
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	self := snapshot.Self.Addresses[0].Addr()
	engine.mu.Lock()
	started := time.Now()
	for range 64 {
		for _, peer := range snapshot.Peers {
			engine.lazy.outbound(tuntest.Ping(peer.Addresses[0].Addr(), self))
		}
	}
	stalled := time.Since(started)
	engine.mu.Unlock()
	if stalled > lazyActivationWait+150*time.Millisecond {
		t.Fatalf("256 packets to 4 uninstalled peers stalled %v", stalled)
	}
	// Once the engine is free, the queued activations land.
	deadline := time.Now().Add(5 * time.Second)
	for engine.PeerPaths().InactiveCount != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("queued activations did not land: %+v", engine.PeerPaths())
		}
		time.Sleep(time.Millisecond)
	}
}

func TestLazyEngineIsolatesAFailedActivation(t *testing.T) {
	t.Parallel()
	engine, fake, _, privateKey, snapshot := newLazyTestEngine(t, 0, 2)
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	target := snapshot.Peers[0]
	if err := engine.SetPreferredEndpoint(snapshot.Revision, target.ID,
		netip.MustParseAddrPort("198.51.100.7:50000")); err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	fake.failNext = 1
	engine.mu.Unlock()
	self := snapshot.Self.Addresses[0].Addr()
	engine.lazy.outbound(tuntest.Ping(target.Addresses[0].Addr(), self))
	key := peerKeyOf(t, target)
	if configuration := lastConfiguration(engine, fake); configuration !=
		"public_key="+hex.EncodeToString(key[:])+"\nremove=true\n" {
		t.Fatalf("a failed activation was not undone:\n%s", configuration)
	}
	paths := engine.PeerPaths()
	if !paths.Available || paths.InactiveCount != 2 {
		t.Fatalf("PeerPaths() after a failed activation = %+v", paths)
	}
	select {
	case <-engine.DeviceStops():
		t.Fatal("one failed activation rebuilt the device")
	default:
	}
	// The next packet tries again, on the map endpoint.
	engine.lazy.outbound(tuntest.Ping(target.Addresses[0].Addr(), self))
	if configuration := lastConfiguration(engine, fake); !strings.Contains(configuration,
		"endpoint="+target.Endpoints[0].String()+"\n") {
		t.Fatalf("the retry wrote:\n%s", configuration)
	}
	if paths := engine.PeerPaths(); paths.InactiveCount != 1 {
		t.Fatalf("PeerPaths() after the retry = %+v", paths)
	}
}

func TestLazyEngineKeepsCountersAcrossEviction(t *testing.T) {
	t.Parallel()
	engine, fake, clock, privateKey, snapshot := newLazyTestEngine(t, 0, 1)
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	peer := snapshot.Peers[0]
	key := peerKeyOf(t, peer)
	self := snapshot.Self.Addresses[0].Addr()
	engine.lazy.outbound(tuntest.Ping(peer.Addresses[0].Addr(), self))
	setTraffic := func(rx, tx uint64) {
		fake.mu.Lock()
		fake.traffic[key] = peerTraffic{rx: rx, tx: tx}
		fake.mu.Unlock()
	}
	setTraffic(100, 50)
	clock.Advance(lazyIdleTimeout + time.Second)
	engine.evictIdleLazyPeers(clock.Now())
	stats := engine.PeerPathStats()
	if len(stats) != 1 || stats[0].PeerID != peer.ID || stats[0].Path != PeerPathUnknown ||
		stats[0].RxBytes != 100 || stats[0].TxBytes != 50 {
		t.Fatalf("PeerPathStats() after eviction = %+v", stats)
	}
	// wireguard-go starts the reinstalled peer at zero.
	setTraffic(0, 0)
	engine.lazy.outbound(tuntest.Ping(peer.Addresses[0].Addr(), self))
	setTraffic(10, 5)
	stats = engine.PeerPathStats()
	if len(stats) != 1 || stats[0].Path != PeerPathDirectUDP || stats[0].RxBytes != 110 || stats[0].TxBytes != 55 {
		t.Fatalf("PeerPathStats() after reinstalling = %+v", stats)
	}
	// The counters survive a new map with the same peer.
	snapshot.Revision++
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	if stats = engine.PeerPathStats(); len(stats) != 1 || stats[0].RxBytes != 110 {
		t.Fatalf("PeerPathStats() after a new map = %+v", stats)
	}
}

type failingTUNOpener struct{}

func (failingTUNOpener) OpenTUN(context.Context, netadmin.TUNConfig) (netadmin.TUN, error) {
	return netadmin.TUN{}, errors.New("no tun")
}

func TestLazyEngineFailedOpenKeepsNoLazyState(t *testing.T) {
	t.Parallel()
	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.Policy = nil
	fake := &trafficFakeDevice{fakeWireGuardDevice: &fakeWireGuardDevice{}, traffic: map[[32]byte]peerTraffic{}}
	engine, err := newWireGuardEngine(failingTUNOpener{}, 41641, &lazyFakeFactory{device: fake}, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine.lazyThreshold = 0
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err == nil {
		t.Fatal("Apply() without a TUN succeeded")
	}
	if engine.lazy.loadIndex() != nil || engine.lazyPlanPeers != nil || engine.lazyResponder != nil {
		t.Fatal("a failed open left lazy state behind")
	}
}

func TestLazyEngineReusesAndClearsItsResponder(t *testing.T) {
	t.Parallel()
	engine, _, _, privateKey, snapshot := newLazyTestEngine(t, 0, 1)
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	responder := engine.lazyResponder
	snapshot.Revision++
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	if engine.lazyResponder != responder {
		t.Fatal("the same key built a second responder")
	}
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	if engine.lazyResponder != nil || responder.Matches([32]byte(privateKey)) {
		t.Fatal("Close kept the responder's key")
	}
}

// TestLazyEngineConcurrentTrafficApplyAndClose runs the packet hooks, the
// worker, Apply, eviction and Close together, for the race detector.
func TestLazyEngineConcurrentTrafficApplyAndClose(t *testing.T) {
	t.Parallel()
	engine, _, clock, privateKey, snapshot := newLazyTestEngine(t, 0, 16)
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatal(err)
	}
	self := snapshot.Self.Addresses[0].Addr()
	stop := make(chan struct{})
	var traffic sync.WaitGroup
	for worker := range 4 {
		traffic.Add(1)
		go func() {
			defer traffic.Done()
			for index := 0; ; index++ {
				select {
				case <-stop:
					return
				default:
				}
				peer := snapshot.Peers[(index+worker)%len(snapshot.Peers)]
				engine.lazy.outbound(tuntest.Ping(peer.Addresses[0].Addr(), self))
				engine.lazy.inbound(tuntest.Ping(self, peer.Addresses[0].Addr()))
			}
		}()
	}
	for round := range 30 {
		next := snapshot
		next.Revision = snapshot.Revision + uint64(round) + 1
		next.Peers = snapshot.Peers[:8+round%8]
		if _, err := engine.Apply(t.Context(), next, privateKey); err != nil {
			t.Fatalf("Apply(round %d) error = %v", round, err)
		}
		clock.Advance(lazyIdleTimeout / 4)
		engine.evictIdleLazyPeers(clock.Now())
		_ = engine.PeerPaths()
		_ = engine.PeerPathStats()
		if round%10 == 9 {
			if err := engine.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
	close(stop)
	traffic.Wait()
}

func TestLazyEngineModes(t *testing.T) {
	t.Parallel()
	engine, _, _, _, _ := newLazyTestEngine(t, lazyPeerThreshold, 0)
	for _, test := range []struct {
		mode    LazyPeerMode
		peers   int
		wantOn  bool
		comment string
	}{
		{LazyPeersAuto, lazyPeerThreshold, false, "auto at the threshold"},
		{LazyPeersAuto, lazyPeerThreshold + 1, true, "auto above the threshold"},
		{LazyPeersOff, lazyPeerThreshold * 10, false, "off"},
		{LazyPeersAlways, 1, true, "always"},
	} {
		engine.SetLazyPeers(test.mode)
		if got := engine.lazyActive(test.peers); got != test.wantOn {
			t.Errorf("%s: lazyActive(%d) = %t", test.comment, test.peers, got)
		}
	}
}
