package dataplane

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"meshtransit.net/client/internal/netadmin"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/packetmeta"
	"meshtransit.net/client/internal/pathdiscovery"
	"meshtransit.net/client/internal/prefixset"
	"meshtransit.net/client/internal/relay"
	"meshtransit.net/client/internal/wghandshake"
)

const (
	maxWireGuardPeers = 10_000 // matches Core's largest map (MESHTRANSIT_CONTROL_MAP_PEER_LIMIT, at most 10,000)
	// maxWireGuardAllowedIPs bounds the peer addresses of one map (overlay
	// and alias addresses of both families).
	maxWireGuardAllowedIPs = 4 * maxWireGuardPeers
	// maxWireGuardRoutes bounds the routes installed after exact aggregation
	// (prefixset.Summarize), which turns contiguous peer addresses into a few
	// prefixes.
	maxWireGuardRoutes        = 512
	maxWireGuardPeerEndpoints = 128
	// Keep direct NAT mappings warm without sending tunnel keepalives over relay paths.
	directPathKeepaliveSeconds = 25
)

var (
	// ErrPeerEndpointUnavailable means no matching active peer configuration
	// exists for an incremental endpoint update.
	ErrPeerEndpointUnavailable = errors.New("dataplane: peer endpoint is unavailable")
	// ErrPeerEndpointGeneration means an endpoint update targets a map other
	// than the one currently installed in the tunnel engine.
	ErrPeerEndpointGeneration = errors.New("dataplane: peer endpoint generation mismatch")
	// ErrPeerEndpointUnauthorized means an endpoint was not authorized by the
	// currently installed control-plane snapshot.
	ErrPeerEndpointUnauthorized = errors.New("dataplane: peer endpoint is not authorized")
)

type wireGuardPeerPlan struct {
	id                  uint64
	key                 [32]byte
	discoveryKey        string
	baseEndpoint        string
	basePath            peerPath
	authorizedEndpoints []netip.AddrPort
	allowedIPs          []netip.Prefix
	// lazy peers are installed on demand and send no persistent keepalive,
	// which would keep their sessions, and so the peers, alive.
	lazy bool
}

type wireGuardPeerState struct {
	key                 [32]byte
	discoveryKey        string
	baseEndpoint        string
	basePath            peerPath
	currentEndpoint     string
	currentPath         peerPath
	relayStartedAt      time.Time
	authorizedEndpoints []netip.AddrPort
	allowedIPs          []netip.Prefix
	sessionResetPending bool
	lazy                bool
}

type peerPath uint8

const (
	peerPathPending peerPath = iota
	peerPathDirect
	peerPathRelay
)

func (path peerPath) String() string {
	switch path {
	case peerPathDirect:
		return "direct"
	case peerPathRelay:
		return "relay"
	default:
		return "pending"
	}
}

// endpointDigest names an endpoint in logs without its address: equal
// endpoints give equal digests.
func endpointDigest(endpoint string) string {
	if endpoint == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(endpoint))
	return hex.EncodeToString(sum[:4])
}

// PeerPathSnapshot reports aggregate path selection without exposing peer
// identities, endpoint addresses, or key material.
type PeerPathSnapshot struct {
	Available            bool
	PeerCount            int
	DirectCount          int
	RelayCount           int
	PendingCount         int
	RelayBootstrapCount  uint64
	DirectPromotionCount uint64
	RelayFallbackCount   uint64
	LastDirectPromotion  time.Duration
	MaxDirectPromotion   time.Duration
	// InactiveCount counts map peers wireguard-go does not hold while lazy
	// peers are active; the Lazy counters count installations, evictions and
	// activation requests dropped (full queue or rate limit).
	InactiveCount       int
	LazyActivationCount uint64
	LazyEvictionCount   uint64
	LazyDroppedCount    uint64
}

// NodePrivateKey is the raw WireGuard-compatible node key. Its formatting is
// deliberately redacted, and callers must clear temporary copies.
type NodePrivateKey [32]byte

func (NodePrivateKey) String() string { return "<node private key redacted>" }

func (NodePrivateKey) GoString() string {
	return "dataplane.NodePrivateKey{<redacted>}"
}

type wireGuardDevice interface {
	Configure(io.Reader) error
	Up() error
	Close()
}

type endpointDiscoveringDevice interface {
	DiscoverySocket() pathdiscovery.Socket
	DiscoverEndpoints(
		context.Context,
		uint64,
		[]netip.AddrPort,
	) (pathdiscovery.DiscoveryResult, error)
}

type natClassifyingDevice interface {
	ClassifyNAT(
		context.Context,
		[]netip.AddrPort,
		[]netip.AddrPort,
	) (pathdiscovery.NATReport, error)
}

type peerProbingDevice interface {
	pathdiscovery.DatagramTransport
	SetPeerProbeHandler(pathdiscovery.DatagramHandler)
}

type relayProbingDevice interface {
	pathdiscovery.RelayDatagramTransport
}

type relayManagingDevice interface {
	RelayHealth() relay.HealthSnapshot
	PrepareRelayRegion(int) error
}

type relayConfiguringDevice interface {
	ReplaceRelayAuthority(homeRegion int, peers []relay.Peer) error
}

// relayFailureDevice reports relay connection failures to a hook.
type relayFailureDevice interface {
	SetRelayFailureHook(func())
}

type wireGuardFactory interface {
	New(
		context.Context,
		netadmin.TUN,
		*policyFilter,
		PacketObserver,
		*relay.Config,
	) (wireGuardDevice, error)
}

// PacketDirection identifies plaintext packet movement at the TUN boundary.
type PacketDirection uint8

const (
	PacketOutbound PacketDirection = iota + 1
	PacketInbound
)

// PacketObserver receives a transient view of plaintext packet headers. An
// implementation must return immediately and must not retain packet bytes.
type PacketObserver interface {
	UpdateNetwork(networkmap.Snapshot)
	ObservePacket(PacketDirection, []byte)
}

// PacketMetadataObserver optionally receives validated payload-free outbound
// headers in local TUN coordinates, before alias translation. Observation occurs
// only after packet admission and outside the policy authority lock.
type PacketMetadataObserver interface {
	ObservePacketMetadata(PacketDirection, packetmeta.Header)
}

type wireGuardPlan struct {
	configuration           []byte
	peerConfiguration       []byte
	configurationHash       [32]byte
	deviceConfigurationHash [32]byte
	addresses               []netip.Prefix
	routes                  []netip.Prefix
	peers                   []wireGuardPeerPlan
	pendingEndpoints        bool
	relayConfig             *relay.Config
	relayFingerprint        [32]byte
	relayTopology           [32]byte
	hasRelayFallback        bool
	// mapPeers counts the map's peers when peers holds only the installed
	// ones (lazy peers).
	mapPeers int
}

// WireGuardEngine owns the encrypted userspace packet engine. The daemon
// serializes Apply and Close after stopping the map callback. mu guards the
// device configuration and the installed peers; methods that change or read
// them take it, so work that does not run under the daemon's lock (lazy peer
// activation) is serialized with Apply.
type WireGuardEngine struct {
	mu sync.Mutex
	// relayFailures outlives the devices the engine replaces: each new
	// device signals its relay connection failures into it.
	relayFailures           chan struct{}
	opener                  tunOpener
	factory                 wireGuardFactory
	listenPort              uint16
	device                  wireGuardDevice
	configurationHash       [32]byte
	deviceConfigurationHash [32]byte
	relayFingerprint        [32]byte
	relayTopology           [32]byte
	appliedRevision         uint64
	peers                   map[uint64]wireGuardPeerState
	addresses               []netip.Prefix
	routes                  []netip.Prefix
	filter                  *policyFilter
	observer                PacketObserver
	hostAddresses           func() ([]netip.Addr, error)
	clock                   func() time.Time
	relayBootstraps         uint64
	directPromotions        uint64
	relayFallbacks          uint64
	lastPromotion           time.Duration
	maximumPromotion        time.Duration
	// logger, when set, records each peer's path changes and device stops.
	logger      *slog.Logger
	credentials *relayCredentials
	// deviceStops signals a device that stopped on its own; deviceWatchStop
	// ends the current device's watcher before an intended Close.
	deviceStops     chan struct{}
	deviceWatchStop chan struct{}
	// lazy links the device's packet paths to on-demand peer installation;
	// lazySupported means the factory's devices call its hooks.
	lazy          *lazyPeers
	lazySupported bool
	lazyDisabled  bool
	lazyThreshold int
	// lazyPlanPeers holds every map peer while lazy peers are active;
	// lazyPreferred the paths chosen for peers wireguard-go does not hold.
	lazyPlanPeers map[uint64]wireGuardPeerPlan
	lazyPreferred map[uint64]netip.AddrPort
	// lazyTrafficBase holds the counters of evicted peers, which
	// wireguard-go forgets, so reported counters never go back.
	lazyTrafficBase map[uint64]peerTraffic
	// lazyResponder reads initiations to this node's key; it is reused while
	// the key is the same and cleared once its device is closed.
	lazyResponder *wghandshake.Responder
	// routed keeps the helper's subnet routes in step with the map;
	// routedStatus is what it did with them.
	routed       helperSync[[]netip.Prefix, netadmin.RoutedResult]
	routedStatus SubnetRouteStatus
	// routedGuard is what the client's own sockets stay off where they
	// follow the host's routes (underlay.FollowsRoutes).
	routedGuard []netip.Prefix
	// served keeps the router's forwarding in step with the map; servedStatus
	// is what the helper did with it.
	served       helperSync[[]networkmap.ServedSite, netadmin.ServedResult]
	servedStatus SubnetRouterStatus
	// servedExit keeps the exit node's forwarding in step with the map;
	// exitStatus is what the helper did with it.
	servedExit helperSync[[]networkmap.ServedExit, netadmin.ExitServing]
	exitStatus ExitNodeStatus
	// routerHealth measures the served Sites while the node serves any.
	routerHealth routerHealth
	// enforcementChanges signals enforced policy changes no map carried.
	enforcementChanges chan struct{}
}

// NewWireGuard constructs the Linux encrypted packet engine.
func NewWireGuard(opener tunOpener, listenPort uint16) (*WireGuardEngine, error) {
	return NewWireGuardWithObserver(opener, listenPort, nil)
}

// NewWireGuardWithObserver constructs the direct-path engine with an optional
// non-blocking plaintext-header observer.
func NewWireGuardWithObserver(
	opener tunOpener,
	listenPort uint16,
	observer PacketObserver,
) (*WireGuardEngine, error) {
	factory, err := newWireGuardFactory()
	if err != nil {
		return nil, err
	}

	return newWireGuardEngine(opener, listenPort, factory, observer)
}

func newWireGuardEngine(
	opener tunOpener,
	listenPort uint16,
	factory wireGuardFactory,
	observer PacketObserver,
) (*WireGuardEngine, error) {
	if opener == nil {
		return nil, errors.New("dataplane: tun opener is required")
	}
	if factory == nil {
		return nil, errors.New("dataplane: wireguard factory is required")
	}
	if listenPort == 0 {
		return nil, errors.New("dataplane: wireguard listen port is required")
	}

	credentials := newRelayCredentials(time.Now)
	if aware, ok := factory.(interchangeFactory); ok {
		aware.setRelayCredentials(credentials)
	}
	engine := &WireGuardEngine{
		relayFailures: make(chan struct{}, 1),
		deviceStops:   make(chan struct{}, 1),
		opener:        opener,
		factory:       factory,
		listenPort:    listenPort,
		filter:        newPolicyFilter(),
		observer:      observer,
		hostAddresses: localHostAddresses,
		clock:         time.Now,
		credentials:   credentials,
		lazyThreshold: lazyPeerThreshold,
	}
	engine.lazy = newLazyPeers(engine.installLazyPeer, engine.evictIdleLazyPeers, engine.now)
	if aware, ok := factory.(lazyFactory); ok {
		aware.setLazyPeers(engine.lazy)
		engine.lazySupported = true
	}
	return engine, nil
}

// interchangeFactory is implemented by device factories that can dial
// Interchange relays with the engine's credentials.
type interchangeFactory interface {
	setRelayCredentials(*relayCredentials)
}

// loggingFactory is implemented by device factories that can report the
// device's own errors.
type loggingFactory interface {
	setLogger(*slog.Logger)
}

// stoppingDevice reports when the device has stopped, including when it
// stopped on its own (WireGuard closes itself when the TUN cannot be read).
type stoppingDevice interface {
	Done() <-chan struct{}
}

// Apply atomically replaces the peer configuration derived from one validated
// map. Not-yet-known endpoints remain fail-closed without terminating the
// control stream.
func (e *WireGuardEngine) Apply(
	ctx context.Context,
	snapshot networkmap.Snapshot,
	privateKey NodePrivateKey,
) (State, error) {
	if e == nil || e.filter == nil {
		return StateFailed, errors.New("dataplane: packet engine is not initialized")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if snapshotHasAliases(snapshot) {
		validated, err := networkmap.ValidateAndClone(snapshot, e.clock().UTC())
		if err != nil {
			_ = e.closeLocked()
			e.filter.UpdateNetwork(networkmap.Snapshot{})
			return StateFailed, err
		}
		snapshot = validated
	}
	if err := e.filter.validateAliasTransition(snapshot); err != nil {
		_ = e.closeLocked()
		e.filter.UpdateNetwork(networkmap.Snapshot{})
		return StateFailed, err
	}
	e.filter.suspendFor(snapshot)
	e.credentials.setGrant(snapshot.Interchange)
	// Built once per map: the filter, WireGuard and the helper's routes must
	// agree, and the build costs a lookup per mesh address.
	routed := newRoutedTable(snapshot)
	state, err := e.applySnapshot(ctx, snapshot, routed, privateKey)
	if err != nil {
		e.filter.UpdateNetwork(networkmap.Snapshot{})
		return state, err
	}
	e.syncRoutedLocked(routed.allPrefixes())
	e.syncServedLocked(snapshot.Served)
	e.syncServedExitLocked(snapshot.ServedExits)
	e.filter.resume()
	return state, nil
}

func (e *WireGuardEngine) applySnapshot(
	ctx context.Context,
	snapshot networkmap.Snapshot,
	routed *routedTable,
	privateKey NodePrivateKey,
) (State, error) {
	if e == nil {
		return StateFailed, errors.New("dataplane: wireguard engine is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return StateFailed, err
	}
	if e.filter == nil {
		return StateFailed, errors.New("dataplane: packet filter is not initialized")
	}
	e.filter.updateNetwork(snapshot, routed)
	if e.observer != nil {
		e.observer.UpdateNetwork(snapshot)
	}

	plan, err := buildRoutedWireGuardPlan(snapshot, routed, privateKey, e.listenPort)
	if err != nil {
		_ = e.closeLocked()

		return StateFailed, err
	}
	defer plan.clearSecrets()

	if e.device != nil && deviceStopped(e.device) {
		// The device closed itself; a compatible map must not keep it.
		if e.logger != nil {
			e.logger.Warn("wireguard device had stopped; rebuilding it")
		}
		_ = e.closeLocked()
	}
	routesChanged := false
	if e.device != nil {
		if !slices.Equal(e.addresses, plan.addresses) || e.relayTopology != plan.relayTopology {
			_ = e.closeLocked()
		} else if !slices.Equal(e.routes, plan.routes) {
			if _, supported := e.opener.(tunRouteConfigurer); !supported {
				_ = e.closeLocked()
			} else {
				routesChanged = true
			}
		}
	}
	plan, err = e.restrictLazyPlan(plan, privateKey)
	if err != nil {
		_ = e.closeLocked()

		return StateFailed, err
	}
	if e.device != nil {
		relayChanged := e.relayFingerprint != plan.relayFingerprint
		relayReplaced := false
		peerConfigurationCompatible := e.deviceConfigurationHash == plan.deviceConfigurationHash &&
			equalPeerDataConfiguration(e.peers, plan.peers)
		if peerConfigurationCompatible && !routesChanged {
			sessionResets := changedPeerSessions(e.peers, plan.peers)
			preservePreferred := equalPeerEndpointAuthority(e.peers, plan.peers) &&
				len(sessionResets) == 0
			if e.appliedRevision == snapshot.Revision &&
				e.configurationHash == plan.configurationHash &&
				preservePreferred && !relayChanged {
				return plan.state(), nil
			}
			if relayChanged {
				if err := e.replaceRelayAuthority(plan); err != nil {
					_ = e.closeLocked()

					return StateFailed, err
				}
				relayReplaced = true
			}
			advanced, err := e.advanceCompatiblePlan(
				snapshot.Revision,
				plan,
				preservePreferred,
			)
			if err != nil {
				return StateFailed, err
			}
			if advanced {
				if err := e.resetPeerSessions(sessionResets); err != nil {
					_ = e.closeLocked()

					return StateFailed, err
				}
				e.markPeerSessionResetPending(sessionResets)
				e.relayFingerprint = plan.relayFingerprint
				e.relayTopology = plan.relayTopology

				return plan.state(), nil
			}
		}
		if relayChanged && !relayReplaced {
			if err := e.replaceRelayAuthority(plan); err != nil {
				_ = e.closeLocked()

				return StateFailed, err
			}
		}
		// The same device keys and port: change only the peers that changed,
		// so the others keep their sessions and paths. Otherwise replace all.
		peerConfiguration := plan.peerConfiguration
		var preserved, sessionResets map[uint64]struct{}
		if e.deviceConfigurationHash == plan.deviceConfigurationHash {
			peerConfiguration, preserved, sessionResets = wireGuardPeerDiff(e.peers, plan.peers)
		}
		if len(peerConfiguration) != 0 {
			if err := e.device.Configure(bytes.NewReader(peerConfiguration)); err != nil {
				_ = e.closeLocked()

				return StateFailed, errors.New("dataplane: applying wireguard peer configuration failed")
			}
		}
		if routesChanged {
			configurer, supported := e.opener.(tunRouteConfigurer)
			if !supported {
				_ = e.closeLocked()

				return StateFailed, errors.New("dataplane: live tun route update is unavailable")
			}
			if err := configurer.ConfigureTUNRoutes(ctx, netadmin.TUNConfig{
				Addresses: append([]netip.Prefix(nil), plan.addresses...),
				Routes:    append([]netip.Prefix(nil), plan.routes...),
			}); err != nil {
				_ = e.closeLocked()

				return StateFailed, fmt.Errorf("dataplane: replacing tun routes: %w", err)
			}
		}
		e.adoptPlanPreserving(snapshot.Revision, plan, preserved)
		e.markPeerSessionResetPendingIDs(sessionResets)

		return plan.state(), nil
	}

	device, err := e.openDevice(ctx, plan)
	if err != nil {
		e.forgetLazyPeers()
		return StateFailed, err
	}
	// Before Up, which dials the home region: its first failure must signal.
	if failing, ok := device.(relayFailureDevice); ok {
		failing.SetRelayFailureHook(e.signalRelayFailure)
	}
	if err := device.Configure(bytes.NewReader(plan.configuration)); err != nil {
		device.Close()
		e.forgetLazyPeers()

		return StateFailed, fmt.Errorf("dataplane: applying wireguard configuration: %w", err)
	}
	// Before Up: the first packet may be to a peer not yet installed.
	e.lazy.attach()
	if err := device.Up(); err != nil {
		e.lazy.detach()
		device.Close()
		e.forgetLazyPeers()

		return StateFailed, fmt.Errorf("dataplane: starting wireguard device: %w", err)
	}
	e.device = device
	e.watchDevice(device)
	e.adoptPlan(snapshot.Revision, plan)

	return plan.state(), nil
}

// errTUNReceiveShut means a TUN reached meshd already unable to deliver
// packets (seen on macOS); another TUN from the helper usually works.
var errTUNReceiveShut = errors.New("dataplane: tun arrived with its receive side shut")

const (
	tunOpenAttempts = 5
	tunReopenDelay  = 200 * time.Millisecond
)

// openDevice asks the helper for a TUN and wraps it in a WireGuard device,
// asking again when the TUN arrives unable to deliver packets.
func (e *WireGuardEngine) openDevice(ctx context.Context, plan wireGuardPlan) (wireGuardDevice, error) {
	for attempt := 1; ; attempt++ {
		device, err := e.openDeviceOnce(ctx, plan)
		if !errors.Is(err, errTUNReceiveShut) || attempt == tunOpenAttempts {
			return device, err
		}
		if e.logger != nil {
			e.logger.Warn("tun arrived with its receive side shut; opening another", "attempt", attempt)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(tunReopenDelay):
		}
	}
}

func (e *WireGuardEngine) openDeviceOnce(ctx context.Context, plan wireGuardPlan) (wireGuardDevice, error) {
	tunDevice, err := e.opener.OpenTUN(ctx, netadmin.TUNConfig{
		Addresses: append([]netip.Prefix{}, plan.addresses...),
		Routes:    append([]netip.Prefix{}, plan.routes...),
	})
	if err != nil {
		return nil, fmt.Errorf("dataplane: opening tun: %w", err)
	}
	if err := validateTUN(tunDevice, plan); err != nil {
		closeTUN(tunDevice)

		return nil, err
	}
	device, err := e.factory.New(ctx, tunDevice, e.filter, e.observer, plan.relayConfig)
	if err != nil {
		closeTUN(tunDevice)

		return nil, fmt.Errorf("dataplane: creating wireguard device: %w", err)
	}

	return device, nil
}

func deviceStopped(device wireGuardDevice) bool {
	stopping, ok := device.(stoppingDevice)
	if !ok {
		return false
	}
	select {
	case <-stopping.Done():
		return true
	default:
		return false
	}
}

// watchDevice signals DeviceStops when device stops without Close.
func (e *WireGuardEngine) watchDevice(device wireGuardDevice) {
	stopping, ok := device.(stoppingDevice)
	if !ok {
		return
	}
	stop := make(chan struct{})
	e.deviceWatchStop = stop
	logger := e.logger
	go func() {
		select {
		case <-stop:
			return
		case <-stopping.Done():
		}
		select {
		case <-stop: // Close closes stop before the device
			return
		default:
		}
		if logger != nil {
			logger.Warn("wireguard device stopped on its own")
		}
		select {
		case e.deviceStops <- struct{}{}:
		default: // a signal is already pending
		}
	}()
}

// DeviceStops signals when the device stopped on its own, so the daemon can
// rebuild the data plane at once instead of at the next map.
func (e *WireGuardEngine) DeviceStops() <-chan struct{} {
	if e == nil {
		return nil
	}

	return e.deviceStops
}

func (e *WireGuardEngine) replaceRelayAuthority(plan wireGuardPlan) error {
	device, supported := e.device.(relayConfiguringDevice)
	if !supported || plan.relayConfig == nil {
		return errors.New("dataplane: live relay authority update is unavailable")
	}
	if err := device.ReplaceRelayAuthority(
		plan.relayConfig.HomeRegion,
		append([]relay.Peer(nil), plan.relayConfig.Peers...),
	); err != nil {
		return errors.New("dataplane: replacing relay peer authority failed")
	}

	return nil
}

func (p wireGuardPlan) state() State {
	if len(p.peers) == 0 && p.mapPeers == 0 {
		return StateIdle
	}
	if p.pendingEndpoints {
		return StateWaitingEndpoint
	}
	if p.hasRelayFallback {
		return StateEncryptedRelay
	}

	return StateEncrypted
}

func (p *wireGuardPlan) clearSecrets() {
	if p == nil {
		return
	}
	clear(p.configuration)
	clear(p.peerConfiguration)
	if p.relayConfig != nil {
		clear(p.relayConfig.PrivateKey[:])
	}
}

// DiscoverySocket returns the active shared UDP socket generation.
func (e *WireGuardEngine) DiscoverySocket() pathdiscovery.Socket {
	if e == nil {
		return pathdiscovery.Socket{}
	}
	device, supported := e.device.(endpointDiscoveringDevice)
	if !supported {
		return pathdiscovery.Socket{}
	}

	return device.DiscoverySocket()
}

// DiscoverEndpoints performs one bounded discovery round on the exact UDP
// socket owned by the active encrypted packet engine.
func (e *WireGuardEngine) DiscoverEndpoints(
	ctx context.Context,
	scope uint64,
	servers []netip.AddrPort,
) (pathdiscovery.DiscoveryResult, error) {
	if e == nil {
		return pathdiscovery.DiscoveryResult{}, errors.New(
			"dataplane: wireguard engine is not initialized",
		)
	}
	if err := ctx.Err(); err != nil {
		return pathdiscovery.DiscoveryResult{}, err
	}
	if scope == 0 {
		return pathdiscovery.DiscoveryResult{}, pathdiscovery.ErrInvalidScope
	}
	device, supported := e.device.(endpointDiscoveringDevice)
	if !supported {
		return pathdiscovery.DiscoveryResult{}, errors.New(
			"dataplane: endpoint discovery is unavailable",
		)
	}
	socket := device.DiscoverySocket()
	if !socket.IsOpen() {
		return pathdiscovery.DiscoveryResult{}, pathdiscovery.ErrTransportClosed
	}
	hostCandidates := pathdiscovery.Set{}
	var hostErr error
	if e.hostAddresses != nil {
		addresses, err := e.hostAddresses()
		if err != nil {
			hostErr = err
		} else {
			hostCandidates, hostErr = pathdiscovery.HostCandidates(
				addresses,
				socket.Port,
				e.addresses,
			)
		}
	}
	if len(servers) == 0 {
		if hostCandidates.Len() == 0 {
			return pathdiscovery.DiscoveryResult{}, errors.Join(
				pathdiscovery.ErrNoSTUNServers,
				hostErr,
			)
		}

		return pathdiscovery.DiscoveryResult{
			Scope:      scope,
			Socket:     socket,
			Candidates: hostCandidates,
		}, nil
	}
	result, err := device.DiscoverEndpoints(
		ctx,
		scope,
		append([]netip.AddrPort(nil), servers...),
	)
	if err != nil {
		if errors.Is(err, pathdiscovery.ErrNoSTUNResponse) && hostCandidates.Len() != 0 {
			return pathdiscovery.DiscoveryResult{
				Scope:         scope,
				Socket:        socket,
				Candidates:    hostCandidates,
				FailedServers: len(servers),
			}, nil
		}

		return result, errors.Join(err, hostErr)
	}
	if result.Scope != scope || result.Socket != socket {
		return pathdiscovery.DiscoveryResult{}, pathdiscovery.ErrSocketChanged
	}
	merged, err := pathdiscovery.Merge(result.Candidates, hostCandidates)
	if err != nil {
		return pathdiscovery.DiscoveryResult{}, err
	}
	result.Candidates = merged

	return result, nil
}

// NATClassification runs one NAT classification prepared by
// PrepareNATClassification. It needs no engine lock.
type NATClassification func(context.Context) (pathdiscovery.NATReport, error)

// PrepareNATClassification snapshots what a classification of the shared
// encrypted-packet socket needs (docs/protocol/nat-classification.md). The
// caller holds the same lock it holds for Apply; the returned function then
// runs without it, so a classification never blocks map updates.
func (e *WireGuardEngine) PrepareNATClassification(
	servers []netip.AddrPort,
) (pathdiscovery.Socket, NATClassification, error) {
	if e == nil {
		return pathdiscovery.Socket{}, nil, errors.New("dataplane: wireguard engine is not initialized")
	}
	device, supported := e.device.(natClassifyingDevice)
	if !supported {
		return pathdiscovery.Socket{}, nil, errors.New("dataplane: nat classification is unavailable")
	}
	if len(servers) == 0 {
		return pathdiscovery.Socket{}, nil, pathdiscovery.ErrNoSTUNServers
	}
	socket := e.DiscoverySocket()
	if !socket.IsOpen() {
		return pathdiscovery.Socket{}, nil, pathdiscovery.ErrTransportClosed
	}
	// The socket's own addresses let the classifier recognise a host without
	// NAT; a lookup failure only costs that distinction.
	var local []netip.AddrPort
	if e.hostAddresses != nil {
		if addresses, err := e.hostAddresses(); err == nil {
			if candidates, err := pathdiscovery.HostCandidates(addresses, socket.Port, e.addresses); err == nil {
				local = candidates.Endpoints()
			}
		}
	}
	servers = append([]netip.AddrPort(nil), servers...)

	return socket, func(ctx context.Context) (pathdiscovery.NATReport, error) {
		return device.ClassifyNAT(ctx, servers, local)
	}, nil
}

// Socket returns the active generation of the shared encrypted-packet socket.
func (e *WireGuardEngine) Socket() pathdiscovery.Socket {
	if e == nil || e.device == nil {
		return pathdiscovery.Socket{}
	}
	device, supported := e.device.(peerProbingDevice)
	if !supported {
		return pathdiscovery.Socket{}
	}

	return device.Socket()
}

// SendDatagram sends one bounded peer-probe packet through the shared socket.
func (e *WireGuardEngine) SendDatagram(
	packet []byte,
	destination netip.AddrPort,
) (pathdiscovery.Socket, error) {
	if e == nil || e.device == nil {
		return pathdiscovery.Socket{}, pathdiscovery.ErrTransportClosed
	}
	device, supported := e.device.(peerProbingDevice)
	if !supported {
		return pathdiscovery.Socket{}, errors.New(
			"dataplane: peer-probe transport is unavailable",
		)
	}

	return device.SendDatagram(packet, destination)
}

// SendRelayDatagram sends one bounded peer-probe packet to a peer through its
// relay.
func (e *WireGuardEngine) SendRelayDatagram(packet []byte, peerNode [32]byte) error {
	if e == nil || e.device == nil {
		return pathdiscovery.ErrTransportClosed
	}
	device, supported := e.device.(relayProbingDevice)
	if !supported {
		return errors.New("dataplane: relay probe transport is unavailable")
	}

	return device.SendRelayDatagram(packet, peerNode)
}

// SetPeerProbeHandler atomically attaches or detaches the active session from
// shared-socket demultiplexing. A nil handler detaches.
func (e *WireGuardEngine) SetPeerProbeHandler(
	handler pathdiscovery.DatagramHandler,
) error {
	if e == nil || e.device == nil {
		if handler == nil {
			return nil
		}

		return pathdiscovery.ErrTransportClosed
	}
	device, supported := e.device.(peerProbingDevice)
	if !supported {
		return errors.New("dataplane: peer-probe handler is unavailable")
	}
	device.SetPeerProbeHandler(handler)

	return nil
}

// RelayFailures receives a signal after a relay connection of the current
// device fails; signals coalesce. The daemon re-chooses the home relay on it.
func (e *WireGuardEngine) RelayFailures() <-chan struct{} {
	if e == nil {
		return nil
	}

	return e.relayFailures
}

func (e *WireGuardEngine) signalRelayFailure() {
	select {
	case e.relayFailures <- struct{}{}:
	default: // a signal is already pending
	}
}

// RelayHealth returns non-secret authenticated connection state for home
// selection. The daemon serializes this call with Apply and Close.
func (e *WireGuardEngine) RelayHealth() relay.HealthSnapshot {
	if e == nil || e.device == nil {
		return relay.HealthSnapshot{}
	}
	device, supported := e.device.(relayManagingDevice)
	if !supported {
		return relay.HealthSnapshot{}
	}

	return device.RelayHealth()
}

// PeerPaths returns aggregate endpoint state for the installed peers. The
// daemon serializes this call with Apply, incremental updates, and Close.
func (e *WireGuardEngine) PeerPaths() PeerPathSnapshot {
	if e == nil {
		return PeerPathSnapshot{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.device == nil {
		return PeerPathSnapshot{}
	}
	snapshot := PeerPathSnapshot{
		Available:            true,
		PeerCount:            max(len(e.peers), len(e.lazyPlanPeers)),
		InactiveCount:        max(len(e.lazyPlanPeers)-len(e.peers), 0),
		RelayBootstrapCount:  e.relayBootstraps,
		DirectPromotionCount: e.directPromotions,
		RelayFallbackCount:   e.relayFallbacks,
		LastDirectPromotion:  e.lastPromotion,
		MaxDirectPromotion:   e.maximumPromotion,
	}
	snapshot.LazyActivationCount, snapshot.LazyEvictionCount, snapshot.LazyDroppedCount = e.lazy.counts()
	for _, peer := range e.peers {
		switch peer.currentPath {
		case peerPathDirect:
			snapshot.DirectCount++
		case peerPathRelay:
			snapshot.RelayCount++
		default:
			snapshot.PendingCount++
		}
	}

	return snapshot
}

// PrepareRelayRegion opens a control-authorized relay connection without
// changing packet routing. Home selection waits for RelayHealth confirmation.
func (e *WireGuardEngine) PrepareRelayRegion(regionID int) error {
	if e == nil || e.device == nil {
		return pathdiscovery.ErrTransportClosed
	}
	device, supported := e.device.(relayManagingDevice)
	if !supported {
		return errors.New("dataplane: relay preparation is unavailable")
	}

	return device.PrepareRelayRegion(regionID)
}

// SetPreferredEndpoint applies or reasserts one authenticated path selection
// for the exact peer and map revision currently installed in the tunnel engine.
func (e *WireGuardEngine) SetPreferredEndpoint(
	mapRevision uint64,
	peerID uint64,
	endpoint netip.AddrPort,
) error {
	if e == nil {
		return ErrPeerEndpointUnavailable
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.device == nil || peerID == 0 {
		return ErrPeerEndpointUnavailable
	}
	if mapRevision == 0 || mapRevision != e.appliedRevision {
		return ErrPeerEndpointGeneration
	}
	peer, exists := e.peers[peerID]
	if !exists {
		if lazy, err := e.lazyPreferredEndpoint(peerID, endpoint, false); lazy {
			return err
		}
		return ErrPeerEndpointUnavailable
	}
	// Map endpoints are authorized outright; others (CALL_ME_MAYBE,
	// peer-reflexive) reach here only after the peer answered an
	// authenticated probe from exactly that public endpoint.
	if !slices.Contains(peer.authorizedEndpoints, endpoint) && !validDatagramEndpoint(endpoint) {
		return ErrPeerEndpointUnauthorized
	}
	if peer.sessionResetPending {
		reset := wireGuardPeerPlan{
			id:           peerID,
			key:          peer.key,
			discoveryKey: peer.discoveryKey,
			baseEndpoint: endpoint.String(),
			basePath:     peerPathDirect,
			allowedIPs:   append([]netip.Prefix(nil), peer.allowedIPs...),
			lazy:         peer.lazy,
		}
		if err := e.resetPeerSessions([]wireGuardPeerPlan{reset}); err != nil {
			_ = e.closeLocked()

			return err
		}
		e.recordPathTransition(peerID, &peer, reset.basePath, reset.baseEndpoint)
		peer.currentEndpoint = reset.baseEndpoint
		peer.currentPath = reset.basePath
		peer.sessionResetPending = false
		e.peers[peerID] = peer

		return nil
	}

	return e.configurePeerEndpoint(peerID, peer, endpoint.String(), peerPathDirect, true)
}

// RestorePreferredEndpoint returns one peer to the deterministic endpoint from
// the currently installed control-plane snapshot.
func (e *WireGuardEngine) RestorePreferredEndpoint(
	mapRevision uint64,
	peerID uint64,
) error {
	if e == nil {
		return ErrPeerEndpointUnavailable
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.device == nil || peerID == 0 {
		return ErrPeerEndpointUnavailable
	}
	if mapRevision == 0 || mapRevision != e.appliedRevision {
		return ErrPeerEndpointGeneration
	}
	peer, exists := e.peers[peerID]
	if !exists {
		if lazy, err := e.lazyPreferredEndpoint(peerID, netip.AddrPort{}, true); lazy {
			return err
		}
	}
	if !exists || peer.baseEndpoint == "" {
		return ErrPeerEndpointUnavailable
	}

	return e.configurePeerEndpoint(peerID, peer, peer.baseEndpoint, peer.basePath, false)
}

// advanceCompatiblePlan adopts peer endpoint authority without replacing the
// WireGuard peers or reopening the shared UDP socket. An unchanged authority
// keeps its authenticated preferred endpoint while the selector transfers the
// remaining proof lease. Changed authority first restores the control-plane
// endpoint so stale proof cannot cross generations.
func (e *WireGuardEngine) advanceCompatiblePlan(
	revision uint64,
	plan wireGuardPlan,
	preservePreferred bool,
) (bool, error) {
	for _, peer := range plan.peers {
		installed := e.peers[peer.id]
		if preservePreferred && installed.currentPath == peerPathDirect {
			continue
		}
		if peer.baseEndpoint == "" {
			if installed.currentEndpoint != "" {
				return false, nil
			}
			continue
		}
		if err := e.configurePeerEndpoint(
			peer.id,
			installed,
			peer.baseEndpoint,
			peer.basePath,
			false,
		); err != nil {
			return false, err
		}
	}
	nextPeers := make(map[uint64]wireGuardPeerState, len(plan.peers))
	for _, peer := range plan.peers {
		installed := e.peers[peer.id]
		installed.baseEndpoint = peer.baseEndpoint
		installed.basePath = peer.basePath
		installed.authorizedEndpoints = append(
			[]netip.AddrPort(nil),
			peer.authorizedEndpoints...,
		)
		installed.allowedIPs = append([]netip.Prefix(nil), peer.allowedIPs...)
		installed.discoveryKey = peer.discoveryKey
		installed.lazy = peer.lazy
		nextPeers[peer.id] = installed
	}
	e.configurationHash = plan.configurationHash
	e.deviceConfigurationHash = plan.deviceConfigurationHash
	e.peers = nextPeers
	e.appliedRevision = revision

	return true, nil
}

func (e *WireGuardEngine) resetPeerSessions(peers []wireGuardPeerPlan) error {
	if len(peers) == 0 {
		return nil
	}
	// A changed discovery identity proves that the remote probe session was
	// replaced. Recreate only that encrypted peer so stale transport keys do
	// not wait for the tunnel handshake retry timer, while preserving the TUN,
	// shared UDP socket, routes, and unrelated peer sessions.
	var configuration bytes.Buffer
	for _, peer := range peers {
		writeWireGuardPeerKey(&configuration, peer.key)
		configuration.WriteString("remove=true\n")
		writeWireGuardPeerConfiguration(&configuration, peer)
	}
	if err := e.device.Configure(bytes.NewReader(configuration.Bytes())); err != nil {
		return errors.New("dataplane: resetting peer session failed")
	}

	return nil
}

func (e *WireGuardEngine) markPeerSessionResetPending(peers []wireGuardPeerPlan) {
	for _, peer := range peers {
		installed, exists := e.peers[peer.id]
		if !exists || installed.key != peer.key {
			continue
		}
		installed.sessionResetPending = true
		e.peers[peer.id] = installed
	}
}

// markPeerSessionResetPendingIDs is markPeerSessionResetPending for the
// peers a diff removed and added again.
func (e *WireGuardEngine) markPeerSessionResetPendingIDs(peerIDs map[uint64]struct{}) {
	for peerID := range peerIDs {
		if installed, exists := e.peers[peerID]; exists {
			installed.sessionResetPending = true
			e.peers[peerID] = installed
		}
	}
}

func (e *WireGuardEngine) configurePeerEndpoint(
	peerID uint64,
	peer wireGuardPeerState,
	endpoint string,
	path peerPath,
	reassert bool,
) error {
	if endpoint == "" || (path != peerPathDirect && path != peerPathRelay) {
		return ErrPeerEndpointUnavailable
	}
	if peer.currentEndpoint == endpoint && peer.currentPath == path && !reassert {
		return nil
	}
	var configuration bytes.Buffer
	configuration.WriteString("public_key=")
	var encodedPublic [64]byte
	hex.Encode(encodedPublic[:], peer.key[:])
	configuration.Write(encodedPublic[:])
	configuration.WriteString("\nupdate_only=true\nendpoint=")
	configuration.WriteString(endpoint)
	configuration.WriteByte('\n')
	writeWireGuardKeepalive(&configuration, path, peer.lazy)
	if err := e.device.Configure(bytes.NewReader(configuration.Bytes())); err != nil {
		_ = e.closeLocked()

		return errors.New("dataplane: applying peer endpoint failed")
	}
	e.recordPathTransition(peerID, &peer, path, endpoint)
	peer.currentEndpoint = endpoint
	peer.currentPath = path
	e.peers[peerID] = peer

	return nil
}

func (e *WireGuardEngine) adoptPlan(revision uint64, plan wireGuardPlan) {
	e.adoptPlanPreserving(revision, plan, nil)
}

// adoptPlanPreserving records plan as installed. Peers in preserved were left
// untouched in the device, so they keep their current path and timers.
func (e *WireGuardEngine) adoptPlanPreserving(revision uint64, plan wireGuardPlan, preserved map[uint64]struct{}) {
	previous := e.peers
	e.configurationHash = plan.configurationHash
	e.deviceConfigurationHash = plan.deviceConfigurationHash
	e.relayFingerprint = plan.relayFingerprint
	e.relayTopology = plan.relayTopology
	e.appliedRevision = revision
	e.addresses = append([]netip.Prefix(nil), plan.addresses...)
	e.routes = append([]netip.Prefix(nil), plan.routes...)
	e.peers = make(map[uint64]wireGuardPeerState, len(plan.peers))
	now := e.now()
	for _, peer := range plan.peers {
		state := wireGuardPeerState{
			key:                 peer.key,
			discoveryKey:        peer.discoveryKey,
			baseEndpoint:        peer.baseEndpoint,
			basePath:            peer.basePath,
			currentEndpoint:     peer.baseEndpoint,
			currentPath:         peer.basePath,
			authorizedEndpoints: append([]netip.AddrPort(nil), peer.authorizedEndpoints...),
			allowedIPs:          append([]netip.Prefix(nil), peer.allowedIPs...),
			lazy:                peer.lazy,
		}
		if _, kept := preserved[peer.id]; kept {
			if installed, ok := previous[peer.id]; ok {
				state.currentEndpoint, state.currentPath = installed.currentEndpoint, installed.currentPath
				state.relayStartedAt, state.sessionResetPending = installed.relayStartedAt, installed.sessionResetPending
				e.peers[peer.id] = state
				continue
			}
		}
		if state.basePath == peerPathRelay {
			state.relayStartedAt = now
			e.relayBootstraps++
		}
		e.peers[peer.id] = state
	}
}

// wireGuardPeerDiff returns the UAPI configuration that turns the installed
// peers into the planned ones without replace_peers: every installed key the
// plan no longer has is removed explicitly, new and changed peers are written
// in full, and a peer whose discovery identity changed is removed and added
// again to drop its session. It also returns the peers left untouched and the
// peers whose sessions were reset.
func wireGuardPeerDiff(
	current map[uint64]wireGuardPeerState,
	planned []wireGuardPeerPlan,
) ([]byte, map[uint64]struct{}, map[uint64]struct{}) {
	plannedKeys := make(map[[32]byte]struct{}, len(planned))
	for _, peer := range planned {
		plannedKeys[peer.key] = struct{}{}
	}
	removed := make([][32]byte, 0)
	for _, installed := range current {
		if _, kept := plannedKeys[installed.key]; !kept {
			removed = append(removed, installed.key)
		}
	}
	slices.SortFunc(removed, func(left, right [32]byte) int { return bytes.Compare(left[:], right[:]) })
	var configuration bytes.Buffer
	for _, key := range removed {
		writeWireGuardPeerKey(&configuration, key)
		configuration.WriteString("remove=true\n")
	}
	preserved := make(map[uint64]struct{}, len(planned))
	resets := make(map[uint64]struct{})
	for _, peer := range planned {
		installed, exists := current[peer.id]
		sameKey := exists && installed.key == peer.key
		if sameKey && installed.discoveryKey == peer.discoveryKey && installed.baseEndpoint == peer.baseEndpoint &&
			installed.basePath == peer.basePath && installed.lazy == peer.lazy &&
			slices.Equal(installed.allowedIPs, peer.allowedIPs) {
			preserved[peer.id] = struct{}{}
			continue
		}
		if sameKey && installed.discoveryKey != peer.discoveryKey {
			writeWireGuardPeerKey(&configuration, peer.key)
			configuration.WriteString("remove=true\n")
			resets[peer.id] = struct{}{}
		}
		writeWireGuardPeerConfiguration(&configuration, peer)
	}
	return configuration.Bytes(), preserved, resets
}

// SetLogger records each peer's path changes (direct, relay) with the peer's
// numeric ID and a short digest of the endpoint, never the address, and the
// WireGuard device's own errors. Call it before the first Apply.
func (e *WireGuardEngine) SetLogger(logger *slog.Logger) {
	if e == nil {
		return
	}
	e.logger = logger
	if aware, ok := e.factory.(loggingFactory); ok && logger != nil {
		aware.setLogger(logger.With("source", "wireguard"))
	}
}

func (e *WireGuardEngine) recordPathTransition(peerID uint64, peer *wireGuardPeerState, next peerPath, endpoint string) {
	if e == nil || peer == nil {
		return
	}
	if e.logger != nil && (peer.currentPath != next || peer.currentEndpoint != endpoint) {
		e.logger.Info("peer path changed", "peer", peerID, "from", peer.currentPath.String(),
			"to", next.String(), "endpoint", endpointDigest(endpoint))
	}
	if peer.currentPath == next {
		return
	}
	now := e.now()
	switch {
	case peer.currentPath == peerPathRelay && next == peerPathDirect:
		e.directPromotions++
		if !peer.relayStartedAt.IsZero() {
			duration := now.Sub(peer.relayStartedAt)
			if duration < 0 {
				duration = 0
			}
			e.lastPromotion = duration
			if duration > e.maximumPromotion {
				e.maximumPromotion = duration
			}
		}
		peer.relayStartedAt = time.Time{}
	case peer.currentPath == peerPathDirect && next == peerPathRelay:
		e.relayFallbacks++
		peer.relayStartedAt = now
	case next == peerPathRelay:
		e.relayBootstraps++
		peer.relayStartedAt = now
	}
}

func (e *WireGuardEngine) now() time.Time {
	if e != nil && e.clock != nil {
		return e.clock()
	}

	return time.Now()
}

// Close destroys the userspace device, which closes the TUN descriptor and
// causes Linux to remove the non-persistent interface and its routes.
func (e *WireGuardEngine) Close() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.closeLocked()
}

func (e *WireGuardEngine) closeLocked() error {
	if e == nil {
		return nil
	}
	e.resetRoutedLocked()
	e.resetServedLocked()
	e.resetServedExitLocked()
	if e.device == nil {
		e.forgetLazyPeers()
		return nil
	}
	if e.deviceWatchStop != nil {
		close(e.deviceWatchStop)
		e.deviceWatchStop = nil
	}
	// Release the packet paths waiting on activation first: closing the
	// device waits for them.
	e.lazy.reset()
	e.device.Close()
	e.forgetLazyPeers()
	e.device = nil
	e.configurationHash = [32]byte{}
	e.deviceConfigurationHash = [32]byte{}
	e.relayFingerprint = [32]byte{}
	e.relayTopology = [32]byte{}
	e.appliedRevision = 0
	e.peers = nil
	e.addresses = nil
	e.routes = nil

	return nil
}

// closeTUN releases a TUN the factory did not take; closing twice is safe.
func closeTUN(tunDevice netadmin.TUN) {
	if tunDevice.File != nil {
		_ = tunDevice.File.Close()
	}
	if tunDevice.Device != nil {
		_ = tunDevice.Device.Close()
	}
}

func validateTUN(tunDevice netadmin.TUN, plan wireGuardPlan) error {
	if (tunDevice.File == nil) == (tunDevice.Device == nil) || tunDevice.Name == "" || tunDevice.MTU < 1280 ||
		tunDevice.MTU > 9000 {
		return errors.New("dataplane: helper returned invalid tun metadata")
	}
	if !slices.Equal(tunDevice.Addresses, plan.addresses) ||
		!slices.Equal(tunDevice.Routes, plan.routes) {
		return errors.New("dataplane: helper network configuration does not match the signed map")
	}

	return nil
}

func buildWireGuardPlan(
	snapshot networkmap.Snapshot,
	privateKey NodePrivateKey,
	listenPort uint16,
) (wireGuardPlan, error) {
	return buildRoutedWireGuardPlan(snapshot, newRoutedTable(snapshot), privateKey, listenPort)
}

func buildRoutedWireGuardPlan(
	snapshot networkmap.Snapshot,
	routed *routedTable,
	privateKey NodePrivateKey,
	listenPort uint16,
) (wireGuardPlan, error) {
	if snapshot.Revision == 0 || snapshot.Self.ID == 0 {
		return wireGuardPlan{}, errors.New("dataplane: snapshot identity is invalid")
	}
	if len(snapshot.Peers) > maxWireGuardPeers {
		return wireGuardPlan{}, errors.New("dataplane: peer count is outside the allowed range")
	}
	var zeroPrivateKey NodePrivateKey
	if subtle.ConstantTimeCompare(privateKey[:], zeroPrivateKey[:]) == 1 {
		return wireGuardPlan{}, errors.New("dataplane: node private key is zero")
	}
	selfKey, err := parseNodePublicKey(snapshot.Self.PublicKey)
	if err != nil {
		return wireGuardPlan{}, errors.New("dataplane: self public key is invalid")
	}
	derivedPrivate, err := ecdh.X25519().NewPrivateKey(privateKey[:])
	if err != nil || subtle.ConstantTimeCompare(derivedPrivate.PublicKey().Bytes(), selfKey[:]) != 1 {
		return wireGuardPlan{}, errors.New("dataplane: private key does not match the signed self node")
	}
	allSelfAddresses, err := validateHostPrefixes("self address", snapshot.Self.Addresses, 8)
	if err != nil || len(allSelfAddresses) == 0 {
		return wireGuardPlan{}, errors.New("dataplane: self addresses are invalid")
	}

	plannedPeers := make([]wireGuardPeerPlan, 0, len(snapshot.Peers))
	relayConfig, err := buildRelayConfig(snapshot, privateKey, selfKey)
	if err != nil {
		return wireGuardPlan{}, err
	}
	relayRegions := make(map[[32]byte]int)
	if relayConfig != nil {
		for _, peer := range relayConfig.Peers {
			relayRegions[[32]byte(peer.Key)] = peer.HomeRegion
		}
	}
	selectedSelfAddresses := append([]netip.Prefix{}, allSelfAddresses...)
	// The primary router of each served Site also carries its prefixes; the
	// packet filter admits them only once the helper installed them.
	routedPrefixes := routed.servedPrefixes()
	allRoutes := make([]netip.Prefix, 0, len(snapshot.Peers))
	seenKeys := make(map[[32]byte]struct{}, len(snapshot.Peers))
	seenIDs := map[uint64]struct{}{snapshot.Self.ID: {}}
	pendingEndpoints := false
	for _, peer := range snapshot.Peers {
		if peer.ID == 0 || peer.Expired || !peer.MachineAuthorized {
			return wireGuardPlan{}, errors.New("dataplane: peer is not authorized")
		}
		if _, exists := seenIDs[peer.ID]; exists {
			return wireGuardPlan{}, errors.New("dataplane: peer id is duplicated")
		}
		seenIDs[peer.ID] = struct{}{}
		peerKey, err := parseNodePublicKey(peer.PublicKey)
		if err != nil || peerKey == selfKey {
			return wireGuardPlan{}, errors.New("dataplane: peer public key is invalid")
		}
		if _, exists := seenKeys[peerKey]; exists {
			return wireGuardPlan{}, errors.New("dataplane: peer public key is duplicated")
		}
		seenKeys[peerKey] = struct{}{}
		peerAddresses, err := validateHostPrefixes("peer address", peer.Addresses, 8)
		if err != nil || len(peerAddresses) == 0 {
			return wireGuardPlan{}, errors.New("dataplane: peer addresses are invalid")
		}
		allowedIPs, err := validateHostPrefixes("peer route", peer.AllowedIPs, 32)
		if err != nil || len(allowedIPs) == 0 {
			return wireGuardPlan{}, errors.New("dataplane: peer routes are invalid")
		}
		peerAddressSet := make(map[netip.Prefix]struct{}, len(peerAddresses))
		for _, prefix := range peerAddresses {
			peerAddressSet[prefix] = struct{}{}
		}
		allowedIPs = slices.DeleteFunc(allowedIPs, func(prefix netip.Prefix) bool {
			_, authorized := peerAddressSet[prefix]

			return !authorized
		})
		if len(allowedIPs) == 0 {
			return wireGuardPlan{}, errors.New("dataplane: peer has no direct host route")
		}
		directRoutes := len(allowedIPs)
		allowedIPs = append(allowedIPs, routedPrefixes[peer.ID]...)
		if len(peer.Endpoints) > maxWireGuardPeerEndpoints {
			return wireGuardPlan{}, errors.New("dataplane: peer endpoint count exceeds limit")
		}
		authorizedEndpoints := validPeerEndpoints(peer.Endpoints)
		if len(authorizedEndpoints) != len(peer.Endpoints) {
			return wireGuardPlan{}, errors.New("dataplane: peer endpoints are invalid")
		}
		directEndpoint, err := selectEndpoint(peer.Endpoints)
		if err != nil {
			return wireGuardPlan{}, err
		}
		baseEndpoint := ""
		basePath := peerPathPending
		if regionID := relayRegions[peerKey]; regionID != 0 {
			baseEndpoint = formatRelayEndpoint(regionID, relay.Key(peerKey))
			basePath = peerPathRelay
		} else if directEndpoint.IsValid() {
			baseEndpoint = directEndpoint.String()
			basePath = peerPathDirect
		}
		if baseEndpoint == "" {
			pendingEndpoints = true
		}
		plannedPeers = append(plannedPeers, wireGuardPeerPlan{
			id:                  peer.ID,
			key:                 peerKey,
			discoveryKey:        peer.DiscoveryKey,
			baseEndpoint:        baseEndpoint,
			basePath:            basePath,
			authorizedEndpoints: authorizedEndpoints,
			allowedIPs:          allowedIPs,
		})
		allRoutes = append(allRoutes, allowedIPs[:directRoutes]...)
	}
	if len(allRoutes) > maxWireGuardAllowedIPs {
		return wireGuardPlan{}, errors.New("dataplane: peer address count is outside the allowed range")
	}
	addresses := deduplicatePrefixes(selectedSelfAddresses)
	if len(addresses) == 0 {
		return wireGuardPlan{}, errors.New("dataplane: policy-selected self addresses are invalid")
	}
	peerPrefixes, err := uniquePrefixes(allRoutes)
	if err != nil {
		return wireGuardPlan{}, err
	}
	// Exact aggregation: the routes cover the peer addresses and nothing else.
	routes := prefixset.Summarize(peerPrefixes)
	if len(routes) > maxWireGuardRoutes {
		return wireGuardPlan{}, errors.New("dataplane: route count is outside the allowed range")
	}
	for _, route := range routes {
		if slices.ContainsFunc(addresses, route.Overlaps) {
			return wireGuardPlan{}, errors.New("dataplane: peer route overlaps a self address")
		}
	}
	slices.SortFunc(plannedPeers, func(left, right wireGuardPeerPlan) int {
		return bytes.Compare(left.key[:], right.key[:])
	})

	var configuration bytes.Buffer
	configuration.WriteString("private_key=")
	var encodedPrivate [64]byte
	hex.Encode(encodedPrivate[:], privateKey[:])
	configuration.Write(encodedPrivate[:])
	clear(encodedPrivate[:])
	configuration.WriteByte('\n')
	configuration.WriteString("listen_port=")
	configuration.Write(strconv.AppendUint(nil, uint64(listenPort), 10))
	configuration.WriteByte('\n')
	deviceConfigurationHash := sha256.Sum256(configuration.Bytes())
	var peerConfiguration bytes.Buffer
	peerConfiguration.WriteString("replace_peers=true\n")
	for _, peer := range plannedPeers {
		writeWireGuardPeerConfiguration(&peerConfiguration, peer)
	}
	configuration.Write(peerConfiguration.Bytes())
	encoded := configuration.Bytes()
	encodedPeers := peerConfiguration.Bytes()

	plan := wireGuardPlan{
		configuration:           encoded,
		peerConfiguration:       encodedPeers,
		configurationHash:       sha256.Sum256(encoded),
		deviceConfigurationHash: deviceConfigurationHash,
		addresses:               addresses,
		routes:                  routes,
		peers:                   plannedPeers,
		pendingEndpoints:        pendingEndpoints,
		relayConfig:             relayConfig,
		hasRelayFallback:        relayConfig != nil && len(relayConfig.Peers) != 0,
	}
	if relayConfig != nil {
		plan.relayFingerprint = relay.Fingerprint(*relayConfig)
		plan.relayTopology = relay.TopologyFingerprint(*relayConfig)
	}

	return plan, nil
}

func writeWireGuardPeerConfiguration(
	configuration *bytes.Buffer,
	peer wireGuardPeerPlan,
) {
	writeWireGuardPeerKey(configuration, peer.key)
	configuration.WriteString("protocol_version=1\n")
	if peer.baseEndpoint != "" {
		configuration.WriteString("endpoint=")
		configuration.WriteString(peer.baseEndpoint)
		configuration.WriteByte('\n')
	}
	writeWireGuardKeepalive(configuration, peer.basePath, peer.lazy)
	configuration.WriteString("replace_allowed_ips=true\n")
	for _, allowedIP := range peer.allowedIPs {
		configuration.WriteString("allowed_ip=")
		configuration.WriteString(allowedIP.String())
		configuration.WriteByte('\n')
	}
}

func writeWireGuardKeepalive(configuration *bytes.Buffer, path peerPath, lazy bool) {
	configuration.WriteString("persistent_keepalive_interval=")
	if path == peerPathDirect && !lazy {
		configuration.WriteString(strconv.Itoa(directPathKeepaliveSeconds))
	} else {
		configuration.WriteByte('0')
	}
	configuration.WriteByte('\n')
}

func writeWireGuardPeerKey(configuration *bytes.Buffer, key [32]byte) {
	configuration.WriteString("public_key=")
	var encodedPublic [64]byte
	hex.Encode(encodedPublic[:], key[:])
	configuration.Write(encodedPublic[:])
	configuration.WriteByte('\n')
}

func equalPeerEndpointAuthority(
	current map[uint64]wireGuardPeerState,
	planned []wireGuardPeerPlan,
) bool {
	if len(current) != len(planned) {
		return false
	}
	for _, peer := range planned {
		installed, exists := current[peer.id]
		if !exists || installed.key != peer.key ||
			installed.discoveryKey != peer.discoveryKey ||
			!slices.Equal(installed.authorizedEndpoints, peer.authorizedEndpoints) {
			return false
		}
	}

	return true
}

func equalPeerDataConfiguration(
	current map[uint64]wireGuardPeerState,
	planned []wireGuardPeerPlan,
) bool {
	if len(current) != len(planned) {
		return false
	}
	for _, peer := range planned {
		installed, exists := current[peer.id]
		if !exists || installed.key != peer.key || installed.lazy != peer.lazy ||
			!slices.Equal(installed.allowedIPs, peer.allowedIPs) {
			return false
		}
	}

	return true
}

func changedPeerSessions(
	current map[uint64]wireGuardPeerState,
	planned []wireGuardPeerPlan,
) []wireGuardPeerPlan {
	changed := make([]wireGuardPeerPlan, 0)
	for _, peer := range planned {
		installed, exists := current[peer.id]
		if exists && installed.key == peer.key &&
			installed.discoveryKey != peer.discoveryKey {
			changed = append(changed, peer)
		}
	}

	return changed
}

func buildRelayConfig(
	snapshot networkmap.Snapshot,
	privateKey NodePrivateKey,
	publicKey [32]byte,
) (*relay.Config, error) {
	if len(snapshot.Relays) == 0 {
		return nil, nil
	}
	homeRegion := selectHomeRelay(snapshot.Relays, snapshot.Self.HomeRelay)
	_, homeExists := usableRelayRegion(snapshot.Relays, homeRegion)
	if !homeExists {
		return nil, nil
	}
	config := relay.Config{
		PrivateKey: relay.Key(privateKey),
		PublicKey:  relay.Key(publicKey),
		HomeRegion: homeRegion,
		Regions:    make(map[int]relay.Region, len(snapshot.Relays)),
		Peers:      make([]relay.Peer, 0, len(snapshot.Peers)),
	}
	regionIDs := make([]int, 0, len(snapshot.Relays))
	for regionID := range snapshot.Relays {
		regionIDs = append(regionIDs, regionID)
	}
	slices.Sort(regionIDs)
	for _, regionID := range regionIDs {
		if region, exists := usableRelayRegion(snapshot.Relays, regionID); exists {
			config.Regions[regionID] = region
		}
	}
	for _, node := range snapshot.Peers {
		peerRegion := selectHomeRelay(snapshot.Relays, node.HomeRelay)
		if node.HomeRelay <= 0 {
			peerRegion = homeRegion
		}
		region, exists := usableRelayRegion(snapshot.Relays, peerRegion)
		if !exists {
			continue
		}
		key, err := parseNodePublicKey(node.PublicKey)
		if err != nil {
			return nil, errors.New("dataplane: relay peer key is invalid")
		}
		address := firstNodeAddress(node.Addresses)
		if !address.IsValid() {
			return nil, errors.New("dataplane: relay peer address is invalid")
		}
		config.Regions[region.ID] = region
		config.Peers = append(config.Peers, relay.Peer{
			Key:        relay.Key(key),
			HomeRegion: peerRegion,
			Address:    address,
		})
	}
	validated, err := relay.Validate(config)
	clear(config.PrivateKey[:])
	if err != nil {
		return nil, fmt.Errorf("dataplane: compiling relay authority: %w", err)
	}

	return &validated, nil
}

// selectHomeRelay preserves a usable control preference and otherwise chooses
// the lowest usable signed region. The deterministic fallback keeps peers on
// the same rendezvous region until control echoes a measured preference.
func selectHomeRelay(regions map[int]networkmap.RelayRegion, preferred int) int {
	if _, exists := usableRelayRegion(regions, preferred); exists {
		return preferred
	}
	regionIDs := make([]int, 0, len(regions))
	for regionID := range regions {
		regionIDs = append(regionIDs, regionID)
	}
	slices.Sort(regionIDs)
	for _, regionID := range regionIDs {
		if _, exists := usableRelayRegion(regions, regionID); exists {
			return regionID
		}
	}

	return 0
}

func usableRelayRegion(
	regions map[int]networkmap.RelayRegion,
	regionID int,
) (relay.Region, bool) {
	region, exists := regions[regionID]
	if !exists || region.ID != regionID {
		return relay.Region{}, false
	}
	converted := relay.Region{
		ID:    region.ID,
		Nodes: make([]relay.Node, 0, len(region.Nodes)),
	}
	for _, node := range region.Nodes {
		// Only Interchange nodes, which carry a relay key, can be dialled.
		if node.STUNOnly || node.RelayKey == ([32]byte{}) {
			continue
		}
		port := node.RelayPort
		if port == 0 {
			port = 443
		}
		converted.Nodes = append(converted.Nodes, relay.Node{
			Name:     node.Name,
			HostName: node.HostName,
			CertName: node.CertName,
			IPv4:     node.IPv4,
			IPv6:     node.IPv6,
			Port:     uint16(port),
			RelayKey: node.RelayKey,
			UDPPort:  uint16(node.UDPPort), //nolint:gosec // validated 0..65535
		})
	}

	return converted, len(converted.Nodes) != 0
}

func firstNodeAddress(prefixes []netip.Prefix) netip.Addr {
	addresses := make([]netip.Addr, 0, len(prefixes))
	for _, prefix := range prefixes {
		if prefix.IsValid() {
			addresses = append(addresses, prefix.Addr().Unmap())
		}
	}
	if len(addresses) == 0 {
		return netip.Addr{}
	}
	slices.SortFunc(addresses, netip.Addr.Compare)

	return addresses[0]
}

func validPeerEndpoints(endpoints []netip.AddrPort) []netip.AddrPort {
	valid := make([]netip.AddrPort, 0, len(endpoints))
	for _, endpoint := range endpoints {
		address := endpoint.Addr()
		if endpoint.IsValid() && !address.Is4In6() &&
			address.IsGlobalUnicast() && !address.IsLinkLocalUnicast() &&
			endpoint.Port() != 0 {
			valid = append(valid, endpoint)
		}
	}
	slices.SortFunc(valid, func(left, right netip.AddrPort) int {
		return left.Compare(right)
	})

	return slices.Compact(valid)
}

func parseNodePublicKey(value string) ([32]byte, error) {
	const prefix = "nodekey:"
	if len(value) != len(prefix)+64 || !strings.HasPrefix(value, prefix) || value != strings.ToLower(value) {
		return [32]byte{}, errors.New("invalid node public key")
	}
	var decoded [32]byte
	if _, err := hex.Decode(decoded[:], []byte(value[len(prefix):])); err != nil {
		return [32]byte{}, errors.New("invalid node public key")
	}
	if decoded == [32]byte{} {
		return [32]byte{}, errors.New("invalid node public key")
	}

	return decoded, nil
}

func validateHostPrefixes(
	kind string,
	prefixes []netip.Prefix,
	maximum int,
) ([]netip.Prefix, error) {
	if len(prefixes) > maximum {
		return nil, fmt.Errorf("dataplane: too many %ss", kind)
	}
	validated := append([]netip.Prefix(nil), prefixes...)
	for index, prefix := range validated {
		address := prefix.Addr().Unmap()
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr() != address ||
			prefix.Bits() != address.BitLen() || !address.IsGlobalUnicast() ||
			address.IsLinkLocalUnicast() {
			return nil, fmt.Errorf("dataplane: %s must be a canonical host prefix", kind)
		}
		validated[index] = netip.PrefixFrom(address, address.BitLen())
	}

	return uniquePrefixes(validated)
}

func uniquePrefixes(prefixes []netip.Prefix) ([]netip.Prefix, error) {
	values := append([]netip.Prefix(nil), prefixes...)
	slices.SortFunc(values, func(left, right netip.Prefix) int {
		return left.Addr().Compare(right.Addr())
	})
	for index := 1; index < len(values); index++ {
		if values[index] == values[index-1] {
			return nil, errors.New("dataplane: route or address is duplicated")
		}
	}

	return values, nil
}

func selectEndpoint(endpoints []netip.AddrPort) (netip.AddrPort, error) {
	if len(endpoints) == 0 {
		return netip.AddrPort{}, nil
	}
	valid := make([]netip.AddrPort, 0, len(endpoints))
	for _, endpoint := range endpoints {
		address := endpoint.Addr()
		if !endpoint.IsValid() || address.Is4In6() || !address.IsGlobalUnicast() ||
			address.IsLinkLocalUnicast() || endpoint.Port() == 0 {
			continue
		}
		valid = append(valid, endpoint)
	}
	if len(valid) == 0 {
		return netip.AddrPort{}, errors.New("dataplane: peer endpoints are invalid")
	}
	slices.SortFunc(valid, func(left, right netip.AddrPort) int {
		leftPrivate := left.Addr().IsPrivate()
		rightPrivate := right.Addr().IsPrivate()
		if leftPrivate != rightPrivate {
			if leftPrivate {
				return 1
			}

			return -1
		}

		return left.Compare(right)
	})

	return valid[0], nil
}

func deduplicatePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	values := append([]netip.Prefix(nil), prefixes...)
	slices.SortFunc(values, func(left, right netip.Prefix) int {
		return left.Addr().Compare(right.Addr())
	})
	return slices.Compact(values)
}
