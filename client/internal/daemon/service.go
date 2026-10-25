// Package daemon coordinates profile state and the future tunnel engine boundary.
package daemon

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/big"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"meshtransit.net/shared/disco"
	"meshtransit.net/shared/key"

	"meshtransit.net/client/internal/captive"
	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/dnsconfig"
	"meshtransit.net/client/internal/identity"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/pathdiscovery"
	"meshtransit.net/client/internal/peerprobe"
	"meshtransit.net/client/internal/profile"
	"meshtransit.net/client/internal/relay"
	"meshtransit.net/client/internal/routesettings"
	"meshtransit.net/client/internal/runtimehealth"
	"meshtransit.net/client/internal/version"
)

var (
	// ErrControlProbe indicates that the remote compatibility check failed.
	ErrControlProbe = errors.New("daemon: control probe failed")
	// ErrControlTrust indicates that control-key trust could not be established.
	ErrControlTrust = errors.New("daemon: control trust failed")
	// ErrControlNotTrusted indicates that registration was attempted before pinning.
	ErrControlNotTrusted = errors.New("daemon: control key is not trusted")
	// ErrRegistration indicates that node registration failed.
	ErrRegistration = errors.New("daemon: registration failed")
	// ErrNodeKeyRotation indicates that an authenticated Node-key transition failed.
	ErrNodeKeyRotation = errors.New("daemon: node key rotation failed")
	// ErrAuthorizationPending indicates that browser authorization is not complete yet.
	ErrAuthorizationPending = errors.New("daemon: browser authorization is pending")
	// ErrNoPendingAuthorization indicates that there is no browser flow to complete.
	ErrNoPendingAuthorization = errors.New("daemon: no pending browser authorization")
	// ErrServiceRunning indicates that this service already owns an active supervisor.
	ErrServiceRunning  = errors.New("daemon: service supervisor is already running")
	errRuntimeRecovery = errors.New("daemon: runtime recovery required")
	// errDataPlaneStopped ends a session whose data plane device stopped on
	// its own; the session then rebuilds it like any runtime failure.
	errDataPlaneStopped = errors.New("daemon: data plane device stopped")
)

const (
	// StateOffline means the active profile is not synchronized with control.
	StateOffline = "offline"
	// StateOnline means the active profile has a synchronized control session.
	// DataPlane and DNS report forwarding and resolver readiness independently.
	StateOnline = "online"
	// DataPlanePending makes the incomplete data-plane state explicit to callers.
	DataPlanePending = "not_implemented"
	// DNSInactive means the active map does not currently configure host DNS.
	DNSInactive = "inactive"
	// DNSPending means a DNS map was validated but no host implementation is enabled.
	DNSPending = "not_implemented"
	// DNSConfigured means the local resolver and host DNS configuration are active.
	DNSConfigured = "configured"
	// DNSFailed means a DNS transaction failed closed.
	DNSFailed = "failed"
	// ControlTrustUnconfigured means no per-profile control key is pinned.
	ControlTrustUnconfigured = "unconfigured"
	// ControlTrustPinned means the active profile has a persisted control key pin.
	ControlTrustPinned = "pinned"
	// RegistrationUnregistered means the profile has not been authorized.
	RegistrationUnregistered = "unregistered"
	// RegistrationPending means a browser authorization URL is awaiting completion.
	RegistrationPending = "authorization_required"
	// RegistrationRegistered means the last registration response authorized the node.
	RegistrationRegistered = "registered"
	// ControlSessionInactive means no registered active profile can be synchronized.
	ControlSessionInactive = "inactive"
	// ControlSessionConnecting means a registered profile is opening its map stream.
	ControlSessionConnecting = "connecting"
	// ControlSessionSynchronized means a validated snapshot has been published.
	ControlSessionSynchronized = "synchronized"
	// ControlSessionReconnecting means the control connection was lost after
	// synchronizing: the last map and the tunnels stay up while it reconnects.
	ControlSessionReconnecting = "reconnecting"
	// ControlSessionBlocked means a permanent trust, registration, or map error stopped sync.
	ControlSessionBlocked = "blocked"
	// ControlSessionSuspended means an administrator suspended this Device; it
	// keeps its identity and retries until the Device is resumed.
	ControlSessionSuspended = "suspended"

	completionPollTimeout  = 3 * time.Second
	rotationPersistTimeout = 5 * time.Second
	dnsCleanupTimeout      = 5 * time.Second
	minRuntimeRetry        = time.Second
	maxRuntimeRetry        = 30 * time.Second
	suspendedRetry         = 30 * time.Second
	// A Device resumed soon after it was suspended reconnects within a few
	// seconds; a long suspension costs Core one attempt every suspendedRetry.
	suspendedRetryFast    = 3 * time.Second
	suspendedRetryMedium  = 10 * time.Second
	suspendedFastPeriod   = time.Minute
	suspendedMediumPeriod = 5 * time.Minute
	runtimeRetryReset     = 30 * time.Second
	// maxDataPlaneStopRetry caps the backoff after the data plane device
	// stopped on its own: rebuilding it is local, and the window that stops
	// it (boot, a network change) ends within seconds.
	maxDataPlaneStopRetry = 4 * time.Second
	// maxQuickDataPlaneStops is how many quick stops in a row keep the short
	// backoff (capRetryForCause).
	maxQuickDataPlaneStops = 3
	minEndpointRefresh     = 20 * time.Second
	maxEndpointRefresh     = 26 * time.Second
	// minEventRefreshSpacing spaces discovery rounds that a network change or
	// a relay failure starts (port mapping and cloud address changes are
	// rare, local, and published at once):
	// an event after a quiet spell runs a round at once, and events sooner
	// than this after the last event's round share one round when it ends,
	// so a flapping interface or relay does not send STUN in a loop.
	minEventRefreshSpacing = 5 * time.Second
	relayPreparationPoll   = time.Second
	relayPreparationWait   = 1500 * time.Millisecond
	relayPreparationTick   = 50 * time.Millisecond
)

// Status is the daemon-owned status model before it is mapped to a wire format.
type Status struct {
	Build     version.Info
	State     string
	DataPlane string
	DNS       string
	// DNSError is why the host refused the last map's DNS, while DNS is
	// failed (TD-CLI-31).
	DNSError           string
	ActiveProfileID    string
	ProfileCount       int
	CompatibilityNote  string
	ControlTrust       string
	Registration       string
	ControlFingerprint string
	ControlSession     string
	NetmapRevision     uint64
	NetworkName        string
	SelfAddresses      []string
	// DeviceExpiresAt is the Device's key expiry in the current map; zero
	// before a map arrives.
	DeviceExpiresAt time.Time
	// DeviceExpiry classifies DeviceExpiresAt (DeviceExpiryState).
	DeviceExpiry    string
	PeerCount       int
	PolicyRuleCount int
	PeerPaths       dataplane.PeerPathSnapshot
	SubnetRoutes    dataplane.SubnetRouteStatus
	// RouteSites is the router each Site's traffic goes to.
	RouteSites   []RouteSiteView
	SubnetRouter dataplane.SubnetRouterStatus
	// ExitNode is how the node forwards as an exit node.
	ExitNode dataplane.ExitNodeStatus
	// Exit is the exit node this node sends its Internet traffic to, nil
	// when it uses none, and ExitRoute what the helper does with it.
	Exit      *ExitView
	ExitRoute dataplane.ExitRouteStatus
	// Captive is a captive portal found while the host uses an exit node.
	Captive         CaptiveView
	PathProbes      PathProbeStatus
	Relay           relay.HealthSnapshot
	NetworkChanges  NetworkChangeStatus
	RuntimeRecovery RuntimeRecoveryStatus
	Runtime         runtimehealth.Snapshot
	NAT             NATStatus
	PortMapping     PortMappingStatus
	Cloud           CloudStatus
}

// NetworkChangeStatus contains process-local aggregate network-event counters.
type NetworkChangeStatus struct {
	Available         bool
	Observed          uint64
	EndpointRefreshes uint64
}

// RuntimeRecoveryStatus contains process-local aggregate recovery counters.
type RuntimeRecoveryStatus struct {
	Failures   uint64
	Recoveries uint64
	Pending    bool
}

// PathProbeStatus contains redacted process-local direct-path diagnostics.
type PathProbeStatus struct {
	Available bool
	Snapshot  pathdiscovery.ProbeTelemetrySnapshot
}

// ControlProbe is the sanitized control compatibility result returned locally.
type ControlProbe struct {
	ProfileID        string
	ControlURL       string
	Protocol         string
	Capability       int
	KeyFingerprint   string
	LinkFingerprint  string
	NoiseEstablished bool
	NoiseVersion     int
}

// ControlTrust is the non-secret result of pin creation or verification.
type ControlTrust struct {
	ProfileID      string
	Fingerprint    string
	AlreadyTrusted bool
}

// Login is the non-secret result of one registration request.
type Login struct {
	ProfileID string
	State     string
	AuthURL   string
}

// NodeKeyRotation is the non-secret result of a committed key transition.
type NodeKeyRotation struct {
	ProfileID string
	State     string
}

const nodeKeyRotationCompleted = "rotated"

type controlProber interface {
	Probe(context.Context, string) (controlplane.Result, error)
	BootstrapTrust(context.Context, string, string) (controlplane.TrustResult, error)
	VerifyTrust(context.Context, string, controlplane.KeyMaterial, string) error
	Register(
		context.Context,
		string,
		controlplane.KeyMaterial,
		controlplane.RegisterOptions,
	) (controlplane.RegistrationResult, error)
	RotateNodeKey(
		context.Context,
		string,
		controlplane.KeyMaterial,
		[]byte,
		controlplane.RegisterOptions,
	) (controlplane.RegistrationResult, error)
	Logout(context.Context, string, controlplane.KeyMaterial, controlplane.RegisterOptions) error
	StreamNetmap(
		context.Context,
		string,
		controlplane.KeyMaterial,
		controlplane.NetmapOptions,
		controlplane.NetmapHandler,
	) error
}

// DataPlaneController is consumed by the daemon after map validation.
type DataPlaneController interface {
	Apply(context.Context, networkmap.Snapshot, dataplane.NodePrivateKey) (dataplane.State, error)
	Close() error
}

type endpointDiscoverer interface {
	DiscoverySocket() pathdiscovery.Socket
	DiscoverEndpoints(
		context.Context,
		uint64,
		[]netip.AddrPort,
	) (pathdiscovery.DiscoveryResult, error)
}

type relayHealthDataPlane interface {
	relayStatusDataPlane
	PrepareRelayRegion(int) error
}

type relayStatusDataPlane interface {
	RelayHealth() relay.HealthSnapshot
}

// relayFailureDataPlane signals relay connection failures so the home relay
// is re-chosen at once.
type relayFailureDataPlane interface {
	RelayFailures() <-chan struct{}
}

// deviceStopDataPlane signals a data plane device that stopped on its own,
// which no map would otherwise notice until the next one arrives.
type deviceStopDataPlane interface {
	DeviceStops() <-chan struct{}
}

type peerPathStatusDataPlane interface {
	PeerPaths() dataplane.PeerPathSnapshot
}

// subnetRouteRechecker checks the installed subnet routes again against the
// host's networks after they change.
type subnetRouteRechecker interface {
	RecheckSubnetRoutes()
}

type subnetRouteStatusDataPlane interface {
	SubnetRoutes() dataplane.SubnetRouteStatus
}

type subnetRouterStatusDataPlane interface {
	SubnetRouter() dataplane.SubnetRouterStatus
}

type peerProbeDataPlane interface {
	pathdiscovery.DatagramTransport
	SetPeerProbeHandler(pathdiscovery.DatagramHandler) error
}

type lockedPeerProbeTransport struct {
	mu        *sync.Mutex
	dataPlane peerProbeDataPlane
}

var _ pathdiscovery.DatagramTransport = (*lockedPeerProbeTransport)(nil)

func (t *lockedPeerProbeTransport) Socket() pathdiscovery.Socket {
	if t == nil || t.mu == nil || t.dataPlane == nil {
		return pathdiscovery.Socket{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.dataPlane.Socket()
}

func (t *lockedPeerProbeTransport) SendDatagram(
	packet []byte,
	destination netip.AddrPort,
) (pathdiscovery.Socket, error) {
	if t == nil || t.mu == nil || t.dataPlane == nil {
		return pathdiscovery.Socket{}, pathdiscovery.ErrTransportClosed
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.dataPlane.SendDatagram(packet, destination)
}

// SendRelayDatagram forwards a probe packet through the relay when the data
// plane supports it.
func (t *lockedPeerProbeTransport) SendRelayDatagram(packet []byte, peerNode [32]byte) error {
	if t == nil || t.mu == nil || t.dataPlane == nil {
		return pathdiscovery.ErrTransportClosed
	}
	relayed, ok := t.dataPlane.(pathdiscovery.RelayDatagramTransport)
	if !ok {
		return pathdiscovery.ErrTransportClosed
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	return relayed.SendRelayDatagram(packet, peerNode)
}

// DNSController consumes validated maps and owns transactional local resolver
// plus host configuration. Reset keeps it reusable across profile changes;
// Close permanently releases it during process shutdown.
type DNSController interface {
	Apply(context.Context, networkmap.Snapshot) (bool, error)
	Reset(context.Context) error
	Close(context.Context) error
}

// Service coordinates use cases without depending on HTTP or CLI details.
type Service struct {
	profiles             *profile.Store
	identities           *identity.Store
	build                version.Info
	prober               controlProber
	dataPlane            DataPlaneController
	dns                  DNSController
	hostname             string
	configuredCandidates pathdiscovery.Set
	enableDeviceAliases  bool
	enableSubnetRoutes   bool
	enableSubnetRouter   bool
	enableExitNode       bool
	enableExits          bool
	// gateway: a Kubernetes gateway replica (Options.Gateway);
	// gatewayCommitWait is Core's commit bound it waits out before probing.
	gateway           bool
	gatewayCommitWait time.Duration
	// exitForwarder answers an exit node's consumers' DNS; exitPins are
	// the exit nodes users approved.
	exitForwarder *dnsconfig.ExitForwarder
	// exitRelayDropped is the count of unusable relay targets last logged
	// (syncExitForwarder, under dataPlaneMu).
	exitRelayDropped int
	// exitRelayPool is the Exit Pool whose relay list the forwarder holds.
	exitRelayPool string
	exitPins      *exitPins
	// captive tracks a captive portal while the host uses an exit node,
	// which captiveDetector finds (exit node design §17.3).
	captive           *captiveTracker
	captiveDetector   atomic.Pointer[captive.Detector]
	routeSettingsPath string
	restartMarkerPath string
	// routeSites is the router of each Site of the current session, exit
	// the exit node used (nil when none is wanted), exitSticky the exit
	// node a new session keeps using, and exitPools the candidates of each
	// pool Core grants, by reference, which approval checks while no exit
	// node is used.
	routeSitesMu         sync.Mutex
	routeSites           []RouteSiteView
	exit                 *ExitView
	exitSticky           exitSticky
	exitPools            map[string][]string
	loadRouteSettings    func(string) (routesettings.Settings, error)
	clock                func() time.Time
	runtimeRetryDelay    func(time.Duration) time.Duration
	endpointRefreshDelay func() time.Duration
	// eventRefreshSpacing overrides minEventRefreshSpacing in tests.
	eventRefreshSpacing time.Duration
	newDiscoKey         func() (key.DiscoPrivate, error)
	localEndpointsMu    sync.Mutex
	localEndpointSink   func(pathdiscovery.Set)
	// peerSession is the current map's peers and the session's probe
	// runtime, for the connection test (peer_directory.go).
	peerSession    peerSession
	logger         *slog.Logger
	networkChanges <-chan struct{}
	syncSignal     chan struct{}
	// loggingOut holds the session loop down while Logout runs; downAcks
	// counts the times the loop has stopped the runtime for a down.
	loggingOut       atomic.Bool
	downAcks         atomic.Uint64
	registrationGate chan struct{}
	dataPlaneMu      sync.Mutex
	dnsApplyMu       sync.Mutex // orders DNS applies (applyNewestDNS)
	// dnsEvidence is the DNS last applied, and dnsRepublish how the session
	// hands it to Core; dnsControlURL names the session's Core for the root
	// zone to leave to the network (dns_evidence.go).
	dnsEvidenceMu     sync.Mutex
	dnsEvidence       dnsEvidence
	dnsRepublish      func()
	dnsControlURL     string
	supervisorMu      sync.Mutex
	supervisorRunning bool
	syncMu            sync.RWMutex
	syncState         syncStatus
	discoveryScope    uint64
	networkObserved   atomic.Uint64
	networkRefreshes  atomic.Uint64
	runtimeFailures   atomic.Uint64
	runtimeRecoveries atomic.Uint64
	runtimePending    atomic.Bool
	pathProbes        *pathdiscovery.ProbeTelemetry
	nat               *natState
	portMapper        PortMapper
	cloud             CloudAddresses
}

type syncStatus struct {
	profileID       string
	state           string
	revision        uint64
	networkName     string
	selfAddresses   []string
	selfKeyExpiry   time.Time
	peerCount       int
	policyRuleCount int
	dataPlane       string
	dns             string
}

type endpointRefreshRequest struct {
	active           bool
	periodic         bool
	socket           pathdiscovery.Socket
	controlHomeRelay int
	usableRelays     []int
	preferredRelays  []int
	servers          []pathdiscovery.RelayServer
}

// Options contains host facts and injectable time for the daemon use cases.
type Options struct {
	EnableDeviceAliases bool
	// EnableSubnetRoutes declares routes.subnet.v1 (mtcp-v1 §7.6).
	EnableSubnetRoutes bool
	// EnableSubnetRouter declares router.subnet.v1 and offers the subnets
	// of the settings at RouteSettingsPath (mtcp-v1 §7.6, §8.2).
	EnableSubnetRouter bool
	// EnableExitNode declares router.exit.v1 and offers to be an exit node
	// while the settings at RouteSettingsPath turn exit mode on (mtcp-v1
	// §7.7).
	EnableExitNode bool
	// EnableExits declares routes.exit.v1 and sends the host's Internet
	// traffic through the Exit Pool the settings at RouteSettingsPath name
	// (mtcp-v1 §7.7).
	EnableExits bool
	// ExitPinsDir, with EnableExits, is where the exit nodes users
	// approved are kept; empty keeps them in memory.
	ExitPinsDir       string
	RouteSettingsPath string
	// LoadRouteSettings reads RouteSettingsPath; nil uses routesettings.Load,
	// which requires a file only root can change. A mobile app keeps its
	// settings in storage private to it.
	LoadRouteSettings func(string) (routesettings.Settings, error)
	// RestartMarkerPath, when set, is the file a package upgrade writes just
	// before it restarts meshd: a stopping router then does not tell Core it
	// is going away, as it comes straight back.
	RestartMarkerPath  string
	Hostname           string
	Clock              func() time.Time
	DataPlane          DataPlaneController
	DNS                DNSController
	Logger             *slog.Logger
	AdvertiseEndpoints []netip.AddrPort
	NetworkChanges     <-chan struct{}
	// PortMapper maps the WireGuard port on the local gateway; nil turns
	// port mapping off.
	PortMapper PortMapper
	// CloudAddresses reads the instance's public cloud addresses; nil turns
	// cloud metadata lookups off.
	CloudAddresses CloudAddresses
	// Gateway runs a Kubernetes gateway replica (meshgw): its control
	// client is mtcpclient.NewGateway, it joins a cluster, never logs out,
	// and its control session stops, for meshgw to restart, when Core no
	// longer takes its keys (mtcp-v1 §6.6–6.8).
	Gateway bool
}

// New creates a daemon service from explicit dependencies.
func New(
	profiles *profile.Store,
	identities *identity.Store,
	build version.Info,
	prober controlProber,
	options Options,
) (*Service, error) {
	if profiles == nil {
		return nil, errors.New("daemon: profile store is required")
	}
	if prober == nil {
		return nil, errors.New("daemon: control prober is required")
	}
	if identities == nil {
		return nil, errors.New("daemon: identity store is required")
	}
	if options.Hostname == "" {
		return nil, errors.New("daemon: hostname is required")
	}
	if options.EnableDeviceAliases && options.DataPlane == nil {
		return nil, errors.New("daemon: Device aliases require a packet engine")
	}
	if (options.EnableSubnetRoutes || options.EnableSubnetRouter || options.EnableExitNode || options.EnableExits) &&
		options.DataPlane == nil {
		return nil, errors.New("daemon: subnet routes and exit nodes require a packet engine")
	}
	if (options.EnableSubnetRouter || options.EnableExitNode || options.EnableExits) && options.RouteSettingsPath == "" {
		return nil, errors.New("daemon: a subnet router or exit node requires its route settings path")
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	if options.LoadRouteSettings == nil {
		options.LoadRouteSettings = routesettings.Load
	}
	var pins *exitPins
	var captiveRelays *captiveTracker
	if options.EnableExits {
		opened, err := openExitPins(options.ExitPinsDir)
		if err != nil {
			return nil, err
		}
		pins = opened
		pins.logger = options.Logger
		captiveRelays = newCaptiveTracker(options.ExitPinsDir)
		// Before the first connection to Core: a kill switch root's
		// settings hold already cuts the host's resolver off.
		_, _ = exitPreferenceOf(options.LoadRouteSettings, options.RouteSettingsPath, nil)
	}
	configuredCandidates := make(
		[]pathdiscovery.Candidate,
		0,
		len(options.AdvertiseEndpoints),
	)
	for _, endpoint := range options.AdvertiseEndpoints {
		candidate, err := pathdiscovery.NewCandidate(
			endpoint,
			pathdiscovery.SourceConfigured,
		)
		if err != nil {
			return nil, fmt.Errorf("daemon: configured endpoint is invalid: %w", err)
		}
		configuredCandidates = append(configuredCandidates, candidate)
	}
	configuredSet, err := pathdiscovery.NewSet(configuredCandidates)
	if err != nil {
		return nil, fmt.Errorf("daemon: configured endpoints are invalid: %w", err)
	}

	initialDataPlane := DataPlanePending
	if options.DataPlane != nil {
		initialDataPlane = string(dataplane.StateIdle)
	}

	registrationGate := make(chan struct{}, 1)
	registrationGate <- struct{}{}

	service := &Service{
		profiles:             profiles,
		identities:           identities,
		build:                build,
		prober:               prober,
		dataPlane:            options.DataPlane,
		dns:                  options.DNS,
		hostname:             options.Hostname,
		configuredCandidates: configuredSet,
		enableDeviceAliases:  options.EnableDeviceAliases,
		enableSubnetRoutes:   options.EnableSubnetRoutes,
		enableSubnetRouter:   options.EnableSubnetRouter,
		enableExitNode:       options.EnableExitNode,
		enableExits:          options.EnableExits,
		gateway:              options.Gateway,
		gatewayCommitWait:    gatewayCommitBound,
		exitForwarder:        exitForwarderFor(options),
		exitPins:             pins,
		captive:              captiveRelays,
		routeSettingsPath:    options.RouteSettingsPath,
		restartMarkerPath:    options.RestartMarkerPath,
		loadRouteSettings:    options.LoadRouteSettings,
		clock:                options.Clock,
		runtimeRetryDelay:    jitteredRuntimeRetryDelay,
		endpointRefreshDelay: randomEndpointRefreshDelay,
		newDiscoKey:          key.NewDiscoPrivate,
		logger:               options.Logger,
		networkChanges:       options.NetworkChanges,
		syncSignal:           make(chan struct{}, 1),
		registrationGate:     registrationGate,
		pathProbes:           pathdiscovery.NewProbeTelemetry(),
		nat:                  newNATState(),
		portMapper:           options.PortMapper,
		cloud:                options.CloudAddresses,
		syncState: syncStatus{
			state:     ControlSessionInactive,
			dataPlane: initialDataPlane,
			dns:       DNSInactive,
		},
	}
	if reapplier, ok := options.DNS.(dnsReapplier); ok {
		reapplier.OnReapply(service.reappliedDNS)
	}
	return service, nil
}

// Run supervises the registered active profile's network-map stream. It keeps
// local management available after permanent remote failures and retries only
// after an operator-visible state change.
func (s *Service) Run(ctx context.Context) (runErr error) {
	if !s.beginRun() {
		return ErrServiceRunning
	}
	defer s.endRun()
	defer func() {
		runErr = errors.Join(runErr, s.closeDNS(), s.stopDataPlane())
		s.exitPins.settle() // the pins a session took are written before it ends
	}()
	// The restart the marker announced has happened: a later stop is real.
	clearRestartMarker(s.restartMarkerPath, s.logger)
	if s.captive != nil {
		detector := s.newCaptiveDetector()
		s.captiveDetector.Store(detector)
		captiveCtx, stopCaptive := context.WithCancel(ctx)
		defer stopCaptive()
		go detector.Run(captiveCtx)
		go s.runCaptiveWindow(captiveCtx)
	}
	if s.enableExitNode {
		// The exit node's own way out is followed whether or not Core's
		// stream is up: its forwarder tells consumers (TD-CLI-72).
		uplinkCtx, stopUplink := context.WithCancel(ctx)
		defer stopUplink()
		go watchExitUplink(uplinkCtx, s.exitNodeStatus, routeHealthPoll)
	}

	// Signals raised before the supervisor starts are already reflected in the
	// persisted stores that the first loop iteration reads.
	select {
	case <-s.syncSignal:
	default:
	}
	runtimeRetry := minRuntimeRetry
	// quickStops counts consecutive data plane stops of sessions that did
	// not stay synchronized for runtimeRetryReset (capRetryForCause).
	quickStops := 0
	var suspendedSince time.Time
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if s.heldDown() {
			// meshctl down, or Logout taking the map stream's place.
			if err := s.stopRuntime(); err != nil {
				return err
			}
			s.setSyncStatus(syncStatus{
				profileID: s.profiles.Snapshot().ActiveProfileID,
				state:     ControlSessionDown,
				dataPlane: s.defaultDataPlaneState(),
				dns:       DNSInactive,
			})
			s.downAcks.Add(1)
			if err := s.waitForSyncSignal(ctx); err != nil {
				return err
			}

			continue
		}
		active, err := s.profiles.Active(ctx)
		if errors.Is(err, profile.ErrNotFound) {
			if err := s.stopRuntime(); err != nil {
				return err
			}
			s.setSyncStatus(syncStatus{
				state:     ControlSessionInactive,
				dataPlane: s.defaultDataPlaneState(),
				dns:       DNSInactive,
			})
			if err := s.waitForSyncSignal(ctx); err != nil {
				return err
			}

			continue
		}
		if err != nil {
			return fmt.Errorf("reading active profile for control sync: %w", err)
		}
		record, err := s.identities.Get(ctx, active.ID)
		if err == nil && record.IsRegistered() && record.IsGateway() != s.gateway {
			// A gateway's state under meshd, or the other way round: its
			// keys must not take the other kind's paths.
			return ErrGatewayModeMismatch
		}
		if errors.Is(err, identity.ErrNotFound) || (err == nil && !record.IsRegistered()) {
			if err := s.stopRuntime(); err != nil {
				return err
			}
			s.setSyncStatus(syncStatus{
				profileID: active.ID,
				state:     ControlSessionInactive,
				dataPlane: s.defaultDataPlaneState(),
				dns:       DNSInactive,
			})
			if err := s.waitForSyncSignal(ctx); err != nil {
				return err
			}

			continue
		}
		if err != nil {
			return fmt.Errorf("reading identity for control sync: %w", err)
		}
		if record.HasPendingNodeKeyRotation() && !s.gateway {
			// A gateway settles a staged node key by probing at its start
			// (PrepareGatewayKeys): its former node key is refused.
			resumed, rotationErr := s.resumeNodeKeyRotation(ctx)
			if rotationErr == nil && resumed {
				runtimeRetry = minRuntimeRetry

				continue
			}
			if errors.Is(rotationErr, controlplane.ErrNodeKeyRotationRefused) {
				// The staged key was discarded; sync with the current key.
				s.logControlSessionFailure("node key rotation refused", rotationErr)

				continue
			}
			if rotationErr != nil {
				s.logControlSessionFailure("node key rotation resume failed", rotationErr)
				recoverable := errors.Is(rotationErr, controlplane.ErrRegistrationTemporary)
				controlState := ControlSessionBlocked
				if recoverable {
					controlState = ControlSessionConnecting
				}
				s.setSyncStatus(syncStatus{
					profileID: active.ID,
					state:     controlState,
					dataPlane: s.defaultDataPlaneState(),
					dns:       DNSInactive,
				})
				if recoverable {
					s.runtimeFailures.Add(1)
					s.runtimePending.Store(true)
					backoffElapsed, waitErr := s.waitForRuntimeRecoveryAtLeast(ctx, runtimeRetry,
						controlplane.RetryAfterOf(rotationErr))
					if waitErr != nil {
						return waitErr
					}
					if backoffElapsed {
						runtimeRetry = nextRuntimeRetry(runtimeRetry)
					} else {
						runtimeRetry = minRuntimeRetry
					}

					continue
				}
				if err := s.waitForSyncSignal(ctx); err != nil {
					return err
				}
				runtimeRetry = minRuntimeRetry

				continue
			}
		}
		identityMaterial := record.Material()
		protocolMaterial := toProtocolMaterial(identityMaterial)
		// Binds a REVOKED answer to the keys this session used (below).
		sessionKeys := credentialDigest(identityMaterial)
		clearIdentityMaterial(identityMaterial)
		privateKey := dataplane.NodePrivateKey{}
		if s.dataPlane != nil {
			rawPrivateKey, keyErr := controlplane.NodePrivateRaw(protocolMaterial)
			if keyErr != nil {
				clearProtocolMaterial(protocolMaterial)

				return fmt.Errorf("reading data-plane node key: %w", keyErr)
			}
			privateKey = dataplane.NodePrivateKey(rawPrivateKey)
			clear(rawPrivateKey[:])
		}
		discoveryScope, err := s.nextDiscoveryScope()
		if err != nil {
			clear(privateKey[:])
			clearProtocolMaterial(protocolMaterial)

			return err
		}
		// One disco key per control session serves the legacy probe format
		// and Interchange relays, whose tickets bind it.
		discoKey, err := s.newDiscoKey()
		if err != nil {
			clear(privateKey[:])
			clearProtocolMaterial(protocolMaterial)

			return fmt.Errorf("creating disco key: %w", err)
		}

		if relayIdentity, ok := s.dataPlane.(relayIdentityDataPlane); ok {
			s.dataPlaneMu.Lock()
			relayIdentity.SetRelayIdentity(discoKey)
			s.dataPlaneMu.Unlock()
		}
		s.setSyncStatus(syncStatus{
			profileID: active.ID,
			state:     ControlSessionConnecting,
			dataPlane: s.currentDataPlaneState(),
			dns:       s.currentDNSState(),
		})
		streamCtx, cancelStream := context.WithCancelCause(ctx)
		cancel := context.CancelFunc(func() { cancelStream(nil) })
		streamDone := make(chan error, 1)
		if stopping, ok := s.dataPlane.(deviceStopDataPlane); ok {
			watchDataPlaneStops(streamCtx, stopping.DeviceStops(), cancelStream)
		}
		var probeRuntime *peerprobe.Runtime
		var probeDataPlane peerProbeDataPlane
		var pathController *pathEndpointController
		// Local router choices of this session (design §6.3), and the router
		// of each Site reported to Core and shown in status.
		failover := newRouteFailover(s.clock)
		failover.exitHeld = s.captive.held
		if live, ok := s.dns.(dnsLivenessController); ok {
			// The resolver asks last the resolver Devices this session saw
			// stop.
			live.SetResolverLiveness(failoverLiveness{failover: failover})
		}
		s.captive.setExitAnswered(failover.exitAnsweredAfter)
		var routeSelection chan []controlplane.RouteSiteSelection
		if s.enableSubnetRoutes {
			routeSelection = make(chan []controlplane.RouteSiteSelection, 1)
		}
		// The exit node used (exit node design §9), from the host's settings
		// and the last session's choice.
		var exitSelection chan controlplane.RouteExitSelection
		readExitPreference := func() (exitPreference, bool) {
			return exitPreferenceOf(s.loadRouteSettings, s.routeSettingsPath, s.logger)
		}
		if s.enableExits {
			exitSelection = make(chan controlplane.RouteExitSelection, 1)
			// Unreadable settings start with none: the helper's kill switch
			// holds meanwhile, and the next read applies them.
			preference, _ := readExitPreference()
			failover.seedExit(preference, s.exitStickySnapshot(), s.exitPins)
		}
		publishRouteSelection := func() {
			reports, views := failover.selections()
			s.setRouteSites(views)
			if routeSelection != nil {
				offerLatest(routeSelection, reports)
			}
			if exitSelection != nil {
				report, view, sticky := failover.exitSelection()
				s.setExit(view, sticky, failover.exitCandidates())
				offerLatest(exitSelection, report)
			}
		}
		if dataPlane, supported := s.dataPlane.(peerProbeDataPlane); supported {
			probeDataPlane = dataPlane
			var pathObserver peerprobe.PathObserver
			if endpoints, supported := s.dataPlane.(preferredEndpointDataPlane); supported {
				pathController, err = newPathEndpointController(
					streamCtx,
					pathdiscovery.NewPathSelector(),
					endpoints,
					&s.dataPlaneMu,
					s.pathProbes,
					s.clock,
					cancel,
				)
				if err != nil {
					cancel()
					clear(privateKey[:])
					clearProtocolMaterial(protocolMaterial)

					return fmt.Errorf("creating path endpoint controller: %w", err)
				}
				pathObserver = pathController
			}
			pathObserver = routeFailoverObserver{next: pathObserver, failover: failover}
			probeRuntime, err = peerprobe.NewRuntime(
				streamCtx,
				discoKey,
				&lockedPeerProbeTransport{
					mu:        &s.dataPlaneMu,
					dataPlane: dataPlane,
				},
				pathObserver,
				s.pathProbes,
			)
			if err != nil {
				pathController.Close()
				cancel()
				clear(privateKey[:])
				clearProtocolMaterial(protocolMaterial)

				return fmt.Errorf("creating peer-probe runtime: %w", err)
			}
			runtime := probeRuntime
			s.setLocalEndpointSink(func(candidates pathdiscovery.Set) {
				runtime.SetLocalEndpoints(discoEndpoints(candidates), s.nat.get().NAT)
			})
			s.peerSession.setMeasurer(runtime)
		}
		// Path statistics (mtcp-v1 §8.3) follow the session's data plane.
		var pathStats chan controlplane.PathStatsReport
		var pathSampler *pathStatsSampler
		stopPathStats := func() {}
		if statsPlane, supported := s.dataPlane.(pathStatsDataPlane); supported {
			pathStats = make(chan controlplane.PathStatsReport, 1)
			pathSampler = newPathStatsSampler(s.clock())
			pathCtx, pathCancel := context.WithCancel(streamCtx)
			pathDone := make(chan struct{})
			go func() {
				defer close(pathDone)
				runPathStats(pathCtx, pathSampler, func() []dataplane.PeerPathStat {
					s.dataPlaneMu.Lock()
					defer s.dataPlaneMu.Unlock()
					return statsPlane.PeerPathStats()
				}, pathStats, s.clock)
			}()
			stopPathStats = func() {
				pathCancel()
				<-pathDone
			}
		}
		stopFailover := func() {}
		if activityPlane, supported := s.dataPlane.(routedActivityDataPlane); supported {
			failoverCtx, failoverCancel := context.WithCancel(streamCtx)
			var failoverWorkers sync.WaitGroup
			applyLocalChoices := func() error {
				s.dataPlaneMu.Lock()
				// Under the lock: the map callback applies maps under it too,
				// so this is the newest map with the local choices.
				current := failover.current()
				if current.Revision == 0 {
					s.dataPlaneMu.Unlock()
					return nil
				}
				_, err := s.dataPlane.Apply(failoverCtx, current, privateKey)
				if err == nil {
					publishRouteSelection()
				}
				s.dataPlaneMu.Unlock()
				if err != nil && failoverCtx.Err() != nil {
					return err // the session is ending: nothing to recover
				}
				if err != nil {
					cancelStream(fmt.Errorf("%w: applying a local router choice: %w", errRuntimeRecovery, err))
					return err
				}
				s.logger.Info("local router and exit choices changed; Sites not listed follow Core",
					append([]any{"choices", failover.choices()}, failover.exitLogAttrs()...)...)
				if s.dns != nil && s.enableExits {
					// The exit node's forwarder answers the names now.
					if _, _, err := s.applyNewestDNS(failoverCtx, failover, current); err != nil {
						return err
					}
				}
				return nil
			}
			failoverWorkers.Go(func() {
				var readExit func() dataplane.ExitActivity
				if exitPlane, supported := s.dataPlane.(exitActivityDataPlane); supported && s.enableExits {
					readExit = func() dataplane.ExitActivity {
						s.dataPlaneMu.Lock()
						defer s.dataPlaneMu.Unlock()
						return exitPlane.ExitActivity()
					}
				}
				runRouteFailover(failoverCtx, failover, func() []dataplane.RoutedActivity {
					s.dataPlaneMu.Lock()
					defer s.dataPlaneMu.Unlock()
					return activityPlane.RoutedActivity()
				}, readExit, applyLocalChoices)
			})
			if probeRuntime != nil {
				failoverWorkers.Go(func() {
					watchResolverLiveness(failoverCtx, failover, probeRuntime.SetRelayLiveness)
				})
			}
			if s.enableExits {
				failoverWorkers.Go(func() {
					watchExitPreference(failoverCtx, failover, readExitPreference, routeOfferPoll, applyLocalChoices)
				})
			}
			stopFailover = func() {
				failoverCancel()
				failoverWorkers.Wait()
			}
		}
		dnsRetries := &dnsRetry{}
		// lastDNS is the map whose DNS was last applied or kept (TD-CLI-33).
		var lastDNS networkmap.Snapshot
		hasLastDNS := false
		cleanupSession := func() error {
			// Before the runtime resets DNS: no retry may apply it again.
			dnsRetries.stop()
			// What the session hands Core about DNS ends with it.
			s.setDNSRepublish(nil)
			s.recordDNSEvidence(dnsEvidence{})
			// The session's pings end: no resolver Device is judged by them.
			if live, ok := s.dns.(dnsLivenessController); ok {
				live.SetResolverLiveness(nil)
			}
			failover.closeLiveness()
			// Before the private key is cleared: it applies maps with it.
			stopFailover()
			s.setRouteSites(nil)
			s.clearExit()
			s.exitForwarder.Configure(nil, nil)
			stopPathStats()
			s.setLocalEndpointSink(nil)
			s.peerSession.setMeasurer(nil)
			s.peerSession.setDirectory(nil)
			if probeRuntime != nil {
				probeRuntime.Close()
			}
			pathController.Close()
			var detachErr error
			if probeDataPlane != nil {
				s.dataPlaneMu.Lock()
				detachErr = probeDataPlane.SetPeerProbeHandler(nil)
				s.dataPlaneMu.Unlock()
			}
			clear(privateKey[:])
			clearProtocolMaterial(protocolMaterial)

			return detachErr
		}
		var discoveryRequests chan endpointRefreshRequest
		var endpointUpdates chan controlplane.EndpointUpdate
		var refreshDone <-chan error
		var sessionDiscoverer endpointDiscoverer
		var synchronizedAt time.Time
		if discoverer, supported := s.dataPlane.(endpointDiscoverer); supported {
			sessionDiscoverer = discoverer
			discoveryRequests = make(chan endpointRefreshRequest, 1)
			endpointUpdates = make(chan controlplane.EndpointUpdate, 1)
			done := make(chan error, 1)
			refreshDone = done
			go func() {
				done <- s.runEndpointRefresh(
					streamCtx,
					discoveryScope,
					discoverer,
					discoveryRequests,
					endpointUpdates,
				)
			}()
		}
		lastRefreshRequest := endpointRefreshRequest{}
		hasRefreshRequest := false
		var enforcementReports chan controlplane.EnforcementReport
		var enforcement *enforcementPublisher
		enforcedPolicy, reportsEnforcement := s.dataPlane.(enforcedPolicyDataPlane)
		if reportsEnforcement {
			enforcementReports = make(chan controlplane.EnforcementReport, 1)
			enforcement = &enforcementPublisher{
				reports: enforcementReports, enforced: enforcedPolicy, dns: s.currentDNSEvidence,
			}
			if changing, ok := s.dataPlane.(enforcementChangesDataPlane); ok {
				go republishEnforcement(streamCtx, changing.EnforcementChanges(), enforcement)
			}
			// New DNS evidence goes to Core at once, with the filter's.
			s.setDNSRepublish(enforcement.publish)
		}
		s.dnsEvidenceMu.Lock()
		s.dnsControlURL = active.ControlURL
		s.dnsEvidenceMu.Unlock()
		nextControlKey, _ := record.NextControlKey()
		var hostOffers chan controlplane.HostOffer
		// How the resolver sees the zones' resolvers (DNS design D1b §9).
		var dnsHealth chan []controlplane.ResolverHealth
		if measured, ok := s.dns.(dnsHealthController); ok {
			dnsHealth = make(chan []controlplane.ResolverHealth, 1)
			go publishDNSHealth(streamCtx, measured, dnsHealth)
		}
		var routeHealth chan []controlplane.RouteSiteHealth
		var exitHealth chan controlplane.RouteExitHealth
		if s.enableExitNode {
			exitHealth = make(chan controlplane.RouteExitHealth)
			go watchExitHealth(streamCtx, s.exitNodeStatus, routeHealthPoll, exitHealth)
		}
		if controller, ok := s.dns.(dnsSwitch); ok && s.loadRouteSettings != nil && s.routeSettingsPath != "" {
			go watchDNSSwitch(streamCtx, s.loadRouteSettings, s.routeSettingsPath, routeOfferPoll, controller)
		}
		if s.enableSubnetRouter || s.enableExitNode {
			hostOffers = make(chan controlplane.HostOffer)
			go watchRouteOffer(streamCtx, s.loadRouteSettings, s.routeSettingsPath, routeOfferPoll, s.logger,
				hostOffers)
		}
		if s.enableSubnetRouter {
			routeHealth = make(chan []controlplane.RouteSiteHealth)
			go watchRouteHealth(streamCtx, s.subnetRouterStatus, routeHealthPoll, routeHealth)
		}
		go func() {
			streamDone <- s.prober.StreamNetmap(
				streamCtx,
				active.ControlURL,
				protocolMaterial,
				controlplane.NetmapOptions{
					EnableDeviceAliases: s.enableDeviceAliases,
					EnableSubnetRoutes:  s.enableSubnetRoutes,
					EnableSubnetRouter:  s.enableSubnetRouter,
					EnableExitNode:      s.enableExitNode,
					EnableExits:         s.enableExits,
					// Forward zones need this client's resolver.
					EnableDNSForward:   s.dns != nil,
					ExitSelection:      exitSelection,
					HostOffers:         hostOffers,
					ExitHealth:         exitHealth,
					RouteHealth:        routeHealth,
					DNSHealth:          dnsHealth,
					RouteSelection:     routeSelection,
					AnnounceGoingAway:  func() bool { return !restartExpected(s.restartMarkerPath, s.clock()) },
					CaptiveWindows:     s.captiveWindowsToReport(),
					CaptiveWindowsSent: s.captive.windowsSent,
					Hostname:           s.hostname,
					Version:            "meshd/" + s.build.Version,
					PinnedFingerprint:  record.ControlKeyFingerprint(),
					PeerProbePublicKey: peerprobe.MapDiscoveryKey(discoKey.Public()),
					Candidates:         s.configuredCandidates,
					EndpointUpdates:    endpointUpdates,
					EnforcementReports: enforcementReports,
					PathStats:          pathStats,
					NextControlKey:     nextControlKey,
					ControlKeysChanged: func(ctx context.Context, next []byte) error {
						return s.stageNextControlKey(ctx, active.ID, next)
					},
					ConnectionChanged: func(connected bool) {
						s.setControlConnected(active.ID, connected)
					},
				},
				func(callbackCtx context.Context, snapshot networkmap.Snapshot) (callbackErr error) {
					defer func() {
						if callbackErr != nil {
							callbackErr = fmt.Errorf(
								"%w: %w",
								errRuntimeRecovery,
								callbackErr,
							)
						}
					}()
					if err := callbackCtx.Err(); err != nil {
						return err
					}
					if s.profiles.Snapshot().ActiveProfileID != active.ID {
						return nil
					}
					if pathSampler != nil {
						pathSampler.observe(snapshot)
					}
					selfAddresses := make([]string, len(snapshot.Self.Addresses))
					for index, address := range snapshot.Self.Addresses {
						selfAddresses[index] = address.String()
					}
					dataPlaneState := s.defaultDataPlaneState()
					if probeRuntime != nil {
						probeRuntime.Deactivate()
					}
					if pathController != nil {
						if err := pathController.Pause(callbackCtx); err != nil {
							return fmt.Errorf("pausing path endpoint controller: %w", err)
						}
					}
					if snapshot.DroppedAliasPeers != 0 && s.logger != nil {
						s.logger.Warn("shared Devices left out of the map: their alias is expired or unusable",
							"peers", snapshot.DroppedAliasPeers)
					}
					probeSocket := pathdiscovery.Socket{}
					var probeAttachErr error
					// The map with the local router and exit choices: DNS
					// follows the exit node too.
					effective := snapshot
					if s.dataPlane != nil {
						s.dataPlaneMu.Lock()
						effective = failover.effective(snapshot)
						state, err := s.dataPlane.Apply(callbackCtx, effective, privateKey)
						if err == nil {
							s.syncExitForwarder(snapshot)
							if s.captive != nil {
								s.captive.noteRelays(snapshot.Relays)
							}
							s.peerSession.setDirectory(newPeerDirectory(snapshot))
							publishRouteSelection()
							// Routers and resolver Devices reached only through
							// the relay still prove they are up, for local
							// failover and DNS.
							failover.syncRelayLiveness(probeRuntime.SetRelayLiveness, true)
						}
						if err == nil && reportsEnforcement {
							enforcement.publish()
						}
						if err == nil && probeDataPlane != nil {
							if len(snapshot.Peers) == 0 {
								probeAttachErr = probeDataPlane.SetPeerProbeHandler(nil)
							} else {
								probeAttachErr = probeDataPlane.SetPeerProbeHandler(probeRuntime)
								probeSocket = probeDataPlane.Socket()
							}
						}
						s.dataPlaneMu.Unlock()
						if err != nil {
							s.setSyncStatus(syncStatus{
								profileID: active.ID,
								state:     ControlSessionBlocked,
								dataPlane: string(dataplane.StateFailed),
							})

							return fmt.Errorf("applying data plane: %w", err)
						}
						dataPlaneState = string(state)
					}
					if probeAttachErr != nil {
						return fmt.Errorf("attaching peer-probe transport: %w", probeAttachErr)
					}
					if probeRuntime != nil && len(snapshot.Peers) != 0 {
						if !probeSocket.IsOpen() {
							return pathdiscovery.ErrTransportClosed
						}
						generation := pathdiscovery.ProbeGeneration{
							Scope:       discoveryScope,
							MapRevision: snapshot.Revision,
							Socket:      probeSocket,
						}
						if pathController != nil {
							if err := pathController.Activate(
								callbackCtx,
								snapshot,
								generation,
							); err != nil {
								return fmt.Errorf("activating path endpoint controller: %w", err)
							}
						}
						_, _, err := probeRuntime.Activate(
							snapshot,
							generation,
						)
						if err != nil {
							return fmt.Errorf("activating peer probes: %w", err)
						}
					} else if pathController != nil {
						if err := pathController.Deactivate(callbackCtx); err != nil {
							return fmt.Errorf("deactivating path endpoint controller: %w", err)
						}
					}
					if discoveryRequests != nil {
						s.dataPlaneMu.Lock()
						request, err := endpointRequest(
							snapshot,
							sessionDiscoverer,
						)
						s.dataPlaneMu.Unlock()
						if err != nil {
							return err
						}
						if !hasRefreshRequest || !lastRefreshRequest.equal(request) {
							offerLatest(discoveryRequests, request)
							lastRefreshRequest = request
							hasRefreshRequest = true
						}
					}
					dnsState := DNSInactive
					var retryDNS func() bool
					if s.dns != nil {
						// A host that refuses DNS fails DNS only: restarting the
						// runtime would fetch the same map. Retries with backoff
						// apply this map again until a newer one arrives.
						var dnsErr, lastDNSFailure error
						previous, hadPrevious := lastDNS, hasLastDNS
						// Without a data plane the retry has no newer map to
						// apply, so each map applies at once.
						same := func() bool {
							s.dnsEvidenceMu.Lock()
							controlURL := s.dnsControlURL
							s.dnsEvidenceMu.Unlock()
							// A reapply that succeeded since ended the failure.
							return s.dataPlane != nil && hadPrevious &&
								s.currentDNSEvidence().reason == dnsReasonApplyFailed &&
								sameDNS(previous, effective, controlURL)
						}
						kept := !dnsRetries.apply(same, func() bool {
							dnsState, lastDNSFailure, dnsErr = s.applyNewestDNS(callbackCtx, failover, effective)
							return dnsErr == nil && dnsState != DNSFailed
						})
						lastDNS, hasLastDNS = effective, true
						if kept {
							// The pending retry applies this map with its
							// backoff; it is the only retry.
							dnsState = DNSFailed
						}
						if dnsErr != nil {
							if callbackCtx.Err() == nil {
								s.setSyncStatus(syncStatus{
									profileID: active.ID,
									state:     ControlSessionBlocked,
									dataPlane: dataPlaneState,
									dns:       DNSFailed,
								})
							}

							return dnsErr
						}
						// A map the plan refuses fails the same way every time.
						if !kept && dnsState == DNSFailed && !errors.Is(lastDNSFailure, dnsconfig.ErrInvalid) {
							retryDNS = func() bool {
								state, _, err := s.applyNewestDNS(streamCtx, failover, effective)
								if streamCtx.Err() != nil {
									return true
								}
								if err != nil {
									state = DNSFailed
								}
								s.setDNSState(state)
								return state != DNSFailed
							}
						}
					} else if !snapshot.DNS.Empty() {
						// An empty DNS view asks nothing of a node without DNS
						// (TD-CLI-23).
						dnsState = DNSPending
					}
					s.recordRuntimeRecovery()
					s.setSyncStatus(syncStatus{
						profileID:       active.ID,
						state:           ControlSessionSynchronized,
						revision:        snapshot.Revision,
						networkName:     snapshot.NetworkName,
						selfAddresses:   selfAddresses,
						selfKeyExpiry:   snapshot.Self.KeyExpiry,
						peerCount:       len(snapshot.Peers),
						policyRuleCount: len(snapshot.Policy),
						dataPlane:       dataPlaneState,
						dns:             dnsState,
					})
					if retryDNS != nil {
						dnsRetries.schedule(retryDNS)
					}
					if synchronizedAt.IsZero() {
						synchronizedAt = s.clock()
					}

					return nil
				},
			)
		}()

		select {
		case <-ctx.Done():
			cancel()
			<-streamDone
			if refreshDone != nil {
				<-refreshDone
			}
			cleanupErr := cleanupSession()

			return errors.Join(ctx.Err(), cleanupErr)
		case <-s.syncSignal:
			runtimeRetry = minRuntimeRetry
			cancel()
			<-streamDone
			if refreshDone != nil {
				<-refreshDone
			}
			if err := cleanupSession(); err != nil {
				return fmt.Errorf("detaching peer-probe transport: %w", err)
			}
			if err := s.stopRuntime(); err != nil {
				return err
			}

			continue
		case streamErr := <-streamDone:
			if cause := context.Cause(streamCtx); errors.Is(cause, errDataPlaneStopped) {
				streamErr = fmt.Errorf("%w: %w", errRuntimeRecovery, cause)
			}
			s.logControlSessionFailure("map stream stopped", streamErr)
			cancel()
			if refreshDone != nil {
				<-refreshDone
			}
			if err := cleanupSession(); err != nil {
				return fmt.Errorf("detaching peer-probe transport: %w", err)
			}
			pathErr := pathController.Err()
			// The controller cancels the session itself, so the stream only
			// reports cancellation; record the controller's own cause.
			s.logControlSessionFailure("path endpoint controller stopped the session", pathErr)
			dataPlaneState := s.currentDataPlaneState()
			dnsState := s.currentDNSState()
			runtimeStopErr := s.stopRuntime()
			if runtimeStopErr != nil {
				dataPlaneState = string(dataplane.StateFailed)
				dnsState = DNSFailed
			}
			if dataPlaneState != string(dataplane.StateFailed) {
				if pathErr != nil {
					dataPlaneState = string(dataplane.StateFailed)
				} else {
					dataPlaneState = s.defaultDataPlaneState()
				}
			}
			if dnsState != DNSFailed {
				dnsState = DNSInactive
			}
			// A stop the path controller caused is a local runtime failure:
			// rebuild with backoff, never wait for an operator.
			recoverable := errors.Is(streamErr, errRuntimeRecovery) || pathErr != nil
			suspended := errors.Is(streamErr, controlplane.ErrNetmapAuthorityPaused)
			rotated := errors.Is(streamErr, controlplane.ErrControlKeyRotated)
			if s.gateway && !recoverable && !rotated {
				// A gateway never re-registers by itself: meshgw restarts and
				// probes its keys, or an administrator removes the Device.
				s.setSyncStatus(syncStatus{
					profileID: active.ID, state: ControlSessionBlocked,
					dataPlane: dataPlaneState, dns: dnsState,
				})
				return errors.Join(fmt.Errorf("%w: %w", ErrGatewayStopped, streamErr), runtimeStopErr)
			}
			revokedKeysReplaced := false
			if !recoverable && errors.Is(streamErr, controlplane.ErrNetmapAuthorityRevoked) {
				// mtcp-v1 section 10: Core revoked this Device and will never
				// accept its keys again; only a REVOKED or LOGGED_OUT lifecycle
				// produces this error. Give the profile new keys so the next
				// login registers from scratch, as a logout would.
				replaced, err := s.replaceRevokedCredentials(ctx, active.ID, sessionKeys)
				if err != nil {
					s.logControlSessionFailure("replacing the keys of the revoked Device failed", err)
				}
				revokedKeysReplaced = replaced
			}
			controlState := ControlSessionBlocked
			switch {
			case suspended:
				controlState = ControlSessionSuspended
			case recoverable, rotated:
				controlState = ControlSessionConnecting
			case revokedKeysReplaced:
				controlState = ControlSessionInactive // no registered Device left
			}
			s.setSyncStatus(syncStatus{
				profileID: active.ID,
				state:     controlState,
				dataPlane: dataPlaneState,
				dns:       dnsState,
			})
			if runtimeStopErr != nil {
				return fmt.Errorf(
					"stopping runtime after map stream failure: %w",
					runtimeStopErr,
				)
			}
			if rotated {
				// Core moved to the key it announced; switch and connect again.
				if err := s.promoteNextControlKey(ctx, active.ID, nextControlKey); err != nil {
					s.logControlSessionFailure("switching to the next control key failed", err)
					s.setSyncStatus(syncStatus{
						profileID: active.ID, state: ControlSessionBlocked,
						dataPlane: dataPlaneState, dns: dnsState,
					})
					if err := s.waitForSyncSignal(ctx); err != nil {
						return err
					}
				}
				runtimeRetry = minRuntimeRetry

				continue
			}
			if suspended {
				// Not a failure: wait for an administrator to resume the Device.
				now := s.clock()
				if suspendedSince.IsZero() || !synchronizedAt.IsZero() {
					suspendedSince = now // suspended in this session, or anew
				}
				// Core's retry_after is a floor: a Core under load may ask
				// suspended Devices to wait longer than the local schedule.
				if _, err := s.waitForRuntimeRecoveryAtLeast(ctx, suspendedRetryDelay(now.Sub(suspendedSince)),
					controlplane.RetryAfterOf(streamErr)); err != nil {
					return err
				}
				runtimeRetry = minRuntimeRetry

				continue
			}
			if recoverable {
				quickStops = countQuickStops(quickStops, streamErr, synchronizedAt, s.clock())
				if runtimeRetry, err = s.recoverRuntime(ctx, runtimeRetry, synchronizedAt); err != nil {
					return err
				}
				runtimeRetry = capRetryForCause(runtimeRetry, streamErr, quickStops)

				continue
			}
			if err := s.waitForSyncSignal(ctx); err != nil {
				return err
			}
			runtimeRetry = minRuntimeRetry
		case refreshErr := <-refreshDone:
			s.logControlSessionFailure("endpoint refresh stopped", refreshErr)
			cancel()
			<-streamDone
			if err := cleanupSession(); err != nil {
				return fmt.Errorf("detaching peer-probe transport: %w", err)
			}
			pathErr := pathController.Err()
			// The controller cancels the session itself, so the stream only
			// reports cancellation; record the controller's own cause.
			s.logControlSessionFailure("path endpoint controller stopped the session", pathErr)
			dataPlaneState := s.currentDataPlaneState()
			dnsState := s.currentDNSState()
			runtimeStopErr := s.stopRuntime()
			if runtimeStopErr != nil {
				dataPlaneState = string(dataplane.StateFailed)
				dnsState = DNSFailed
			}
			if dataPlaneState != string(dataplane.StateFailed) {
				if pathErr != nil {
					dataPlaneState = string(dataplane.StateFailed)
				} else {
					dataPlaneState = s.defaultDataPlaneState()
				}
			}
			if dnsState != DNSFailed {
				dnsState = DNSInactive
			}
			// Endpoint discovery and relay selection are local runtime work:
			// a failure rebuilds the session with backoff.
			s.setSyncStatus(syncStatus{
				profileID: active.ID,
				state:     ControlSessionConnecting,
				dataPlane: dataPlaneState,
				dns:       dnsState,
			})
			if runtimeStopErr != nil {
				return fmt.Errorf(
					"stopping runtime after endpoint refresh failure: %w",
					runtimeStopErr,
				)
			}
			if runtimeRetry, err = s.recoverRuntime(ctx, runtimeRetry, synchronizedAt); err != nil {
				return err
			}
		}
	}
}

// capRetryForCause keeps the backoff short when the data plane device
// stopped on its own, for the first maxQuickDataPlaneStops stops in a row.
// A device that keeps stopping soon after it starts is not a passing
// window: it then backs off like any other failure, so one broken Device
// costs Core a session at most every maxRuntimeRetry.
func capRetryForCause(retry time.Duration, cause error, quickStops int) time.Duration {
	if errors.Is(cause, errDataPlaneStopped) && quickStops <= maxQuickDataPlaneStops {
		return min(retry, maxDataPlaneStopRetry)
	}
	return retry
}

// countQuickStops returns the new count of consecutive quick data plane
// stops: a stop of a session synchronized for less than runtimeRetryReset
// adds one, anything else starts over.
func countQuickStops(stops int, cause error, synchronizedAt, now time.Time) int {
	if !errors.Is(cause, errDataPlaneStopped) {
		return 0
	}
	if !synchronizedAt.IsZero() && now.Sub(synchronizedAt) >= runtimeRetryReset {
		return 1 // a long session ended: this is the first quick stop again
	}
	return stops + 1
}

// watchDataPlaneStops ends the session with errDataPlaneStopped when the
// data plane device stops on its own. A signal left from before the session
// is dropped: the session's first map rebuilds a stopped device anyway.
func watchDataPlaneStops(ctx context.Context, stops <-chan struct{}, cancel context.CancelCauseFunc) {
	if stops == nil {
		return
	}
	select {
	case <-stops:
	default:
	}
	go func() {
		select {
		case <-stops:
			cancel(errDataPlaneStopped)
		case <-ctx.Done():
		}
	}()
}

// recoverRuntime records a local runtime failure and waits out its backoff
// (cut short by a sync signal), returning the next retry delay.
func (s *Service) recoverRuntime(ctx context.Context, retry time.Duration, synchronizedAt time.Time) (time.Duration, error) {
	s.runtimeFailures.Add(1)
	s.runtimePending.Store(true)
	retry = runtimeRetryAfterSession(retry, synchronizedAt, s.clock())
	backoffElapsed, err := s.waitForRuntimeRecovery(ctx, retry)
	if err != nil {
		return retry, err
	}
	if backoffElapsed {
		return nextRuntimeRetry(retry), nil
	}
	return minRuntimeRetry, nil
}

func (s *Service) logControlSessionFailure(message string, err error) {
	if s != nil && s.logger != nil && err != nil && !errors.Is(err, context.Canceled) {
		s.logger.Warn(message, "error", err)
	}
}

func endpointRequest(
	snapshot networkmap.Snapshot,
	discoverer endpointDiscoverer,
) (endpointRefreshRequest, error) {
	if discoverer == nil {
		return endpointRefreshRequest{}, errors.New("daemon: endpoint discoverer is unavailable")
	}
	socket := discoverer.DiscoverySocket()
	if !socket.IsOpen() {
		return endpointRefreshRequest{}, pathdiscovery.ErrTransportClosed
	}
	servers, err := pathdiscovery.ServersFromRelayMap(snapshot.Relays)
	if errors.Is(err, pathdiscovery.ErrNoSTUNServers) {
		servers = nil
	} else if err != nil {
		return endpointRefreshRequest{}, fmt.Errorf("deriving discovery servers: %w", err)
	}

	return endpointRefreshRequest{
		active:           true,
		periodic:         len(snapshot.Peers) != 0,
		socket:           socket,
		controlHomeRelay: snapshot.Self.HomeRelay,
		usableRelays:     usableRelayRegionIDs(snapshot.Relays),
		preferredRelays:  preferredRelayRegionIDs(snapshot.Relays),
		servers:          append([]pathdiscovery.RelayServer(nil), servers...),
	}, nil
}

// preferredRelayRegionIDs lists the Private Interchange regions.
func preferredRelayRegionIDs(regions map[int]networkmap.RelayRegion) []int {
	var regionIDs []int
	for regionID, region := range regions {
		if region.Preferred && region.ID == regionID {
			regionIDs = append(regionIDs, regionID)
		}
	}
	slices.Sort(regionIDs)
	return regionIDs
}

func (r endpointRefreshRequest) equal(other endpointRefreshRequest) bool {
	return r.active == other.active && r.periodic == other.periodic &&
		r.socket == other.socket &&
		r.controlHomeRelay == other.controlHomeRelay &&
		slices.Equal(r.usableRelays, other.usableRelays) &&
		slices.Equal(r.preferredRelays, other.preferredRelays) &&
		slices.Equal(r.servers, other.servers)
}

func usableRelayRegionIDs(regions map[int]networkmap.RelayRegion) []int {
	regionIDs := make([]int, 0, len(regions))
	for regionID, region := range regions {
		if regionID <= 0 || region.ID != regionID || regionID > 65_535 {
			continue
		}
		for _, node := range region.Nodes {
			if !node.STUNOnly {
				regionIDs = append(regionIDs, regionID)

				break
			}
		}
	}
	slices.Sort(regionIDs)

	return regionIDs
}

func offerLatest[T any](updates chan T, value T) {
	select {
	case updates <- value:
		return
	default:
	}
	select {
	case <-updates:
	default:
	}
	select {
	case updates <- value:
	default:
	}
}

func (s *Service) runEndpointRefresh(
	ctx context.Context,
	scope uint64,
	discoverer endpointDiscoverer,
	requests <-chan endpointRefreshRequest,
	updates chan controlplane.EndpointUpdate,
) error {
	if discoverer == nil || requests == nil || updates == nil {
		return errors.New("daemon: endpoint refresh dependencies are missing")
	}
	natRequests, natNetwork, stopNAT := s.startNATClassification(ctx, discoverer)
	defer stopNAT()
	portChanges, stopPortMapping := s.startPortMapping(ctx)
	defer stopPortMapping()
	cloudChanges, stopCloud := s.startCloudAddresses(ctx)
	defer stopCloud()
	var natChanges <-chan struct{}
	if s.nat != nil {
		natChanges = s.nat.changes
	}
	var relayFailures <-chan struct{}
	if failing, ok := discoverer.(relayFailureDataPlane); ok {
		relayFailures = failing.RelayFailures()
	}
	tracker := pathdiscovery.NewTracker()
	homeSelector := relay.NewHomeSelector()
	current := endpointRefreshRequest{}
	var currentCandidates pathdiscovery.Set
	lastPublished := controlplane.EndpointUpdate{Candidates: s.configuredCandidates}
	hasPublished := true
	hasCurrent := false
	serverCursor := 0
	networkChanges := s.networkChanges
	var timer *time.Timer
	var timerChannel <-chan time.Time
	defer func() { stopRefreshTimer(timer) }()
	// lastEventRound is when an event last ran a discovery round, deferred
	// says the armed timer serves deferred events, and pendingNetwork keeps
	// a network change until a round runs for it.
	var lastEventRound time.Time
	deferred := false
	pendingNetwork := false
	// deferEvent reports whether an event must wait for the spacing, and if
	// so arms the timer for the round that will serve it. Otherwise the
	// event runs a round now, which starts the spacing.
	deferEvent := func() bool {
		if !hasCurrent || !current.active {
			return false // no round runs for it, so it starts no spacing
		}
		now := s.clock()
		spacing := minEventRefreshSpacing
		if s.eventRefreshSpacing > 0 {
			spacing = s.eventRefreshSpacing
		}
		wait := spacing - now.Sub(lastEventRound)
		if lastEventRound.IsZero() || wait <= 0 {
			lastEventRound = now
			return false
		}
		stopRefreshTimer(timer)
		timer = time.NewTimer(min(wait, spacing))
		timerChannel = timer.C
		deferred = true
		return true
	}
	publish := func(candidates pathdiscovery.Set, preferredRelay int) {
		update := controlplane.EndpointUpdate{
			Candidates:        candidates,
			PreferredRelay:    preferredRelay,
			HasPreferredRelay: true,
			Connectivity:      s.connectivity(),
		}
		if hasPublished && lastPublished.PreferredRelay == preferredRelay &&
			lastPublished.HasPreferredRelay == update.HasPreferredRelay &&
			lastPublished.Candidates.Equal(candidates) &&
			lastPublished.Connectivity == update.Connectivity {
			return
		}
		offerLatest(updates, update)
		lastPublished = update
		hasPublished = true
		s.notifyLocalEndpoints(candidates)
		s.setExitPublicAddresses(candidates)
		if s.logger != nil {
			s.logger.Info("endpoints published", "candidates", candidates.Len(),
				"home_relay", preferredRelay, "nat_known", update.Connectivity.NATKnown)
		}
	}

	for {
		resetForSocketChange := false
		networkTriggered := false
		select {
		case <-ctx.Done():
			return ctx.Err()
		case request, open := <-requests:
			if !open {
				return errors.New("daemon: endpoint refresh request channel closed")
			}
			resetForSocketChange = hasCurrent && current.active && request.active &&
				current.socket != request.socket
			current = request
			hasCurrent = true
			serverCursor = 0
			stopRefreshTimer(timer)
			timer = nil
			timerChannel = nil
		case <-timerChannel:
			timer = nil
			timerChannel = nil
			if deferred {
				// The deferred events' round starts the next spacing.
				lastEventRound, deferred = s.clock(), false
			}
		case _, open := <-networkChanges:
			if !open {
				networkChanges = nil

				continue
			}
			s.networkObserved.Add(1)
			if rechecker, ok := s.dataPlane.(subnetRouteRechecker); ok {
				rechecker.RecheckSubnetRoutes()
			}
			if s.logger != nil {
				// Without an active map session the change waits for the
				// session's first discovery round.
				s.logger.Info("host network changed", "refresh_now", hasCurrent && current.active)
			}
			stopRefreshTimer(timer)
			timer = nil
			timerChannel = nil
			if s.portMapper != nil {
				s.portMapper.NetworkChanged()
			}
			if s.cloud != nil {
				s.cloud.NetworkChanged()
			}
			if detector := s.captiveDetector.Load(); detector != nil {
				detector.NetworkChanged()
			}
			pendingNetwork = true
			if deferEvent() {
				continue
			}
		case <-portChanges:
			// The mapped endpoint changed: publish it now.
			stopRefreshTimer(timer)
			timer = nil
			timerChannel = nil
		case <-cloudChanges:
			// The cloud public addresses changed: publish them now.
			stopRefreshTimer(timer)
			timer = nil
			timerChannel = nil
		case <-relayFailures:
			// A relay connection failed: re-choose the home relay now.
			stopRefreshTimer(timer)
			timer = nil
			timerChannel = nil
			if deferEvent() {
				continue
			}
		case <-natChanges:
			// A new NAT classification: report it with the current
			// candidates, without another discovery round.
			if hasCurrent && current.active {
				publish(currentCandidates, lastPublished.PreferredRelay)
			}

			continue
		}
		if !hasCurrent {
			continue
		}
		// Whatever starts this round, it serves a network change still
		// waiting for one.
		networkTriggered, pendingNetwork = networkTriggered || pendingNetwork, false
		deferred = false
		if s.portMapper != nil {
			if current.active && current.socket.IsOpen() {
				s.portMapper.SetPort(current.socket.Port)
			} else {
				s.portMapper.SetPort(0)
			}
		}
		if resetForSocketChange {
			_, err := tracker.Reset(s.clock(), s.configuredCandidates)
			if err != nil {
				return err
			}
		}
		if !current.active {
			result, err := tracker.Reset(s.clock(), s.configuredCandidates)
			if err != nil {
				return err
			}
			currentCandidates = result.Candidates
			homeSelector.Reset()
			publish(currentCandidates, 0)
			hasCurrent = false

			continue
		}
		homeSelector.SetPreferred(current.preferredRelays)
		selection, err := homeSelector.Reconcile(
			current.controlHomeRelay,
			current.usableRelays,
		)
		if err != nil {
			return fmt.Errorf("reconciling relay selection: %w", err)
		}
		expired, err := tracker.Expire(s.clock())
		if err != nil {
			return err
		}
		currentCandidates = expired.Candidates
		if expired.Changed {
			publish(currentCandidates, selection.RegionID)
		}
		batch, nextCursor, err := pathdiscovery.NextServerBatch(
			current.servers,
			selection.RegionID,
			serverCursor,
		)
		if err != nil {
			return fmt.Errorf("selecting relay probe batch: %w", err)
		}
		serverCursor = nextCursor
		observed, serverLatencies, health, err := s.discoverEndpoints(
			ctx,
			scope,
			discoverer,
			current.socket,
			batch,
		)
		if err != nil {
			return err
		}
		tracked, err := tracker.Update(s.clock(), observed)
		if err != nil {
			return err
		}
		currentCandidates = tracked.Candidates
		regionLatencies, err := relayRegionLatencies(
			batch,
			serverLatencies,
			current.usableRelays,
		)
		if err != nil {
			return err
		}
		relayDataPlane, hasRelayHealth := discoverer.(relayHealthDataPlane)
		selection, err = homeSelector.Observe(s.clock(), regionLatencies, health)
		if err != nil {
			return fmt.Errorf("selecting home relay: %w", err)
		}
		preparingRelay := false
		if selection.PreparationRegionID != 0 && hasRelayHealth {
			s.dataPlaneMu.Lock()
			prepareErr := relayDataPlane.PrepareRelayRegion(selection.PreparationRegionID)
			s.dataPlaneMu.Unlock()
			if prepareErr == nil {
				preparingRelay = true
				// Connecting to a nearby relay takes milliseconds: wait for it
				// briefly and confirm the move now, instead of after another
				// poll and discovery round.
				if health, connected := s.awaitRelayRegion(ctx, relayDataPlane,
					selection.PreparationRegionID); connected {
					confirmed, observeErr := homeSelector.Observe(s.clock(), regionLatencies, health)
					if observeErr == nil {
						selection = confirmed
						preparingRelay = confirmed.PreparationRegionID != 0
					}
				}
			} else if s.logger != nil {
				s.logger.Debug(
					"relay preparation deferred",
					"region_id", selection.PreparationRegionID,
					"error", prepareErr,
				)
			}
		}
		if networkTriggered {
			s.networkRefreshes.Add(1)
		}
		publish(currentCandidates, selection.RegionID)
		if natRequests != nil {
			offerLatest(natRequests, natRequest{
				socket:  current.socket,
				servers: pathdiscovery.NATServers(current.servers),
			})
			if networkTriggered {
				signalNetworkChange(natNetwork)
			}
		}
		if !current.periodic {
			continue
		}
		if s.endpointRefreshDelay == nil {
			return errors.New("daemon: endpoint refresh delay is unavailable")
		}
		delay := s.endpointRefreshDelay()
		if delay <= 0 {
			return errors.New("daemon: endpoint refresh delay is invalid")
		}
		if !tracked.ExpiresAt.IsZero() {
			untilExpiry := tracked.ExpiresAt.Sub(s.clock())
			if untilExpiry < delay {
				if untilExpiry < 0 {
					untilExpiry = 0
				}
				delay = untilExpiry
			}
		}
		if preparingRelay && relayPreparationPoll < delay {
			delay = relayPreparationPoll
		}
		timer = time.NewTimer(delay)
		timerChannel = timer.C
	}
}

func (s *Service) discoverEndpoints(
	ctx context.Context,
	scope uint64,
	discoverer endpointDiscoverer,
	expectedSocket pathdiscovery.Socket,
	servers []pathdiscovery.RelayServer,
) (pathdiscovery.Set, []pathdiscovery.ServerLatency, relay.HealthSnapshot, error) {
	endpoints := make([]netip.AddrPort, len(servers))
	for index, server := range servers {
		endpoints[index] = server.Endpoint
	}
	s.dataPlaneMu.Lock()
	if expectedSocket.IsOpen() && discoverer.DiscoverySocket() != expectedSocket {
		s.dataPlaneMu.Unlock()

		return s.configuredCandidates, nil, relay.HealthSnapshot{}, nil
	}
	port := discoverer.DiscoverySocket().Port
	result, err := discoverer.DiscoverEndpoints(ctx, scope, endpoints)
	health := relay.HealthSnapshot{}
	if relayDataPlane, supported := discoverer.(relayHealthDataPlane); supported {
		health = relayDataPlane.RelayHealth()
	}
	s.dataPlaneMu.Unlock()
	if err == nil {
		local, localErr := s.localCandidates(result.Candidates)
		if localErr != nil {
			return pathdiscovery.Set{}, nil, relay.HealthSnapshot{}, fmt.Errorf("merging local endpoints: %w", localErr)
		}
		merged, mergeErr := pathdiscovery.Merge(
			local,
			s.cloudCandidates(port),
			result.Candidates,
		)
		if mergeErr != nil {
			return pathdiscovery.Set{}, nil, relay.HealthSnapshot{}, fmt.Errorf(
				"merging direct endpoints: %w",
				mergeErr,
			)
		}

		return merged,
			append([]pathdiscovery.ServerLatency(nil), result.ServerLatencies...),
			health,
			nil
	}
	if ctx.Err() != nil {
		return pathdiscovery.Set{}, nil, relay.HealthSnapshot{}, ctx.Err()
	}
	if errors.Is(err, pathdiscovery.ErrNoSTUNResponse) ||
		errors.Is(err, pathdiscovery.ErrNoSTUNServers) ||
		errors.Is(err, pathdiscovery.ErrSocketChanged) ||
		errors.Is(err, pathdiscovery.ErrTransportClosed) {
		local, localErr := s.localCandidates(pathdiscovery.Set{})
		if localErr == nil {
			local, localErr = pathdiscovery.Merge(local, s.cloudCandidates(port))
		}
		if localErr != nil {
			return pathdiscovery.Set{}, nil, relay.HealthSnapshot{}, fmt.Errorf("merging local endpoints: %w", localErr)
		}

		return local, nil, health, nil
	}

	return pathdiscovery.Set{}, nil, relay.HealthSnapshot{}, fmt.Errorf(
		"discovering direct endpoints: %w",
		err,
	)
}

func relayRegionLatencies(
	servers []pathdiscovery.RelayServer,
	observed []pathdiscovery.ServerLatency,
	usableRegions []int,
) ([]relay.RegionLatency, error) {
	usable := make(map[int]struct{}, len(usableRegions))
	for _, regionID := range usableRegions {
		if regionID <= 0 {
			return nil, errors.New("daemon: usable relay region is invalid")
		}
		usable[regionID] = struct{}{}
	}
	regions := make(map[netip.AddrPort]int, len(servers))
	for _, server := range servers {
		if server.RegionID <= 0 || !server.Endpoint.IsValid() {
			return nil, errors.New("daemon: relay probe server is invalid")
		}
		if _, exists := regions[server.Endpoint]; exists {
			return nil, errors.New("daemon: relay probe server is duplicated")
		}
		regions[server.Endpoint] = server.RegionID
	}
	latencies := make(map[int]time.Duration, len(observed))
	seen := make(map[netip.AddrPort]struct{}, len(observed))
	for _, latency := range observed {
		regionID, exists := regions[latency.Server]
		if !exists || latency.Latency <= 0 {
			return nil, errors.New("daemon: relay latency observation is invalid")
		}
		if _, exists := seen[latency.Server]; exists {
			return nil, errors.New("daemon: relay latency observation is duplicated")
		}
		seen[latency.Server] = struct{}{}
		if _, selectable := usable[regionID]; !selectable {
			continue
		}
		current, exists := latencies[regionID]
		if !exists || latency.Latency < current {
			latencies[regionID] = latency.Latency
		}
	}
	regionIDs := make([]int, 0, len(latencies))
	for regionID := range latencies {
		regionIDs = append(regionIDs, regionID)
	}
	slices.Sort(regionIDs)
	result := make([]relay.RegionLatency, 0, len(regionIDs))
	for _, regionID := range regionIDs {
		result = append(result, relay.RegionLatency{
			RegionID: regionID,
			Latency:  latencies[regionID],
		})
	}

	return result, nil
}

// awaitRelayRegion polls relay health until regionID's connection is up or
// relayPreparationWait passes, and returns the last snapshot.
func (s *Service) awaitRelayRegion(
	ctx context.Context,
	relayDataPlane relayHealthDataPlane,
	regionID int,
) (relay.HealthSnapshot, bool) {
	deadline := time.NewTimer(relayPreparationWait)
	defer deadline.Stop()
	ticker := time.NewTicker(relayPreparationTick)
	defer ticker.Stop()
	for {
		s.dataPlaneMu.Lock()
		health := relayDataPlane.RelayHealth()
		s.dataPlaneMu.Unlock()
		for _, region := range health.Regions {
			if region.RegionID == regionID && region.Connected {
				return health, true
			}
		}
		select {
		case <-ctx.Done():
			return health, false
		case <-deadline.C:
			return health, false
		case <-ticker.C:
		}
	}
}

func randomEndpointRefreshDelay() time.Duration {
	span := maxEndpointRefresh - minEndpointRefresh
	random, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(span)))
	if err != nil {
		return minEndpointRefresh + span/2
	}

	return minEndpointRefresh + time.Duration(random.Int64())
}

func stopRefreshTimer(timer *time.Timer) {
	if timer == nil || timer.Stop() {
		return
	}
	select {
	case <-timer.C:
	default:
	}
}

func (s *Service) nextDiscoveryScope() (uint64, error) {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	if s.discoveryScope == math.MaxUint64 {
		return 0, errors.New("daemon: discovery scope is exhausted")
	}
	s.discoveryScope++

	return s.discoveryScope, nil
}

// TrustControl creates a per-profile identity only after the operator-provided
// fingerprint matches HTTPS discovery and the Noise server proves possession.
func (s *Service) TrustControl(ctx context.Context, expectedFingerprint string) (ControlTrust, error) {
	active, err := s.profiles.Active(ctx)
	if err != nil {
		return ControlTrust{}, err
	}

	record, err := s.identities.Get(ctx, active.ID)
	if err == nil {
		canonical, verifyErr := verifyStoredPin(expectedFingerprint, record)
		if verifyErr != nil {
			return ControlTrust{}, fmt.Errorf("%w: %w", ErrControlTrust, verifyErr)
		}
		if verifyErr := s.prober.VerifyTrust(
			ctx,
			active.ControlURL,
			toProtocolMaterial(record.Material()),
			record.ControlKeyFingerprint(),
		); verifyErr != nil {
			return ControlTrust{}, fmt.Errorf("%w: %w", ErrControlTrust, verifyErr)
		}

		return ControlTrust{
			ProfileID:      active.ID,
			Fingerprint:    canonical,
			AlreadyTrusted: true,
		}, nil
	}
	if !errors.Is(err, identity.ErrNotFound) {
		return ControlTrust{}, fmt.Errorf("%w: reading identity: %w", ErrControlTrust, err)
	}

	trusted, err := s.prober.BootstrapTrust(ctx, active.ControlURL, expectedFingerprint)
	if err != nil {
		return ControlTrust{}, fmt.Errorf("%w: %w", ErrControlTrust, err)
	}
	record, err = identity.NewRecord(
		active.ID,
		toIdentityMaterial(trusted.Material),
		trusted.Fingerprint,
		s.clock(),
	)
	if err != nil {
		return ControlTrust{}, fmt.Errorf("%w: creating identity record: %w", ErrControlTrust, err)
	}
	if err := s.identities.Create(ctx, record); err != nil {
		if errors.Is(err, identity.ErrExists) {
			return s.TrustControl(ctx, expectedFingerprint)
		}

		return ControlTrust{}, fmt.Errorf("%w: persisting identity: %w", ErrControlTrust, err)
	}

	return ControlTrust{
		ProfileID:   active.ID,
		Fingerprint: trusted.Fingerprint,
	}, nil
}

// ProbeControl verifies the active profile's HTTPS control-key endpoint. The
// raw server key remains inside the compatibility adapter.
func (s *Service) ProbeControl(ctx context.Context) (ControlProbe, error) {
	active, err := s.profiles.Active(ctx)
	if err != nil {
		return ControlProbe{}, err
	}

	result, err := s.prober.Probe(ctx, active.ControlURL)
	if err != nil {
		return ControlProbe{}, fmt.Errorf("%w: %w", ErrControlProbe, err)
	}

	return ControlProbe{
		ProfileID:        active.ID,
		ControlURL:       active.ControlURL,
		Protocol:         result.Protocol,
		Capability:       result.Capability,
		KeyFingerprint:   result.KeyFingerprint,
		LinkFingerprint:  result.LinkFingerprint,
		NoiseEstablished: result.NoiseEstablished,
		NoiseVersion:     result.NoiseVersion,
	}, nil
}

// Status returns a point-in-time view and honors caller cancellation.
func (s *Service) Status(ctx context.Context) (Status, error) {
	if err := ctx.Err(); err != nil {
		return Status{}, err
	}

	snapshot := s.profiles.Snapshot()
	controlTrust := ControlTrustUnconfigured
	registration := RegistrationUnregistered
	controlFingerprint := ""
	if snapshot.ActiveProfileID != "" {
		record, err := s.identities.Get(ctx, snapshot.ActiveProfileID)
		switch {
		case err == nil:
			controlTrust = ControlTrustPinned
			controlFingerprint = record.ControlKeyFingerprint()
			switch {
			case record.IsRegistered():
				registration = RegistrationRegistered
			case record.HasPendingAuth():
				registration = RegistrationPending
			}
		case errors.Is(err, identity.ErrNotFound):
		default:
			return Status{}, fmt.Errorf("reading active identity status: %w", err)
		}
	}

	syncState := s.getSyncStatus()
	if syncState.profileID != snapshot.ActiveProfileID {
		syncState = syncStatus{state: ControlSessionInactive}
	}

	dataPlaneState := syncState.dataPlane
	if dataPlaneState == "" {
		dataPlaneState = s.defaultDataPlaneState()
	}
	dnsState := syncState.dns
	if dnsState == "" {
		dnsState = DNSInactive
	}
	compatibilityNote := "control synchronization is available; encrypted tunnel is not active"
	switch dataPlaneState {
	case string(dataplane.StateIdle):
		compatibilityNote = "data plane is enabled; no authorized peer path is active"
	case string(dataplane.StateTUNReady):
		compatibilityNote = "tun descriptor is ready; encryption, routes, dns, and packet forwarding are not active"
	case string(dataplane.StateWaitingEndpoint):
		compatibilityNote = "encrypted direct path is waiting for a peer endpoint"
	case string(dataplane.StatePolicyUnsupported):
		compatibilityNote = "encrypted path is fail-closed because the current packet gate cannot enforce this policy safely"
	case string(dataplane.StateEncrypted):
		if dnsState == DNSConfigured {
			compatibilityNote = "encrypted direct path, host packet policy, and dns are active; no usable signed relay is available and generalized routes are not implemented"
		} else {
			compatibilityNote = "encrypted direct path and host packet policy are active; no usable signed relay is available, dns is not active, and generalized routes are not implemented"
		}
	case string(dataplane.StateEncryptedRelay):
		if dnsState == DNSConfigured {
			compatibilityNote = "encrypted mesh with bounded relay fallback, authenticated direct paths, host packet policy, and dns is active; generalized routes are not implemented"
		} else {
			compatibilityNote = "encrypted mesh with bounded relay fallback, authenticated direct paths, and host packet policy is active; dns is not active and generalized routes are not implemented"
		}
	case string(dataplane.StateFailed):
		compatibilityNote = "data plane failed closed; encrypted tunnel is not active"
	}
	daemonState := StateOffline
	// Reconnecting keeps the last map: the mesh still works.
	if syncState.state == ControlSessionSynchronized || syncState.state == ControlSessionReconnecting {
		daemonState = StateOnline
	}
	peerPaths, relayStatus, subnetRoutes := s.dataPlaneStatus()

	return Status{
		Build:              s.build,
		State:              daemonState,
		DataPlane:          dataPlaneState,
		DNS:                dnsState,
		DNSError:           s.currentDNSFailure(dnsState),
		ActiveProfileID:    snapshot.ActiveProfileID,
		ProfileCount:       len(snapshot.Profiles),
		CompatibilityNote:  compatibilityNote,
		ControlTrust:       controlTrust,
		Registration:       registration,
		ControlFingerprint: controlFingerprint,
		ControlSession:     syncState.state,
		NetmapRevision:     syncState.revision,
		NetworkName:        syncState.networkName,
		SelfAddresses:      append([]string(nil), syncState.selfAddresses...),
		DeviceExpiresAt:    deviceExpiryOf(registration, syncState),
		DeviceExpiry:       DeviceExpiryState(deviceExpiryOf(registration, syncState), s.clock()),
		PeerCount:          syncState.peerCount,
		PolicyRuleCount:    syncState.policyRuleCount,
		PeerPaths:          peerPaths,
		SubnetRoutes:       subnetRoutes,
		RouteSites:         s.routeSitesSnapshot(),
		SubnetRouter:       s.subnetRouterStatus(),
		ExitNode:           s.exitNodeStatus(),
		Exit:               s.exitSnapshot(),
		ExitRoute:          s.exitRouteStatus(),
		Captive:            s.captiveView(),
		PathProbes:         s.pathProbeStatus(),
		Relay:              relayStatus,
		NetworkChanges: NetworkChangeStatus{
			Available:         s.networkChanges != nil,
			Observed:          s.networkObserved.Load(),
			EndpointRefreshes: s.networkRefreshes.Load(),
		},
		RuntimeRecovery: RuntimeRecoveryStatus{
			Failures:   s.runtimeFailures.Load(),
			Recoveries: s.runtimeRecoveries.Load(),
			Pending:    s.runtimePending.Load(),
		},
		Runtime:     runtimehealth.Read(),
		NAT:         s.natStatus(),
		PortMapping: s.portMappingStatus(),
		Cloud:       s.cloudStatus(),
	}, nil
}

func (s *Service) pathProbeStatus() PathProbeStatus {
	if s == nil {
		return PathProbeStatus{}
	}
	_, hasTransport := s.dataPlane.(peerProbeDataPlane)
	_, hasEndpointControl := s.dataPlane.(preferredEndpointDataPlane)

	return PathProbeStatus{
		Available: hasTransport && hasEndpointControl,
		Snapshot:  s.pathProbes.Snapshot(),
	}
}

func (s *Service) recordRuntimeRecovery() {
	if s.runtimePending.Swap(false) {
		s.runtimeRecoveries.Add(1)
	}
}

func (s *Service) subnetRouterStatus() dataplane.SubnetRouterStatus {
	if s == nil || s.dataPlane == nil {
		return dataplane.SubnetRouterStatus{}
	}
	s.dataPlaneMu.Lock()
	defer s.dataPlaneMu.Unlock()
	if reporter, supported := s.dataPlane.(subnetRouterStatusDataPlane); supported {
		return reporter.SubnetRouter()
	}
	return dataplane.SubnetRouterStatus{}
}

func (s *Service) dataPlaneStatus() (dataplane.PeerPathSnapshot, relay.HealthSnapshot, dataplane.SubnetRouteStatus) {
	if s == nil || s.dataPlane == nil {
		return dataplane.PeerPathSnapshot{}, relay.HealthSnapshot{}, dataplane.SubnetRouteStatus{}
	}
	s.dataPlaneMu.Lock()
	defer s.dataPlaneMu.Unlock()

	peerPaths := dataplane.PeerPathSnapshot{}
	if reporter, supported := s.dataPlane.(peerPathStatusDataPlane); supported {
		peerPaths = reporter.PeerPaths()
	}
	relayStatus := relay.HealthSnapshot{}
	if reporter, supported := s.dataPlane.(relayStatusDataPlane); supported {
		relayStatus = reporter.RelayHealth()
	}
	relayStatus.Regions = append([]relay.RegionHealth(nil), relayStatus.Regions...)
	subnetRoutes := dataplane.SubnetRouteStatus{}
	if reporter, supported := s.dataPlane.(subnetRouteStatusDataPlane); supported {
		subnetRoutes = reporter.SubnetRoutes()
	}

	return peerPaths, relayStatus, subnetRoutes
}

// StartLogin registers the active profile with either an in-memory auth key or
// an interactive browser flow. The auth key is never persisted.
func (s *Service) StartLogin(ctx context.Context, authKey string) (Login, error) {
	if s.gateway {
		// A gateway joins its cluster (JoinCluster), never logs in.
		return Login{}, ErrGatewayModeMismatch
	}
	release, err := s.acquireRegistration(ctx)
	if err != nil {
		return Login{}, err
	}
	defer release()

	return s.register(ctx, authKey, "")
}

// CompleteLogin performs a short follow-up poll using the persisted browser URL.
func (s *Service) CompleteLogin(ctx context.Context) (Login, error) {
	return s.completeLogin(ctx, completionPollTimeout)
}

// RotateNodeKey stages a fresh key durably, requests one authenticated remote
// transition, then promotes the staged key only after remote success.
func (s *Service) RotateNodeKey(ctx context.Context) (NodeKeyRotation, error) {
	release, err := s.acquireRegistration(ctx)
	if err != nil {
		return NodeKeyRotation{}, err
	}
	defer release()

	result, rotated, err := s.rotateNodeKeyLocked(ctx, true)
	if err != nil {
		return NodeKeyRotation{}, err
	}
	if !rotated {
		return NodeKeyRotation{}, ErrNodeKeyRotation
	}
	s.signalControlSync()

	return result, nil
}

func (s *Service) resumeNodeKeyRotation(ctx context.Context) (bool, error) {
	release, err := s.acquireRegistration(ctx)
	if err != nil {
		return false, err
	}
	defer release()

	_, rotated, err := s.rotateNodeKeyLocked(ctx, false)
	if err != nil {
		return false, err
	}

	return rotated, nil
}

func (s *Service) rotateNodeKeyLocked(
	ctx context.Context,
	createPending bool,
) (NodeKeyRotation, bool, error) {
	active, err := s.profiles.Active(ctx)
	if err != nil {
		return NodeKeyRotation{}, false, err
	}
	record, err := s.identities.Get(ctx, active.ID)
	if errors.Is(err, identity.ErrNotFound) {
		return NodeKeyRotation{}, false, ErrControlNotTrusted
	}
	if err != nil {
		return NodeKeyRotation{}, false, fmt.Errorf("%w: reading identity: %w", ErrNodeKeyRotation, err)
	}
	if !record.IsRegistered() || record.HasPendingAuth() {
		return NodeKeyRotation{}, false, fmt.Errorf("%w: node is not registered", ErrNodeKeyRotation)
	}
	pendingNodePrivateKey := record.PendingNodePrivateKey()
	if len(pendingNodePrivateKey) == 0 {
		if !createPending {
			return NodeKeyRotation{}, false, nil
		}
		pendingNodePrivateKey, err = controlplane.GenerateNodePrivateKey()
		if err != nil {
			return NodeKeyRotation{}, false, fmt.Errorf("%w: %w", ErrNodeKeyRotation, err)
		}
		record, err = s.identities.BeginNodeKeyRotation(
			ctx,
			active.ID,
			pendingNodePrivateKey,
		)
		if err != nil {
			clear(pendingNodePrivateKey)

			return NodeKeyRotation{}, false, fmt.Errorf("%w: staging new key: %w", ErrNodeKeyRotation, err)
		}
	}
	defer clear(pendingNodePrivateKey)

	identityMaterial := record.Material()
	protocolMaterial := toProtocolMaterial(identityMaterial)
	clearIdentityMaterial(identityMaterial)
	defer clearProtocolMaterial(protocolMaterial)
	result, err := s.prober.RotateNodeKey(
		ctx,
		active.ControlURL,
		protocolMaterial,
		pendingNodePrivateKey,
		controlplane.RegisterOptions{
			Hostname:          s.hostname,
			Version:           s.product() + "/" + s.build.Version,
			PinnedFingerprint: record.ControlKeyFingerprint(),
		},
	)
	if errors.Is(err, controlplane.ErrNodeKeyRotationRefused) {
		// Control did not apply it and keeps the current key: drop the staged
		// key so the Device goes on with the current one instead of waiting.
		persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rotationPersistTimeout)
		defer cancel()
		if _, abandonErr := s.identities.AbandonNodeKeyRotation(persistCtx, active.ID, pendingNodePrivateKey); abandonErr != nil {
			// Not ErrNodeKeyRotationRefused: the key stays staged and is retried.
			return NodeKeyRotation{}, false, fmt.Errorf("%w: discarding refused key: %w", ErrNodeKeyRotation, abandonErr)
		}
	}
	if err != nil {
		return NodeKeyRotation{}, false, fmt.Errorf("%w: %w", ErrNodeKeyRotation, err)
	}
	if result.State != controlplane.RegistrationStateAuthorized || !result.MachineAuthorized {
		return NodeKeyRotation{}, false, fmt.Errorf("%w: control returned non-authoritative result", ErrNodeKeyRotation)
	}
	persistCtx, cancel := context.WithTimeout(
		context.WithoutCancel(ctx),
		rotationPersistTimeout,
	)
	defer cancel()
	if _, err := s.identities.CompleteNodeKeyRotation(
		persistCtx,
		active.ID,
		pendingNodePrivateKey,
	); err != nil {
		return NodeKeyRotation{}, false, fmt.Errorf("%w: promoting confirmed key: %w", ErrNodeKeyRotation, err)
	}

	return NodeKeyRotation{ProfileID: active.ID, State: nodeKeyRotationCompleted}, true, nil
}

func (s *Service) completeLogin(ctx context.Context, pollTimeout time.Duration) (Login, error) {
	release, err := s.acquireRegistration(ctx)
	if err != nil {
		return Login{}, err
	}
	defer release()

	active, err := s.profiles.Active(ctx)
	if err != nil {
		return Login{}, err
	}
	record, err := s.identities.Get(ctx, active.ID)
	if errors.Is(err, identity.ErrNotFound) {
		return Login{}, ErrControlNotTrusted
	}
	if err != nil {
		return Login{}, fmt.Errorf("reading identity for login completion: %w", err)
	}
	if !record.HasPendingAuth() {
		return Login{}, ErrNoPendingAuthorization
	}

	pollCtx, cancel := context.WithTimeout(ctx, pollTimeout)
	defer cancel()
	result, err := s.registerWithRecord(
		pollCtx,
		ctx,
		active,
		record,
		"",
		record.PendingAuthURL(),
	)
	if err != nil {
		if ctx.Err() != nil {
			return Login{}, ctx.Err()
		}
		if errors.Is(err, controlplane.ErrRegistrationTemporary) {
			if err := waitForCompletionPoll(ctx, pollCtx); err != nil {
				return Login{}, err
			}

			return Login{}, fmt.Errorf("%w: %w", ErrAuthorizationPending, err)
		}
		if errors.Is(pollCtx.Err(), context.DeadlineExceeded) {
			return Login{}, ErrAuthorizationPending
		}

		return Login{}, err
	}
	if result.State == RegistrationPending {
		if err := waitForCompletionPoll(ctx, pollCtx); err != nil {
			return Login{}, err
		}
	}

	return result, nil
}

func waitForCompletionPoll(ctx, pollCtx context.Context) error {
	if pollCtx.Err() == nil {
		<-pollCtx.Done()
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	return nil
}

func (s *Service) register(ctx context.Context, authKey, followupURL string) (Login, error) {
	active, err := s.profiles.Active(ctx)
	if err != nil {
		return Login{}, err
	}
	record, err := s.identities.Get(ctx, active.ID)
	if errors.Is(err, identity.ErrNotFound) {
		return Login{}, ErrControlNotTrusted
	}
	if err != nil {
		return Login{}, fmt.Errorf("reading identity for registration: %w", err)
	}
	// An explicit login rechecks the pinned control plane. Only the server knows
	// whether a persisted browser intent is still live or needs replacement.
	// Failure leaves the previous pending URL and identity untouched.
	return s.registerWithRecord(ctx, ctx, active, record, authKey, followupURL)
}

func (s *Service) registerWithRecord(
	requestCtx context.Context,
	stateCtx context.Context,
	active profile.Profile,
	record identity.Record,
	authKey string,
	followupURL string,
) (Login, error) {
	identityMaterial := record.Material()
	protocolMaterial := toProtocolMaterial(identityMaterial)
	clearIdentityMaterial(identityMaterial)
	defer clearProtocolMaterial(protocolMaterial)
	result, err := s.prober.Register(
		requestCtx,
		active.ControlURL,
		protocolMaterial,
		controlplane.RegisterOptions{
			Hostname:          s.hostname,
			Version:           "meshd/" + s.build.Version,
			PinnedFingerprint: record.ControlKeyFingerprint(),
			AuthKey:           authKey,
			FollowupURL:       followupURL,
		},
	)
	if err != nil {
		return Login{}, fmt.Errorf("%w: %w", ErrRegistration, err)
	}

	login := Login{ProfileID: active.ID}
	switch result.State {
	case controlplane.RegistrationStateAuthorized:
		login.State = RegistrationRegistered
		if _, err := s.identities.SetRegistration(stateCtx, active.ID, "", true); err != nil {
			return Login{}, fmt.Errorf("persisting authorized registration: %w", err)
		}
		s.signalControlSync()
	case controlplane.RegistrationStateAuthorizationRequired:
		login.State = RegistrationPending
		login.AuthURL = result.AuthURL
		if _, err := s.identities.SetRegistration(stateCtx, active.ID, result.AuthURL, false); err != nil {
			return Login{}, fmt.Errorf("persisting pending registration: %w", err)
		}
	default:
		return Login{}, fmt.Errorf("%w: unsupported registration state", ErrRegistration)
	}

	return login, nil
}

// stageNextControlKey stores the next control key an authenticated KeyUpdate
// announced, or clears it when next is empty.
func (s *Service) stageNextControlKey(ctx context.Context, profileID string, next []byte) error {
	fingerprint := ""
	if len(next) != 0 {
		raw, err := controlplane.ParseControlPublicKey(next)
		if err != nil {
			return err
		}
		fingerprint = controlplane.ControlKeyFingerprint(raw)
	}
	if _, err := s.identities.StageNextControlKey(ctx, profileID, next, fingerprint); err != nil {
		return err
	}
	if fingerprint != "" && s.logger != nil {
		s.logger.Info("next control key staged", "profile", profileID, "fingerprint", fingerprint)
	}
	return nil
}

// promoteNextControlKey makes the staged next key the profile's control key
// and pin.
func (s *Service) promoteNextControlKey(ctx context.Context, profileID string, next []byte) error {
	record, err := s.identities.PromoteNextControlKey(ctx, profileID, next)
	if err != nil {
		return err
	}
	if s.logger != nil {
		s.logger.Info("control key rotated", "profile", profileID, "fingerprint", record.ControlKeyFingerprint())
	}
	return nil
}

func toIdentityMaterial(material controlplane.KeyMaterial) identity.Material {
	return identity.Material{
		MachinePrivateKey: append([]byte(nil), material.MachinePrivateKey...),
		NodePrivateKey:    append([]byte(nil), material.NodePrivateKey...),
		ControlPublicKey:  append([]byte(nil), material.ControlPublicKey...),
	}
}

func toProtocolMaterial(material identity.Material) controlplane.KeyMaterial {
	return controlplane.KeyMaterial{
		MachinePrivateKey: append([]byte(nil), material.MachinePrivateKey...),
		NodePrivateKey:    append([]byte(nil), material.NodePrivateKey...),
		ControlPublicKey:  append([]byte(nil), material.ControlPublicKey...),
	}
}

// verifyStoredPin compares an operator pin with a trusted profile: a
// "sha256:" fingerprint against the stored one, an enrollment link ck=
// against the stored control key.
func verifyStoredPin(pin string, record identity.Record) (string, error) {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(pin)), "sha256:") {
		return controlplane.VerifyFingerprint(pin, record.ControlKeyFingerprint())
	}
	material := record.Material()
	defer clearIdentityMaterial(material)
	return controlplane.VerifyControlPin(pin, material.ControlPublicKey)
}

func clearIdentityMaterial(material identity.Material) {
	clear(material.MachinePrivateKey)
	clear(material.NodePrivateKey)
	clear(material.ControlPublicKey)
}

func clearProtocolMaterial(material controlplane.KeyMaterial) {
	clear(material.MachinePrivateKey)
	clear(material.NodePrivateKey)
	clear(material.ControlPublicKey)
}

// ListProfiles returns a defensive snapshot of all configured profiles.
func (s *Service) ListProfiles(ctx context.Context) (profile.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return profile.Snapshot{}, err
	}

	return s.profiles.Snapshot(), nil
}

// CreateProfile validates and persists one control-plane profile.
func (s *Service) CreateProfile(
	ctx context.Context,
	input profile.CreateInput,
) (profile.Profile, error) {
	previousActiveID := s.profiles.Snapshot().ActiveProfileID
	created, err := s.profiles.Create(ctx, input)
	if err == nil && previousActiveID == "" {
		s.signalControlSync()
	}

	return created, err
}

// ActivateProfile switches the selected profile without merging network views.
func (s *Service) ActivateProfile(ctx context.Context, id string) (profile.Profile, error) {
	previousActiveID := s.profiles.Snapshot().ActiveProfileID
	selected, err := s.profiles.Activate(ctx, id)
	if err == nil && previousActiveID != selected.ID {
		s.signalControlSync()
	}

	return selected, err
}

func (s *Service) waitForSyncSignal(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.syncSignal:
		return nil
	}
}

// waitForRuntimeRecovery bounds retries after a local map consumer failed.
// A persisted state change interrupts the wait so profile and registration
// transitions are never delayed behind recovery backoff.
func (s *Service) waitForRuntimeRecovery(
	ctx context.Context,
	base time.Duration,
) (bool, error) {
	return s.waitForRuntimeRecoveryAtLeast(ctx, base, 0)
}

// waitForRuntimeRecoveryAtLeast waits like waitForRuntimeRecovery, but never
// less than floor: the wait Core asked for is not cut by the jitter.
func (s *Service) waitForRuntimeRecoveryAtLeast(
	ctx context.Context,
	base time.Duration,
	floor time.Duration,
) (bool, error) {
	if s.runtimeRetryDelay == nil {
		return false, errors.New("daemon: runtime retry delay is unavailable")
	}
	delay := s.runtimeRetryDelay(base)
	if delay < 0 {
		return false, errors.New("daemon: runtime retry delay is invalid")
	}
	delay = max(delay, floor)
	timer := time.NewTimer(delay)
	defer stopRefreshTimer(timer)
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-s.syncSignal:
		return false, nil
	case <-timer.C:
		return true, nil
	}
}

// suspendedRetryDelay is how long a suspended Device waits before asking
// again, given how long it has been suspended.
func suspendedRetryDelay(suspendedFor time.Duration) time.Duration {
	switch {
	case suspendedFor < suspendedFastPeriod:
		return suspendedRetryFast
	case suspendedFor < suspendedMediumPeriod:
		return suspendedRetryMedium
	default:
		return suspendedRetry
	}
}

func nextRuntimeRetry(current time.Duration) time.Duration {
	if current < minRuntimeRetry {
		return minRuntimeRetry
	}
	if current >= maxRuntimeRetry || current > maxRuntimeRetry/2 {
		return maxRuntimeRetry
	}

	return current * 2
}

func runtimeRetryAfterSession(
	current time.Duration,
	synchronizedAt time.Time,
	now time.Time,
) time.Duration {
	if !synchronizedAt.IsZero() && now.Sub(synchronizedAt) >= runtimeRetryReset {
		return minRuntimeRetry
	}

	return current
}

func jitteredRuntimeRetryDelay(base time.Duration) time.Duration {
	if base <= time.Nanosecond {
		return base
	}
	half := base / 2
	random, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(half)))
	if err != nil {
		return half
	}

	return half + time.Duration(random.Int64())
}

func (s *Service) acquireRegistration(ctx context.Context) (func(), error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-s.registrationGate:
		return func() { s.registrationGate <- struct{}{} }, nil
	}
}

func (s *Service) beginRun() bool {
	s.supervisorMu.Lock()
	defer s.supervisorMu.Unlock()
	if s.supervisorRunning {
		return false
	}
	s.supervisorRunning = true

	return true
}

func (s *Service) endRun() {
	s.supervisorMu.Lock()
	s.supervisorRunning = false
	s.supervisorMu.Unlock()
}

func (s *Service) signalControlSync() {
	select {
	case s.syncSignal <- struct{}{}:
	default:
	}
}

func (s *Service) setSyncStatus(status syncStatus) {
	status.selfAddresses = append([]string(nil), status.selfAddresses...)
	s.syncMu.Lock()
	// The Device's expiry outlives a reconnect or a stream Core ended
	// because it expired: only a map of the same profile replaces it, so the
	// warning stays visible when it matters most. Stopping, logging out or an
	// unregistered profile (as on the way to a new registration) drop it.
	if status.selfKeyExpiry.IsZero() && status.profileID != "" && status.profileID == s.syncState.profileID &&
		status.state != ControlSessionInactive && status.state != ControlSessionDown {
		status.selfKeyExpiry = s.syncState.selfKeyExpiry
	}
	s.syncState = status
	s.syncMu.Unlock()
}

// setControlConnected moves a synchronized profile to reconnecting when its
// control connection is lost and back when a new session has a map; every
// other state is left to the session loop.
func (s *Service) setControlConnected(profileID string, connected bool) {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	if s.syncState.profileID != profileID {
		return
	}
	switch {
	case !connected && s.syncState.state == ControlSessionSynchronized:
		s.syncState.state = ControlSessionReconnecting
	case connected && s.syncState.state == ControlSessionReconnecting:
		s.syncState.state = ControlSessionSynchronized
	}
}

func (s *Service) getSyncStatus() syncStatus {
	s.syncMu.RLock()
	defer s.syncMu.RUnlock()

	status := s.syncState
	status.selfAddresses = append([]string(nil), status.selfAddresses...)

	return status
}

func (s *Service) defaultDataPlaneState() string {
	if s.dataPlane == nil {
		return DataPlanePending
	}

	return string(dataplane.StateIdle)
}

func (s *Service) currentDataPlaneState() string {
	status := s.getSyncStatus()
	if status.dataPlane == "" {
		return s.defaultDataPlaneState()
	}

	return status.dataPlane
}

func (s *Service) currentDNSState() string {
	status := s.getSyncStatus()
	if status.dns == "" {
		return DNSInactive
	}

	return status.dns
}

func (s *Service) stopRuntime() error {
	return errors.Join(s.resetDNS(), s.stopDataPlane())
}

// applyNewestDNS applies the DNS of the newest map with the newest local
// router and exit choices, or of snapshot when the failover has none as new:
// a map callback and a local exit change apply DNS concurrently, and the
// older of the two must never land last (an exit route whose resolvers the
// plan lacks answers every Internet name SERVFAIL).
func (s *Service) applyNewestDNS(ctx context.Context, failover *routeFailover, snapshot networkmap.Snapshot) (
	string, error, error,
) {
	s.dnsApplyMu.Lock()
	defer s.dnsApplyMu.Unlock()
	if newest := failover.current(); newest.Revision >= snapshot.Revision && newest.Revision != 0 {
		snapshot = newest
	}
	return s.applyMapDNS(ctx, snapshot)
}

// applyMapDNS applies a map's DNS. When the host refuses it, the mesh names
// are removed rather than left at an earlier map, whose addresses may now
// belong to someone else, and the state is DNSFailed with the failure. The
// last error means the context ended or the names could not be removed.
func (s *Service) applyMapDNS(ctx context.Context, snapshot networkmap.Snapshot) (string, error, error) {
	if infrastructure, ok := s.dns.(dnsInfrastructureController); ok {
		s.dnsEvidenceMu.Lock()
		controlURL := s.dnsControlURL
		s.dnsEvidenceMu.Unlock()
		infrastructure.SetInfrastructureNames(infrastructureNames(controlURL, snapshot))
	}
	configured, err := s.dns.Apply(ctx, snapshot)
	switch {
	case err != nil && ctx.Err() != nil:
		return DNSFailed, err, fmt.Errorf("applying dns configuration: %w", err)
	case err != nil:
		s.recordDNSEvidence(dnsEvidence{known: true, reason: dnsReasonApplyFailed, failure: err.Error()})
		s.logControlSessionFailure("applying dns configuration failed; mesh names are off", err)
		if resetErr := s.resetDNS(); resetErr != nil {
			return DNSFailed, err, fmt.Errorf("applying dns configuration: %w", errors.Join(err, resetErr))
		}
		return DNSFailed, err, nil
	case configured:
		s.recordDNSEvidence(s.appliedDNSEvidence(snapshot))
		return DNSConfigured, nil, nil
	default:
		// Nothing for the host to apply: the digest of what the map holds,
		// none being the empty configuration's.
		s.recordDNSEvidence(s.appliedDNSEvidence(snapshot))
		return DNSInactive, nil, nil
	}
}

// setDNSState records a retried DNS apply on a synchronized session.
func (s *Service) setDNSState(state string) {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	if s.syncState.state == ControlSessionSynchronized {
		s.syncState.dns = state
	}
}

func (s *Service) resetDNS() error {
	if s.dns == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), dnsCleanupTimeout)
	defer cancel()
	if err := s.dns.Reset(ctx); err != nil {
		return fmt.Errorf("resetting dns configuration: %w", err)
	}

	return nil
}

func (s *Service) closeDNS() error {
	if s.dns == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), dnsCleanupTimeout)
	defer cancel()
	if err := s.dns.Close(ctx); err != nil {
		return fmt.Errorf("closing dns configuration: %w", err)
	}

	return nil
}

func (s *Service) stopDataPlane() error {
	if s.dataPlane == nil {
		return nil
	}
	s.dataPlaneMu.Lock()
	err := s.dataPlane.Close()
	s.dataPlaneMu.Unlock()
	if err != nil {
		return fmt.Errorf("closing data plane: %w", err)
	}

	return nil
}

// relayIdentityDataPlane is implemented by data planes that reach
// Interchange relays with the session's disco key.
type relayIdentityDataPlane interface {
	SetRelayIdentity(key.DiscoPrivate)
}

// enforcedPolicyDataPlane reports the digest of the rules its packet filter
// enforces (R1-69).
type enforcedPolicyDataPlane interface {
	EnforcedPolicy() (dataplane.EnforcedPolicy, bool)
}

// enforcementChangesDataPlane signals enforced policy changes that no map
// update carried, such as the route digest once the helper answered.
type enforcementChangesDataPlane interface {
	EnforcementChanges() <-chan struct{}
}

// republishEnforcement sends the enforced policy again after each change
// signalled outside a map update, until ctx ends.
func republishEnforcement(ctx context.Context, changes <-chan struct{}, enforcement *enforcementPublisher) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-changes:
			enforcement.publish()
		}
	}
}

// enforcementPublisher hands the map session the enforced policy with the
// DNS evidence. The map callback, the data plane's changes and new DNS
// evidence each publish; reading both and offering the report under one
// lock keeps an older report from replacing a newer one.
type enforcementPublisher struct {
	mu       sync.Mutex
	reports  chan controlplane.EnforcementReport
	enforced enforcedPolicyDataPlane
	dns      func() dnsEvidence
}

// publish offers the latest enforced policy and DNS evidence, when the
// filter's is known.
func (p *enforcementPublisher) publish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if enforced, known := p.enforced.EnforcedPolicy(); known {
		publishEnforcement(p.reports, enforced, p.dns())
	}
}

// publishEnforcement hands the latest enforced policy to the map session,
// replacing a report that was not sent yet.
func publishEnforcement(reports chan controlplane.EnforcementReport, enforced dataplane.EnforcedPolicy,
	dns dnsEvidence,
) {
	report := withDNSEvidence(controlplane.EnforcementReport{
		Digest: enforced.Digest, Grants: enforced.Grants,
		AppliedAt:   enforced.AppliedAt,
		RouteDigest: enforced.RouteDigest, RouteEntries: enforced.RouteEntries,
	}, dns)
	select {
	case reports <- report:
		return
	default:
	}
	select {
	case <-reports:
	default:
	}
	select {
	case reports <- report:
	default:
	}
}

// notifyLocalEndpoints hands the latest discovered candidates to the
// session's probe runtime, which advertises them in CALL_ME_MAYBE.
func (s *Service) notifyLocalEndpoints(candidates pathdiscovery.Set) {
	s.localEndpointsMu.Lock()
	sink := s.localEndpointSink
	s.localEndpointsMu.Unlock()
	if sink != nil {
		sink(candidates)
	}
}

func (s *Service) setLocalEndpointSink(sink func(pathdiscovery.Set)) {
	s.localEndpointsMu.Lock()
	s.localEndpointSink = sink
	s.localEndpointsMu.Unlock()
}

// discoEndpoints translates discovered candidates to CALL_ME_MAYBE entries.
func discoEndpoints(candidates pathdiscovery.Set) []disco.Endpoint {
	out := make([]disco.Endpoint, 0, candidates.Len())
	for _, candidate := range candidates.Candidates() {
		kind := disco.EndpointHost
		switch candidate.Source() {
		case pathdiscovery.SourceServerReflexive:
			kind = disco.EndpointServerReflex
		case pathdiscovery.SourcePortMapping:
			kind = disco.EndpointPortMapped
		case pathdiscovery.SourceConfigured:
			kind = disco.EndpointStatic
		default:
		}
		out = append(out, disco.Endpoint{Kind: kind, Addr: candidate.Endpoint()})
	}
	return out
}

// The DNS controllers of every platform order resolver Devices by liveness.
var _ dnsLivenessController = (*dnsconfig.Manager)(nil)
