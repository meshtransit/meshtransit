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

	"meshtransit.net/client/internal/controlplane"
	"meshtransit.net/client/internal/dataplane"
	"meshtransit.net/client/internal/identity"
	"meshtransit.net/client/internal/networkmap"
	"meshtransit.net/client/internal/pathdiscovery"
	"meshtransit.net/client/internal/peerprobe"
	"meshtransit.net/client/internal/profile"
	"meshtransit.net/client/internal/relay"
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
	minEndpointRefresh    = 20 * time.Second
	maxEndpointRefresh    = 26 * time.Second
	relayPreparationPoll  = 5 * time.Second
)

// Status is the daemon-owned status model before it is mapped to a wire format.
type Status struct {
	Build              version.Info
	State              string
	DataPlane          string
	DNS                string
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
	PeerCount          int
	PolicyRuleCount    int
	PeerPaths          dataplane.PeerPathSnapshot
	PathProbes         PathProbeStatus
	Relay              relay.HealthSnapshot
	NetworkChanges     NetworkChangeStatus
	RuntimeRecovery    RuntimeRecoveryStatus
	Runtime            runtimehealth.Snapshot
	NAT                NATStatus
	PortMapping        PortMappingStatus
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

type peerPathStatusDataPlane interface {
	PeerPaths() dataplane.PeerPathSnapshot
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
	clock                func() time.Time
	runtimeRetryDelay    func(time.Duration) time.Duration
	endpointRefreshDelay func() time.Duration
	newDiscoKey          func() (key.DiscoPrivate, error)
	localEndpointsMu     sync.Mutex
	localEndpointSink    func(pathdiscovery.Set)
	logger               *slog.Logger
	networkChanges       <-chan struct{}
	syncSignal           chan struct{}
	registrationGate     chan struct{}
	dataPlaneMu          sync.Mutex
	supervisorMu         sync.Mutex
	supervisorRunning    bool
	syncMu               sync.RWMutex
	syncState            syncStatus
	discoveryScope       uint64
	networkObserved      atomic.Uint64
	networkRefreshes     atomic.Uint64
	runtimeFailures      atomic.Uint64
	runtimeRecoveries    atomic.Uint64
	runtimePending       atomic.Bool
	pathProbes           *pathdiscovery.ProbeTelemetry
	nat                  *natState
	portMapper           PortMapper
}

type syncStatus struct {
	profileID       string
	state           string
	revision        uint64
	networkName     string
	selfAddresses   []string
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
	servers          []pathdiscovery.RelayServer
}

// Options contains host facts and injectable time for the daemon use cases.
type Options struct {
	EnableDeviceAliases bool
	Hostname            string
	Clock               func() time.Time
	DataPlane           DataPlaneController
	DNS                 DNSController
	Logger              *slog.Logger
	AdvertiseEndpoints  []netip.AddrPort
	NetworkChanges      <-chan struct{}
	// PortMapper maps the WireGuard port on the local gateway; nil turns
	// port mapping off.
	PortMapper PortMapper
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
	if options.Clock == nil {
		options.Clock = time.Now
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

	return &Service{
		profiles:             profiles,
		identities:           identities,
		build:                build,
		prober:               prober,
		dataPlane:            options.DataPlane,
		dns:                  options.DNS,
		hostname:             options.Hostname,
		configuredCandidates: configuredSet,
		enableDeviceAliases:  options.EnableDeviceAliases,
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
		syncState: syncStatus{
			state:     ControlSessionInactive,
			dataPlane: initialDataPlane,
			dns:       DNSInactive,
		},
	}, nil
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
	}()

	// Signals raised before the supervisor starts are already reflected in the
	// persisted stores that the first loop iteration reads.
	select {
	case <-s.syncSignal:
	default:
	}
	runtimeRetry := minRuntimeRetry
	var suspendedSince time.Time
	for {
		if err := ctx.Err(); err != nil {
			return err
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
		if record.HasPendingNodeKeyRotation() {
			resumed, rotationErr := s.resumeNodeKeyRotation(ctx)
			if rotationErr == nil && resumed {
				runtimeRetry = minRuntimeRetry

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
					backoffElapsed, waitErr := s.waitForRuntimeRecovery(ctx, runtimeRetry)
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
		streamCtx, cancel := context.WithCancel(ctx)
		streamDone := make(chan error, 1)
		var probeRuntime *peerprobe.Runtime
		var probeDataPlane peerProbeDataPlane
		var pathController *pathEndpointController
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
		cleanupSession := func() error {
			stopPathStats()
			s.setLocalEndpointSink(nil)
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
		enforcedPolicy, reportsEnforcement := s.dataPlane.(enforcedPolicyDataPlane)
		if reportsEnforcement {
			enforcementReports = make(chan controlplane.EnforcementReport, 1)
		}
		go func() {
			streamDone <- s.prober.StreamNetmap(
				streamCtx,
				active.ControlURL,
				protocolMaterial,
				controlplane.NetmapOptions{
					EnableDeviceAliases: s.enableDeviceAliases,
					Hostname:            s.hostname,
					Version:             "meshd/" + s.build.Version,
					PinnedFingerprint:   record.ControlKeyFingerprint(),
					PeerProbePublicKey:  peerprobe.MapDiscoveryKey(discoKey.Public()),
					Candidates:          s.configuredCandidates,
					EndpointUpdates:     endpointUpdates,
					EnforcementReports:  enforcementReports,
					PathStats:           pathStats,
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
					probeSocket := pathdiscovery.Socket{}
					var probeAttachErr error
					if s.dataPlane != nil {
						s.dataPlaneMu.Lock()
						state, err := s.dataPlane.Apply(callbackCtx, snapshot, privateKey)
						if err == nil && reportsEnforcement {
							if enforced, known := enforcedPolicy.EnforcedPolicy(); known {
								publishEnforcement(enforcementReports, enforced)
							}
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
					if s.dns != nil {
						configured, err := s.dns.Apply(callbackCtx, snapshot)
						if err != nil {
							s.setSyncStatus(syncStatus{
								profileID: active.ID,
								state:     ControlSessionBlocked,
								dataPlane: dataPlaneState,
								dns:       DNSFailed,
							})

							return fmt.Errorf("applying dns configuration: %w", err)
						}
						if configured {
							dnsState = DNSConfigured
						}
					} else if snapshot.DNS != nil {
						dnsState = DNSPending
					}
					s.recordRuntimeRecovery()
					s.setSyncStatus(syncStatus{
						profileID:       active.ID,
						state:           ControlSessionSynchronized,
						revision:        snapshot.Revision,
						networkName:     snapshot.NetworkName,
						selfAddresses:   selfAddresses,
						peerCount:       len(snapshot.Peers),
						policyRuleCount: len(snapshot.Policy),
						dataPlane:       dataPlaneState,
						dns:             dnsState,
					})
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
			recoverable := errors.Is(streamErr, errRuntimeRecovery)
			suspended := errors.Is(streamErr, controlplane.ErrNetmapAuthorityPaused)
			controlState := ControlSessionBlocked
			switch {
			case suspended:
				controlState = ControlSessionSuspended
			case recoverable:
				controlState = ControlSessionConnecting
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
			if suspended {
				// Not a failure: wait for an administrator to resume the Device.
				now := s.clock()
				if suspendedSince.IsZero() || !synchronizedAt.IsZero() {
					suspendedSince = now // suspended in this session, or anew
				}
				if _, err := s.waitForRuntimeRecovery(ctx, suspendedRetryDelay(now.Sub(suspendedSince))); err != nil {
					return err
				}
				runtimeRetry = minRuntimeRetry

				continue
			}
			if recoverable {
				s.runtimeFailures.Add(1)
				s.runtimePending.Store(true)
				runtimeRetry = runtimeRetryAfterSession(
					runtimeRetry,
					synchronizedAt,
					s.clock(),
				)
				backoffElapsed, err := s.waitForRuntimeRecovery(ctx, runtimeRetry)
				if err != nil {
					return err
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
			s.setSyncStatus(syncStatus{
				profileID: active.ID,
				state:     ControlSessionBlocked,
				dataPlane: dataPlaneState,
				dns:       dnsState,
			})
			if runtimeStopErr != nil {
				return fmt.Errorf(
					"stopping runtime after endpoint refresh failure: %w",
					runtimeStopErr,
				)
			}
			if err := s.waitForSyncSignal(ctx); err != nil {
				return err
			}
		}
	}
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
		servers:          append([]pathdiscovery.RelayServer(nil), servers...),
	}, nil
}

func (r endpointRefreshRequest) equal(other endpointRefreshRequest) bool {
	return r.active == other.active && r.periodic == other.periodic &&
		r.socket == other.socket &&
		r.controlHomeRelay == other.controlHomeRelay &&
		slices.Equal(r.usableRelays, other.usableRelays) &&
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
	publish := func(candidates pathdiscovery.Set, preferredRelay int) {
		update := controlplane.EndpointUpdate{
			Candidates:        candidates,
			PreferredRelay:    preferredRelay,
			HasPreferredRelay: true,
		}
		if hasPublished && lastPublished.PreferredRelay == preferredRelay &&
			lastPublished.HasPreferredRelay == update.HasPreferredRelay &&
			lastPublished.Candidates.Equal(candidates) {
			return
		}
		offerLatest(updates, update)
		lastPublished = update
		hasPublished = true
		s.notifyLocalEndpoints(candidates)
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
		case _, open := <-networkChanges:
			if !open {
				networkChanges = nil

				continue
			}
			s.networkObserved.Add(1)
			networkTriggered = true
			stopRefreshTimer(timer)
			timer = nil
			timerChannel = nil
			if s.portMapper != nil {
				s.portMapper.NetworkChanged()
			}
		case <-portChanges:
			// The mapped endpoint changed: publish it now.
			stopRefreshTimer(timer)
			timer = nil
			timerChannel = nil
		}
		if !hasCurrent {
			continue
		}
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
			compatibilityNote = "encrypted direct path and host packet policy are active; no usable signed relay is available, and dns and generalized routes are not implemented"
		}
	case string(dataplane.StateEncryptedRelay):
		if dnsState == DNSConfigured {
			compatibilityNote = "encrypted mesh with bounded relay fallback, authenticated direct paths, host packet policy, and dns is active; generalized routes are not implemented"
		} else {
			compatibilityNote = "encrypted mesh with bounded relay fallback, authenticated direct paths, and host packet policy is active; dns and generalized routes are not implemented"
		}
	case string(dataplane.StateFailed):
		compatibilityNote = "data plane failed closed; encrypted tunnel is not active"
	}
	daemonState := StateOffline
	if syncState.state == ControlSessionSynchronized {
		daemonState = StateOnline
	}
	peerPaths, relayStatus := s.dataPlaneStatus()

	return Status{
		Build:              s.build,
		State:              daemonState,
		DataPlane:          dataPlaneState,
		DNS:                dnsState,
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
		PeerCount:          syncState.peerCount,
		PolicyRuleCount:    syncState.policyRuleCount,
		PeerPaths:          peerPaths,
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

func (s *Service) dataPlaneStatus() (dataplane.PeerPathSnapshot, relay.HealthSnapshot) {
	if s == nil || s.dataPlane == nil {
		return dataplane.PeerPathSnapshot{}, relay.HealthSnapshot{}
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

	return peerPaths, relayStatus
}

// StartLogin registers the active profile with either an in-memory auth key or
// an interactive browser flow. The auth key is never persisted.
func (s *Service) StartLogin(ctx context.Context, authKey string) (Login, error) {
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
			Version:           "meshd/" + s.build.Version,
			PinnedFingerprint: record.ControlKeyFingerprint(),
		},
	)
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
	if s.runtimeRetryDelay == nil {
		return false, errors.New("daemon: runtime retry delay is unavailable")
	}
	delay := s.runtimeRetryDelay(base)
	if delay < 0 {
		return false, errors.New("daemon: runtime retry delay is invalid")
	}
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
	s.syncState = status
	s.syncMu.Unlock()
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

// publishEnforcement hands the latest enforced policy to the map session,
// replacing a report that was not sent yet. Only the map callback sends.
func publishEnforcement(reports chan controlplane.EnforcementReport, enforced dataplane.EnforcedPolicy) {
	report := controlplane.EnforcementReport{
		Digest: enforced.Digest, Grants: enforced.Grants,
		AppliedAt: enforced.AppliedAt,
	}
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
