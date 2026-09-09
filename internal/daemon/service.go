// Package daemon coordinates profile state and the future tunnel engine boundary.
package daemon

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/netip"
	"slices"
	"sync"
	"time"

	peerwire "github.com/meshtransit/meshd/internal/compat/disco"
	"github.com/meshtransit/meshd/internal/compat/ts2021"
	"github.com/meshtransit/meshd/internal/dataplane"
	"github.com/meshtransit/meshd/internal/identity"
	"github.com/meshtransit/meshd/internal/networkmap"
	"github.com/meshtransit/meshd/internal/pathdiscovery"
	"github.com/meshtransit/meshd/internal/peerprobe"
	"github.com/meshtransit/meshd/internal/profile"
	"github.com/meshtransit/meshd/internal/version"
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
	// ErrAuthorizationPending indicates that browser authorization is not complete yet.
	ErrAuthorizationPending = errors.New("daemon: browser authorization is pending")
	// ErrNoPendingAuthorization indicates that there is no browser flow to complete.
	ErrNoPendingAuthorization = errors.New("daemon: no pending browser authorization")
)

const (
	// StateOffline means the daemon is healthy but no data plane is running.
	StateOffline = "offline"
	// StateOnline means an encrypted data plane is actively forwarding packets.
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
	completionPollTimeout = 3 * time.Second
	dnsCleanupTimeout     = 5 * time.Second
	minEndpointRefresh    = 20 * time.Second
	maxEndpointRefresh    = 26 * time.Second
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

type controlProber interface {
	Probe(context.Context, string) (ts2021.Result, error)
	BootstrapTrust(context.Context, string, string) (ts2021.TrustResult, error)
	VerifyTrust(context.Context, string, ts2021.KeyMaterial, string) error
	Register(
		context.Context,
		string,
		ts2021.KeyMaterial,
		ts2021.RegisterOptions,
	) (ts2021.RegistrationResult, error)
	StreamNetmap(
		context.Context,
		string,
		ts2021.KeyMaterial,
		ts2021.NetmapOptions,
		ts2021.NetmapHandler,
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
	clock                func() time.Time
	endpointRefreshDelay func() time.Duration
	newPeerProbeIdentity func() (*peerwire.Identity, error)
	syncSignal           chan struct{}
	dataPlaneMu          sync.Mutex
	syncMu               sync.RWMutex
	syncState            syncStatus
	discoveryScope       uint64
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
	active  bool
	socket  pathdiscovery.Socket
	servers []netip.AddrPort
}

// Options contains host facts and injectable time for the daemon use cases.
type Options struct {
	Hostname           string
	Clock              func() time.Time
	DataPlane          DataPlaneController
	DNS                DNSController
	AdvertiseEndpoints []netip.AddrPort
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

	return &Service{
		profiles:             profiles,
		identities:           identities,
		build:                build,
		prober:               prober,
		dataPlane:            options.DataPlane,
		dns:                  options.DNS,
		hostname:             options.Hostname,
		configuredCandidates: configuredSet,
		clock:                options.Clock,
		endpointRefreshDelay: randomEndpointRefreshDelay,
		newPeerProbeIdentity: peerwire.NewIdentity,
		syncSignal:           make(chan struct{}, 1),
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
	defer func() {
		runErr = errors.Join(runErr, s.closeDNS(), s.stopDataPlane())
	}()

	// Signals raised before the supervisor starts are already reflected in the
	// persisted stores that the first loop iteration reads.
	select {
	case <-s.syncSignal:
	default:
	}
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
		identityMaterial := record.Material()
		protocolMaterial := toProtocolMaterial(identityMaterial)
		clearIdentityMaterial(identityMaterial)
		privateKey := dataplane.NodePrivateKey{}
		if s.dataPlane != nil {
			rawPrivateKey, keyErr := ts2021.NodePrivateRaw(protocolMaterial)
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
		probeIdentity, err := s.newPeerProbeIdentity()
		if err != nil {
			clear(privateKey[:])
			clearProtocolMaterial(protocolMaterial)

			return fmt.Errorf("creating peer-probe identity: %w", err)
		}
		probePublicKey, err := probeIdentity.Public()
		if err != nil {
			probeIdentity.Close()
			clear(privateKey[:])
			clearProtocolMaterial(protocolMaterial)

			return fmt.Errorf("reading peer-probe public key: %w", err)
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
		if dataPlane, supported := s.dataPlane.(peerProbeDataPlane); supported {
			probeDataPlane = dataPlane
			probeRuntime, err = peerprobe.NewRuntime(
				streamCtx,
				probeIdentity,
				&lockedPeerProbeTransport{
					mu:        &s.dataPlaneMu,
					dataPlane: dataPlane,
				},
				nil,
			)
			if err != nil {
				cancel()
				probeIdentity.Close()
				clear(privateKey[:])
				clearProtocolMaterial(protocolMaterial)

				return fmt.Errorf("creating peer-probe runtime: %w", err)
			}
		}
		cleanupSession := func() error {
			if probeRuntime != nil {
				probeRuntime.Close()
			}
			var detachErr error
			if probeDataPlane != nil {
				s.dataPlaneMu.Lock()
				detachErr = probeDataPlane.SetPeerProbeHandler(nil)
				s.dataPlaneMu.Unlock()
			}
			probeIdentity.Close()
			clear(privateKey[:])
			clearProtocolMaterial(protocolMaterial)

			return detachErr
		}
		var discoveryRequests chan endpointRefreshRequest
		var candidateUpdates chan pathdiscovery.Set
		var refreshDone <-chan error
		var sessionDiscoverer endpointDiscoverer
		if discoverer, supported := s.dataPlane.(endpointDiscoverer); supported {
			sessionDiscoverer = discoverer
			discoveryRequests = make(chan endpointRefreshRequest, 1)
			candidateUpdates = make(chan pathdiscovery.Set, 1)
			done := make(chan error, 1)
			refreshDone = done
			go func() {
				done <- s.runEndpointRefresh(
					streamCtx,
					discoveryScope,
					discoverer,
					discoveryRequests,
					candidateUpdates,
				)
			}()
		}
		lastRefreshRequest := endpointRefreshRequest{}
		hasRefreshRequest := false
		go func() {
			streamDone <- s.prober.StreamNetmap(
				streamCtx,
				active.ControlURL,
				protocolMaterial,
				ts2021.NetmapOptions{
					Hostname:           s.hostname,
					Version:            "meshd/" + s.build.Version,
					PinnedFingerprint:  record.ControlKeyFingerprint(),
					PeerProbePublicKey: probePublicKey.String(),
					Candidates:         s.configuredCandidates,
					EndpointUpdates:    candidateUpdates,
				},
				func(callbackCtx context.Context, snapshot networkmap.Snapshot) error {
					if err := callbackCtx.Err(); err != nil {
						return err
					}
					if s.profiles.Snapshot().ActiveProfileID != active.ID {
						return nil
					}
					selfAddresses := make([]string, len(snapshot.Self.Addresses))
					for index, address := range snapshot.Self.Addresses {
						selfAddresses[index] = address.String()
					}
					dataPlaneState := s.defaultDataPlaneState()
					if probeRuntime != nil {
						probeRuntime.Deactivate()
					}
					probeSocket := pathdiscovery.Socket{}
					var probeAttachErr error
					if s.dataPlane != nil {
						s.dataPlaneMu.Lock()
						state, err := s.dataPlane.Apply(callbackCtx, snapshot, privateKey)
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
						_, _, err := probeRuntime.Activate(
							snapshot,
							pathdiscovery.ProbeGeneration{
								Scope:       discoveryScope,
								MapRevision: snapshot.Revision,
								Socket:      probeSocket,
							},
						)
						if err != nil {
							return fmt.Errorf("activating peer probes: %w", err)
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
		case <-streamDone:
			cancel()
			if refreshDone != nil {
				<-refreshDone
			}
			if err := cleanupSession(); err != nil {
				return fmt.Errorf("detaching peer-probe transport: %w", err)
			}
			dataPlaneState := s.currentDataPlaneState()
			dnsState := s.currentDNSState()
			if err := s.stopRuntime(); err != nil {
				dataPlaneState = string(dataplane.StateFailed)
				dnsState = DNSFailed
			}
			if dataPlaneState != string(dataplane.StateFailed) {
				dataPlaneState = s.defaultDataPlaneState()
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
			if err := s.waitForSyncSignal(ctx); err != nil {
				return err
			}
		case <-refreshDone:
			cancel()
			<-streamDone
			if err := cleanupSession(); err != nil {
				return fmt.Errorf("detaching peer-probe transport: %w", err)
			}
			dataPlaneState := s.currentDataPlaneState()
			dnsState := s.currentDNSState()
			if err := s.stopRuntime(); err != nil {
				dataPlaneState = string(dataplane.StateFailed)
				dnsState = DNSFailed
			}
			if dataPlaneState != string(dataplane.StateFailed) {
				dataPlaneState = s.defaultDataPlaneState()
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
			if err := s.waitForSyncSignal(ctx); err != nil {
				return err
			}
		}
	}
}

func endpointRequest(
	snapshot networkmap.Snapshot,
	discoverer endpointDiscoverer,
) (endpointRefreshRequest, error) {
	if len(snapshot.Peers) == 0 {
		return endpointRefreshRequest{}, nil
	}
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
		active:  true,
		socket:  socket,
		servers: append([]netip.AddrPort(nil), servers...),
	}, nil
}

func (r endpointRefreshRequest) equal(other endpointRefreshRequest) bool {
	return r.active == other.active && r.socket == other.socket &&
		slices.Equal(r.servers, other.servers)
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
	updates chan pathdiscovery.Set,
) error {
	if discoverer == nil || requests == nil || updates == nil {
		return errors.New("daemon: endpoint refresh dependencies are missing")
	}
	tracker := pathdiscovery.NewTracker()
	current := endpointRefreshRequest{}
	hasCurrent := false
	var timer *time.Timer
	var timerChannel <-chan time.Time
	defer func() { stopRefreshTimer(timer) }()

	for {
		resetForSocketChange := false
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
			stopRefreshTimer(timer)
			timer = nil
			timerChannel = nil
		case <-timerChannel:
			timer = nil
			timerChannel = nil
		}
		if !hasCurrent {
			continue
		}
		if resetForSocketChange {
			result, err := tracker.Reset(s.clock(), s.configuredCandidates)
			if err != nil {
				return err
			}
			if result.Changed {
				offerLatest(updates, result.Candidates)
			}
		}
		if !current.active {
			result, err := tracker.Reset(s.clock(), s.configuredCandidates)
			if err != nil {
				return err
			}
			if result.Changed {
				offerLatest(updates, result.Candidates)
			}
			hasCurrent = false

			continue
		}

		expired, err := tracker.Expire(s.clock())
		if err != nil {
			return err
		}
		if expired.Changed {
			offerLatest(updates, expired.Candidates)
		}
		observed, err := s.discoverEndpoints(ctx, scope, discoverer, current.servers)
		if err != nil {
			return err
		}
		tracked, err := tracker.Update(s.clock(), observed)
		if err != nil {
			return err
		}
		if tracked.Changed {
			offerLatest(updates, tracked.Candidates)
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
		timer = time.NewTimer(delay)
		timerChannel = timer.C
	}
}

func (s *Service) discoverEndpoints(
	ctx context.Context,
	scope uint64,
	discoverer endpointDiscoverer,
	servers []netip.AddrPort,
) (pathdiscovery.Set, error) {
	s.dataPlaneMu.Lock()
	result, err := discoverer.DiscoverEndpoints(ctx, scope, servers)
	s.dataPlaneMu.Unlock()
	if err == nil {
		merged, mergeErr := pathdiscovery.Merge(
			s.configuredCandidates,
			result.Candidates,
		)
		if mergeErr != nil {
			return pathdiscovery.Set{}, fmt.Errorf("merging direct endpoints: %w", mergeErr)
		}

		return merged, nil
	}
	if ctx.Err() != nil {
		return pathdiscovery.Set{}, ctx.Err()
	}
	if errors.Is(err, pathdiscovery.ErrNoSTUNResponse) ||
		errors.Is(err, pathdiscovery.ErrNoSTUNServers) ||
		errors.Is(err, pathdiscovery.ErrSocketChanged) ||
		errors.Is(err, pathdiscovery.ErrTransportClosed) {
		return s.configuredCandidates, nil
	}

	return pathdiscovery.Set{}, fmt.Errorf("discovering direct endpoints: %w", err)
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
		canonical, verifyErr := ts2021.VerifyFingerprint(
			expectedFingerprint,
			record.ControlKeyFingerprint(),
		)
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
		compatibilityNote = "data-plane poc is enabled; no authorized peer path is active"
	case string(dataplane.StateTUNReady):
		compatibilityNote = "tun descriptor is ready; encryption, routes, dns, and packet forwarding are not active"
	case string(dataplane.StateWaitingEndpoint):
		compatibilityNote = "encrypted direct path is waiting for a peer endpoint"
	case string(dataplane.StatePolicyUnsupported):
		compatibilityNote = "encrypted poc is fail-closed because the current packet gate cannot enforce this policy safely"
	case string(dataplane.StateEncrypted):
		if dnsState == DNSConfigured {
			compatibilityNote = "encrypted direct path, host packet policy, and dns are active; relay and generalized routes are not implemented"
		} else {
			compatibilityNote = "encrypted direct path and host packet policy are active; relay, dns, and generalized routes are not implemented"
		}
	case string(dataplane.StateFailed):
		compatibilityNote = "data-plane poc failed closed; encrypted tunnel is not active"
	}
	daemonState := StateOffline
	if dataPlaneState == string(dataplane.StateEncrypted) {
		daemonState = StateOnline
	}

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
	}, nil
}

// StartLogin registers the active profile with either an in-memory auth key or
// an interactive browser flow. The auth key is never persisted.
func (s *Service) StartLogin(ctx context.Context, authKey string) (Login, error) {
	return s.register(ctx, authKey, "")
}

// CompleteLogin performs a short follow-up poll using the persisted browser URL.
func (s *Service) CompleteLogin(ctx context.Context) (Login, error) {
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

	pollCtx, cancel := context.WithTimeout(ctx, completionPollTimeout)
	defer cancel()
	result, err := s.registerWithRecord(pollCtx, active, record, "", record.PendingAuthURL())
	if err != nil {
		if ctx.Err() != nil {
			return Login{}, ctx.Err()
		}
		if errors.Is(pollCtx.Err(), context.DeadlineExceeded) {
			return Login{}, ErrAuthorizationPending
		}

		return Login{}, err
	}

	return result, nil
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
	if authKey == "" && followupURL == "" && record.HasPendingAuth() {
		return Login{
			ProfileID: active.ID,
			State:     RegistrationPending,
			AuthURL:   record.PendingAuthURL(),
		}, nil
	}

	return s.registerWithRecord(ctx, active, record, authKey, followupURL)
}

func (s *Service) registerWithRecord(
	ctx context.Context,
	active profile.Profile,
	record identity.Record,
	authKey string,
	followupURL string,
) (Login, error) {
	result, err := s.prober.Register(
		ctx,
		active.ControlURL,
		toProtocolMaterial(record.Material()),
		ts2021.RegisterOptions{
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
	case ts2021.RegistrationStateAuthorized:
		login.State = RegistrationRegistered
		if _, err := s.identities.SetRegistration(ctx, active.ID, "", true); err != nil {
			return Login{}, fmt.Errorf("persisting authorized registration: %w", err)
		}
		s.signalControlSync()
	case ts2021.RegistrationStateAuthorizationRequired:
		login.State = RegistrationPending
		login.AuthURL = result.AuthURL
		if _, err := s.identities.SetRegistration(ctx, active.ID, result.AuthURL, false); err != nil {
			return Login{}, fmt.Errorf("persisting pending registration: %w", err)
		}
	default:
		return Login{}, fmt.Errorf("%w: unsupported registration state", ErrRegistration)
	}

	return login, nil
}

func toIdentityMaterial(material ts2021.KeyMaterial) identity.Material {
	return identity.Material{
		MachinePrivateKey: append([]byte(nil), material.MachinePrivateKey...),
		NodePrivateKey:    append([]byte(nil), material.NodePrivateKey...),
		ControlPublicKey:  append([]byte(nil), material.ControlPublicKey...),
	}
}

func toProtocolMaterial(material identity.Material) ts2021.KeyMaterial {
	return ts2021.KeyMaterial{
		MachinePrivateKey: append([]byte(nil), material.MachinePrivateKey...),
		NodePrivateKey:    append([]byte(nil), material.NodePrivateKey...),
		ControlPublicKey:  append([]byte(nil), material.ControlPublicKey...),
	}
}

func clearIdentityMaterial(material identity.Material) {
	clear(material.MachinePrivateKey)
	clear(material.NodePrivateKey)
	clear(material.ControlPublicKey)
}

func clearProtocolMaterial(material ts2021.KeyMaterial) {
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
