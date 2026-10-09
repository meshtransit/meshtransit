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
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/meshtransit/meshtransit/client/internal/netadmin"
	"github.com/meshtransit/meshtransit/client/internal/networkmap"
	"github.com/meshtransit/meshtransit/client/internal/packetmeta"
	"github.com/meshtransit/meshtransit/client/internal/pathdiscovery"
	"github.com/meshtransit/meshtransit/client/internal/relay"
)

const (
	maxWireGuardPeers         = 256
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
}

type peerPath uint8

const (
	peerPathPending peerPath = iota
	peerPathDirect
	peerPathRelay
)

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

type peerProbingDevice interface {
	pathdiscovery.DatagramTransport
	SetPeerProbeHandler(pathdiscovery.DatagramHandler)
}

type relayManagingDevice interface {
	RelayHealth() relay.HealthSnapshot
	PrepareRelayRegion(int) error
}

type relayConfiguringDevice interface {
	ReplaceRelayPeers([]relay.Peer) error
}

type wireGuardFactory interface {
	New(
		context.Context,
		*os.File,
		int,
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
}

// WireGuardEngine owns the encrypted userspace packet engine. The daemon
// serializes Apply and Close after stopping the map callback.
type WireGuardEngine struct {
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

	return &WireGuardEngine{
		opener:        opener,
		factory:       factory,
		listenPort:    listenPort,
		filter:        newPolicyFilter(),
		observer:      observer,
		hostAddresses: localHostAddresses,
		clock:         time.Now,
	}, nil
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
	if snapshotHasAliases(snapshot) {
		validated, err := networkmap.ValidateAndClone(snapshot, e.clock().UTC())
		if err != nil {
			_ = e.Close()
			e.filter.UpdateNetwork(networkmap.Snapshot{})
			return StateFailed, err
		}
		snapshot = validated
	}
	if err := e.filter.validateAliasTransition(snapshot); err != nil {
		_ = e.Close()
		e.filter.UpdateNetwork(networkmap.Snapshot{})
		return StateFailed, err
	}
	e.filter.suspendFor(snapshot)
	state, err := e.applySnapshot(ctx, snapshot, privateKey)
	if err != nil {
		e.filter.UpdateNetwork(networkmap.Snapshot{})
		return state, err
	}
	e.filter.resume()
	return state, nil
}

func (e *WireGuardEngine) applySnapshot(
	ctx context.Context,
	snapshot networkmap.Snapshot,
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
	e.filter.UpdateNetwork(snapshot)
	if e.observer != nil {
		e.observer.UpdateNetwork(snapshot)
	}

	plan, err := buildWireGuardPlan(snapshot, privateKey, e.listenPort)
	if err != nil {
		_ = e.Close()

		return StateFailed, err
	}
	defer plan.clearSecrets()

	routesChanged := false
	if e.device != nil {
		if !slices.Equal(e.addresses, plan.addresses) || e.relayTopology != plan.relayTopology {
			_ = e.Close()
		} else if !slices.Equal(e.routes, plan.routes) {
			if _, supported := e.opener.(tunRouteConfigurer); !supported {
				_ = e.Close()
			} else {
				routesChanged = true
			}
		}
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
				if err := e.replaceRelayPeers(plan); err != nil {
					_ = e.Close()

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
					_ = e.Close()

					return StateFailed, err
				}
				e.markPeerSessionResetPending(sessionResets)
				e.relayFingerprint = plan.relayFingerprint
				e.relayTopology = plan.relayTopology

				return plan.state(), nil
			}
		}
		if relayChanged && !relayReplaced {
			if err := e.replaceRelayPeers(plan); err != nil {
				_ = e.Close()

				return StateFailed, err
			}
		}
		if err := e.device.Configure(bytes.NewReader(plan.peerConfiguration)); err != nil {
			_ = e.Close()

			return StateFailed, errors.New("dataplane: applying wireguard peer configuration failed")
		}
		if routesChanged {
			configurer, supported := e.opener.(tunRouteConfigurer)
			if !supported {
				_ = e.Close()

				return StateFailed, errors.New("dataplane: live tun route update is unavailable")
			}
			if err := configurer.ConfigureTUNRoutes(ctx, netadmin.TUNConfig{
				Addresses: append([]netip.Prefix(nil), plan.addresses...),
				Routes:    append([]netip.Prefix(nil), plan.routes...),
			}); err != nil {
				_ = e.Close()

				return StateFailed, fmt.Errorf("dataplane: replacing tun routes: %w", err)
			}
		}
		e.adoptPlan(snapshot.Revision, plan)

		return plan.state(), nil
	}

	tunDevice, err := e.opener.OpenTUN(ctx, netadmin.TUNConfig{
		Addresses: append([]netip.Prefix{}, plan.addresses...),
		Routes:    append([]netip.Prefix{}, plan.routes...),
	})
	if err != nil {
		return StateFailed, fmt.Errorf("dataplane: opening tun: %w", err)
	}
	if err := validateTUN(tunDevice, plan); err != nil {
		if tunDevice.File != nil {
			_ = tunDevice.File.Close()
		}

		return StateFailed, err
	}
	device, err := e.factory.New(
		ctx,
		tunDevice.File,
		tunDevice.MTU,
		e.filter,
		e.observer,
		plan.relayConfig,
	)
	if err != nil {
		_ = tunDevice.File.Close()

		return StateFailed, fmt.Errorf("dataplane: creating wireguard device: %w", err)
	}
	if err := device.Configure(bytes.NewReader(plan.configuration)); err != nil {
		device.Close()

		return StateFailed, fmt.Errorf("dataplane: applying wireguard configuration: %w", err)
	}
	if err := device.Up(); err != nil {
		device.Close()

		return StateFailed, fmt.Errorf("dataplane: starting wireguard device: %w", err)
	}
	e.device = device
	e.adoptPlan(snapshot.Revision, plan)

	return plan.state(), nil
}

func (e *WireGuardEngine) replaceRelayPeers(plan wireGuardPlan) error {
	device, supported := e.device.(relayConfiguringDevice)
	if !supported || plan.relayConfig == nil {
		return errors.New("dataplane: live relay authority update is unavailable")
	}
	if err := device.ReplaceRelayPeers(append([]relay.Peer(nil), plan.relayConfig.Peers...)); err != nil {
		return errors.New("dataplane: replacing relay peer authority failed")
	}

	return nil
}

func (p wireGuardPlan) state() State {
	if len(p.peers) == 0 {
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
	if e == nil || e.device == nil {
		return PeerPathSnapshot{}
	}
	snapshot := PeerPathSnapshot{
		Available:            true,
		PeerCount:            len(e.peers),
		RelayBootstrapCount:  e.relayBootstraps,
		DirectPromotionCount: e.directPromotions,
		RelayFallbackCount:   e.relayFallbacks,
		LastDirectPromotion:  e.lastPromotion,
		MaxDirectPromotion:   e.maximumPromotion,
	}
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
	if e == nil || e.device == nil || peerID == 0 {
		return ErrPeerEndpointUnavailable
	}
	if mapRevision == 0 || mapRevision != e.appliedRevision {
		return ErrPeerEndpointGeneration
	}
	peer, exists := e.peers[peerID]
	if !exists {
		return ErrPeerEndpointUnavailable
	}
	if !slices.Contains(peer.authorizedEndpoints, endpoint) {
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
		}
		if err := e.resetPeerSessions([]wireGuardPeerPlan{reset}); err != nil {
			_ = e.Close()

			return err
		}
		e.recordPathTransition(&peer, reset.basePath)
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
	if e == nil || e.device == nil || peerID == 0 {
		return ErrPeerEndpointUnavailable
	}
	if mapRevision == 0 || mapRevision != e.appliedRevision {
		return ErrPeerEndpointGeneration
	}
	peer, exists := e.peers[peerID]
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
	writeWireGuardKeepalive(&configuration, path)
	if err := e.device.Configure(bytes.NewReader(configuration.Bytes())); err != nil {
		_ = e.Close()

		return errors.New("dataplane: applying peer endpoint failed")
	}
	e.recordPathTransition(&peer, path)
	peer.currentEndpoint = endpoint
	peer.currentPath = path
	e.peers[peerID] = peer

	return nil
}

func (e *WireGuardEngine) adoptPlan(revision uint64, plan wireGuardPlan) {
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
		}
		if state.basePath == peerPathRelay {
			state.relayStartedAt = now
			e.relayBootstraps++
		}
		e.peers[peer.id] = state
	}
}

func (e *WireGuardEngine) recordPathTransition(peer *wireGuardPeerState, next peerPath) {
	if e == nil || peer == nil || peer.currentPath == next {
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
	if e == nil || e.device == nil {
		return nil
	}
	e.device.Close()
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

func validateTUN(tunDevice netadmin.TUN, plan wireGuardPlan) error {
	if tunDevice.File == nil || tunDevice.Name == "" || tunDevice.MTU < 1280 ||
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
		allRoutes = append(allRoutes, allowedIPs...)
	}
	if len(allRoutes) > maxWireGuardRoutes {
		return wireGuardPlan{}, errors.New("dataplane: route count is outside the allowed range")
	}
	addresses := deduplicatePrefixes(selectedSelfAddresses)
	if len(addresses) == 0 {
		return wireGuardPlan{}, errors.New("dataplane: policy-selected self addresses are invalid")
	}
	routes, err := uniquePrefixes(allRoutes)
	if err != nil {
		return wireGuardPlan{}, err
	}
	for _, route := range routes {
		if slices.Contains(addresses, route) {
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
	writeWireGuardKeepalive(configuration, peer.basePath)
	configuration.WriteString("replace_allowed_ips=true\n")
	for _, allowedIP := range peer.allowedIPs {
		configuration.WriteString("allowed_ip=")
		configuration.WriteString(allowedIP.String())
		configuration.WriteByte('\n')
	}
}

func writeWireGuardKeepalive(configuration *bytes.Buffer, path peerPath) {
	configuration.WriteString("persistent_keepalive_interval=")
	if path == peerPathDirect {
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
		if !exists || installed.key != peer.key ||
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
		if node.STUNOnly {
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
