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

	"github.com/meshtransit/meshd/internal/netadmin"
	"github.com/meshtransit/meshd/internal/networkmap"
	"github.com/meshtransit/meshd/internal/pathdiscovery"
	"github.com/meshtransit/meshd/internal/relay"
)

const (
	maxWireGuardPeers         = 256
	maxWireGuardRoutes        = 512
	maxWireGuardPeerEndpoints = 128
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
	baseEndpoint        string
	authorizedEndpoints []netip.AddrPort
	allowedIPs          []netip.Prefix
}

type wireGuardPeerState struct {
	key                 [32]byte
	baseEndpoint        string
	currentEndpoint     string
	authorizedEndpoints []netip.AddrPort
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

type wireGuardPlan struct {
	configuration     []byte
	configurationHash [32]byte
	addresses         []netip.Prefix
	routes            []netip.Prefix
	peers             []wireGuardPeerPlan
	pendingEndpoints  bool
	relayConfig       *relay.Config
	relayFingerprint  [32]byte
	hasRelayFallback  bool
}

// WireGuardEngine owns the encrypted userspace packet engine. The daemon
// serializes Apply and Close after stopping the map callback.
type WireGuardEngine struct {
	opener            tunOpener
	factory           wireGuardFactory
	listenPort        uint16
	device            wireGuardDevice
	configurationHash [32]byte
	relayFingerprint  [32]byte
	appliedRevision   uint64
	peers             map[uint64]wireGuardPeerState
	addresses         []netip.Prefix
	routes            []netip.Prefix
	filter            *policyFilter
	observer          PacketObserver
	hostAddresses     func() ([]netip.Addr, error)
}

// NewWireGuard constructs the Linux direct-path POC packet engine.
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
	if len(snapshot.Peers) == 0 {
		_ = e.Close()

		return StateIdle, nil
	}

	plan, err := buildWireGuardPlan(snapshot, privateKey, e.listenPort)
	if err != nil {
		_ = e.Close()

		return StateFailed, err
	}
	defer plan.clearSecrets()

	if e.device != nil {
		if !slices.Equal(e.addresses, plan.addresses) ||
			!slices.Equal(e.routes, plan.routes) ||
			e.relayFingerprint != plan.relayFingerprint {
			_ = e.Close()
		}
	}
	if e.device != nil {
		if e.configurationHash == plan.configurationHash &&
			equalPeerEndpointAuthority(e.peers, plan.peers) {
			if e.appliedRevision == snapshot.Revision {
				return plan.state(), nil
			}
			advanced, err := e.advanceEquivalentPlan(snapshot.Revision, plan.peers)
			if err != nil {
				return StateFailed, err
			}
			if advanced {
				return plan.state(), nil
			}
		}
		if err := e.device.Configure(bytes.NewReader(plan.configuration)); err != nil {
			_ = e.Close()

			return StateFailed, errors.New("dataplane: applying wireguard peer configuration failed")
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

		return StateFailed, errors.New("dataplane: creating wireguard device failed")
	}
	if err := device.Configure(bytes.NewReader(plan.configuration)); err != nil {
		device.Close()

		return StateFailed, errors.New("dataplane: applying wireguard configuration failed")
	}
	if err := device.Up(); err != nil {
		device.Close()

		return StateFailed, errors.New("dataplane: starting wireguard device failed")
	}
	e.device = device
	e.adoptPlan(snapshot.Revision, plan)

	return plan.state(), nil
}

func (p wireGuardPlan) state() State {
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

// SetPreferredEndpoint applies one authenticated path selection to the exact
// peer and map revision currently installed in the tunnel engine.
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

	return e.configurePeerEndpoint(peerID, peer, endpoint.String())
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

	return e.configurePeerEndpoint(peerID, peer, peer.baseEndpoint)
}

// advanceEquivalentPlan binds a new map revision without reopening the shared
// UDP socket. A path selected under the previous revision is first returned to
// its control-plane endpoint so stale path proof cannot cross generations.
func (e *WireGuardEngine) advanceEquivalentPlan(
	revision uint64,
	planned []wireGuardPeerPlan,
) (bool, error) {
	for _, peer := range planned {
		installed := e.peers[peer.id]
		if installed.currentEndpoint != installed.baseEndpoint && installed.baseEndpoint == "" {
			return false, nil
		}
	}
	for _, peer := range planned {
		installed := e.peers[peer.id]
		if err := e.configurePeerEndpoint(peer.id, installed, installed.baseEndpoint); err != nil {
			return false, err
		}
	}
	e.appliedRevision = revision

	return true, nil
}

func (e *WireGuardEngine) configurePeerEndpoint(
	peerID uint64,
	peer wireGuardPeerState,
	endpoint string,
) error {
	if endpoint == "" {
		return ErrPeerEndpointUnavailable
	}
	if peer.currentEndpoint == endpoint {
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
	if err := e.device.Configure(bytes.NewReader(configuration.Bytes())); err != nil {
		_ = e.Close()

		return errors.New("dataplane: applying peer endpoint failed")
	}
	peer.currentEndpoint = endpoint
	e.peers[peerID] = peer

	return nil
}

func (e *WireGuardEngine) adoptPlan(revision uint64, plan wireGuardPlan) {
	e.configurationHash = plan.configurationHash
	e.relayFingerprint = plan.relayFingerprint
	e.appliedRevision = revision
	e.addresses = append([]netip.Prefix(nil), plan.addresses...)
	e.routes = append([]netip.Prefix(nil), plan.routes...)
	e.peers = make(map[uint64]wireGuardPeerState, len(plan.peers))
	for _, peer := range plan.peers {
		e.peers[peer.id] = wireGuardPeerState{
			key:                 peer.key,
			baseEndpoint:        peer.baseEndpoint,
			currentEndpoint:     peer.baseEndpoint,
			authorizedEndpoints: append([]netip.AddrPort(nil), peer.authorizedEndpoints...),
		}
	}
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
	e.relayFingerprint = [32]byte{}
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
	if len(snapshot.Peers) == 0 || len(snapshot.Peers) > maxWireGuardPeers {
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
		if regionID := relayRegions[peerKey]; regionID != 0 {
			baseEndpoint = formatRelayEndpoint(regionID, relay.Key(peerKey))
		} else if directEndpoint.IsValid() {
			baseEndpoint = directEndpoint.String()
		}
		if baseEndpoint == "" {
			pendingEndpoints = true
		}
		plannedPeers = append(plannedPeers, wireGuardPeerPlan{
			id:                  peer.ID,
			key:                 peerKey,
			baseEndpoint:        baseEndpoint,
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
	configuration.WriteString("\nreplace_peers=true\n")
	for _, peer := range plannedPeers {
		configuration.WriteString("public_key=")
		var encodedPublic [64]byte
		hex.Encode(encodedPublic[:], peer.key[:])
		configuration.Write(encodedPublic[:])
		configuration.WriteString("\nprotocol_version=1\n")
		if peer.baseEndpoint != "" {
			configuration.WriteString("endpoint=")
			configuration.WriteString(peer.baseEndpoint)
			configuration.WriteByte('\n')
		}
		configuration.WriteString("replace_allowed_ips=true\n")
		for _, allowedIP := range peer.allowedIPs {
			configuration.WriteString("allowed_ip=")
			configuration.WriteString(allowedIP.String())
			configuration.WriteByte('\n')
		}
	}
	encoded := configuration.Bytes()

	plan := wireGuardPlan{
		configuration:     encoded,
		configurationHash: sha256.Sum256(encoded),
		addresses:         addresses,
		routes:            routes,
		peers:             plannedPeers,
		pendingEndpoints:  pendingEndpoints,
		relayConfig:       relayConfig,
		hasRelayFallback:  relayConfig != nil,
	}
	if relayConfig != nil {
		plan.relayFingerprint = relay.Fingerprint(*relayConfig)
	}

	return plan, nil
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
			installed.baseEndpoint != peer.baseEndpoint ||
			!slices.Equal(installed.authorizedEndpoints, peer.authorizedEndpoints) {
			return false
		}
	}

	return true
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
	home, homeExists := usableRelayRegion(snapshot.Relays, homeRegion)
	if !homeExists {
		return nil, nil
	}
	config := relay.Config{
		PrivateKey: relay.Key(privateKey),
		PublicKey:  relay.Key(publicKey),
		HomeRegion: homeRegion,
		Regions: map[int]relay.Region{
			home.ID: home,
		},
		Peers: make([]relay.Peer, 0, len(snapshot.Peers)),
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
	if len(config.Peers) == 0 {
		clear(config.PrivateKey[:])

		return nil, nil
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
// the same rendezvous region until latency-based selection is published.
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
