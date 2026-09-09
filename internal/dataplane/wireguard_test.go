package dataplane

import (
	"context"
	"crypto/ecdh"
	"encoding/hex"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/meshtransit/meshd/internal/netadmin"
	"github.com/meshtransit/meshd/internal/networkmap"
	"github.com/meshtransit/meshd/internal/pathdiscovery"
)

func TestWireGuardEngineApply(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	opener := &wireGuardTUNOpener{}
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(opener, 41641, &fakeWireGuardFactory{device: device}, nil)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	state, err := engine.Apply(t.Context(), snapshot, privateKey)
	if err != nil || state != StateEncrypted {
		t.Fatalf("Apply() = %q, %v", state, err)
	}
	if opener.calls != 1 || device.upCalls != 1 || device.configureCalls != 1 {
		t.Fatalf(
			"calls open=%d up=%d configure=%d",
			opener.calls,
			device.upCalls,
			device.configureCalls,
		)
	}
	if !slices.Equal(opener.config.Addresses, snapshot.Self.Addresses) ||
		!slices.Equal(opener.config.Routes, snapshot.Peers[0].Addresses) {
		t.Fatalf("helper config = %#v, want signed host prefixes", opener.config)
	}
	for _, expected := range []string{
		"listen_port=41641",
		"endpoint=203.0.113.20:41641",
		"allowed_ip=100.64.0.4/32",
	} {
		if !strings.Contains(device.configuration, expected) {
			t.Fatalf("configuration is missing %q", expected)
		}
	}
	if state, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil || state != StateEncrypted {
		t.Fatalf("repeat Apply() = %q, %v", state, err)
	}
	if opener.calls != 1 || device.configureCalls != 1 {
		t.Fatalf("repeat calls open=%d configure=%d", opener.calls, device.configureCalls)
	}
	if err := engine.Close(); err != nil || device.closeCalls != 1 {
		t.Fatalf("Close() error=%v calls=%d", err, device.closeCalls)
	}
}

func TestWireGuardEngineReopensTUNWhenSignedRoutesChange(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	opener := &wireGuardTUNOpener{}
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(
		opener,
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if state, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil || state != StateEncrypted {
		t.Fatalf("initial Apply() = %q, %v", state, err)
	}

	newRoute := netip.MustParsePrefix("100.64.0.5/32")
	snapshot.Peers[0].Addresses = []netip.Prefix{newRoute}
	snapshot.Peers[0].AllowedIPs = []netip.Prefix{newRoute}
	snapshot.Policy[0].Sources[0].Prefix = newRoute
	if state, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil || state != StateEncrypted {
		t.Fatalf("changed Apply() = %q, %v", state, err)
	}
	if opener.calls != 2 || device.closeCalls != 1 || device.upCalls != 2 {
		t.Fatalf(
			"changed calls open=%d close=%d up=%d",
			opener.calls,
			device.closeCalls,
			device.upCalls,
		)
	}
	if !slices.Equal(opener.config.Routes, []netip.Prefix{newRoute}) {
		t.Fatalf("changed helper routes = %#v", opener.config.Routes)
	}
}

func TestWireGuardEngineWaitsForEndpoint(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.Peers[0].Endpoints = nil
	opener := &wireGuardTUNOpener{}
	device := &fakeWireGuardDevice{}
	engine, err := newWireGuardEngine(
		opener,
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	state, err := engine.Apply(t.Context(), snapshot, privateKey)
	if err != nil || state != StateWaitingEndpoint || opener.calls != 1 {
		t.Fatalf("Apply() = %q, %v, opens=%d", state, err, opener.calls)
	}
	if device.upCalls != 1 || device.configureCalls != 1 {
		t.Fatalf(
			"device calls up=%d configure=%d",
			device.upCalls,
			device.configureCalls,
		)
	}
	if strings.Contains(device.configuration, "endpoint=") {
		t.Fatalf("pending configuration contains endpoint: %q", device.configuration)
	}
	if !strings.Contains(device.configuration, "allowed_ip=100.64.0.4/32") {
		t.Fatalf("pending configuration is missing peer route: %q", device.configuration)
	}
}

func TestWireGuardEngineDiscoversOnActiveDevice(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.Peers[0].Endpoints = nil
	server := netip.MustParseAddrPort("192.0.2.10:3478")
	candidate, err := pathdiscovery.NewCandidate(
		netip.MustParseAddrPort("198.51.100.20:41641"),
		pathdiscovery.SourceServerReflexive,
	)
	if err != nil {
		t.Fatalf("NewCandidate() error = %v", err)
	}
	candidates, err := pathdiscovery.NewSet([]pathdiscovery.Candidate{candidate})
	if err != nil {
		t.Fatalf("NewSet() error = %v", err)
	}
	device := &fakeWireGuardDevice{
		discoverySocket: pathdiscovery.Socket{Port: 41641, Generation: 3},
		discoveryResult: pathdiscovery.DiscoveryResult{
			Scope:      7,
			Socket:     pathdiscovery.Socket{Port: 41641, Generation: 3},
			Candidates: candidates,
		},
	}
	engine, err := newWireGuardEngine(
		&wireGuardTUNOpener{},
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	engine.hostAddresses = func() ([]netip.Addr, error) { return nil, nil }
	if got := engine.DiscoverySocket(); got != device.discoverySocket {
		t.Fatalf("DiscoverySocket() = %#v, want %#v", got, device.discoverySocket)
	}

	result, err := engine.DiscoverEndpoints(t.Context(), 7, []netip.AddrPort{server})
	if err != nil {
		t.Fatalf("DiscoverEndpoints() error = %v", err)
	}
	if result.Scope != 7 || !result.Candidates.Equal(candidates) {
		t.Fatalf("DiscoverEndpoints() = %#v", result)
	}
	if device.discoveryScope != 7 || !slices.Equal(device.discoveryServers, []netip.AddrPort{server}) {
		t.Fatalf(
			"device discovery scope=%d servers=%v",
			device.discoveryScope,
			device.discoveryServers,
		)
	}
	if err := engine.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if got := engine.DiscoverySocket(); got.IsOpen() {
		t.Fatalf("DiscoverySocket() after Close = %#v", got)
	}
}

func TestWireGuardEngineRejectsDiscoveryWithoutActiveDevice(t *testing.T) {
	t.Parallel()

	engine, err := newWireGuardEngine(
		&wireGuardTUNOpener{},
		41641,
		&fakeWireGuardFactory{},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.DiscoverEndpoints(
		t.Context(),
		1,
		[]netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:3478")},
	); err == nil {
		t.Fatal("DiscoverEndpoints() error = nil")
	}
}

func TestWireGuardEnginePublishesHostCandidateWhenSTUNIsUnavailable(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.Peers[0].Endpoints = nil
	socket := pathdiscovery.Socket{Port: 41641, Generation: 4}
	device := &fakeWireGuardDevice{
		discoverySocket: socket,
		discoveryErr:    pathdiscovery.ErrNoSTUNResponse,
	}
	engine, err := newWireGuardEngine(
		&wireGuardTUNOpener{},
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	engine.hostAddresses = func() ([]netip.Addr, error) {
		return []netip.Addr{
			netip.MustParseAddr("192.168.1.20"),
			snapshot.Self.Addresses[0].Addr(),
		}, nil
	}

	result, err := engine.DiscoverEndpoints(
		t.Context(),
		9,
		[]netip.AddrPort{netip.MustParseAddrPort("192.0.2.10:3478")},
	)
	if err != nil {
		t.Fatalf("DiscoverEndpoints() error = %v", err)
	}
	want := netip.MustParseAddrPort("192.168.1.20:41641")
	got := result.Candidates.Candidates()
	if result.Scope != 9 || result.Socket != socket || len(got) != 1 ||
		got[0].Endpoint() != want || got[0].Source() != pathdiscovery.SourceHost {
		t.Fatalf("DiscoverEndpoints() = %#v, candidates %#v", result, got)
	}
}

func TestWireGuardEnginePublishesHostCandidateWithoutSTUNServer(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.Peers[0].Endpoints = nil
	socket := pathdiscovery.Socket{Port: 41641, Generation: 5}
	device := &fakeWireGuardDevice{discoverySocket: socket}
	engine, err := newWireGuardEngine(
		&wireGuardTUNOpener{},
		41641,
		&fakeWireGuardFactory{device: device},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	if _, err := engine.Apply(t.Context(), snapshot, privateKey); err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	engine.hostAddresses = func() ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.168.1.21")}, nil
	}

	result, err := engine.DiscoverEndpoints(t.Context(), 10, nil)
	if err != nil {
		t.Fatalf("DiscoverEndpoints() error = %v", err)
	}
	if got := result.Candidates.Endpoints(); !slices.Equal(got, []netip.AddrPort{
		netip.MustParseAddrPort("192.168.1.21:41641"),
	}) {
		t.Fatalf("DiscoverEndpoints() candidates = %v", got)
	}
	if device.discoveryCalls != 0 {
		t.Fatalf("device discovery calls = %d, want 0", device.discoveryCalls)
	}
}

func TestWireGuardEngineAcceptsNarrowPolicy(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.Policy[0].Protocols = []uint8{6}
	snapshot.Policy[0].Destinations[0].PortFrom = 18080
	snapshot.Policy[0].Destinations[0].PortTo = 18080
	opener := &wireGuardTUNOpener{}
	engine, err := newWireGuardEngine(
		opener,
		41641,
		&fakeWireGuardFactory{},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	state, err := engine.Apply(t.Context(), snapshot, privateKey)
	if err != nil || state != StateEncrypted || opener.calls != 1 {
		t.Fatalf("Apply() = %q, %v, opens=%d", state, err, opener.calls)
	}
}

func TestWireGuardEngineStartsForOutboundOnlyNode(t *testing.T) {
	t.Parallel()

	privateKey, snapshot := testWireGuardSnapshot(t)
	snapshot.Policy = []networkmap.Rule{}
	opener := &wireGuardTUNOpener{}
	engine, err := newWireGuardEngine(
		opener,
		41641,
		&fakeWireGuardFactory{},
		nil,
	)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	state, err := engine.Apply(t.Context(), snapshot, privateKey)
	if err != nil || state != StateEncrypted || opener.calls != 1 {
		t.Fatalf("Apply() = %q, %v, opens=%d", state, err, opener.calls)
	}
}

func TestNodePrivateKeyFormattingIsRedacted(t *testing.T) {
	t.Parallel()

	key := NodePrivateKey{1, 2, 3}
	if strings.Contains(key.String(), "1") || strings.Contains(key.GoString(), "1") {
		t.Fatal("node private key formatting disclosed key bytes")
	}
}

func testWireGuardSnapshot(t *testing.T) (NodePrivateKey, networkmap.Snapshot) {
	t.Helper()

	privateKey := NodePrivateKey{}
	for index := range privateKey {
		privateKey[index] = byte(index + 1)
	}
	peerPrivate := make([]byte, 32)
	for index := range peerPrivate {
		peerPrivate[index] = byte(index + 33)
	}
	curve := ecdh.X25519()
	self, err := curve.NewPrivateKey(privateKey[:])
	if err != nil {
		t.Fatalf("NewPrivateKey(self) error = %v", err)
	}
	peer, err := curve.NewPrivateKey(peerPrivate)
	if err != nil {
		t.Fatalf("NewPrivateKey(peer) error = %v", err)
	}
	publicText := func(value []byte) string {
		return "nodekey:" + hex.EncodeToString(value)
	}
	selfAddress := netip.MustParsePrefix("100.64.0.3/32")
	peerAddress := netip.MustParsePrefix("100.64.0.4/32")

	return privateKey, networkmap.Snapshot{
		Self: networkmap.Node{
			PublicKey: publicText(self.PublicKey().Bytes()),
			Addresses: []netip.Prefix{selfAddress},
		},
		Peers: []networkmap.Node{{
			PublicKey:         publicText(peer.PublicKey().Bytes()),
			Addresses:         []netip.Prefix{peerAddress},
			AllowedIPs:        []netip.Prefix{peerAddress},
			Endpoints:         []netip.AddrPort{netip.MustParseAddrPort("203.0.113.20:41641")},
			MachineAuthorized: true,
		}},
		Policy: []networkmap.Rule{{
			Sources: []networkmap.Selector{{
				Kind:   networkmap.SelectorPrefix,
				Prefix: peerAddress,
			}},
			Destinations: []networkmap.Destination{{
				Selector: networkmap.Selector{
					Kind:   networkmap.SelectorPrefix,
					Prefix: selfAddress,
				},
				PortFrom: 0,
				PortTo:   65535,
			}},
		}},
	}
}

type wireGuardTUNOpener struct {
	calls  int
	config netadmin.TUNConfig
}

func (o *wireGuardTUNOpener) OpenTUN(
	_ context.Context,
	config netadmin.TUNConfig,
) (netadmin.TUN, error) {
	o.calls++
	o.config = netadmin.TUNConfig{
		Addresses: append([]netip.Prefix{}, config.Addresses...),
		Routes:    append([]netip.Prefix{}, config.Routes...),
	}
	file, err := os.Open(os.DevNull)
	if err != nil {
		return netadmin.TUN{}, err
	}

	return netadmin.TUN{
		File:      file,
		Name:      "mesh0",
		MTU:       1280,
		Addresses: append([]netip.Prefix{}, config.Addresses...),
		Routes:    append([]netip.Prefix{}, config.Routes...),
	}, nil
}

type fakeWireGuardFactory struct {
	device *fakeWireGuardDevice
}

func (f *fakeWireGuardFactory) New(
	*os.File,
	int,
	*policyFilter,
	PacketObserver,
) (wireGuardDevice, error) {
	if f.device == nil {
		f.device = &fakeWireGuardDevice{}
	}

	return f.device, nil
}

type fakeWireGuardDevice struct {
	configuration    string
	configureCalls   int
	upCalls          int
	closeCalls       int
	discoveryScope   uint64
	discoveryServers []netip.AddrPort
	discoverySocket  pathdiscovery.Socket
	discoveryResult  pathdiscovery.DiscoveryResult
	discoveryErr     error
	discoveryCalls   int
}

func (d *fakeWireGuardDevice) Configure(configuration io.Reader) error {
	d.configureCalls++
	encoded, err := io.ReadAll(configuration)
	if err != nil {
		return err
	}
	d.configuration = string(encoded)

	return nil
}

func (d *fakeWireGuardDevice) Up() error {
	d.upCalls++

	return nil
}

func (d *fakeWireGuardDevice) Close() { d.closeCalls++ }

func (d *fakeWireGuardDevice) DiscoverySocket() pathdiscovery.Socket {
	return d.discoverySocket
}

func (d *fakeWireGuardDevice) DiscoverEndpoints(
	_ context.Context,
	scope uint64,
	servers []netip.AddrPort,
) (pathdiscovery.DiscoveryResult, error) {
	d.discoveryCalls++
	d.discoveryScope = scope
	d.discoveryServers = append([]netip.AddrPort(nil), servers...)

	return d.discoveryResult, d.discoveryErr
}
