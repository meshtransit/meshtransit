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
	engine, err := newWireGuardEngine(opener, 41641, &fakeWireGuardFactory{}, nil)
	if err != nil {
		t.Fatalf("newWireGuardEngine() error = %v", err)
	}
	state, err := engine.Apply(t.Context(), snapshot, privateKey)
	if err != nil || state != StateWaitingEndpoint || opener.calls != 0 {
		t.Fatalf("Apply() = %q, %v, opens=%d", state, err, opener.calls)
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
	configuration  string
	configureCalls int
	upCalls        int
	closeCalls     int
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
